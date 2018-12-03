import enum
import math
import queue
import os
import socket
import signal
import sys
import threading
import time

from LFTP_config import Header, SERVER_DIR, \
  SERVER_PORT, headerParse, generateISN, \
  SEND_REQUEST_STR, RECV_REQUEST_STR, UNKNOWN, \
  log, warn, debug, MAX_BUFFER_ITEM, \
  INIT_SSTHRESH, MSS, MTU, HEADER_LEN, \
  networkEnv, networkEnv_title, \
  SAMPLE_INTERVAL, MAX_TIMEOUT_COUNT

@enum.unique
class ConnectionState(enum.Enum):
  WAIT_CONNECT = 1
  ACTIVE = 2
@enum.unique
class CongestMode(enum.Enum):
  SLOW_START = 1
  CONGESTING_AVOIDANCE = 2
  FAST_RECOVERY= 3
CongestModeStr = {
  CongestMode.SLOW_START: 'slow start',
  CongestMode.CONGESTING_AVOIDANCE: 'congesting avoidance',
  CongestMode.FAST_RECOVERY: 'fast recovery'
}

class LFTP_Buffer:
  def __init__(self, beg, end, bs:bytes):
    self.beg = beg
    self.end = end
    self.bytes = bs

class LFTP_SendCtl:
  def __init__(self, rwnd):
    self.buffer:list(LFTP_Buffer) = []
    self.cwnd = 1
    self.rwnd = rwnd
    self.ssthresh = INIT_SSTHRESH
    self.mode:CongestMode = CongestMode.SLOW_START
    self.dupAckCount = 0

class LFTP_ReceiveCtl:
  def __init__(self):
    # the ack receiver has sent
    self.buffer:list(LFTP_Buffer) = []

class Timer:
  def __init__(self):
    now = time.time()
    self.EstimatedRTT = 1
    self.DevRTT = 0
    self.TimeoutInterval = 1
    self.sampleACK = 0
    self.sendSampleTime = now
    self.lastSampleTime = now
    self.isSampling = True
    self.leaveTime = sys.maxsize
    self.LastDatagramSent = None
    self.timeoutCount = 0

class LFTP_Connection():
  def __init__(self, isServer=False):
    self._socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    port = SERVER_PORT if isServer else 0
    self._socket.bind(('127.0.0.1', port))
    self.isServer = isServer
    self.mailbox = queue.Queue()
    self.LastUpdateTime = time.time()
    self.mutex = threading.Lock()

    '''
    self._table is the table of connection. Each item in the table
    represents one connection. The possible attributes of the item
    are as followed:
      - state: the state of the connection, it has type of 
          ConnectionState.
      - server_isn: It means literally.
      - client_isn: It means literally.
      - LastByteAck: the seq the other side has acknowledge.
      - LastByteSent: the last byte sent
      - LastByteRecv: the last byte received
      - type: indicating sender or reader, it has type of LFTP_State
      - file: the file to be transmitted
      - path: the file path waiting to be transmitted
      - ctl: the control variable of the sender or receiver, it has 
          type of LFTP_SendCtl or LFTP_ReceiveCtl.
      - timer: the timer used to control time out event
      - performTest: dictionary, record the runtime information to 
          check the performance
      - flag: dictionary, record the information about the last
          segment received, the information may be:
          * dupAck: bool, indicated whether the segment has duplicate
                    ack
          * overdue: bool, indicated whether the segment has overdue
    '''
    self._table = {}
  
  def listen(self):
    def _listen_handle(self):
      while True:
        segment, addr = self.mailbox.get(block=True)
        self.route(segment, addr)
    threading._start_new_thread(_listen_handle, (self,))
    self._beginTimer()
    if self.isServer:
      log('LFTP server begin listening on port: {}'.format(SERVER_PORT))
    while True:
      segment, addr = self._socket.recvfrom(MTU)
      self.mailbox.put_nowait((segment, addr))

  def newConnectionTo(self, addr, connectionType, path, performTest=False):
    client_isn = generateISN()
    connection = {
      'state': ConnectionState.WAIT_CONNECT,
      'client_isn': client_isn,
      'server_isn': UNKNOWN,
      'LastByteAck': client_isn,
      'LastByteRecv': UNKNOWN,
      'LastByteSent': -1,
      'type': connectionType,
      'path': path,
      'rwnd': MAX_BUFFER_ITEM * MSS,
      'timer': Timer(),
      'flag': {
        'dupAck': False,
        'overdue': False,
      }
    }
    self._table[addr] = connection
    if performTest:
      connection['performTest'] = {
        'title': networkEnv_title,
        'beginTime': time.time(),
        'time': [0],
        'byte': [0]
      }
    if connectionType == SEND_REQUEST_STR:
      connection['ctl'] = LFTP_SendCtl(MAX_BUFFER_ITEM*MSS)
      connection['file'] = open(path, mode='rb')
      log('waiting to send file to {}'.format(addr))
    elif connectionType == RECV_REQUEST_STR:
      connection['ctl'] = LFTP_ReceiveCtl()
      connection['file'] = open(path, mode='wb')
      log('waiting to receive file to {}'.format(addr))
    else:
      warn('known creating type')
      exit(0)

    self._response(addr, SYN=True, body=b'')
    self._beginTimer()
    print('') # empty line

    while True:
      segment, addr = self._socket.recvfrom(MTU)
      self.route(segment, addr)

  # ============================================
  # route
  @networkEnv
  def route(self, segment, addr):
    with self.mutex:
      header, body = headerParse(segment)

      inOrder = True
      # update control variable
      if addr in self._table:
        connection = self._table[addr]
        connection['flag']['overdue'] = False
        connection['flag']['dupAck'] = (header.ack <= connection['LastByteAck'])
        if not connection['flag']['dupAck']:
          connection['LastByteAck'] = header.ack

        if connection['LastByteRecv'] != UNKNOWN \
            and header.seq < connection['LastByteRecv']:
          inOrder = False
          connection['flag']['overdue'] = True
        elif connection['LastByteRecv'] == UNKNOWN \
            or connection['LastByteRecv'] == header.seq:
          bodyLen = len(body)
          if bodyLen == 0:
            connection['LastByteRecv'] = header.seq + 1
          else:
            connection['LastByteRecv'] = header.seq + bodyLen
        else:
          # the segment comes in advance
          inOrder = False
        assert(not (inOrder and connection['flag']['overdue']))

        # update Estimate RTT
        self._estimateRTT(addr, header, inOrder)

      log('{} [{}]'.format(addr, ' inOrder' if inOrder else 'disOrder'))
      log('datagram: {}, body length: {}'
            .format(header.shortStr(), len(body))
      )
      
      # route
      if header.REJ:
        warn('{} Connection was rejected'.format(addr))
      elif header.FIN and inOrder:
        if header.ACK:
          # the second or fourth wave
          self._closeConnection(addr)
        else:
          # the first or third wave
          if len(body) != 0:
            warn(body.decode())
          self._AllowToClose(addr)
      elif addr in self._table:
        state = self._table[addr]['state']
        if state == ConnectionState.WAIT_CONNECT and inOrder:
          self._route_wait_connect(addr, header, body)
        elif state == ConnectionState.ACTIVE and (header.ACK or header.SYN):
          log('{} drop disorder datagram'.format(addr))
        elif state == ConnectionState.ACTIVE:
          self._route_active(addr, header, body)
        elif not inOrder:
          log('{} drop disorder datagram'.format(addr))
        else:
          warn('known state: {}'.format(state))
      elif inOrder:
        # the connection unestablished
        if header.SYN and self.isServer:
          # the first handshake
          self._newConnectionFrom(addr, header)
        else:
          msg = 'unestablished connection'
          self._reject(addr, header, msg.encode())
          log('{} reject to server: {}'.format(addr, msg))
      else:
        log('{} disorder segment'.format(addr))
      # print empty line
    print('')

  def _route_wait_connect(self, addr, header:Header, body:bytes):
    connection = self._table[addr]
    if header.SYN and header.ACK and connection['server_isn'] == UNKNOWN:
      # the second handshake
      if connection['LastByteAck'] != connection['client_isn'] + 1:
        warn('{} not correct ack'.format(addr))
        return
      connection['server_isn'] = header.seq

      body = connection['type'].encode() + b' ' + connection['path'].encode()
      self._response(addr, ACK=True, body=body)
      log('the second handshake from {}'.format(addr))
    elif header.ACK:
      # the third handshake: 
      #   waiting confirm connection type (sender or reader)
      succ, connectionType, path = self._requestParse(body)
      path = SERVER_DIR + path
      if succ:
        if connectionType == RECV_REQUEST_STR:
          self._newSender(addr, header, path)
          log('{} establish connection: get from server'.format(addr))
        elif connectionType == SEND_REQUEST_STR:
          self._newReceiver(addr, header, path)
          log('{} establish connection: send to server'.format(addr))
        else:
          warn('[exception] known connection type: {}'.format(connectionType))
          return
      else:
        warn('{} can not parse "{}"'.format(addr, body))
        return
    else:
      log('{} unknown message:\nheader: \n{}'.format(addr, header))
      return
    # activate
    self._table[addr]['state'] = ConnectionState.ACTIVE

  def _route_active(self, addr, header:Header, body:bytes):
    if self._table[addr]['type'] == RECV_REQUEST_STR:
      self._handle_recv(addr, header, body)
    elif self._table[addr]['type'] == SEND_REQUEST_STR:
      self._handle_send(addr, header)
    else:
      warn('unknow LFTP state: {}'.format(self._table[addr]['type']))

  # ============================================
  # connection control
  def _newConnectionFrom(self, addr, header:Header):
    self._updateTimer()

    server_isn = generateISN()

    client_isn = header.seq
    self._table[addr] = {
      'state': ConnectionState.WAIT_CONNECT,
      'client_isn': client_isn,
      'server_isn': server_isn,
      'LastByteAck': server_isn,
      'LastByteRecv': header.seq + 1,
      'LastByteSent': -1,
      'rwnd': MAX_BUFFER_ITEM * MSS,
      'timer': Timer(),
      'flag': {
        'dupAck': False,
        'overdue': False,
      }
    }
    self._response(addr, body=b'', SYN=True, ACK=True)
    log('wait for connecting')

  def _newSender(self, addr, header:Header, path:str):
    if not os.path.exists(path):
      self._finish(addr, b'FILE_NOT_FOUND')
      return
    try:
      connection = self._table[addr]
      connection['file'] = open(path, mode='rb')
      connection['type'] = SEND_REQUEST_STR
      connection['ctl'] = LFTP_SendCtl(header.rwnd)
      connection['state'] = ConnectionState.ACTIVE
      self._response(addr, body=b'')
    except IOError as e:
      err = str(e)
      self._finish(addr, err.encode())
      warn('{} {}'.format(addr, err))
    
  def _newReceiver(self, addr, header:Header, path:str):
    if os.path.exists(path):
      oripath = path[len(SERVER_DIR):]
      msg = 'ERROR: file {} has existed in server.'.format(oripath).encode()
      self._finish(addr, msg)
      return
    try:
      connection = self._table[addr]
      connection['file'] = open(path, mode='wb')
      connection['type'] = RECV_REQUEST_STR
      connection['state'] = ConnectionState.ACTIVE
      connection['ctl'] = LFTP_ReceiveCtl()
      self._response(addr, body=b'')
    except IOError as e:
      err = str(e)
      self._finish(addr, err.encode())
      warn('{} {}'.format(addr, err))

  def _closeConnection(self, addr):
    if addr in self._table:
      if 'file' in self._table[addr]:
        self._table[addr]['file'].close()
      if 'performTest' in self._table[addr]:
        import pickle
        test = self._table[addr]['performTest']
        path = test['title']
        with open('performTest/' + path, 'wb') as f:
          pickle.dump({
            'time': test['time'],
            'byte': test['byte']
          }, f)
      del self._table[addr]
      log('{} close the connection successfully'.format(addr))
    else:
      log('{} close the connection successfully (the connection has been closed before)'.format(addr))
    if not self.isServer:
      exit(0)

  # ============================================
  # segment handle and response
  def _handle_send(self, addr, header:Header):
    connection = self._table[addr]
    ctl = self._table[addr]['ctl']
    ctl.rwnd = header.rwnd
    mode = ctl.mode
    log('sender is in the {} mode'.format(CongestModeStr[mode]))

    if connection['flag']['dupAck']:
      log('duplicate ack')
    else:
      log('new ack')
    
    # acknowledge the segment
    buffer = ctl.buffer
    while len(buffer) and buffer[0].beg < header.ack:
      buffer.pop(0)
    
    # congest control FSM
    if mode == CongestMode.SLOW_START:
      if connection['flag']['dupAck']:
        # duplicate ACK
        ctl.dupAckCount += 1
        if ctl.dupAckCount == 3:
          ctl.ssthresh = ctl.cwnd // 2
          ctl.cwnd = ctl.ssthresh + 3*MSS
          self._resend(addr)
          ctl.mode = CongestMode.FAST_RECOVERY
          log('{} change to fast recovery mode'.format(addr))
      else:
        # new ACK
        ctl.cwnd += MSS
        ctl.dupAckCount = 0
        self._sendNewSegments(addr, header)
      if ctl.cwnd >= ctl.ssthresh:
        ctl.mode = CongestMode.CONGESTING_AVOIDANCE
        log('{} change to congesting avoidance mode'.format(addr))
    elif mode == CongestMode.CONGESTING_AVOIDANCE:
      if connection['flag']['dupAck']:
        # duplicate ACK
        ctl.dupAckCount += 1
        if ctl.dupAckCount == 3:
          ctl.mode = CongestMode.FAST_RECOVERY
          log('{} change to fast recovery mode'.format(addr))
          ctl.ssthresh = ctl.cwnd // 2
          ctl.cwnd = ctl.ssthresh + 3*MSS
          self._resend(addr)
      else:
        # new ACK
        ctl.cwnd += MSS * (MSS // ctl.cwnd)
        ctl.dupAckCount = 0
        self._sendNewSegments(addr, header)
    elif mode == CongestMode.FAST_RECOVERY:
      if connection['flag']['dupAck']:
        # duplicate ACK
        ctl.cwnd += MSS
        self._resend(addr)
        self._sendNewSegments(addr, header)
      else:
        # new ACK
        ctl.cwnd = ctl.ssthresh
        ctl.dupAckCount = 0
        ctl.mode = CongestMode.CONGESTING_AVOIDANCE
        self._sendNewSegments(addr, header)
        log('{} change to congesting avoidance mode'.format(addr))
    else:
      warn('{} known congest mode')
      assert(False)
    self._logCongestVar(addr)

  def _handle_recv(self, addr, header:Header, body:bytes):
    connection = self._table[addr]
    buffer = self._table[addr]['ctl'].buffer
    if connection['flag']['overdue']:
      return

    if len(body) == 0:
      log('{} get segment (seq: {}, length: 0: empty segment)'
            .format(addr, header.seq)
      )
      self._response(addr)
      return
    
    # the variable LastByteRecv should be changed by handle_recv itself
    if len(body) == 0 \
          and connection['LastByteRecv'] == header.seq + 1:
      connection['LastByteRecv'] = header.seq
    elif len(body) != 0 \
          and connection['LastByteRecv'] == header.seq + len(body):
      connection['LastByteRecv'] = header.seq
    
    i = 0
    while i < len(buffer) and header.seq > buffer[i].beg:
      i += 1
    # insert new segment into queue
    if i < len(buffer) and header.seq != buffer[i].beg:
      buffer.insert(i, LFTP_Buffer(header.seq, header.seq+len(body), body))
    elif i == len(buffer) and header.seq >= connection['LastByteRecv']:
      buffer.insert(i, LFTP_Buffer(header.seq, header.seq+len(body), body))
    
    # when buffer is full
    if len(buffer) >= MAX_BUFFER_ITEM:
      buffer.pop(-1)

    while len(buffer) != 0 and buffer[0].beg == connection['LastByteRecv']:
      # correct segment
      connection['file'].write(buffer[0].bytes)
      connection['LastByteRecv'] = buffer[0].end
      # record runtime information
      if 'performTest' in connection:
        self._getRuntimeInfo(addr)

      log('{} receive correct segment, seq: {}'.format(addr, buffer[0].beg))
      buffer.pop(0)

    connection['rwnd'] = (MAX_BUFFER_ITEM-len(buffer)) * MSS
    self._response(addr, body=b'')

  def _sendNewSegments(self, addr, header:Header):
    connection = self._table[addr]
    ctl = self._table[addr]['ctl']
    buffer = self._table[addr]['ctl'].buffer

    # calculate the new bytes needed to be sent
    waitLen = min(ctl.cwnd, ctl.rwnd) \
                - (connection['LastByteSent'] - connection['LastByteAck'])
    
    if waitLen <= 0:
      log('{} no segment has been sended'.format(addr))
      self._updateTimer()
      return
    
    # split waitLen bytes into N pieces
    N = math.ceil(waitLen / MSS)
    p = [connection['LastByteSent'] + ((i*waitLen) // N) for i in range(N+1)]
    sendBase = len(buffer)
    for i in range(N):
      b = connection['file'].read(p[i+1] - p[i])
      if len(b) == 0:
        break
      buffer.append(LFTP_Buffer(p[i], p[i+1], b))

    # send segment
    if sendBase == len(buffer) and len(buffer) == 0:
      log('{} transfer finishes, waiting to close connection'.format(addr))
      self._updateTimer()
      self._finish(addr)
    elif sendBase == len(buffer) and len(buffer) != 0:
      log('{} waiting for segments ack'.format(addr))
      self._updateTimer()
    else:
      oriAck = connection['LastByteAck']
      for i in range(sendBase, len(buffer)):
        connection['LastByteAck'] = buffer[i].beg
        self._response(addr, body=buffer[i].bytes)
      connection['LastByteAck'] = oriAck
      connection['LastByteSent'] = buffer[-1].end
      log('{} {} segment(s) has been sended'.format(addr, len(buffer)-sendBase))

  def _resend(self, addr):
    connection = self._table[addr]
    if 'type' in connection and connection['type'] == SEND_REQUEST_STR \
        and len(self._table[addr]['ctl'].buffer) != 0:
      buffer = self._table[addr]['ctl'].buffer[0]

      if not connection['LastByteAck'] == buffer.beg:
        warn('connection[\'LastByteAck\']({}) != buffer.beg({})'.format(
          connection['LastByteAck'], buffer.beg
        ))
        for b in self._table[addr]['ctl'].buffer:
          warn('{} {}'.format(b.beg, b.end))

      resHeader = Header(
        seq = connection['LastByteAck'],
        ack = connection['LastByteRecv'],
        rwnd = connection['rwnd'],
      )
      body = buffer.bytes
    else:
      (resHeader, body) = connection['timer'].LastDatagramSent
    self._socket.sendto(resHeader.encode()+body, addr)
    log('{} resend datagram: {} len: {}'.format(addr, resHeader.shortStr(), len(body)))

  def _finish(self, addr, body:bytes=b''):
    self._response(addr, FIN=True, body=body)
    log('{} waiting to close connection'.format(addr))
  
  def _AllowToClose(self, addr):
    self._response(addr, FIN=True, ACK=True)
    log('{} allow to close connection'.format(addr))
    if addr in self._table:
      self._closeConnection(addr)

  def _response(self, addr, body:bytes=b'', 
          SYN=False, ACK=False, FIN=False, SRC=False, REJ=False):
    connection = self._table[addr]
    resHeader = Header(
      seq  = connection['LastByteAck'],
      ack  = connection['LastByteRecv'],
      rwnd = connection['rwnd'],
      SYN  = SYN,
      ACK  = ACK,
      FIN  = FIN,
      SRC  = SRC,
      REJ  = REJ,
    )
    # update LastByteSent
    newLastByteSent = 0
    if len(body) == 0:
      newLastByteSent = resHeader.seq + 1
    else:
      newLastByteSent = resHeader.seq + len(body)
    if newLastByteSent >= connection['LastByteSent']:
      connection['LastByteSent'] = newLastByteSent
    else:
      warn('not new segment')
      
    # send
    datagram = resHeader.encode()+body
    self._socket.sendto(datagram, addr)

    # timeout control
    timer = connection['timer']
    timer.LastDatagramSent = (resHeader, body)
    timer.TimeoutInterval = timer.EstimatedRTT + 4 * timer.DevRTT
    timer.leaveTime = timer.TimeoutInterval
    timer.timeoutCount = 0
    self._updateTimer()

    # test RTT
    now = time.time()
    if not timer.isSampling and now - timer.lastSampleTime > SAMPLE_INTERVAL:
      timer.isSampling = True
      timer.sendSampleTime = now
      timer.lastSampleTime = now
      timer.sampleACK = resHeader.seq

    log('response: {}　len: {}'.format(resHeader.shortStr(), len(body)))

  def _reject(self, addr, header:Header, body:bytes):
    resHeader = Header(
      seq  = header.ack,
      REJ  = True,
    )
    self._socket.sendto(resHeader.encode()+body, addr)

  # ============================================
  # auxiliary function
  def _requestParse(self, body:bytes) -> (bool, str, str):
    ''' Parse the request.

        Args:
            body: the request body waiting to be parsed

        returns:
            succ: indicates whether the parsing is successful
            connectionType: indicates the type of request
                            (lget lsend)
            path: if succeed, it will be the file path
    '''
    pieces = body.decode().split(' ')
    if len(pieces) != 2:
      return (False, '', '')
    elif (pieces[0] != SEND_REQUEST_STR and pieces[0] != RECV_REQUEST_STR):
      return (False, '', '')
    else:
      return (True, pieces[0], pieces[1])

  def _getRuntimeInfo(self, addr):
    connection = self._table[addr]
    buffer = self._table[addr]['ctl'].buffer
    beg = connection['performTest']['beginTime']
    last = connection['performTest']['byte'][-1]
    length = buffer[0].end - buffer[0].beg
    connection['performTest']['time'].append(time.time()-beg)
    connection['performTest']['byte'].append(last+length)

  def _logCongestVar(self, addr):
    connection = self._table[addr]
    log('LastByteAck: {} LastByteSent: {}'.format(
      connection['LastByteAck'], connection['LastByteSent']
    ))
    ctl = self._table[addr]['ctl']
    log('cwnd: {} rwnd: {} ssthresh: {} dupAckCount: {}'.format(
      ctl.cwnd, ctl.rwnd, ctl.ssthresh, ctl.dupAckCount
    ))
    timer = connection['timer']
    log('EstimatedRTT: {:.2f} TimeoutInterval: {:.2f}'.format(
      timer.EstimatedRTT, timer.TimeoutInterval
    ))

  def _debug_log_buffer(self, buffer):
    debug('buffer: ')
    for b in buffer:
      debug(b.beg, b.end)
  # ============================================
  # timeout control
  def _beginTimer(self):
    timeoutMutex = threading.Lock()
    timeoutMutex.acquire()
    def timing(self):
      while True:
        timeoutMutex.acquire()
        log('time out event happen')
        with self.mutex:
          self._updateTimer()
        # print empty line
        print('')
    threading._start_new_thread(timing, (self,))
    def handle(signnum, frame):
      timeoutMutex.release()
    signal.signal(signal.SIGALRM, handle)

  def _updateTimer(self):
    if len(self._table) == 0:
      nextTimeout = 0
      self.LastUpdateTime = time.time()
    else:
      nextTimeout = sys.maxsize
      
      now = time.time()
      passTime = now - self.LastUpdateTime
      self.LastUpdateTime = now
      waitTooLong = []
      for addr, connection in self._table.items():
        timer = connection['timer']
        timer.leaveTime -= passTime
        if timer.leaveTime <= 0:
          if 'type' in connection and connection['type'] == SEND_REQUEST_STR:
            ctl = connection['ctl']
            ctl.mode = CongestMode.SLOW_START
            ctl.ssthresh = ctl.cwnd // 2
            ctl.cwnd = MSS
            ctl.dupAckCount = 0
            log('change to slow start mode')
            self._logCongestVar(addr)
          self._resend(addr)
          timer.TimeoutInterval *= 2
          timer.leaveTime = timer.TimeoutInterval
          timer.timeoutCount += 1
          if timer.timeoutCount >= MAX_TIMEOUT_COUNT:
            log('{} timeout event has happened {} times, close connection'
              .format(addr, MAX_TIMEOUT_COUNT)
            )
            waitTooLong.append(addr)
        if timer.leaveTime < nextTimeout:
          nextTimeout = timer.leaveTime
      for addr in waitTooLong:
        self._closeConnection(addr)
    signal.setitimer(signal.ITIMER_REAL, nextTimeout)
    log('update timer')

  def _estimateRTT(self, addr, header, inOrder:bool):
    timer = self._table[addr]['timer']
    if not timer.isSampling or not inOrder:
      timer.isSampling = False
      return
    elif header.ack != timer.sampleACK:
      return
    now = time.time()
    sampleRTT = now - timer.sendSampleTime
    alpha = 0.125
    beta = 0.25
    timer.EstimatedRTT = (1-alpha) * timer.EstimatedRTT + alpha * sampleRTT
    timer.DevRTT = (1-beta)*timer.DevRTT+beta*abs(sampleRTT-timer.EstimatedRTT)
    timer.TimeoutInterval = timer.EstimatedRTT + 4 * timer.DevRTT
    timer.isSampling = False