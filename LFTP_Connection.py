import math
import enum
import queue
import socket
import os
import threading

from LFTP_config import Header, SERVER_DIR, \
  SERVER_PORT, headerParse, generateISN, \
  SEND_REQUEST_STR, RECV_REQUEST_STR, UNKNOWN, \
  log, warn, debug, MAX_BUFFER_ITEM, \
  INIT_SSTHRESH, MSS, MTU, HEADER_LEN

@enum.unique
class ConnectionState(enum.Enum):
  WAIT_CONNECT = 1
  ACTIVE = 2
@enum.unique
class CongestMode(enum.Enum):
  SLOW_START = 1
  CONGESTING_AVOIDANCE = 2
  FAST_RECOVERY= 3

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

class LFTP_ReceiveCtl:
  def __init__(self):
    # the ack receiver has sent
    self.buffer:list(LFTP_Buffer) = []

class LFTP_Connection():
  def __init__(self, isServer=False):
    self._socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    port = SERVER_PORT if isServer else 0
    self._socket.bind(('127.0.0.1', port))
    self.isServer = isServer
    self.mailbox = queue.Queue()

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
      - dupAck: bool, indicated whether the segment has duplicate ack
      - type: indicating sender or reader, it has type of LFTP_State
      - path: the file path waiting to be transmitted
      - ctl: the control variable of the sender or receiver, it has 
          type of LFTP_SendCtl or LFTP_ReceiveCtl.
      - file: the file to be transmitted
      - LastDataGramSent: the last packet sent most recently, which is
          used for resend function
    '''
    self._table = {}
  
  def listen(self):
    def _listen_handle(self):
      while True:
        segment, addr = self.mailbox.get(block=True)
        self.route(segment, addr)
    threading._start_new_thread(_listen_handle, (self,))
    if self.isServer:
      log('LFTP server begin listening on port: {}'.format(SERVER_PORT))
    while True:
      segment, addr = self._socket.recvfrom(MTU)
      log('{} receive packet (body length: {})'.format(addr, len(segment)-HEADER_LEN))
      self.mailbox.put_nowait((segment, addr))

  # ============================================
  # route
  def route(self, segment, addr):
    header, body = headerParse(segment)

    inOrder = True
    # update control variable
    if addr in self._table:
      connection = self._table[addr]
      connection['dupAck'] = (header.ack < connection['LastByteAck'])
      if not connection['dupAck']:
        connection['LastByteAck'] = header.ack
      if connection['LastByteRecv'] == header.seq \
          or connection['LastByteRecv'] == UNKNOWN:
        bodyLen = len(body)
        bodyLen = 1 if bodyLen == 0 else bodyLen
        connection['LastByteRecv'] = header.seq + bodyLen
      else:
        inOrder = False
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
      elif state == ConnectionState.ACTIVE:
        self._route_active(addr, header, body)
      else:
        warn('known state: {}'.format(state))
    elif inOrder:
      # the connection unestablished
      if header.SYN and self.isServer:
        # the first handshake
        self._newConnectionFrom(addr, header)
      else:
        msg = 'unestablished connection'
        self._response(addr, msg.encode(), REJ=True)
        log('{} reject to server: {}'.format(addr, msg))
    else:
      log('{} disorder segment'.format(addr))

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
    # 激活状态
    self._table[addr]['state'] = ConnectionState.ACTIVE

  def _route_active(self, addr, header:Header, body:bytes):
    if self._table[addr]['type'] == RECV_REQUEST_STR:
      self._handle_recv(addr, header, body)
    elif self._table[addr]['type'] == SEND_REQUEST_STR:
      self._handle_send(addr, header)
    else:
      warn('unknow LFTP state: {}'.format(self._table[addr]['type']))

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

  def _closeConnection(self, addr):
    if addr in self._table:
      if 'file' in self._table[addr]:
        self._table[addr]['file'].close()
      del self._table[addr]
      log('{} close the connection successfully'.format(addr))
    else:
      log('{} close the connection successfully (the connection has been closed before)'.format(addr))
    if not self.isServer:
      exit(0)

  # ============================================
  # 下面这几个函数都涉及超时重发
  def newConnectionTo(self, addr, connectionType, path):
    client_isn = generateISN()
    self._table[addr] = {
      'state': ConnectionState.WAIT_CONNECT,
      'client_isn': client_isn,
      'server_isn': UNKNOWN,
      'LastByteAck': client_isn,
      'LastByteRecv': UNKNOWN,
      'LastByteSent': -1,
      'dupAck': False,
      'type': connectionType,
      'path': path,
      'rwnd': MAX_BUFFER_ITEM * MSS
    }
    if connectionType == SEND_REQUEST_STR:
      self._table[addr]['ctl'] = LFTP_SendCtl(MAX_BUFFER_ITEM*MSS)
      self._table[addr]['file'] = open(path, mode='rb')
      log('waiting to send file to {}'.format(addr))
    elif connectionType == RECV_REQUEST_STR:
      self._table[addr]['ctl'] = LFTP_ReceiveCtl()
      self._table[addr]['file'] = open(path, mode='wb')
      log('waiting to receive file to {}'.format(addr))
    else:
      warn('known creating type')
      exit(0)

    self._response(addr, SYN=True, body=b'')

    while True:
      segment, addr = self._socket.recvfrom(MTU)
      log('{} receive packet (body length: {})'.format(addr, len(segment)-HEADER_LEN))
      self.route(segment, addr)

  def _newConnectionFrom(self, addr, header:Header):
    server_isn = generateISN()
    client_isn = header.seq
    self._table[addr] = {
      'state': ConnectionState.WAIT_CONNECT,
      'client_isn': client_isn,
      'server_isn': server_isn,
      'LastByteAck': server_isn,
      'LastByteRecv': header.seq + 1,
      'LastByteSent': -1,
      'dupAck': False,
      'rwnd': MAX_BUFFER_ITEM * MSS
    }
    self._response(addr, body=b'', SYN=True, ACK=True)
    log('{} wait for connecting'.format(addr))

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

  def _handle_send(self, addr, header:Header):
    connection = self._table[addr]
    ctl = self._table[addr]['ctl']
    ctl.rwnd = header.rwnd
    mode = ctl.mode
    # congest control FSM
    if mode == CongestMode.SLOW_START:
      if connection['dupAck']:
        # duplicate ACK
        connection['dupAck'] += 1
        if connection['dupAck'] == 3:
          ctl.ssthresh = ctl.cwnd // 2
          ctl.cwnd = ctl.ssthresh + 3*MSS
          self._resend(addr, header)
          ctl.mode = CongestMode.FAST_RECOVERY
          log('{} change to fast recovery mode'.format(addr))
      else:
        # new ACK
        ctl.cwnd += MSS
        connection['dupAck'] = 0
        self._sendNewSegments(addr, header)
      if ctl.cwnd >= ctl.ssthresh:
        ctl.mode = CongestMode.CONGESTING_AVOIDANCE
        log('{} change to congesting avoidance mode'.format(addr))
    elif mode == CongestMode.CONGESTING_AVOIDANCE:
      if connection['dupAck']:
        # duplicate ACK
        connection['dupAck'] += 1
        if connection['dupAck'] == 3:
          ctl.mode = CongestMode.FAST_RECOVERY
          log('{} change to fast recovery mode'.format(addr))
          ctl.ssthresh = ctl.cwnd // 2
          ctl.cwnd = ctl.ssthresh + 3*MSS
          self._resend(addr, header)
      else:
        # new ACK
        ctl.cwnd += MSS * (MSS // ctl.cwnd)
        connection['dupAck'] = 0
        self._sendNewSegments(addr, header)
    elif mode == CongestMode.FAST_RECOVERY:
      if connection['dupAck']:
        # duplicate ACK
        ctl.cwnd += MSS
        self._resend(addr, header)
        self._sendNewSegments(addr, header)
      else:
        # new ACK
        ctl.cwnd = ctl.cwnd.ssthresh
        connection['dupAck'] = 0
        ctl.mode = CongestMode.CONGESTING_AVOIDANCE
        log('{} change to congesting avoidance mode'.format(addr))
    else:
      warn('{} known congest mode')
      assert(False)

  def _handle_recv(self, addr, header:Header, body:bytes):
    if len(body) == 0:
      log('{} get segment: (seq: {}, length: 0: empty segment)'.format(addr, header.seq))
      self._response(addr)
      return
    log('{} get segment (seq: {}, length: {})'.format(addr, header.seq, len(body)))
    
    connection = self._table[addr]
    buffer = self._table[addr]['ctl'].buffer
    
    # the variable LastByteRecv should be changed be handle_recv itself
    if len(body) == 0 and connection['LastByteRecv'] == header.seq + 1:
      connection['LastByteRecv'] = header.seq
    elif len(body) != 0 and connection['LastByteRecv'] == header.seq + len(body):
      connection['LastByteRecv'] = header.seq
    
    i = 0
    while i < len(buffer) and header.seq > buffer[i].beg:
      i += 1
    # insert new segment into queue
    if (i < len(buffer) and header.seq != buffer[i].beg) or i == len(buffer):
      buffer.insert(i, LFTP_Buffer(header.seq, header.seq+len(body), body))
    # when buffer is full
    if len(buffer) >= MAX_BUFFER_ITEM:
      buffer.pop(-1)
    while len(buffer) != 0 and buffer[0].beg == connection['LastByteRecv']:
      # correct segment
      self._table[addr]['file'].write(buffer[0].bytes)
      connection['LastByteRecv'] = buffer[0].end
      buffer.pop(0)
      log('{} receive correct segment, seq: {}'.format(addr, header.seq))

    connection['rwnd'] = (MAX_BUFFER_ITEM-len(buffer)) * MSS
    self._response(addr, body=b'')

  def _sendNewSegments(self, addr, header:Header):
    connection = self._table[addr]
    ctl = self._table[addr]['ctl']
    buffer = self._table[addr]['ctl'].buffer

    while len(buffer) and buffer[0].beg < header.ack:
      buffer.pop(0)
    if not (len(buffer) == 0 or buffer[0].beg == header.ack):
      warn('unexpected ack: {}, ({} was expected)'.format(header.ack, connection['LastByteAck']))
      self._closeConnection(addr)
    
    # calculate the new bytes needed to be sent
    waitLen = min(ctl.cwnd, ctl.rwnd) - (connection['LastByteSent'] - connection['LastByteAck'])
    if waitLen <= 0:
      log('{} 0 segment(s) has been sended'.format(addr))
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
      self._finish(addr)
    elif sendBase == len(buffer) and len(buffer) != 0:
      log('{} waiting for segments ack')
    else:
      oriAck = connection['LastByteAck']
      for i in range(sendBase, len(buffer)):
        connection['LastByteAck'] = buffer[i].beg
        self._response(addr, body=buffer[i].bytes)
      connection['LastByteAck'] = oriAck
      connection['LastByteSent'] = buffer[-1].end
      log('{} {} segment(s) has been sended'.format(addr, len(buffer)-sendBase))

  def _resend(self, addr, header:Header):
    connection = self._table[addr]
    if connection['type'] == SEND_REQUEST_STR \
        and len(self._table[addr]['ctl'].buffer) != 0:
      buffer = self._table[addr]['ctl'].buffer[0]
      assert(connection['LastByteAck'] == buffer.beg)
      resHeader = Header(
        seq = connection['LastByteAck'],
        ack = connection['LastByteRecv'],
        rwnd = connection['rwnd'],
      )
      body = buffer.bytes
      self._socket.sendto(resHeader.encode()+body)
    else:
      self._socket.sendto(connection['LastDatagramSent'], addr)

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
    newLastByteSent = 0
    if len(body) == 0:
      newLastByteSent = resHeader.seq + 1
    else:
      newLastByteSent = resHeader.seq + len(body)
    if newLastByteSent > connection['LastByteSent']:
      connection['LastByteSent'] = newLastByteSent
    datagram = resHeader.encode()+body
    self._socket.sendto(datagram, addr)
    connection['LastDatagramSent'] = datagram

class Timer():
  def __init__(self):
    pass
  def setResendFunc(self, addr, func):
    pass
  def _run(self):
    pass