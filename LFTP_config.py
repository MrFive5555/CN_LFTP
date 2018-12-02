import random
import typing
import time

MSS = 1500
HEADER_LEN = 12 # 12B
MTU = MSS + HEADER_LEN

MAX_BUFFER_ITEM = 10
INIT_SSTHRESH = 64 << 10

SEND_REQUEST_STR = 'lsend'
RECV_REQUEST_STR = 'lget'

SERVER_PORT = 2121
SERVER_DIR = 'dir/'

UNKNOWN = 0

class Header():
  """LFTP Header class.

  recored the field in the LFTP header

  Attributes:
      seq: (32b)the accumulated sequence number of the first data byte of this segment for the current session.
      ack: (32b)This acknowledges receipt of all prior bytes (if any).
      rwnd(16b): the receive window length of the receiver.
      SYN: (1b)flag, Synchronize sequence numbers. SYN indicated the request to establish a connection.
      ACK: (1b)flag, indicates that the acknowledgment of SYN or FIN
      FIN: (1b)flag, indicates that request to close the connection
      REJ: (1b)flag, indicates that the end reject to server

  """
  def __init__(self, seq=0, ack=0, rwnd=0, SYN=False, ACK=False, 
               FIN=False, SRC=False, REJ=False, *args, **kwargs):
    self.seq  = seq
    self.ack  = ack
    self.rwnd = rwnd
    self.SYN  = SYN
    self.ACK  = ACK
    self.FIN  = FIN
    self.SRC  = SRC
    self.REJ  = REJ

  def encode(self):
    seq = self.seq.to_bytes(4, 'big')
    ack = self.ack.to_bytes(4, 'big')
    rwnd = self.rwnd.to_bytes(2, 'big')
    flag = 0
    flag |= 1 << 8 if self.SYN else 0
    flag |= 1 << 7 if self.ACK else 0
    flag |= 1 << 6 if self.FIN else 0
    flag |= 1 << 5 if self.SRC else 0
    flag |= 1 << 4 if self.REJ else 0
    flag = flag.to_bytes(2, 'big')
    return seq + ack + rwnd + flag

  def __str__(self):
    string = '' + \
      'seq = {}\n'.format(self.seq) + \
      'ack = {}\n'.format(self.ack) + \
      'rwnd = {}\n'.format(self.rwnd) + \
      'flag: '
    if self.SYN or self.ACK or self.FIN or self.SRC or self.REJ:
      string += 'SYN ' if self.SYN else ''
      string += 'ACK ' if self.ACK else ''
      string += 'FIN ' if self.FIN else ''
      string += 'SRC ' if self.SRC else ''
      string += 'REJ ' if self.REJ else ''
    else:
      string += 'None'
    return string

def headerParse(datagram:bytes) -> (Header, bytes):
  headerByte = datagram[0:HEADER_LEN]
  seq  = int.from_bytes(headerByte[0:4], 'big')
  ack  = int.from_bytes(headerByte[4:8], 'big')
  rwnd = int.from_bytes(headerByte[8:10], 'big')
  flag = int.from_bytes(headerByte[10:12], 'big')

  SYN = flag & 1 << 8 != 0
  ACK = flag & 1 << 7 != 0
  FIN = flag & 1 << 6 != 0
  SRC = flag & 1 << 5 != 0
  REJ = flag & 1 << 4 != 0

  header = Header(seq=seq, ack=ack, rwnd=rwnd, 
          SYN=SYN, ACK=ACK, FIN=FIN, SRC=SRC, REJ=REJ)
  body = datagram[HEADER_LEN:]
  return (header, body)

def generateISN():
  '''generate a random isn
  '''
  return random.randint(50, 100)

def _timestamp():
  return time.strftime('[%m-%d %H:%M:%S] ', time.localtime())
  
def log(*k, **kw):
  print(_timestamp(), end='')
  print(*k, **kw)

def warn(msg:str):
  log('[warning] ' + msg)

def debug(*k, **kw):
  log(*k, **kw)
