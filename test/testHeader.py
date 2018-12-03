import random

from LFTP_config import Header, headerParse
from LFTP_Connection import LFTP_Connection

def testHeaderEncode():
  for _ in range(10):
    seq = random.randint(0, 1 << 31)
    ack = random.randint(0, 1 << 31)
    rwnd = random.randint(0, 1 << 15)
    SYN = random.random() > 0.5
    ACK = random.random() > 0.5
    FIN = random.random() > 0.5
    SRC = random.random() > 0.5
    REJ = random.random() > 0.5
    header = Header(
      seq = seq,
      ack = ack,
      rwnd = rwnd,
      SYN = SYN,
      ACK = ACK,
      FIN = FIN,
      SRC = SRC,
      REJ = REJ)
    answer = header.encode()
    newHeader, _ = headerParse(answer)
    newAnswer = newHeader.encode()
    if answer != newAnswer:
      print('answer: ', answer)
      print('expect: ', newAnswer)

if __name__ == "__main__":
  testHeaderEncode()