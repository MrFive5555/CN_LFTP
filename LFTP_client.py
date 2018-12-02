# python3 LFTP_client.py lsend localhost ./client_input/out
# python3 LFTP_client.py lsend localhost example
# python3 LFTP_client.py lget localhost example

import os
import sys
import socket

from LFTP_config import SERVER_PORT, log, MTU, \
  SEND_REQUEST_STR, RECV_REQUEST_STR, warn
from LFTP_Connection import LFTP_Connection

def hint():
  print('[error] usage: LFTP ' + SEND_REQUEST_STR + ' <myserver> <mylargefile>' + '\n'
    + '           or: LFTP ' + RECV_REQUEST_STR + '  <myserver> <mylargefile>')

def main():
  _type = sys.argv[1]
  if len(sys.argv) != 4 \
    or (_type != 'lget' and _type != 'lsend'):
    hint()
    return

  port = SERVER_PORT
  if sys.argv[2].find(':') == -1:
    host = sys.argv[2]
  else:
    (host, port_s) = (sys.argv[2].split(':'))
    port = int(port_s)

  path = sys.argv[3]
  if _type == 'lsend' and not os.path.exists(path):
    print('the sending file: "{}" do not exist'.format(path))
    return

  serverIP = socket.gethostbyname(host)

  serverAddress = (serverIP, port)

  connections = LFTP_Connection(isServer=False)
  connections.newConnectionTo(addr=serverAddress, connectionType=sys.argv[1], path=sys.argv[3])

if __name__ == "__main__":
  main()