import sys

sys.path.append('./')

from LFTP_Connection import LFTP_Connection

def testPerforment():
  from LFTP_config import SERVER_PORT
  path = sys.argv[1]
  connections = LFTP_Connection(isServer=False)
  connections.newConnectionTo(addr=('127.0.0.1', SERVER_PORT), connectionType='lget', path=path, performTest=True)

testPerforment()
