# python3 LFTP_server.py

import socket
from LFTP_Connection import LFTP_Connection

def main():
  connections = LFTP_Connection(isServer=True)
  connections.listen()

if __name__ == "__main__":
  main()