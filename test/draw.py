import sys

sys.path.append('./')

def drawPerformResult():
  import pickle
  from matplotlib import pyplot as plt
  from LFTP_config import PERFORM_TEST_DIR
  def draw(title):
    with open(PERFORM_TEST_DIR+title, 'rb') as f:
      obj = pickle.load(f)
      # byte = [b / (1 << 10) for b in obj['byte']]
      byte = [b / (1 << 20) for b in obj['byte']]
      plt.plot(obj['time'], byte, label=title)
  titles = {
    # 'simple',
    # 'delay',
    # 'disorder',
    # 'bigDelay',

    'ideal network',
    'simulated network'

    # 'client 0',
    # 'client 1',
    # 'client 2',
  }
  for t in titles:
    draw(t)
  plt.title('transmit plot')
  plt.xlabel('second')
  # plt.ylabel('KB')
  plt.ylabel('MB')
  plt.legend()
  plt.show()

drawPerformResult()