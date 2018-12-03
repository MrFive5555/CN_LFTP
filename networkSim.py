import numpy.random
import random
import time

# decorater
def ideal(route):
  return route

def delay(delayTime, dev):
  def decorator(route):
    def func(self, segment, addr):
      delay_ = delayTime + dev * numpy.random.randn()
      if delay_ < 0:
        delay_ = 0
      time.sleep(delay_)
      route(self, segment, addr)
    return func
  return decorator

def disorder(delayTime, dev):
  def decorator(route):
    def func(self, segment, addr):
      delay_ = delayTime + dev * numpy.random.randn()
      if delay_ < 0:
        delay_ = 0
      time.sleep(delay_)
      buf = []
      while not self.mailbox.empty():
        buf.append(self.mailbox.get())
      random.shuffle(buf)
      while len(buf) != 0:
        self.mailbox.put(buf.pop(0))
      route(self, segment, addr)
    return func
  return decorator

def realNetwork(delayTime, lossingRate):
  def decorator(route):
    dev = 0.2 * delayTime
    def func(self, segment, addr):
      delay_ = delayTime + dev * numpy.random.randn()
      if delay_ < 0:
        delay_ = 0
      time.sleep(delay_)
      buf = []
      while not self.mailbox.empty():
        buf.append(self.mailbox.get())
      random.shuffle(buf)
      while len(buf) != 0:
        self.mailbox.put(buf.pop(0))
      if random.random() > lossingRate:
        route(self, segment, addr)
    return func
  return decorator