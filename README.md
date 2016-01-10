Torcello
========

Just a Python module suitable to use multiple [Tor](https://www.torproject.org/) circuits at the same time

Example usage:
```
import logging
from torcello import Tor
from threading import Thread

logging.root.setLevel(logging.DEBUG)
logFormatter = logging.Formatter('[%(name)s] [%(levelname)s] %(message)s')
consoleHandler = logging.StreamHandler()
consoleHandler.setFormatter(logFormatter)
consoleHandler.setLevel(logging.DEBUG)
logging.root.addHandler(consoleHandler)

log = logging.getLogger('doer')

def do_something():
    tor = Tor()
    for a in range(20):
        response = tor.open('http://ip.barjomet.com')
        log.info('Hooray, here is desired data: %s' %  response)
        tor.new_ip()

for c in range(10):
    Thread(target=do_something).start()

Tor.clean()
```
-------------------------------------------
It depends on:

[SocksiPyHandler](https://gist.github.com/e000/869791)

[SocksiPy](http://socksipy.sourceforge.net/)

A Python SOCKS module.

(C) 2006 Dan-Haim. All rights reserved.

See LICENSE file for details
