Torcello
========

Just a Python module suitable to use multiple [Tor](https://www.torproject.org/) circuits at the same time

Example usage:
```
from torcello import Tor
from threading import Thread

def do_something():
    tor = Tor()
    for one in range(5):
        response = tor.get('http://ip.barjomet.com')
        print('Hooray, here is desired data: %s' %  response.text)
        tor.new_ip()
    tor.destroy()

for incident in range(5):
    Thread(target=do_something).start()
```
also try rotating proxy:
```
from time import sleep
from torcello import Tor
from threading import Thread

for one in range(12):
    Thread(target=Tor).start()

while len(Tor.order) < 10:
    print('Waiting for tor, %s tor instances is ready' % len(Tor.order))
    sleep(5)


for incident in range(20):
    response = Tor.first().get('http://ip.barjomet.com')
    print('Hooray, here is desired data: %s' %  response.text)
    while not Tor.next_tor():
        sleep(1)

Tor.clean()
```
-------------------------------------------
It depends on:

[SocksiPyHandler](https://gist.github.com/e000/869791)

[SocksiPy](http://socksipy.sourceforge.net/)

A Python SOCKS module.

(C) 2006 Dan-Haim. All rights reserved.

See LICENSE file for details
