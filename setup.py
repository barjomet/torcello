from distutils.core import setup

VERSION = "0.1.15"

long_description = """How to use::


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

also try it as rotating proxy::


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
  
    # Delete all instances and close all Tor daemons
    Tor.clean()"""


setup(name='Torcello',
      version=VERSION,
      description='Just a Python module suitable to use multiple Tor circuits at the same time',
      long_description=long_description,
      url="https://github.com/barjomet/torcello",
      license="BSD",
      author = "Oleksii Ivanchuk",
      author_email = "barjomet@barjomet.com",
      keywords = ["tor", "socks", "proxy"],
      py_modules=['torcello'],
      install_requires=['pysocks'],
      classifiers=[
          'Development Status :: 4 - Beta',
          'Intended Audience :: Developers',
          'Operating System :: MacOS :: MacOS X',
          'Operating System :: Microsoft :: Windows',
          'Operating System :: POSIX',
          'Programming Language :: Python',
          ]
      )
