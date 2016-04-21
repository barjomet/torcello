from distutils.core import setup

VERSION = "0.1.5"



setup(name='Torcello',
      version=VERSION,
      description='Just a Python module suitable to use multiple Tor circuits at the same time',
      url="https://github.com/barjomet/torcello",
      license="BSD",
      author = "Oleksii Ivanchuk",
      author_email = "barjomet@barjomet.com",
      keywords = ["tor", "socks", "proxy"],
      py_modules=['torcello'],
      install_requires=['pysocks']
      )
