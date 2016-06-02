# -*- coding: utf-8 -*-



import cookielib
import httplib
import logging
import os
import shutil
import socket
import string
import sys
import subprocess
import tempfile
import time
from threading import Thread
import urllib
import urllib2

from sockshandler import SocksiPyHandler
import socks as socks



__version__ = '0.1.15'
__author__ = 'Oleksii Ivanchuk (barjomet@barjomet.com)'




class Response(object):

    cookies = status_code = text = None

    def __init__(self, text, status_code, cookies=None):
        self.text = text
        self.status_code = status_code
        self.cookies = cookies


    def __bool__(self):
        if self.status_code in (200, 302):  return True
        else: return False


    __nonzero__=__bool__


    def __repr__(self):
        return "<TorcelloResponse status_code:%s at %s>" % (self.status_code,
                                                       id(self))




class Tor:

    check_ip_atempts = 1
    check_ip_timeout = 3
    data_dir = os.path.join(sys._MEIPASS, 'data') if hasattr(sys, '_MEIPASS') else tempfile.mkdtemp()
    delta = 6
    instances = []
    ip = None
    ip_services = [
        'http://ipinfo.io/ip',
        'http://ident.me/',
        'http://ip.barjomet.com',
        'http://icanhazip.com',
        'http://checkip.amazonaws.com/'
    ]
    last_new_id_time = 0
    log = logging.getLogger(__name__)
    log.addHandler(logging.NullHandler())
    log_file_path = None
    log_level='notice'
    order = []
    tor_cmd = None
    tor_path='Tor'
    tor_process = None


    def __init__(self, id=None, password=None, socks_port=None, control_host='127.0.0.1', control_port=None, start_port=9060):

        if id != None: self.id =id
        else: self.id = self.get_id()

        self.init_logging()

        if password: self.password = password
        else: self.generate_password()

        self.__class__.instances.insert(self.id, self)

        self.host = control_host
        self.socks_port = socks_port or start_port + self.id*2
        self.control_port = control_port or self.socks_port + 1

        if not self.tor_cmd: self.discover_tor_cmd()

        if not os.path.exists(self.data_dir): os.makedirs(self.data_dir)

        self.changing_ip = True
        self.run()


    def __repr__(self):
        return "<TorcelloTor id:%s, socks_port:%s, ip:%s at %s>" % \
                (self.id, self.socks_port, self.ip, id(self))


    def __del(self):
        self.log.debug('Cleaning temp data')
        self.stop()
        shutil.rmtree(os.path.join(self.data_dir, 'tor%s' % self.id),
                      ignore_errors=True)


    @classmethod
    def clean(cls):
        for one in cls.instances:
            one.__del()
        cls.instances = []
        cls.order = []
        shutil.rmtree(cls.data_dir, ignore_errors=True)


    @classmethod
    def discover_tor_cmd(cls):
        executable = 'tor.exe' if os.name == 'nt' else 'tor'

        if cls.tor_path:
            if hasattr(sys, '_MEIPASS'):
                path = os.path.join(sys._MEIPASS, cls.tor_path)
            else:
                path = os.path.abspath(cls.tor_path)
            cls.tor_cmd = os.path.join(path, executable)

        if not cls.tor_path or not os.path.isfile(cls.tor_cmd):
            cls.tor_cmd = 'tor.exe' if os.name == 'nt' else 'tor'

        cls.log.info(cls.version())


    @classmethod
    def first(cls):
        if len(cls.order): return cls.order[0]


    @classmethod
    def next_tor(cls):
        if cls.first() and not cls.first().changing_ip:
            Thread(target=cls.first().new_ip).start()
            cls.order.append(cls.order.pop(0))
            return True


    @classmethod
    def version(cls):
        try:
            version = subprocess.check_output([cls.tor_cmd,
                                               '--quiet',
                                               '--version'])
            return version.rstrip()
        except OSError as e:
            if e.errno == os.errno.ENOENT:
                cls.log.debug('No executable "%s" found' % self.cls)
            else:
                cls.log.debug(repr(e))
                raise


    @property
    def runtime_args(self):
        args = [
            self.tor_cmd,
            '--quiet',
            '--CookieAuthentication', '0',
            '--HashedControlPassword', '%s' % self.hash_password(),
            '--ControlPort', '%s' % self.control_port,
            '--PidFile', '%s.pid' % os.path.join(self.data_dir,
                                                 '%s' % self.id),
            '--SocksPort', '%s' % self.socks_port,
            '--DataDirectory', '%s' % os.path.join(self.data_dir,
                                                   'tor%s' % self.id)
        ]
        if self.log_file_path:
            if not os.path.exists(self.data_dir):
                os.makedirs(self.data_dir)
            logs_dir = os.path.abspath(self.log_file_path)
            if not os.path.exists(logs_dir):
                    os.makedirs(logs_dir)
            args += [
                '--Log', '{level} file {log_file}'.format(
                    level = self.log_level or 'notice',
                    log_file = os.path.join(
                        logs_dir,
                        'tor%s.log' % self.id
                    )
                )
            ]
        return args


    def check_ip(self):
        for attempt in range(len(self.ip_services)):
            try:
                return self.get(self.ip_services[0],
                                timeout=self.check_ip_timeout).text.rstrip()
            except:
                self.ip_services.append(self.ip_services.pop(0))


    def destroy(self):
        self.__class__.instances.remove(self)
        self.__del()




    def generate_password(self):
        chars = string.ascii_letters
        length = 16
        self.password = ''.join(
            chars[ord(os.urandom(1)) % len(chars)] for _ in range(length)
        )


    def get(self, url, **kwargs):
        return self.open(url, **kwargs)


    def get_id(self):
        ids = [one.id for one in self.__class__.instances]
        new_possible_id = len(ids)
        for who in range(new_possible_id-1):
            if who != ids[who]:
                return who
        return new_possible_id


    def get_pid(self):
        with open(os.path.join(self.data_dir, '%s.pid' % self.id)) as f:
            self.pid = int(f.read().strip())
        return self.pid


    def halt(self):
        return self.send_signal('HALT')


    def hash_password(self):
        while True:
            hashed_password = subprocess.check_output(
                [
                    Tor.tor_cmd,
                    '--quiet',
                    '--hash-password',
                    self.password
                ]
            ).strip()
            if hashed_password:
                return hashed_password


    def init_logging(self):
        self.log = logging.getLogger('%s_%s' % (__name__, self.id))
        self.log.addHandler(logging.NullHandler())


    def kill(self):
        try:
            self.get_pid()
            os.kill(self.pid, 9)
        except Exception:
            return False
        return True


    def new_id(self):
        return self.send_signal('NEWNYM')


    def new_ip(self):
        if not self.changing_ip:
            self.changing_ip = True
            if not self.ip:
                self.ip = self.check_ip()
            if time.time() - self.last_new_id_time < self.delta:
                self.log.debug('Restarting Tor to renew IP')
                self.restart()
                self.log.info('New IP: %s' % self.ip)
                self.changing_ip = False
                self.last_new_id_time = 0
                return self.ip
            else:
                if self.new_id():
                    self.log.debug('Checking that IP cnanged')
                    time.sleep(0.5)
                    for attempt in range(self.check_ip_atempts):
                        new_ip = self.check_ip()
                        if new_ip and new_ip != self.ip:
                            self.log.info('New IP: %s' % new_ip)
                            self.ip = new_ip
                            self.changing_ip = False
                            self.last_new_id_time = time.time()
                            return new_ip
                        time.sleep(1)
            self.restart()
            return self.ip


    def open(self, url, data=None, headers=None, cookies=None, timeout=60):
        self.log.debug('%s request to %s\nHeaders: %s\nTimeout: %s'
                       % ('GET' if data else 'POST', url, headers, timeout))
        cookies = cookies or cookielib.LWPCookieJar()
        opener = urllib2.build_opener(SocksiPyHandler(socks.PROXY_TYPE_SOCKS5,
                                                      self.host, self.socks_port),
                                      urllib2.HTTPCookieProcessor(cookies)
        )
        status_code = None
        if headers:
            opener.addheaders = [item for item in headers.items()]
        try:
            response = opener.open(url, data, timeout)
        except httplib.IncompleteRead as e:
            response = e.partial
        except Exception as e:
            if hasattr(e, 'code'):
                status_code = e.code
            self.log.debug('Failed to open %s, %s' % (url,e))
            return Response(None, None, cookies)
        try:
            text = response.read()
        except Exception as e:
            text = None
            self.log.debug('Unable to read response content: %s' % repr(e))
        try:
            status_code = status_code or response.getcode()
        except Exception as e:
            status_code = None
            self.log.debug('Error during getting response status code: %s' % repr(e))

        return Response(text, status_code, cookies)


    def post(self, url, data, **kwargs):
        return self.open(url, data=urllib.urlencode(data), **kwargs)


    def restart(self):
        self.log.debug('Waiting until Tor daemon is dead')
        while self.stop():
            time.sleep(0.25)
        return self.run()


    def run(self):
        while True:
            if not self.tor_started():
                try:
                    self.log.info('Starting Tor process')
                    self.log.debug('Running: %s' % ' '.join(self.runtime_args))
                    proc = subprocess.Popen(self.runtime_args)
                    self.tor_process = proc
                except Exception as e:
                    self.log.error('Failed to start Tor process: %s' % repr(e))
                    return False

            time.sleep(0.5)
            for attempt in range(self.check_ip_atempts):
                try:
                    if self.tor_started(): self.ip = self.check_ip()
                    else: time.sleep(1)

                    if self.ip:
                        self.__class__.order.append(self)
                        self.changing_ip = False
                        return True

                except Exception as e :
                    self.log.error('Tor not responding, %s' % e)

            self.log.error('Tor connection is not functional')
            self.log.info('Restarting Tor process')
            return self.restart()


    def send_signal(self, signal):
        try:
            s = socket.socket()
            s.connect((self.host, self.control_port))
            s.send('AUTHENTICATE "%s"\r\n' % self.password)
            resp = s.recv(1024)

            if resp.startswith('250'):
                s.send('signal %s\r\n' % signal)
                resp = s.recv(1024)

                if resp.startswith('250'):
                    self.log.debug('Tor control signal "%s": SUCCESS' % signal)
                    return True
                else:
                    self.log.debug("response 2:%s" % resp)

            else:
                self.log.debug("response 1:%s" % resp)

        except Exception as e:
            self.log.error('Tor %s signal FAILED, %s' % (signal, e))


    def shutdown(self):
        return self.send_signal('SHUTDOWN')


    def stop(self):
        if self.shutdown(): self.terminate()
        else: self.kill()


    def terminate(self):
        self.log.info('Terminatig Tor process')
        try:
            self.tor_process.terminate()
            self.tor_process = None
            return True
        except Exception as e:
            self.log.error('Failed to terminate Tor process: %s' % e)
            return False


    def tor_started(self):
        try:
            self.get_pid()
            return True
        except:
            return False
