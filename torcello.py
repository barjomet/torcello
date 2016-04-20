# -*- coding: utf-8 -*-



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
import urllib2

from sockshandler import SocksiPyHandler
import socks as socks



__version__ = '0.1.4'
__author__ = 'Oleksii Ivanchuk (barjomet@barjomet.com)'


log = logging.getLogger(__name__)
log.addHandler(logging.NullHandler())


class Response(object):
    def __init__(self, text, status_code):
        self.text = text
        self.status_code = status_code

class Tor:

    instances = []
    order = []
    data_dir = os.path.join(sys._MEIPASS, 'data') if hasattr(sys, '_MEIPASS') else tempfile.mkdtemp()


    def __init__(self, id=None, delta=3, tor_start=20, socks_port=None, control_host='127.0.0.1', control_port=None, start_port=9060, tor_path='Tor', log_file_path='log', log_level='notice'):

        if id != None:
            self.id =id
        else:
            self.id = self.get_id()

        self.delta = delta
        self.tor_start = tor_start
        self.log = logging.getLogger('%s_%s' % (__name__, self.id+1))
        self.log.addHandler(logging.NullHandler())
        self.log_file_path = None
        self.log_level = log_level

        self.__class__.instances.insert(self.id, self)

        if not hasattr(self, 'tor_cmd'):
            self.discover_tor_cmd(tor_path)

        if not os.path.exists(self.data_dir):
            os.makedirs(self.data_dir)

        self.host = control_host
        self.socks_port = socks_port or start_port + self.id*2
        self.control_port = control_port or self.socks_port + 1
        #self.generate_password()
        self.password = 'HugeSecret'

        self.changing_ip = True

        self.ip_services = [
            'http://ipinfo.io/ip',
            'http://ident.me/',
            'http://ip.barjomet.com',
            'http://icanhazip.com',
            'http://checkip.amazonaws.com/'
        ]
        self.tor_process = None
        self.ip = None
        self.run()


    def __del(self):
        self.log.debug('Cleaning temp data')
        self.stop()
        shutil.rmtree(os.path.join(self.data_dir, 'tor%s' % self.id), ignore_errors=True)


    @classmethod
    def clean(cls):
        for one in cls.instances:
            one.__del()
        cls.instances = []
        cls.order = []
        shutil.rmtree(cls.data_dir, ignore_errors=True)


    @classmethod
    def first(cls):
        if len(cls.order):
            return cls.order[0]



    @classmethod
    def next_tor(cls):
        if cls.first():
            if not cls.first().changing_ip:
                Thread(target=cls.first().new_ip).start()
                cls.order.append(cls.order.pop(0))
                return True



    def check_ip(self, attempts=None):
        if not attempts:
            attempts = len(self.ip_services)
        for attempt in range(int(attempts)):
            try:
                return self.get(self.ip_services[0], timeout=4).text.rstrip()
            except:
                self.ip_services.append(self.ip_services.pop(0))
            time.sleep(1)


    def destroy(self):
        self.__class__.instances.remove(self)
        self.__del()


    def discover_tor_cmd(self, tor_path):
        executable = 'tor.exe' if os.name == 'nt' else 'tor'

        if tor_path:
            if hasattr(sys, '_MEIPASS'):
                path = os.path.join(sys._MEIPASS, tor_path)
            else:
                path = os.path.abspath(tor_path)
            self.__class__.tor_cmd = os.path.join(path, executable)

        if not tor_path or not os.path.isfile(self.tor_cmd):
            self.__class__.tor_cmd = executable

        log.info(self.version())


    def generate_password(self):
        chars = string.ascii_letters
        length = 16
        self.password = ''.join(
            chars[ord(os.urandom(1)) % len(chars)] for _ in range(length)
        )


    def get(self, url, data=None, headers=None, timeout=60):
        self.log.debug('GET request to %s\nHeaders: %s\nTimeout: %s' % (url, headers, timeout))
        text = None
        status_code = None
        opener = urllib2.build_opener(
            SocksiPyHandler(socks.PROXY_TYPE_SOCKS5, self.host, self.socks_port)
        )
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
        try:
            text = response.read()
        except:
            pass
        try:
            status_code = status_code or response.getcode()
        except:
            pass

        return Response(text, status_code)


    def get_id(self):
        ids = [one.id for one in self.__class__.instances]
        new_possible_id = len(ids)
        for who in range(new_possible_id-1):
            if who != ids[who]:
                return who
        return new_possible_id


    def get_pid(self):
        with open(os.path.join(self.data_dir, '%s.pid' % self.id)) as f:
            pid = f.read().strip()
        return int(pid)


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


    def kill(self):
        try:
            os.kill(self.get_pid(), 9)
        except:
            pass


    def new_id(self):
        return self.send_signal('NEWNYM')


    def new_ip(self):
        if not self.changing_ip:
            self.changing_ip = True
            if not self.ip:
                self.ip = self.check_ip()
            if not hasattr(self, 'last_time_new_id'):
                self.last_time_new_id = 0
            if time.time() - self.last_time_new_id < self.delta:
                log.debug('Restarting Tor to renew IP')
                self.stop()
                self.run()
                self.changing_ip = False
                self.last_time_new_id = 0
                return self.ip
            else:
                if self.new_id():
                    self.log.debug('Checking that IP cnanged')
                    for attempt in range(2):
                        new_ip = self.check_ip(1)
                        if new_ip and new_ip != self.ip:
                            self.log.info('New IP: %s' % new_ip)
                            self.ip = new_ip
                            self.changing_ip = False
                            self.last_time_new_id = time.time()
                            return new_ip
                        time.sleep(1)
            self.stop()
            self.run()
            return self.ip


    def run(self):
        while True:
            try:
                runtime_args = [
                    self.tor_cmd,
                    '--quiet',
                    '--CookieAuthentication', '0',
                    '--HashedControlPassword', '%s' % self.hash_password(),
                    '--ControlPort', '%s' % self.control_port,
                    '--PidFile', '%s.pid' % os.path.join(self.data_dir, '%s' % self.id),
                    '--SocksPort', '%s' % self.socks_port,
                    '--DataDirectory', '%s' % os.path.join(self.data_dir, 'tor%s' % self.id)
                ]
                if self.log_file_path:
                    if not os.path.exists(self.data_dir):
                            os.makedirs(self.data_dir)
                    logs_dir = os.path.abspath(self.log_file_path)
                    if not os.path.exists(logs_dir):
                            os.makedirs(logs_dir)
                    runtime_args += [
                        '--Log', '{level} file {log_file}'.format(
                            level = self.log_level or 'notice',
                            log_file = os.path.join(
                                logs_dir,
                                'tor%s.log' % self.id
                            )
                        )
                    ]
                try:
                    self.get_pid()
                except Exception as e:
                    self.log.info('Starting Tor process')
                    self.log.debug('Running: %s' % ' '.join(runtime_args))
                    proc = subprocess.Popen(runtime_args)
            except Exception as e:
                self.log.error('Failed to start Tor process: %s' % repr(e))
                return False
            for attempt in range(1):
                time.sleep(1)
                try:
                    #self.tor_process = proc
                    self.ip = self.check_ip(self.tor_start)
                    if self.ip:
                        self.__class__.order.append(self)
                        self.log.info('Tor successfully started, IP: %s' % self.ip)
                        self.changing_ip = False
                        return True
                except Exception as e :
                    self.log.error('Tor not responding, %s' % e)
            self.log.error('Tor connection is not functional')
            try:
                self.stop()
            except:
                pass
            self.log.info('Retrying to start Tor process')
            return self.run()


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
        if not self.shutdown():
            self.kill()


    def terminate(self):
        self.log.info('Terminatig Tor process')
        try:
            self.tor_process.terminate()
            self.tor_process = None
            return True
        except Exception as e:
            self.log.error('Failed to terminate Tor process: %s' % e)
            return False


    def version(self):
        try:
            version = subprocess.check_output([self.tor_cmd, '--quiet', '--version'])
            return version.rstrip()
        except OSError as e:
            if e.errno == os.errno.ENOENT:
                log.debug('No executable "%s" found' % self.tor_cmd)
            else:
                log.debug(repr(e))
                raise
