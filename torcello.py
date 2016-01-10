from deps.sockshandler import SocksiPyHandler
import deps.socks as socks
import logging
import os
import requests
import shutil
import socket
import string
import sys
import subprocess
import tempfile
import time
import urllib2


__version__ = '0.1.0'
__author__ = 'Oleksii Ivanchuk (barjomet@barjomet.com)'


log = logging.getLogger(__name__)
logging.getLogger("requests").setLevel(logging.WARNING)


class Tor:

    instances = []
    data_dir = os.path.join(sys._MEIPASS, 'data') if hasattr(sys, '_MEIPASS') else tempfile.mkdtemp()


    def __init__(self, socks_port=None, control_host='127.0.0.1', control_port=None, start_port=9050, tor_path='Tor', log_file_path='log', log_level='notice'):

        self.id = self.get_id()

        self.log = logging.getLogger('%s_%s' % (__name__, self.id))
        self.log_file_path = log_file_path
        self.log_level = log_level

        self.__class__.instances.insert(self.id, self)

        if not hasattr(self, 'tor_cmd'):
            self.discover_tor_cmd(tor_path)

        self.host = control_host
        self.socks_port = socks_port or start_port + self.id*2
        self.control_port = control_port or self.socks_port + 1
        self.generate_password()

        self.ip_services = [
            'http://ipinfo.io/ip',
            'http://ident.me/',
            'http://ip.barjomet.com',
            'http://icanhazip.com',
            'http://checkip.amazonaws.com/'
        ]
        self.tor_process = None
        self.run()


    def _del(self):
        self.log.debug('Cleaning temp data')
        self.terminate()
        shutil.rmtree(os.path.join(self.data_dir, 'tor%s' % self.id), ignore_errors=True)
        try:
            self.__class__.instances.remove(self)
        except:
            pass


    @staticmethod
    def clean():
        for one in Tor.instances:
            one._del()
        Tor.instances = []
        shutil.rmtree(Tor.data_dir, ignore_errors=True)


    def check_ip(self):
        for attempt in range(len(self.ip_services)):
            try:
                return self.open(self.ip_services[0]).rstrip()
            except:
                self.ip_services = self.ip_services+[self.ip_services.pop(0)]
            time.sleep(1)


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


    def get_id(self):
        ids = [one.id for one in self.__class__.instances]
        new_possible_id = len(ids)
        for who in range(new_possible_id-1):
            if who != ids[who]:
                return who
        return new_possible_id


    def hash_password(self):
        return subprocess.check_output(
            [
                Tor.tor_cmd,
                '--quiet',
                '--hash-password',
                self.password
            ]
        ).strip()


    def new_id(self):
        return self.send_signal('NEWNYM')


    def new_ip(self):
        if not self.ip:
            self.ip = self.check_ip()
        if self.new_id():
            while True:
                for attempt in range(10):
                    new_ip = self.check_ip()
                    if new_ip and new_ip != self.ip:
                        self.log.info('New IP: %s' % new_ip)
                        self.ip = new_ip
                        return new_ip
                    time.sleep(1)
            else:
                self.run()
        else:
            self.run()
            self.new_ip()


    def open(self, url, headers=None):
        opener = urllib2.build_opener(
            SocksiPyHandler(socks.PROXY_TYPE_SOCKS4, self.host, self.socks_port)
        )
        if headers:
            opener.addheaders = [item for item in headers.items()]
        try:
            return opener.open(url).read()
        except Exception as e:
            self.log.info('Failed to open %s, %s' % (url,repr(e)))


    def run(self):
        self.log.info('Starting Tor process')
        while True:
            try:
                runtime_args = [
                    self.tor_cmd,
                    '--quiet',
                    '--CookieAuthentication', '0',
                    '--HashedControlPassword', '%s' % self.hash_password(),
                    '--ControlPort', '%s' % self.control_port,
                    '--PidFile', '%s/%s.pid' % (self.data_dir, self.id),
                    '--SocksPort', '%s' % self.socks_port,
                    '--DataDirectory', '%s/tor%s' % (self.data_dir, self.id)
                ]
                if self.log_file_path:
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
                self.log.debug('Running: %s' % ' '.join(runtime_args))
                proc = subprocess.Popen(runtime_args)
            except Exception as e:
                self.log.error('Failed to start Tor process: %s' % repr(e))
                return False
            for attempt in range(3):
                time.sleep(3)
                try:
                    self.tor_process = proc
                    self.ip = self.check_ip()
                    self.log.info('Tor successfully started, IP: %s' % self.ip)
                    return True
                except:
                    pass
            self.log.error('Tor connection is not functional')
            try:
                self.stop()
            except:
                pass
            self.log.info('Retrying to start Tor process')
            self.shutdown()


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
            self.terminate()


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
