#!/usr/bin/env python

import unittest
import os

ftp_py_globals = {}

def proxyLog(a, b, c, d):
    pass

class TestParseFtpInbandAuth(unittest.TestCase):

    @staticmethod
    def newObject():
        global ftp_py_globals
        return ftp_py_globals["AbstractFtpProxy"](None)

    def test_no_ats(self):
        o = self.newObject()
        self.assertFalse(o.parseInbandAuth('USER', 'fred'))

    def test_current_no_port(self):
        o = self.newObject()
        self.assertTrue(o.parseInbandAuth('USER', 'fred@ftpserver.com'))
        self.assertTrue(o.parseInbandAuth('PASS', 'lightbringer'))

        self.assertEqual(o.username, 'fred')
        self.assertEqual(o.proxy_username, None)
        self.assertEqual(o.hostname, 'ftpserver.com')
        self.assertEqual(o.hostport, None)
        self.assertEqual(o.password, 'lightbringer')
        self.assertEqual(o.proxy_password, None)

    def test_current_empty(self):
        o = self.newObject()
        self.assertTrue(o.parseInbandAuth('USER', '@'))

        self.assertEqual(o.username, '')
        self.assertEqual(o.proxy_username, None)
        self.assertEqual(o.hostname, '')
        self.assertEqual(o.hostport, None)
        self.assertEqual(o.password, None)
        self.assertEqual(o.proxy_password, None)

    def test_current_numeric_host(self):
        o = self.newObject()
        self.assertTrue(o.parseInbandAuth('USER', 'fred@222'))

        self.assertEqual(o.username, 'fred')
        self.assertEqual(o.proxy_username, None)
        self.assertEqual(o.hostname, '222')
        self.assertEqual(o.hostport, None)
        self.assertEqual(o.password, None)
        self.assertEqual(o.proxy_password, None)

    def test_user_lowercase(self):
        o = self.newObject()
        self.assertTrue(o.parseInbandAuth('user', 'fred@ftpserver.com'))

        self.assertEqual(o.username, 'fred')
        self.assertEqual(o.proxy_username, None)
        self.assertEqual(o.hostname, 'ftpserver.com')
        self.assertEqual(o.hostport, None)
        self.assertEqual(o.password, None)
        self.assertEqual(o.proxy_password, None)

    def test_current_with_port(self):
        o = self.newObject()
        self.assertTrue(o.parseInbandAuth('USER', 'fred@ftpserver.com:2020'))
        self.assertTrue(o.parseInbandAuth('PASS', 'lightbringer'))

        self.assertEqual(o.username, 'fred')
        self.assertEqual(o.proxy_username, None)
        self.assertEqual(o.hostname, 'ftpserver.com')
        self.assertEqual(o.hostport, 2020)
        self.assertEqual(o.password, 'lightbringer')
        self.assertEqual(o.proxy_password, None)

    def test_current_empty_with_port(self):
        o = self.newObject()
        self.assertFalse(o.parseInbandAuth('USER', '@:'))

    def test_current_numeric_host_with_port(self):
        o = self.newObject()
        self.assertTrue(o.parseInbandAuth('USER', 'fred@222:111'))

        self.assertEqual(o.username, 'fred')
        self.assertEqual(o.proxy_username, None)
        self.assertEqual(o.hostname, '222')
        self.assertEqual(o.hostport, 111)
        self.assertEqual(o.password, None)
        self.assertEqual(o.proxy_password, None)

    def test_full_no_port(self):
        o = self.newObject()
        self.assertTrue(o.parseInbandAuth('USER', 'fred@proxyfred@ftpserver.com:ftppass@proxypass'))

        self.assertEqual(o.username, 'fred')
        self.assertEqual(o.proxy_username, 'proxyfred')
        self.assertEqual(o.hostname, 'ftpserver.com')
        self.assertEqual(o.hostport, None)
        self.assertEqual(o.password, 'ftppass')
        self.assertEqual(o.proxy_password, 'proxypass')

    def test_full_empty(self):
        o = self.newObject()
        self.assertTrue(o.parseInbandAuth('USER', '@@:@'))

        self.assertEqual(o.username, '')
        self.assertEqual(o.proxy_username, '')
        self.assertEqual(o.hostname, '')
        self.assertEqual(o.hostport, None)
        self.assertEqual(o.password, '')
        self.assertEqual(o.proxy_password, '')

    def test_full_numeric_host_no_port(self):
        o = self.newObject()
        self.assertTrue(o.parseInbandAuth('USER', 'fred@proxyfred@222:ftppass@proxypass'))

        self.assertEqual(o.username, 'fred')
        self.assertEqual(o.proxy_username, 'proxyfred')
        self.assertEqual(o.hostname, '222')
        self.assertEqual(o.hostport, None)
        self.assertEqual(o.password, 'ftppass')
        self.assertEqual(o.proxy_password, 'proxypass')

    def test_full_with_port(self):
        o = self.newObject()
        self.assertTrue(o.parseInbandAuth('USER', 'fred@proxyfred@ftpserver.com:666:ftppass@proxypass'))

        self.assertEqual(o.username, 'fred')
        self.assertEqual(o.proxy_username, 'proxyfred')
        self.assertEqual(o.hostname, 'ftpserver.com')
        self.assertEqual(o.hostport, 666)
        self.assertEqual(o.password, 'ftppass')
        self.assertEqual(o.proxy_password, 'proxypass')

    def test_full_empty_with_port(self):
        o = self.newObject()
        self.assertTrue(o.parseInbandAuth('USER', '@@::@'))

        self.assertEqual(o.username, '')
        self.assertEqual(o.proxy_username, '')
        self.assertEqual(o.hostname, '')
        #self.assertEqual(o.hostport, '')
        self.assertEqual(o.hostport, None)
        #self.assertEqual(o.password, '')
        self.assertEqual(o.password, ':')
        self.assertEqual(o.proxy_password, '')

    def test_full_numeric_host_with_port(self):
        o = self.newObject()
        self.assertTrue(o.parseInbandAuth('USER', 'fred@proxyfred@222:666:ftppass@proxypass'))

        self.assertEqual(o.username, 'fred')
        self.assertEqual(o.proxy_username, 'proxyfred')
        self.assertEqual(o.hostname, '222')
        self.assertEqual(o.hostport, 666)
        self.assertEqual(o.password, 'ftppass')
        self.assertEqual(o.proxy_password, 'proxypass')

    def test_full_with_too_many_colons(self):
        o = self.newObject()
        self.assertTrue(o.parseInbandAuth('USER', 'fred@proxyfred@ftpserver.com:666:ftp:pass@proxypass'))

        self.assertEqual(o.username, 'fred')
        self.assertEqual(o.proxy_username, 'proxyfred')
        self.assertEqual(o.hostname, 'ftpserver.com')
        self.assertEqual(o.hostport, 666)
        self.assertEqual(o.password, 'ftp:pass')
        self.assertEqual(o.proxy_password, 'proxypass')

    def test_full_with_too_many_ats(self):
        o = self.newObject()
        self.assertFalse(o.parseInbandAuth('USER', 'fred@proxyfred@ftpserver.com:666:ftppass@proxy@pass'))

    def test_full_with_too_low_port(self):
        o = self.newObject()
        self.assertTrue(o.parseInbandAuth('USER', 'fred@proxyfred@ftpserver.com:0:ftppass@proxypass'))

        self.assertEqual(o.username, 'fred')
        self.assertEqual(o.proxy_username, 'proxyfred')
        self.assertEqual(o.hostname, 'ftpserver.com')
        self.assertEqual(o.hostport, None)
        self.assertEqual(o.password, '0:ftppass')
        self.assertEqual(o.proxy_password, 'proxypass')

    def test_full_with_too_high_port(self):
        o = self.newObject()
        self.assertTrue(o.parseInbandAuth('USER', 'fred@proxyfred@ftpserver.com:65536:ftppass@proxypass'))

        self.assertEqual(o.username, 'fred')
        self.assertEqual(o.proxy_username, 'proxyfred')
        self.assertEqual(o.hostname, 'ftpserver.com')
        self.assertEqual(o.hostport, None)
        self.assertEqual(o.password, '65536:ftppass')
        self.assertEqual(o.proxy_password, 'proxypass')

    def test_full_with_non_numeric_port(self):
        o = self.newObject()
        self.assertTrue(o.parseInbandAuth('USER', 'fred@proxyfred@ftpserver.com:666a:ftppass@proxypass'))

        self.assertEqual(o.username, 'fred')
        self.assertEqual(o.proxy_username, 'proxyfred')
        self.assertEqual(o.hostname, 'ftpserver.com')
        self.assertEqual(o.hostport, None)
        self.assertEqual(o.password, '666a:ftppass')
        self.assertEqual(o.proxy_password, 'proxypass')

    def test_half_user_no_port(self):
        o = self.newObject()
        self.assertTrue(o.parseInbandAuth('USER', 'fred@proxyfred@ftpserver.com'))
        self.assertTrue(o.parseInbandAuth('PASS', 'mew@mewmew'))

        self.assertEqual(o.username, 'fred')
        self.assertEqual(o.proxy_username, 'proxyfred')
        self.assertEqual(o.hostname, 'ftpserver.com')
        self.assertEqual(o.hostport, None)
        self.assertEqual(o.password, 'mew')
        self.assertEqual(o.proxy_password, 'mewmew')

    def test_half_user_with_port(self):
        o = self.newObject()
        self.assertTrue(o.parseInbandAuth('USER', 'fred@proxyfred@ftpserver.com:999'))
        self.assertTrue(o.parseInbandAuth('PASS', 'foo@bar'))

        self.assertEqual(o.username, 'fred')
        self.assertEqual(o.proxy_username, 'proxyfred')
        self.assertEqual(o.hostname, 'ftpserver.com')
        self.assertEqual(o.hostport, 999)
        self.assertEqual(o.password, 'foo')
        self.assertEqual(o.proxy_password, 'bar')

    def test_half_user_with_bad_port(self):
        o = self.newObject()
        self.assertFalse(o.parseInbandAuth('USER', 'fred@proxyfred@ftpserver.com:0x12'))

    def test_pass_lowercase(self):
        o = self.newObject()
        self.assertTrue(o.parseInbandAuth('USER', 'fred@proxyfred@ftpserver.com'))
        self.assertTrue(o.parseInbandAuth('pass', 'spam@eggs'))

        self.assertEqual(o.username, 'fred')
        self.assertEqual(o.proxy_username, 'proxyfred')
        self.assertEqual(o.hostname, 'ftpserver.com')
        self.assertEqual(o.hostport, None)
        self.assertEqual(o.password, 'spam')
        self.assertEqual(o.proxy_password, 'eggs')

    def test_pass_no_ats(self):
        o = self.newObject()
        self.assertTrue(o.parseInbandAuth('USER', 'fred@proxyfred@ftpserver.com'))
        self.assertFalse(o.parseInbandAuth('pass', 'spam'))

    def test_pass_empty(self):
        o = self.newObject()
        self.assertTrue(o.parseInbandAuth('USER', 'fred@proxyfred@ftpserver.com'))
        self.assertTrue(o.parseInbandAuth('pass', '@'))

        self.assertEqual(o.username, 'fred')
        self.assertEqual(o.proxy_username, 'proxyfred')
        self.assertEqual(o.hostname, 'ftpserver.com')
        self.assertEqual(o.hostport, None)
        self.assertEqual(o.password, '')
        self.assertEqual(o.proxy_password, '')

    def test_pass_numeric_ip(self):
        o = self.newObject()
        self.assertTrue(o.parseInbandAuth('USER', 'ftp@127.0.0.1'))
        self.assertTrue(o.parseInbandAuth('PASS', 'user@'))

        self.assertEqual(o.username, 'ftp')
        self.assertEqual(o.hostname, '127.0.0.1')
        self.assertEqual(o.password, 'user@')
        self.assertEqual(o.proxy_username, None)
        self.assertEqual(o.proxy_password, None)

stub = """
FALSE = 0
TRUE = 1

class Proxy(object):
    def __init__(self, session):
        self.username = None
        self.proxy_username = None
        self.hostname = None
        self.hostport = None
        self.password = None
        self.proxy_password = None

"""

def main():
    # WARNING: hacks ahead
    try:
        path = os.environ['ZWA_MODULE_WORK_DIR'] + '/modules/ftp'       # running from zwa make check/zwa sel (from build dir)
    except KeyError:
        path = '..'                                                     # probably started manually
    ftp_py_file = open(path + '/Ftp.py', 'rU')
    ftp_py_code = stub
    for line in ftp_py_file:
        if line.startswith('from'):
            continue
        if line.startswith('import'):
            continue
        ftp_py_code += line

    global ftp_py_globals
    exec ftp_py_code in ftp_py_globals

    ftp_py_globals["proxyLog"] = proxyLog

    unittest.main()

main()

