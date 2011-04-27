from Zorp.Plug import PlugProxy
from Zorp.Stream import Stream

from Zorp.Core import *
from traceback import *
from time import time, sleep

config.options.kzorp_enabled = FALSE

try:
    import profile
    do_profile = 1
except:
    do_profile = 0

class DummyPlug(PlugProxy):
    count = 0

    def __init__(self, session):
        self.session = session
        DummyPlug.count = DummyPlug.count + 1
        setattr(self.session, self.name, self)
        session.setProxy(self.name)
        log(session.session_id, CORE_SESSION, 5, "Proxy starting; class='%s', proxy='%s'", (self.__class__.__name__, self.name))
        super(DummyPlug, self).__init__(session)

count = 300

def benchmark():
    global listener, count
    for i in range(0, count):
        listener.accepted(stream=Stream(3, "noname"),
        client_address=SockAddrInet('192.168.1.6', 5555),
        client_local=SockAddrInet('192.168.1.5', 80),
        client_listen=SockAddrInet('0.0.0.0', 56789))

def zorp():
    global listener
    try:
        InetZone("test1", "192.168.0.0/24", inbound_services=["s1"], outbound_services=["s2"])
        InetZone("test2", "192.168.0.32/27")
        InetZone("test3", "192.168.0.0/26")
        InetZone("test4", "192.168.0.64/27")
        InetZone("test5", "192.168.0.96/27")
        InetZone("test6", "192.168.0.0/25")
        InetZone("test7", "192.168.0.0/16")
        InetZone("test8", "192.168.1.1/32", admin_parent="test1")
        InetZone("test9", "192.168.1.2/32", admin_parent="test8")
        InetZone("test10", "192.168.1.3/32", admin_parent="test9", umbrella=1)
        InetZone("test11", "192.168.1.4/32", admin_parent="test9")
        InetZone("test12", "192.168.1.5/32", inbound_services=['*'])
        InetZone("test13", "192.168.1.6/32", outbound_services=['*'])

        InetZone("internet", "0.0.0.0/0", inbound_services=["s2"], outbound_services=["s1"])

        Service('test-service', DummyPlug, router=TransparentRouter())

        listener = CSZoneListener(SockAddrInet('0.0.0.0', 56789),
            services={('test1', 'test2'): 'test-service',
            ('test1', 'test3'): 'test-service',
            ('*', '*'): 'test-service'})

        start = time()
        if do_profile:
            profile.run("benchmark()", 'profile.out')
        else:
            benchmark()
        end = time()

        if (DummyPlug.count != count):
            raise Exception("Proxy startup count did not match: count is %d, should be %d " % (DummyPlug.count, count))

    except Exception, e:
        print_exc()
        quit(1)
        return 1

    sleep(2)
    print 'Connection rate: %f' % (1 / ((end-start)/count))
    quit(0)
    return 1
