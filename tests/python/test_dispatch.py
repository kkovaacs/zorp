from Zorp.Core import *
from Zorp.Plug import *

from Zorp.Zorp import quit
from traceback import *

config.options.kzorp_enabled = FALSE

def zorp():
	try:
	        Service('test', PlugProxy)
	        
	        # keyword argument is present that is processed by the C code
	        
	        Listener(SockAddrInet('0.0.0.0', 1999), 'test', transparent=TRUE)
	        Listener(DBSockAddr(SockAddrInet('0.0.0.0', 1999)), 'test', transparent=TRUE)
	        Listener(DBIface('eth0', 1999), 'test', transparent=TRUE)
	        Receiver(SockAddrInet('0.0.0.0', 1999), 'test', transparent=TRUE)
	        Receiver(DBSockAddr(SockAddrInet('0.0.0.0', 1999)), 'test', transparent=TRUE)
	        Receiver(DBIface('eth0', 1999), 'test', transparent=TRUE)
	        Dispatcher(DBSockAddr(SockAddrInet('0.0.0.0', 1999), protocol=ZD_PROTO_TCP), 'test', transparent=TRUE)
	        Dispatcher(DBIface('eth0', 1999, protocol=ZD_PROTO_TCP), 'test', transparent=TRUE)
	        Dispatcher(DBIfaceGroup(100, 1999, protocol=ZD_PROTO_TCP), 'test', transparent=TRUE)
	        #Dispatcher(DBIfaceGroup('ifgroup', 1999, protocol=ZD_PROTO_TCP), 'test', transparent=TRUE)

	        ZoneListener(SockAddrInet('0.0.0.0', 1999), {'all': 'test'}, transparent=TRUE)
	        ZoneListener(DBSockAddr(SockAddrInet('0.0.0.0', 1999)), {'all': 'test'}, transparent=TRUE)
	        ZoneListener(DBIface('eth0', 1999), {'all': 'test'}, transparent=TRUE)
	        ZoneReceiver(SockAddrInet('0.0.0.0', 1999), {'all': 'test'}, transparent=TRUE)
	        ZoneReceiver(DBSockAddr(SockAddrInet('0.0.0.0', 1999)), {'all': 'test'}, transparent=TRUE)
	        ZoneReceiver(DBIface('eth0', 1999), {'all': 'test'}, transparent=TRUE)
	        ZoneDispatcher(DBSockAddr(SockAddrInet('0.0.0.0', 1999), protocol=ZD_PROTO_TCP), {'all': 'test'}, transparent=TRUE)
	        ZoneDispatcher(DBIface('eth0', 1999, protocol=ZD_PROTO_TCP), {'all': 'test'}, transparent=TRUE)
	        ZoneDispatcher(DBIfaceGroup(100, 1999, protocol=ZD_PROTO_TCP), {'all': 'test'}, transparent=TRUE)
	        #ZoneDispatcher(DBIfaceGroup('ifgroup', 1999, protocol=ZD_PROTO_TCP), {'all': 'test'}, transparent=TRUE)

	        CSZoneListener(SockAddrInet('0.0.0.0', 1999), {('all', 'all'): 'test'}, transparent=TRUE)
	        CSZoneListener(DBSockAddr(SockAddrInet('0.0.0.0', 1999)), {('all', 'all'): 'test'}, transparent=TRUE)
	        CSZoneListener(DBIface('eth0', 1999), {('all', 'all'): 'test'}, transparent=TRUE)
	        CSZoneReceiver(SockAddrInet('0.0.0.0', 1999), {('all', 'all'): 'test'}, transparent=TRUE)
	        CSZoneReceiver(DBSockAddr(SockAddrInet('0.0.0.0', 1999)), {('all', 'all'): 'test'}, transparent=TRUE)
	        CSZoneReceiver(DBIface('eth0', 1999), {('all', 'all'): 'test'}, transparent=TRUE)
	        CSZoneDispatcher(DBSockAddr(SockAddrInet('0.0.0.0', 1999), protocol=ZD_PROTO_TCP), {('all', 'all'): 'test'}, transparent=TRUE)
	        CSZoneDispatcher(DBIface('eth0', 1999, protocol=ZD_PROTO_TCP), {('all', 'all'): 'test'}, transparent=TRUE)
	        CSZoneDispatcher(DBIfaceGroup(100, 1999, protocol=ZD_PROTO_TCP), {('all', 'all'): 'test'}, transparent=TRUE)
	        #CSZoneDispatcher(DBIfaceGroup('ifgroup', 1999, protocol=ZD_PROTO_TCP), {('all', 'all'): 'test'}, transparent=TRUE)
	        
	        # no keyword arguments

	        Listener(SockAddrInet('0.0.0.0', 1999), 'test')
	        Listener(DBSockAddr(SockAddrInet('0.0.0.0', 1999)), 'test')
	        Listener(DBIface('eth0', 1999), 'test')
	        Receiver(SockAddrInet('0.0.0.0', 1999), 'test')
	        Receiver(DBSockAddr(SockAddrInet('0.0.0.0', 1999)), 'test')
	        Receiver(DBIface('eth0', 1999), 'test')
	        Dispatcher(DBSockAddr(SockAddrInet('0.0.0.0', 1999), protocol=ZD_PROTO_TCP), 'test')
	        Dispatcher(DBIface('eth0', 1999, protocol=ZD_PROTO_TCP), 'test')

	        ZoneListener(SockAddrInet('0.0.0.0', 1999), {'all': 'test'})
	        ZoneListener(DBSockAddr(SockAddrInet('0.0.0.0', 1999)), {'all': 'test'})
	        ZoneListener(DBIface('eth0', 1999), {'all': 'test'})
	        ZoneReceiver(SockAddrInet('0.0.0.0', 1999), {'all': 'test'})
	        ZoneReceiver(DBSockAddr(SockAddrInet('0.0.0.0', 1999)), {'all': 'test'})
	        ZoneReceiver(DBIface('eth0', 1999), {'all': 'test'})
	        ZoneDispatcher(DBSockAddr(SockAddrInet('0.0.0.0', 1999), protocol=ZD_PROTO_TCP), {'all': 'test'})
	        ZoneDispatcher(DBIface('eth0', 1999, protocol=ZD_PROTO_TCP), {'all': 'test'})

	        CSZoneListener(SockAddrInet('0.0.0.0', 1999), {('all', 'all'): 'test'})
	        CSZoneListener(DBSockAddr(SockAddrInet('0.0.0.0', 1999)), {('all', 'all'): 'test'})
	        CSZoneListener(DBIface('eth0', 1999), {('all', 'all'): 'test'})
	        CSZoneReceiver(SockAddrInet('0.0.0.0', 1999), {('all', 'all'): 'test'})
	        CSZoneReceiver(DBSockAddr(SockAddrInet('0.0.0.0', 1999)), {('all', 'all'): 'test'})
	        CSZoneReceiver(DBIface('eth0', 1999), {('all', 'all'): 'test'})
	        CSZoneDispatcher(DBSockAddr(SockAddrInet('0.0.0.0', 1999), protocol=ZD_PROTO_TCP), {('all', 'all'): 'test'})
	        CSZoneDispatcher(DBIface('eth0', 1999, protocol=ZD_PROTO_TCP), {('all', 'all'): 'test'})
	except Exception, e:
		print_exc()
		quit(1)
		return 1
		
	quit(0)
	return 1
