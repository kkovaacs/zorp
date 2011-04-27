from Zorp.Core import *
from Zorp.Zorp import quit
from Zorp.Zone import root_zone
from Zorp.SockAddr import inet_ntoa
from Zorp.Session import MasterSession
from traceback import *
from time import time
from socket import htonl

config.options.kzorp_enabled = FALSE

def test(str, res, expect):
	if res != expect:
		print str, 'failed,', res, 'should be: ', expect
		raise 'test error'
	else:
		print str, 'ok,', res

def init(name):
	try:
		t1 = InetZone("test1", "192.168.0.0/24", inbound_services=["s1"], outbound_services=["s2"])
		t2 = InetZone("test2", "192.168.0.32/27")
		t3 = InetZone("test3", "192.168.0.0/26")
		t4 = InetZone("test4", "192.168.0.64/27")
		t5 = InetZone("test5", "192.168.0.96/27")
		t6 = InetZone("test6", "192.168.0.0/25")
		t7 = InetZone("test7", "192.168.0.0/16")
		t8 = InetZone("test8", "192.168.1.1/32", admin_parent="test1")
		t9 = InetZone("test9", "192.168.1.2/32", admin_parent="test8")
		t10 = InetZone("test10", "192.168.1.3/32", admin_parent="test9", umbrella=1)
		t11 = InetZone("test11", "192.168.1.4/32", admin_parent="test9")
		t12 = InetZone("test12", "192.168.1.5/32", inbound_services=['*'])
		t13 = InetZone("test13", "192.168.1.6/32", outbound_services=['*'])
		t14 = InetZone("test14", "192.168.0.184", outbound_services=['*'])
		
		test('192.168.0.1', root_zone.findZone(SockAddrInet('192.168.0.1', 10)), t3)
		test('192.168.0.33', root_zone.findZone(SockAddrInet('192.168.0.33', 10)), t2)
		test('192.168.0.65', root_zone.findZone(SockAddrInet('192.168.0.65', 10)), t4)
		test('192.168.0.97', root_zone.findZone(SockAddrInet('192.168.0.97', 10)), t5)
		test('192.168.0.129', root_zone.findZone(SockAddrInet('192.168.0.129', 10)), t1)
		test('192.168.1.129', root_zone.findZone(SockAddrInet('192.168.1.129', 10)), t7)
		test('192.168.0.184', root_zone.findZone(SockAddrInet('192.168.0.184', 10)), t14)

		inet = InetZone("internet", "0.0.0.0/0", inbound_services=["s2"], outbound_services=["s1"])
		test('1.1.1.1', root_zone.findZone(SockAddrInet('1.1.1.1', 10)), inet)
		#for i in range(1,100):
		#	test('masstest1', root_zone.findZone(SockAddrInet(inet_ntoa(htonl(i)), 10)), inet)
		#for i in range(1,100):
		#	test('masstest2', root_zone.findZone(SockAddrInet('192.168.1.129', 10)), t7)
		s = MasterSession()
		s.setService(Service("s1", None))
		s.setServer(SockAddrInet('192.168.1.2', 9999))

		#print time()
		#for i in range(1, 100000):
		#	if s.isServerPermitted() != Z_ACCEPT:
		#		raise 'problema'
		#print time()

		test('service s1#1', t1.isInboundServicePermitted(s), Z_ACCEPT)
		test('service s1#2', t1.isOutboundServicePermitted(s), Z_REJECT)
		test('service s1#3', inet.isInboundServicePermitted(s), Z_REJECT)
		test('service s1#4', inet.isOutboundServicePermitted(s), Z_ACCEPT)
		###
		test('service s1#5', t10.isOutboundServicePermitted(s), Z_REJECT)
		test('service s1#6', t10.isInboundServicePermitted(s), Z_REJECT)
		
		test('service s1#7', t11.isOutboundServicePermitted(s), Z_REJECT)
		test('service s1#8', t11.isInboundServicePermitted(s), Z_ACCEPT)

		test('service s1#9', t12.isInboundServicePermitted(s), Z_ACCEPT)
		test('service s1#10', t12.isOutboundServicePermitted(s), Z_REJECT)

		test('service s1#11', t13.isOutboundServicePermitted(s), Z_ACCEPT)
		test('service s1#12', t13.isInboundServicePermitted(s), Z_REJECT)
		
		
		s.service = Service("s2", None)
		test('service s2#1', t1.isInboundServicePermitted(s), Z_REJECT)
		test('service s2#2', t1.isOutboundServicePermitted(s), Z_ACCEPT)
		test('service s2#3', inet.isInboundServicePermitted(s), Z_ACCEPT)
		test('service s2#4', inet.isOutboundServicePermitted(s), Z_REJECT)
		###
		test('service s2#5', t10.isInboundServicePermitted(s), Z_REJECT)
		test('service s2#6', t10.isOutboundServicePermitted(s), Z_REJECT)

		test('service s2#7', t11.isOutboundServicePermitted(s), Z_ACCEPT)
		test('service s2#8', t11.isInboundServicePermitted(s), Z_REJECT)

		test('service s2#9', t12.isInboundServicePermitted(s), Z_ACCEPT)
		test('service s2#10', t12.isOutboundServicePermitted(s), Z_REJECT)

		test('service s2#11', t13.isOutboundServicePermitted(s), Z_ACCEPT)
		test('service s2#12', t13.isInboundServicePermitted(s), Z_REJECT)

	except Exception, e:
		print_exc()
		quit(1)
		return 1
		
	quit(0)
	return 1
