from Zorp.Core import *
from Zorp.SockAddr import inet_ntoa
from traceback import print_exc

config.options.kzorp_enabled = FALSE

true = 1
false = 0

def test(str, res, expect):
	if res != expect:
		print str, 'failed,', res, 'should be: ', expect
	else:
		print str, 'ok,', res
		
def init(name):
	try:
		dom = InetDomain("192.168.0.1/24")
		test("netaddr(): ", inet_ntoa(dom.netaddr()), "192.168.0.0")
		test("broadcast(): ", inet_ntoa(dom.broadcast()), "192.168.0.255")
		test("netmask(): ", inet_ntoa(dom.netmask()), "255.255.255.0")

	except Exception, e:
		print 'exception: fail', e
		print_exc()
		Zorp.quit(1)
		return 0

	Zorp.quit(0)
	return 1
