#!/usr/bin/env python

import os
import sys
import glob

import socket
socket.IP_TRANSPARENT = 19
socket.SO_KZORP_RESULT = 1678333

from kznf.kznfnetlink import *
from kznf.nfnetlink import *


class KZorpSockoptTest(object):
    def __init__(self, *args):
	super(KZorpSockoptTest, self).__init__(*args)
	self.handle = Handle()
	self.handle.register_subsystem(Subsystem(NFNL_SUBSYS_KZORP))

    def exchange_message(self, message, payload):
	m = self.handle.create_message(NFNL_SUBSYS_KZORP, message, NLM_F_REQUEST | NLM_F_ACK)
	m.set_nfmessage(payload)
	result = self.handle.talk(m, (0, 0), None)
	if result:
	    raise NfnetlinkException, "Error while talking to KZorp"

    def exchange_messages(self, message_list):
	for (message, payload) in message_list:
	    self.exchange_message(message, payload)

    __setup_messages = \
	(
	  (KZNL_MSG_START,            create_start_msg(KZ_TR_TYPE_SERVICE, "test", 123456789L)),
	  (KZNL_MSG_FLUSH_SERVICE,    create_flush_msg()),
	  (KZNL_MSG_ADD_SERVICE,      create_add_proxyservice_msg("service")),
	  (KZNL_MSG_COMMIT,           create_commit_msg()),

	  (KZNL_MSG_START,            create_start_msg(KZ_TR_TYPE_ZONE, KZ_INSTANCE_GLOBAL, 123456789L)),
	  (KZNL_MSG_FLUSH_ZONE,       create_flush_msg()),
	  (KZNL_MSG_ADD_ZONE,         create_add_zone_msg("internet", 0, 0L, 0L, None, None)),
	  (KZNL_MSG_ADD_ZONE_SVC_OUT, create_add_zone_svc_msg("internet", "*")),
	  (KZNL_MSG_ADD_ZONE_SVC_IN,  create_add_zone_svc_msg("internet", "*")),
	  (KZNL_MSG_COMMIT,           create_commit_msg()),

	  (KZNL_MSG_START,            create_start_msg(KZ_TR_TYPE_DISPATCHER, "test", 123456789L)),
	  (KZNL_MSG_FLUSH_DISPATCHER, create_flush_msg()),
	  (KZNL_MSG_ADD_DISPATCHER,   create_add_dispatcher_n_dimension("dispatcher", KZF_DPT_TRANSPARENT, 12345, 1)),
	  (KZNL_MSG_ADD_RULE,         create_add_n_dimension_rule_msg("dispatcher", 1, "service", {})),
	  (KZNL_MSG_COMMIT,           create_commit_msg()),
	)

    def setUp(self):
	self.exchange_messages(self.__setup_messages)

    __teardown_messages = \
	(
	  (KZNL_MSG_START,            create_start_msg(KZ_TR_TYPE_DISPATCHER, "test", 987654321L)),
	  (KZNL_MSG_FLUSH_DISPATCHER, create_flush_msg()),
	  (KZNL_MSG_COMMIT,           create_commit_msg()),

	  (KZNL_MSG_START,            create_start_msg(KZ_TR_TYPE_ZONE, KZ_INSTANCE_GLOBAL, 987654321L)),
	  (KZNL_MSG_FLUSH_ZONE,       create_flush_msg()),
	  (KZNL_MSG_COMMIT,           create_commit_msg()),

	  (KZNL_MSG_START,            create_start_msg(KZ_TR_TYPE_SERVICE, "test", 987654321L)),
	  (KZNL_MSG_FLUSH_SERVICE,    create_flush_msg()),
	  (KZNL_MSG_COMMIT,           create_commit_msg()),
	)

    def tearDown(self):
	self.exchange_messages(self.__teardown_messages)

if __name__ == "__main__":

  if os.getenv("USER") != "root":
    print "ERROR: You need to be root to run the unit test"
    sys.exit(1)

  if glob.glob('/var/run/zorp/*.pid'):
    print "ERROR: pidfile(s) exist in /var/run/zorp directory. Zorp is running?"
    print "       You should stop Zorp and/or delete pid files from /var/run/zorp"
    print "       in order to run this test."
    sys.exit(1)

  test = KZorpSockoptTest()
  test.setUp()

  print "*" * 70
  print "KZorp configuration set up, start get_kzorp_result, then connect to"
  print "any TCP port of the test host with netcat. get_kzorp_result should"
  print "then print the following following:\n"
  print "Cookie: 123456789, client zone: 'internet', server zone: 'internet',"
  print "dispatcher: 'dispatcher', service: 'service'\n"
  print "Then press Enter to flush the KZorp configuration"
  print "*" * 70

  sys.stdin.readline()
  test.tearDown()
