############################################################################
##
## Copyright (c) 2000, 2001, 2002, 2003, 2004, 2005, 2006, 2007, 2008, 2009,
## 2010, 2011 BalaBit IT Ltd, Budapest, Hungary
##
## This program is free software; you can redistribute it and/or modify
## it under the terms of the GNU General Public License as published by
## the Free Software Foundation; either version 2 of the License, or
## (at your option) any later version.
##
## This program is distributed in the hope that it will be useful,
## but WITHOUT ANY WARRANTY; without even the implied warranty of
## MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
## GNU General Public License for more details.
##
## You should have received a copy of the GNU General Public License
## along with this program; if not, write to the Free Software
## Foundation, Inc., 675 Mass Ave, Cambridge, MA 02139, USA.
##
##
############################################################################

import Globals
import random, time, socket, errno
import kznf.kznfnetlink
from Zorp import *

def netlinkmsg_handler(msg):
        pass

def openHandle():
        h = kznf.nfnetlink.Handle()
        s = kznf.nfnetlink.Subsystem(kznf.nfnetlink.NFNL_SUBSYS_KZORP)
        h.register_subsystem(s)
        return h

def exchangeMessage(h, msg, payload):
        m = h.create_message(kznf.nfnetlink.NFNL_SUBSYS_KZORP, msg, kznf.nfnetlink.NLM_F_REQUEST | kznf.nfnetlink.NLM_F_ACK)
        m.set_nfmessage(payload)
        result = h.talk(m, (0, 0), netlinkmsg_handler)
        if result != 0:
                raise kznf.nfnetlink.NfnetlinkException, "Error while talking to kernel; result='%d'" % (result)

def exchangeMessages(h, messages):
        for (msg, payload) in messages:
                exchangeMessage(h, msg, payload)

def startTransaction(h, type, instance_name):
        tries = 7
        wait = 0.1
        while tries > 0:
                try:
                        exchangeMessage(h, kznf.kznfnetlink.KZNL_MSG_START, \
                                        kznf.kznfnetlink.create_start_msg(type, instance_name))
                except socket.error, e:
                        if e[0] == errno.ECONNREFUSED:
                                raise
                except:
                        tries = tries - 1
                        if tries == 0:
                                raise
                        wait = 2 * wait
                        time.sleep(wait * random.random())
                        continue

                break

def commitTransaction(h):
        exchangeMessage(h, kznf.kznfnetlink.KZNL_MSG_COMMIT, \
                        kznf.kznfnetlink.create_commit_msg())

def downloadKZorpConfig(instance_name):

        def walkZones(messages, parent, child):
                messages.extend(child.buildKZorpMessage())
                child.iterAdminChildren(walkZones, messages)

        random.seed()
        h = openHandle()

        # download services
        startTransaction(h, kznf.kznfnetlink.KZ_TR_TYPE_SERVICE, instance_name)
        try:
                exchangeMessage(h, kznf.kznfnetlink.KZNL_MSG_FLUSH_SERVICE, \
                                kznf.kznfnetlink.create_flush_msg())

                for service in Globals.services.values():
                        messages = service.buildKZorpMessage()
                        exchangeMessages(h, messages)

                commitTransaction(h)
        except:
                h.close()
                raise

        # download zones
        startTransaction(h, kznf.kznfnetlink.KZ_TR_TYPE_ZONE, kznf.kznfnetlink.KZ_INSTANCE_GLOBAL)
        try:
                exchangeMessage(h, kznf.kznfnetlink.KZNL_MSG_FLUSH_ZONE, \
                                kznf.kznfnetlink.create_flush_msg())

                for zone in Globals.zones.values():
                        if not zone.admin_parent:
                                messages = zone.buildKZorpMessage()
                                if not messages:
                                        messages = []

                                zone.iterAdminChildren(walkZones, messages)
                                exchangeMessages(h, messages)

                commitTransaction(h)
        except:
                h.close()
                raise

        # download dispatchers
        startTransaction(h, kznf.kznfnetlink.KZ_TR_TYPE_DISPATCHER, instance_name)
        try:
                exchangeMessage(h, kznf.kznfnetlink.KZNL_MSG_FLUSH_DISPATCHER, \
                                kznf.kznfnetlink.create_flush_msg())

                for dispatch in Globals.dispatches:
			try:
				messages = dispatch.buildKZorpMessage()
				exchangeMessages(h, messages)
			except:
				log(None, CORE_ERROR, 0, "Error occured during Dispatcher upload to KZorp; dispatcher='%s', error='%s'" % (dispatch.bindto.format(), sys.exc_value))
				raise

                commitTransaction(h)
        except:
                h.close()
                raise

        h.close()

def flushKZorpConfig(instance_name):

        random.seed()
        h = openHandle()

        # flush dispatchers
        startTransaction(h, kznf.kznfnetlink.KZ_TR_TYPE_DISPATCHER, instance_name)
        try:
                exchangeMessage(h, kznf.kznfnetlink.KZNL_MSG_FLUSH_DISPATCHER, \
                                kznf.kznfnetlink.create_flush_msg())
                commitTransaction(h)
        except:
                h.close()
                raise

        # flush services
        startTransaction(h, kznf.kznfnetlink.KZ_TR_TYPE_SERVICE, instance_name)
        try:
                exchangeMessage(h, kznf.kznfnetlink.KZNL_MSG_FLUSH_SERVICE, \
                                kznf.kznfnetlink.create_flush_msg())
                commitTransaction(h)
        except:
                h.close()
                raise

        h.close()
