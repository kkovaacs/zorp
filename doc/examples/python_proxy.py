############################################################################
##
## Copyright (c) 2000 BalaBit IT Ltd, Budapest, Hungary
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
## $Id: python_proxy.py,v 1.2 2003/09/15 17:40:22 bazsi Exp $
##
############################################################################
# Defines a finger proxy written in Python, and binds it to a service
# listening on 127.0.0.1:7979 and forwarding connections to 127.0.0.1:79
############################################################################

from Zorp.Core import *
from Zorp.AnyPy import AnyPyProxy

InetZone('site-net', '192.168.1.0/24',
         inbound_services=["*"], 
         outbound_services=["*"])

InetZone('local', '127.0.0.0/8',
         inbound_services=["*"],
         outbound_services=["*"])

InetZone('internet', '0.0.0.0/0',
         inbound_services=["*"], 
         outbound_services=["*"])
                                                      

class MyFinger(AnyPyProxy):
	def proxyThread(self):
		# establish connection
		self.connectServer('', 0)
		client = self.session.client_stream
		server = self.session.server_stream
		user = client.read(128)
		server.write(user)
		response = server.read(132)
		while response:
			client.write(response)
			response = server.read(132)
	
def zorp():

 	Service("finger", MyFinger,
		router=DirectedChainer(SockAddrInet('127.0.0.1', 79)))
	Listener(SockAddrInet('127.0.0.1', 7979), "finger")

