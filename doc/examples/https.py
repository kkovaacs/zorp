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
## $Id: https.py,v 1.2 2003/09/15 17:40:22 bazsi Exp $
##
############################################################################
# This example demonstrates the use of a transparent HTTPS (HTTP embedded
# in SSL) proxy.

from Zorp.Core import *
from Zorp.Pssl import *
from Zorp.Http import *

Zorp.firewall_name = 'bzorp@balabit'

InetZone('site-net', '192.168.1.0/24', 
	 inbound_services=["*"], 
	 outbound_services=["*"])

InetZone('local', '127.0.0.0/8',
	 inbound_services=["*"],
	 outbound_services=["*"])

InetZone('internet', '0.0.0.0/0',
	 inbound_services=["*"],
	 outbound_services=["*"])

# transparent Https proxy
class MyHttpsProxy(PsslProxy):

	class EmbeddedHttpProxy(HttpProxy):
		def config(self):
			HttpProxy.config(self)
			self.request_headers["User-Agent"] = (Http.HTTP_CHANGE_VALUE, "Lynx 2.8,1")
			
	def config(self):
		self.server_need_ssl = TRUE
		self.client_need_ssl = TRUE
		self.client_key = '/etc/zorp/server.key'
		self.client_cert = '/etc/zorp/server.crt'
		self.stack_proxy = EmbeddedHttpProxy

def zorp():
 	Service("https", MyHttpsProxy, 
		router=TransparentRouter())
 	Listener(SockAddrInet("0.0.0.0", 8080), "https")

