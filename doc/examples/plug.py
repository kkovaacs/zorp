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
## $Id: plug.py,v 1.3 2003/09/15 17:40:22 bazsi Exp $
##
############################################################################
# Demonstrates the usage of the built-in plug proxy. It listens on
# 127.0.0.1:1999 and connects to 127.0.0.1:25

from Zorp.Core import *
from Zorp.Plug import PlugProxy

InetZone('site-net', '192.168.1.0/24', 
	 inbound_services=["*"], 
	 outbound_services=["*"])

InetZone('local', '127.0.0.0/8',
	 inbound_services=["*"],
	 outbound_services=["*"])

InetZone('internet', '0.0.0.0/0',
	 inbound_services=["*"],
	 outbound_services=["*"])

def zorp():

 	Service("plug", PlugProxy,
		router=DirectedRouter(SockAddrInet('127.0.0.1', 25)))
 	Listener(SockAddrInet("0.0.0.0", 1999), "plug")

