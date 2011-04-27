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

"""
<module maturity="stable">
<summary>
  Module defining interface to the SockAddr.
</summary>
<description>
  <para>
  This module implements <parameter>inet_ntoa</parameter> and <parameter>inet_aton</parameter>. The module also provides an interface
  to the SockAddr services of the Zorp core. SockAddr is used for example to define the bind address of 
  <link linkend="python.Dispatch.Dispatcher">Dispatchers</link>, or the address of the ZAS server in 
  <link linkend="python.AuthDB.AuthenticationProvider">AuthenticationProvider</link> policies.
  </para>
</description>
</module>
"""

from string import split, atoi
from socket import htonl, ntohl

def inet_aton(ip):
	"""
        <function maturity="stable">
          <summary>
            Function to convert an internet address to a 32-bit integer.
          </summary>
          <description>
            <para>
            This function converts the string representation of an IPv4 address
            to an integer in network byte order.
            Returns unsigned long in network byte order.
            </para>
          </description>
          <metainfo>
            <arguments>
              <argument maturity="stable">
                <name>ip</name>
                <type><string/></type>
                <description>A dotted-quad string</description>
              </argument>
            </arguments>
          </metainfo>
        </function>
	"""
	# FIXME: there is no parameter check
	parts = split(ip, '.', 4);
	return htonl(atoi(parts[0]) << 24 | \
		     atoi(parts[1]) << 16 | \
		     atoi(parts[2]) << 8  | \
		     atoi(parts[3]))

def inet_ntoa(ip):
	"""
        <function maturity="stable">
          <summary>
            Function to convert a 32-bit integer into an IPv4 address.
          </summary>
          <description>
          <para>
            This function converts an IP address from network byte order
            into its string representation (dotted quad).
            Returns string representation of the IP address.
            </para>
          </description>
          <metainfo>
            <arguments>
              <argument maturity="stable">
                <name>ip</name>
                <type></type>
                <description>The IP address as a 32-bit integer (network byte order).</description>
              </argument>
            </arguments>
          </metainfo>
        </function>
	"""
	ip = ntohl(ip)
	
	parts = (((ip & 0xff000000) >> 24) & 0xff,
		 (ip & 0x00ff0000) >> 16,
		 (ip & 0x0000ff00) >> 8,
		 (ip & 0x000000ff))
	return "%u.%u.%u.%u" % parts

class SockAddrInet:
	"""
        <class maturity="stable">
          <summary>
            Class encapsulating an IPv4 address:port pair.
          </summary>
          <description>
            <para>
              This class encapsulates an IPv4 address:port pair, similarly to
              the <parameter>sockaddr_in</parameter> struct in C. The class is implemented and exported by
              the Zorp core. The <parameter>SockAddrInet</parameter> Python class serves only 
              documentation purposes, and has no real connection to the 
              behavior implemented in C.
            </para>
            <example>
            	<title>SockAddrInet example</title>
            	<para>
            	The following example defines an IPv4 address:port pair.</para>
            	<synopsis>
SockAddrInet('192.168.10.10', 80)            	
         	</synopsis>
         	<para>
         	The following example uses SockAddrInet in a dispatcher. See <xref linkend="python.Dispatch.Dispatcher"/> for details on Dispatchers.
         	</para>
            	<synopsis>
Dispatcher(transparent=TRUE, bindto=DBSockAddr(protocol=ZD_PROTO_TCP, sa=SockAddrInet('192.168.11.11', 50080)), service="intra_HTTP_inter", backlog=255, rule_port="50080")
         	</synopsis>
            </example>
          </description>
          <metainfo>
            <attributes>
              <attribute maturity="stable">
                <name>type</name>
                <type><string/></type>
                <description>The <parameter>inet</parameter> value that indicates an address in the AF_INET domain.</description>
              </attribute>
              <attribute maturity="stable">
                <name>ip</name>
                <type></type>
                <description>IP address (network byte order).</description>
              </attribute>
              <attribute maturity="stable">
                <name>ip_s</name>
                <type></type>
                <description>IP address in string representation.</description>
              </attribute>
              <attribute maturity="stable">
                <name>port</name>
                <type></type>
                <description>Port number (network byte order).</description>
              </attribute>
            </attributes>
          </metainfo>
        </class>
	"""
	pass
	
class SockAddrInetRange:
	"""
        <class maturity="stable">
          <summary>
            Class encapsulating an IPv4 address and a port range.
          </summary>
          <description>
            <para>
              A specialized SockAddrInet class which allocates a new port
              within the given range of ports when a dispatcher bounds to it.
              The class is implemented and exported by
              the Zorp core. The <parameter>SockAddrInetRange</parameter> Python class serves only 
              documentation purposes, and has no real connection to the 
              behavior implemented in C.
            </para>
          </description>
          <metainfo>
            <attributes>
              <attribute maturity="stable">
                <name>type</name>
                <type><string/></type>
                <description>The <parameter>inet</parameter> value that indicates an address in the AF_INET domain.</description>
              </attribute>
              <attribute maturity="stable">
                <name>ip</name>
                <type></type>
                <description>IP address (network byte order).</description>
              </attribute>
              <attribute maturity="stable">
                <name>ip_s</name>
                <type></type>
                <description>IP address in string representation.</description>
              </attribute>
              <attribute maturity="stable">
                <name>port</name>
                <type></type>
                <description>Port number (network byte order).</description>
              </attribute>
            </attributes>
          </metainfo>
        </class>

	"""
	pass

class SockAddrUnix:
	"""
        <class maturity="stable">
          <summary>
            Class encapsulating a UNIX domain socket.
          </summary>
          <description>
            <para>
              This class encapsulates a UNIX domain socket endpoint.
              The socket is represented by a filename. The <parameter>SockAddrUnix</parameter> 
              Python class serves only 
              documentation purposes, and has no real connection to the 
              behavior implemented in C.
            </para>
            <example>
            	<title>SockAddrUnix example</title>
            	<para>
            	The following example defines a Unix domain socket.</para>
            	<synopsis>
SockAddrUnix('/var/sample.socket')          	
         	</synopsis>
         	<para>
         	The following example uses SockAddrUnix in a DirectedRouter. 
         	</para>
            	<synopsis>
Service(name="demo_service", proxy_class=HttpProxy, router=DirectedRouter(dest_addr=SockAddrUnix('/var/sample.socket'), overrideable=FALSE, forge_addr=FALSE))           	
         	</synopsis>
            </example>            
          </description>
          <metainfo>
            <attributes>
              <attribute maturity="stable">
                <name>type</name>
                <type><string/></type>
                <description>The <parameter>unix</parameter> value that indicates an address in the UNIX domain.</description>
              </attribute>
            </attributes>
          </metainfo>
        </class>

	"""

#class SockAddrInet6(SockAddr):
#	def __init__(self, ip, port):
#		SockAddr.__init__(self, 'inet6')
#		self.ip = ip
#		self.port = port
