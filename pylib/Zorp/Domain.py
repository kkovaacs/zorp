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
    Module defining interface to address domains.
  </summary>
  <description>
    <para>
      This module implements the <parameter>AbstractDomain</parameter> class and its derived classes,
      which encapsulate a set of physical addresses.
    </para>
  </description>
</module>
"""

from Zorp import *
from SockAddr import SockAddrInet, inet_ntoa, inet_aton
from string import split, atoi
from socket import htonl, ntohl
try:
	from SockAddr import inet_pton, inet_ntop
except ImportError:
	pass

class AbstractDomain:
	"""
        <class abstract="yes">
          <summary>
            Abstract base class for address domains.
          </summary>
          <description>
            <para>
              An address domain encapsulates an address type (<parameter>AF_INET</parameter>, <parameter>AF_INET6</parameter>,
              etc.) and provides functions to parse and compare these addresses.
              This functionality is primarily used by Zone classes (see the <link linkend="python.Zone">Service</link> module).
            </para>
          </description>
          <metainfo>
            <attributes>
              <attribute maturity="stable">
                <name>family</name>
                <type></type>
                <description>The address family used by the domain.</description>
              </attribute>
            </attributes>
          </metainfo>
        </class>
	"""
	family = AF_UNSPEC
	
	def __init__(self):
		"""
                <method>
                  <summary>Constructor initializing an instance of the AbstractDomain class.</summary>
                  <description>This constructor is empty and does nothing.</description>
                  <metainfo>
                    <arguments/>
                  </metainfo>
                </method>
		"""
		pass

	def __cmp__(self, other):
		"""
                <method internal="yes">
                  <summary>Function to compare two domains.</summary>
                  <description>
                    <para>
                      This function is a placeholder and is to be overridden by
                      derived classes. It should return <parameter>-1</parameter>, <parameter>0</parameter> or <parameter>1</parameter> for
                      relations less-than, equal-to and greater-than, respectively.
                    </para>
                  </description>
                  <metainfo>
                    <arguments>
                      <argument maturity="stable">
                        <name>other</name>
                        <type></type>
                        <description>The instance compared to this instance.</description>
                      </argument>
                    </arguments>
                  </metainfo>
                </method>
		"""
		raise NotImplementedError

	def contains(self, other):
		"""
		<method internal="yes">
		</method>
		"""
		try:
			if self > other:
				return TRUE
		except ValueError:
			pass
		return FALSE

	def getHostAddr(self, addr):
		"""
		<method internal="yes">
		</method>
		"""
		raise NotImplementedError

	def mapHostAddr(self, addr):
		"""
		<method internal="yes">
		</method>
		"""
		raise NotImplementedError

class InetDomain(AbstractDomain):
	"""
        <class>
          <summary>Class representing IP address ranges, derived from Domain.</summary>
          <description>
            <para>
              A class representing Internet (IPv4) addresses, and IP segments.
              The address is represented in the <parameter>XXX.XXX.XXX.XXX/M</parameter> format, where <parameter>XXX.XXX.XXX.XXX</parameter>
              is the network address, and <parameter>M</parameter> specifies the number of ones (1) in the netmask.
            </para>
            <para>
              Two <parameter>InetDomain</parameter> objects can be compared to each other, and can have the followin relations:</para>
              <itemizedlist>
              <listitem>
              <para>
              <parameter>Class_A</parameter> can contain <parameter>Class_B</parameter>;
              </para>
              </listitem>
              <listitem>
              <para>
              <parameter>Class_A</parameter> can be equal to <parameter>Class_B</parameter>;
              </para>
              </listitem>
              <listitem>
              <para>
              <parameter>Class_B</parameter> can contain <parameter>Class_A</parameter>.
              </para>
              </listitem>
              "equal to" and "contained by". 
              </itemizedlist>
              <para>This comparison is used to organize Zones
              hierarchically. The comparison can raise <parameter>ValueError</parameter> for
              incomparable IP addresses.
            </para>
          </description>
          <metainfo>
            <attributes>
              <attribute maturity="stable">
                <name>mask_bits</name>
                <type></type>
                <description>Number of bits in the netmask.</description>
              </attribute>
              <attribute maturity="stable">
                <name>mask</name>
                <type></type>
                <description>Netmask in network byte order.</description>
              </attribute>
              <attribute maturity="stable">
                <name>ip</name>
                <type></type>
                <description>Network address in network byte order.</description>
              </attribute>
            </attributes>
          </metainfo>
        </class>
       	"""
	def __init__(self, addr=None):
		"""
                <method>
                  <summary>Constructor to initialize an InetDomain instance</summary>
                  <description>
                    <para>
                      This constructor parses the argument <parameter>addr</parameter> and fills
                      instance attributes accordingly.
                    </para>
                  </description>
                  <metainfo>
                    <arguments>
                      <argument maturity="stable">
                        <name>addr</name>
                        <type>
			 <string/>
			</type>
                        <description>
                          <!-- The string representation of an address, or network address in network byte order address range-->
                          The string representation of an address, or network address in network byte order.
                        </description>
                      </argument>
                    </arguments>
                  </metainfo>
                </method>
	       	"""
	        #FIXME: input validation!
	        self.family = AF_INET
	        if not addr:
	        	addr = '0.0.0.0/0'
		parts = split(addr,'/')
		try:
			self.mask_bits = atoi(parts[1])
			self.mask = htonl(((1 << self.mask_bits) - 1) << (32 - self.mask_bits))
		except IndexError:
			self.mask_bits = 32
			self.mask = htonl(0xffffffff)
		self.ip = inet_aton(parts[0]) & self.mask

	def __str__(self):
		"""
                <method internal="yes">
                  <summary>Function returning the string representation of this instance.</summary>
                  <description>
                    This function returns the string representation of this
                    instance in the form address/mask.                   
                  </description>
                  <metainfo>
                    <arguments/>
                  </metainfo>
                </method>
                """
                return "%s/%u" % (inet_ntoa(self.ip), self.mask_bits)

	def __cmp__(self, other):
		"""
                <method internal="yes">
                  <summary>Function to compare this instance to another.</summary>
                  <description>
                    <para>
                      This function compares this instance to another InetDomain
                      instance or to a SockAddrInet instance using set inclusion
                      on addresses.  An address is less than another, if it's
                      fully contained by other.
                      Returns an integer representing the relation between self and other (-1, 0, or 1)
                    </para>
                  </description>
                  <metainfo>
                    <arguments>
                      <argument maturity="stable">
                        <name>other</name>
                        <type></type>
                        <description>the other InetDomain object to compare to</description>
                      </argument>
                    </arguments>
                  </metainfo>
                </method>
		"""
		if isinstance(other, InetDomain):
			if ((self.ip == other.ip) & (self.netmask() == other.netmask())):
				return 0
			if ((self.mask_bits >= other.mask_bits) & ((self.ip & other.netmask()) == other.ip)):
				return -1
			if ((other.mask_bits >= self.mask_bits) & ((other.ip & self.netmask()) == self.ip)):
				return 1
		else:
			try:
				if ((other.ip & self.netmask()) == self.ip):
					return 1
			except AttributeError:
			       	pass
		raise ValueError, '%s and %s are incomparable' % (self, other)

	def getHostAddr(self, addr):
		"""
		<method internal="yes">
		</method>
		"""
		return addr.ip & ~self.netmask()

	def mapHostAddr(self, addr):
		"""
		<method internal="yes">
		</method>
		"""
		return self.netaddr() + (addr & ~self.netmask())
		
	
	def netaddr(self):
		"""
                <method internal="yes">
                  <summary>Function calculating the network address of this address range.</summary>
                  <description>
                    <para>
                      This function returns the network address of the address
                      range represented by this instance.
                      Returns ip address in network byte order
                    </para>
                  </description>
                  <metainfo>
                    <arguments/>
                  </metainfo>
                </method>
		"""
		return self.ip
	
	def broadcast(self):
		"""
                <method internal="yes">
                  <summary>Function calculating the broadcast address of this address range</summary>
                  <description>
                    <para>
                      This function returns the broadcast address of this domain
                      calculated based on attributes.
                      Returns the broadcast address in network byte order
                    </para>
                  </description>
                  <metainfo>
                    <arguments/>
                  </metainfo>
                </method>
		"""
		if self.mask_bits == 0:
			return self.ip
		
		return htonl(ntohl(self.ip) | (0x7fffffff >> (self.mask_bits - 1)))
		
	def netmask(self):
		"""
                <method internal="yes">
                  <summary>Function to calculate the netmask of this address range</summary>
                  <description>
                    <para>
                      This function calculates and returns the netmask of this
                      address range as an integer in network byte order.
                      Returns the network mask as ip in network byte order
                    </para>
                  </description>
                  <metainfo>
                    <arguments/>
                  </metainfo>
                </method>
		"""
		return self.mask


class Inet6Domain(AbstractDomain):
	"""
        <class>
          <summary>Class representing IPv6 address ranges, derived from Domain.</summary>
          <description>
            <para>
            A class representing Internet (IPv6) addresses, and IP segments.
              The address is represented in the <parameter>XXX:XXX:XXX:XXX:XXX:XXX:XXX:XXX/M</parameter> format, 
              where <parameter>XXX:XXX:XXX:XXX:XXX:XXX:XXX:XXX</parameter>
              is the network address, and <parameter>M</parameter> specifies the number of ones (1) in the netmask.              
            </para>
              <para>
              Two <parameter>Inet6Domain</parameter> objects can be compared to each other, and can have the followin relations:</para>
              <itemizedlist>
              <listitem>
              <para>
              <parameter>Class_A</parameter> can contain <parameter>Class_B</parameter>;
              </para>
              </listitem>
              <listitem>
              <para>
              <parameter>Class_A</parameter> can be equal to <parameter>Class_B</parameter>;
              </para>
              </listitem>
              <listitem>
              <para>
              <parameter>Class_B</parameter> can contain <parameter>Class_A</parameter>.
              </para>
              </listitem>
              "equal to" and "contained by". 
              </itemizedlist>
              <para>This comparison is used to organize Zones
              hierarchically. The comparison can raise <parameter>ValueError</parameter> for
              incomparable IP addresses.
            </para>
          </description>
          <metainfo>
            <attributes>
              <attribute maturity="stable">
                <name>mask_bits</name>
                <type></type>
                <description>Number of bits in the netmask.</description>
              </attribute>
              <attribute maturity="stable">
                <name>mask</name>
                <type></type>
                <description>Netmask represented by a tuple of eight 16-bit numbers.</description>
              </attribute>
              <attribute maturity="stable">
                <name>ip</name>
                <type></type>
                <description>Network address represented by a tuple of eight 16-bit numbers.</description>
              </attribute>
            </attributes>
          </metainfo>
        </class>
       	"""
	def __init__(self, addr=None):
		"""
                <method>
                  <summary>Constructor to initialize an Inet6Domain instance.</summary>
                  <description>
                    <para>
                      This constructor parses the argument <parameter>addr</parameter> and fills
                      instance attributes accordingly.
                    </para>
                  </description>
                  <metainfo>
                    <arguments>
                      <argument maturity="stable">
                        <name>addr</name>
                        <type>
			 <string/>
			</type>
                        <description>String representation of an address or address range.</description>
                      </argument>
                    </arguments>
                  </metainfo>
                </method>
	       	"""
	       	
	       	def calculate_mask(number):
	       		mask=()
	       		while number > 0:
	       			n = min(number, 16)
	       			v = htonl(((1 << n) - 1) << (16 - n))
	       			mask = mask + (v,)
	       			number = number - n
	       		mask = mask + (0, ) * (8 - len(mask))
	       		return mask
	       	
	       	if not addr:
	       		addr = '0::0/0'
	        #FIXME: input validation!
	        self.family = AF_INET6
		parts = split(addr,'/')
		try:
			self.mask_bits = atoi(parts[1])
			self.mask = calculate_mask(self.mask_bits)
		except IndexError:
			self.mask_bits = 128
			self.mask = (65535,) * 8
		self.ip = map(lambda x,y: x&y, inet_pton(AF_INET6, parts[0]), self.mask)

	def __str__(self):
		"""
                <method internal="yes">
                  <summary>Function returning the string representation of this instance</summary>
                  <description>
                    <para>
                      This function returns the string representation of this
                      instance in the form address/mask.
                      Returns a string representing this object
                    </para>
                  </description>
                  <metainfo>
                    <arguments/>
                  </metainfo>
                </method>
                """
                return "%s/%u" % (inet_ntop(AF_INET6, self.ip), self.mask_bits)

	def __cmp__(self, other):
		"""
                <method internal="yes">
                  <summary>Function to compare this instance to another</summary>
                  <description>
                    <para>
                      This function compares this instance to another InetDomain
                      instance or to a SockAddrInet instance using set inclusion
                      on addresses.  An address is less than another, if it's
                      fully contained by other.
                      Returns an integer representing the relation between self and other (-1, 0, or 1)
                    </para>
                  </description>
                  <metainfo>
                    <arguments>
                      <argument maturity="stable">
                        <name>other</name>
                        <type></type>
                        <description>the other InetDomain object to compare to</description>
                      </argument>
                    </arguments>
                  </metainfo>
                </method>
		"""
		if isinstance(other, Inet6Domain):
			if ((self.ip == other.ip) & (self.netmask() == other.netmask())):
				return 0
			if ((self.mask_bits >= other.mask_bits) & (map(lambda x,y: x&y, self.ip, other.netmask()) == other.ip)):
				return -1
			if ((other.mask_bits >= self.mask_bits) & (map(lambda x,y: x&y, other.ip, self.netmask()) == self.ip)):
				return 1
		else:
			try:
				if (map(lambda x,y: x&y, other.ip, self.netmask()) == self.ip):
					return 1
			except AttributeError:
			       	pass
		raise ValueError, '%s and %s are incomparable' % (self, other)
	
	def netaddr(self):
		"""
                <method internal="yes">
                  <summary>Function calculating the network address of this address range</summary>
                  <description>
                    <para>
                      This function returns the network address of the address
                      range represented by this instance.
                      Returns ip address in network byte order
                    </para>
                  </description>
                  <metainfo>
                    <arguments/>
                  </metainfo>
                </method>
		"""
		return self.ip
	
	def netmask(self):
		"""
                <method internal="yes">
                  <summary>Function to calculate the netmask of this address range</summary>
                  <description>
                    <para>
                      This function calculates and returns the netmask of this
                      address range as an integer in network byte order.
                      Returns the network mask as ip in network byte order
                    </para>
                  </description>
                  <metainfo>
                    <arguments/>
                  </metainfo>
                </method>
		"""
		return self.mask
