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
    Module defining interface to Network Address Translation.
  </summary>
  <description>
    <para>
      Network Address Translation (NAT) is a technology that can be used to
      change source or destination addresses in a connection from one IP
      address to another one. This module defines the classes performing
      the translation for IP addresses.
    </para>
    <para>Zorp supports several different NAT methods using different
    NAT classes, like <link linkend="python.NAT.GeneralNAT">GeneralNAT</link>
    or <link linkend="python.NAT.StaticNAT">StaticNAT</link>. To actually
    perform network address translation in a service, you have to use a
    <link linkend="python.NAT.NATPolicy">NATPolicy</link> instance that contains
    a configured NAT class. NAT policies provide a way to re-use NAT instances
    whithout having to define NAT mappings for each service individually. </para>
  </description>
  <metainfo>
    <enums>
      <enum maturity="stable" id="enum.NAT.type">
        <description>
        </description>
        <item><name>NAT_SNAT</name></item>
        <item><name>NAT_DNAT</name></item>
      </enum>
    </enums>
  </metainfo>
</module>
"""

from Zorp import *
from SockAddr import SockAddrInet, inet_ntoa
from Domain import InetDomain
from Cache import ShiftCache, TimedCache
import Globals
import types

from random import choice, randint, SystemRandom

import kznf.kznfnetlink
import socket

NAT_SNAT = 0
NAT_DNAT = 1

Globals.nat_policies[None] = None

class NATPolicy:
        """
        <class maturity="stable" type="natpolicy">
          <summary>
            Class encapsulating named NAT instances.
          </summary>
          <description>
            <para>
              This class encapsulates a name and an associated NAT instance.
              NAT policies provide a way to re-use NAT instances whithout
              having to define NAT mappings for each service
              individually.
            </para>
            <example>
            <title>Using Natpolicies</title>
            <para>
            The following example defines a simple NAT policy, and uses this
            policy for SNAT in a service.</para>
            <synopsis>
NATPolicy(name="demo_natpolicy", nat=GeneralNAT(mapping=((InetDomain(addr="10.0.1.0/24"), InetDomain(addr="192.168.1.0/24")),)))

Service(name="office_http_inter", proxy_class=HttpProxy, snat_policy="demo_natpolicy")
            </synopsis>
            </example>
          </description>
        </class>


        """
	def __init__(self, name, nat, cacheable=TRUE):
                """
                <method maturity="stable">
                  <summary>
                    Constructor to initialize a NAT policy.
                  </summary>
                  <description>
                    <para>
                      This contructor initializes a NAT policy.
                    </para>
                  </description>
                  <metainfo>
                    <arguments>
                      <argument>
                        <name>name</name>
                        <type>
                          <string/>
                        </type>
                        <description>Name identifying the NAT policy.</description>
                      </argument>
                      <argument>
                        <name>nat</name>
                        <type>
                          <class filter="nat" instance="yes"/>
                        </type>
                        <description>NAT object which performs address translation.</description>
                      </argument>
                      <argument>
                        <name>cacheable</name>
                        <type>
                          <boolean/>
                        </type>
                        <default>TRUE</default>
                        <description>Enable this parameter to cache the NAT decisions.</description>
                      </argument>
                    </arguments>
                  </metainfo>
                </method>
                """

		self.name = name
		self.nat = nat
		self.cacheable = cacheable
		if self.cacheable:
			self.nat_cache = ShiftCache('nat(%s)' % name, 1000)
		if Globals.nat_policies.has_key(name):
			raise ValueError, "Duplicate NATPolicy name: %s" % name
		Globals.nat_policies[name] = self

	def performTranslation(self, session, addrs, nat_type):
                """
                <method internal="yes">
                </method>
                """
		if session:
			session_id = session.session_id
		else:
			session_id = None
		
		## LOG ##
		# This message reports that the NAT type and the old address before the NAT mapping occurs.
		##
		log(session_id, CORE_DEBUG, 4, "Before NAT mapping; nat_type='%d', src_addr='%s', dst_addr='%s'", (nat_type, str(addrs[NAT_SNAT]), str(addrs[NAT_DNAT])))
			
		if self.cacheable:
			if addrs[NAT_SNAT] and addrs[NAT_DNAT]:
				key = (addrs[NAT_SNAT].ip_s, addrs[NAT_DNAT].ip_s)
			elif addrs[NAT_SNAT]:
				key = (addrs[NAT_SNAT].ip_s, None)
			elif addrs[NAT_DNAT]:
				key = (None, addrs[NAT_DNAT].ip_s)
			else:
				raise ValueError, "NAT without any address set"
				
                        cached = self.nat_cache.lookup(key)
                        if cached:
                        	addr = addrs[nat_type].clone(FALSE)
				addr.ip_s = cached
                        else:
				addr = self.nat.performTranslation(session, addrs, nat_type)
				self.nat_cache.store(key, addr.ip_s)
		else:
			addr = self.nat.performTranslation(session, addrs, nat_type)

		## LOG ##
		# This message reports that the NAT type and the new address after the NAT mapping occurred.
		##
		log(session_id, CORE_DEBUG, 4, "After NAT mapping; nat_type='%d', src_addr='%s', dst_addr='%s', new_addr='%s'", (nat_type, str(addrs[NAT_SNAT]), str(addrs[NAT_DNAT]), str(addr)))
		return addr
		
	def getKZorpMapping(self):
		"""
		<method internal="yes">
		</method>
		"""	
		if hasattr(self.nat, 'getKZorpMapping'):
			return self.nat.getKZorpMapping()
		raise ValueError, "NAT class does not support KZorp representation"

def getNATPolicy(name):
        """
        <function internal="yes">
        </function>
        """
        if name:
        	if Globals.nat_policies.has_key(name):
	                return Globals.nat_policies[name]
		else:
			log(None, CORE_POLICY, 3, "No such NAT policy; policy='%s'", name)
        return None

class AbstractNAT:
	"""
        <class maturity="stable" abstract="yes">
          <summary>
            Class encapsulating the abstract NAT interface.
          </summary>
          <description>
            <para>
              This class encapsulates an interface for application level network
              address translation (NAT). This NAT is different from the NAT used
              by packet filters: it modifies the outgoing source/destination addresses
              just before Zorp connects to the server.
            </para>
            <para>
              Source and destination NATs can be specified when a <link linkend="python.Service.Service">Service</link> is
              created.
            </para>
            <para>
              The NAT settings are used by the <link linkend="python.Chainer.ConnectChainer">ConnectChainer</link>
              class just before connecting to the server.
            </para>
          </description>
        </class>
        """

        def __init__(self):
                """
                <method maturity="stable">
                  <summary>
                    Constructor to initialize an AbstractNAT instance.
                  </summary>
                  <description>
                    <para>
                      This constructor initializes an AbstractNAT instance.
                      Currently it does nothing, but serves as a placeholder for
                      future extensions.
                    </para>
                  </description>
                  <metainfo>
                    <arguments/>
                  </metainfo>
                </method>
		"""
		pass

	def performTranslation(self, session, addrs, nat_type):
		"""
                <method maturity="stable">
                  <summary>
                    Function that performs the address translation.
                  </summary>
                  <description>
                    <para>
                    This function is called before connecting a session
                    to the destination server. The function returns the address (a <link linkend="python.SockAddr">SockAddr</link> instance) to
                    bind to before establishing the connection.
                    </para>
                  </description>
                  <metainfo>
                    <arguments>
                      <argument maturity="stable">
                        <name>session</name>
                        <type></type>
                        <description>Session which is about to connect the server.</description>
                      </argument>
                      <argument maturity="stable">
                        <name>addrs</name>
                        <type></type>
                        <description>tuple of (source, destination) address, any of them can be none in case of the other translation</description>
                      </argument>
                      <argument maturity="stable">
                        <name>nat_type</name>
                        <type></type>
                        <description>translation type, either NAT_SNAT or NAT_DNAT</description>
                      </argument>
                    </arguments>
                  </metainfo>
                </method>
                """
                raise NotImplementedError

class GeneralNAT(AbstractNAT):
        """
        <class maturity="stable">
          <summary>
            Class encapsulating a general subnet-to-subnet NAT.
          </summary>
          <description>
            <para>
              This class encapsulates a general subnet-to-subnet NAT. It
              requires a list of <parameter>from, to, translated to</parameter> parameters:</para>
              <itemizedlist>
              <listitem>
              <para><emphasis>from</emphasis>: the source address of the connection.</para>
              </listitem>
              <listitem>
              <para><emphasis>to</emphasis>: the destination address of the connection.</para>
              </listitem>
              <listitem>
              <para><emphasis>translated to</emphasis>: the translated address.</para>
              </listitem>
              </itemizedlist>
              <para>If the NAT policy is used as SNAT, the translated address is 
              used to translate the source address of the connection;
              if the NAT policy is used as DNAT, the translated address is 
              used to translate the destination address of the connection.
              The translation occurs according to the first matching rule.
            </para>
           <example>
            <title>GeneralNat example</title>
            <para>
            The following example defines a simple GeneralNAT policy that maps
            connections coming from the <parameter>192.168.1.0/24</parameter> subnet 
            and targeting the <parameter>192.168.10.0/24</parameter> subnet into the
            <parameter>10.70.0.0/24</parameter> subnet.</para>
            <synopsis>NATPolicy(name="Demo_GeneralNAT", nat=GeneralNAT(mapping=((InetDomain(addr="192.168.1.0/24"), InetDomain(addr="192.168.10.0/24"), InetDomain(addr="10.70.0.0/24")),)))</synopsis>
            <para>If the policy is used as SNAT, the <parameter>192.168.1.0/24</parameter>
             subnet is translated into the <parameter>10.70.0.0/24</parameter> subnet and 
             used as the source address of the connection. 
             If the policy is used as DNAT, the <parameter>192.168.10.0/24</parameter>
             subnet is translated into the <parameter>10.70.0.0/24</parameter> subnet and 
             used as the target address of the connection. </para>
            </example>
          </description>
        </class>
        """
	def __init__(self, mapping):
                """
                <method maturity="stable">
                  <summary>
                    Constructor to initialize a GeneralNAT instance.
                  </summary>
                  <description>
                    <para>
                      This constructor initializes a GeneralNAT instance.
                    </para>
                  </description>
                  <metainfo>
                    <arguments>
                      <argument>
                        <name>mapping</name>
                        <type>
                          <list>
                            <tuple>
			      <class filter="domain" instance="yes"/>
			      <class filter="domain" instance="yes"/>
			      <class filter="domain" instance="yes"/>
                            </tuple>
                          </list>
                        </type>
                        <description>
			  List of tuples of InetDomains in (source domain, destination domain,
			  mapped domain) format.
                        </description>
                      </argument>
                    </arguments>
                  </metainfo>
                </method>
                """
		AbstractNAT.__init__(self)
		if type(mapping) != types.TupleType and type(mapping) != types.ListType:
			mapping = (mapping,)

		self.mappings = [[], []]
		self.compatibility_mode = FALSE
		for map in mapping:
			if len(map) == 2:
				self.mappings[NAT_SNAT].append((map[0], map[0].__class__(), map[1]))
				self.mappings[NAT_DNAT].append((map[0].__class__(), map[0], map[1]))
				self.compatibility_mode = TRUE
			else:
				self.mappings[NAT_SNAT].append(map)
				self.mappings[NAT_DNAT].append(map)

	def performTranslation(self, session, addrs, nat_type):
                """
                <method internal="yes">
                </method>
                """
		for map in self.mappings[nat_type]:
			(src_dom, dst_dom, map_dom) = map
			if ((not addrs[NAT_SNAT] or src_dom.contains(addrs[NAT_SNAT])) and 
			    (not addrs[NAT_DNAT] or dst_dom.contains(addrs[NAT_DNAT]))):
			    
				# we have a match is in domain, do translation
				addr = addrs[nat_type].clone(FALSE)
				hostaddr = map[nat_type].getHostAddr(addrs[nat_type])
				addr.ip = map[2].mapHostAddr(hostaddr)
				return addr
		return addrs[nat_type]
	
	def getKZorpMapping(self):
		"""
		<method internal="yes">
		</method>
		"""	
		def domainToKZorpTuple(domain):
			return (kznf.kznfnetlink.KZ_SVC_NAT_MAP_IPS, socket.ntohl(domain.netaddr()), socket.ntohl(domain.broadcast()), 0, 0)
			
		if self.compatibility_mode:
			raise ValueError, "GeneralNAT with old-style mapping parameter does not support KZorp representation"
		
		result = []
		for (src_dom, dst_dom, map_dom) in self.mappings[NAT_SNAT]:
			result.append((domainToKZorpTuple(src_dom), domainToKZorpTuple(dst_dom), domainToKZorpTuple(map_dom)))
		return result

class ForgeClientSourceNAT(AbstractNAT):
	"""
        <class maturity="obsolete">
          <summary>
            Class using the original client address for outgoing connections.
          </summary>
          <description>
            <para>
              This class uses the client's IP address as the source address of the server-side connection. That way the
               server sees that the connection comes from the original client instead of the firewall.
            </para>
            <para>
              This feature is useful when the source address of the server-side conneciton is important, for
              example, to webservers performing address-based access control.
            </para>
            <warning>
            <para>
              This class is OBSOLETE and may be removed in future releases.
              Use the <parameter>forge_addr</parameter> parameter of
              the <link linkend="python.Router">Router</link> class used in the service definition instead.
            </para>
            </warning>
          </description>
        </class>
	"""
	def performTranslation(self, session, addrs, nat_type):
		"""
                <method internal="yes">
                </method>
		"""
		return session.client_address.clone(TRUE)

class StaticNAT(AbstractNAT):
	"""
        <class maturity="stable">
          <summary>
            Class that replaces the source or destination address with
            a predefined address.
          </summary>
          <description>
            <para>
              This class assigns a predefined value to the
              address of the connection.
            </para>
          </description>
        </class>
        """
        def __init__(self, addr):
                """
                <method maturity="stable">
                  <summary>
                    Constructor to initialize a StaticNAT instance.
                  </summary>
                  <description>
                    <para>
                      This constructor initializes a StaticNAT instance.
                    </para>
                  </description>
                  <metainfo>
                    <arguments>
                      <argument maturity="stable">
                        <name>addr</name>
                        <type>
			  <sockaddr/>
			</type>
                        <description>The address that replaces all addresses.</description>
                      </argument>
                    </arguments>
                  </metainfo>
                </method>
		"""
		AbstractNAT.__init__(self)
		self.addr = addr

	def performTranslation(self, session, addrs, nat_type):
		"""
                <method internal="yes">
                </method>
		"""
		
		return self.addr.clone(FALSE)


class OneToOneNAT(AbstractNAT):
	"""
        <class maturity="stable">
          <summary>
            Class translating addresses between two IP ranges.
          </summary>
          <description>
          <note>
              <para>This class is obsolete, use <link linkend="python.NAT.OneToOneMultiNAT">GeneralNAT</link> instead.</para>
            </note>
            <para>
              This class performs 1:1 address translation between the source
              and destination subnets. If the source address
              is outside the given source address range, a <parameter>DACException</parameter> is raised.
              The source and destination subnets must have the same size.
            </para>
            <tip>
            <para>
              Use OneToOneNAT to redirect a
              a block of IP addresses to another block, for example, when the webservers
              located in the DMZ have dedicated IP aliases on the firewall.
            </para>
            </tip>
          </description>
        </class>
        """
        def __init__(self, from_domain, to_domain, default_reject=TRUE):
                """
                <method maturity="stable">
                  <summary>
                    Constructor to initialize a OneToOneNAT instance.
                  </summary>
                  <description>
                    <para>
                      This constructor initializes a OneToOneNAT instance. Arguments must be
                      <parameter>InetDomain</parameter> instances specifying two non-overlapping IP subnets
                      with the same size.
                    </para>
                  </description>
                  <metainfo>
                    <arguments>
                      <argument maturity="stable">
                        <name>from_domain</name>
                        <type>
                          <class filter="domain" instance="yes"/>
                        </type>
                        <description>The source subnet (InetDomain instance).</description>
                      </argument>
                      <argument maturity="stable">
                        <name>to_domain</name>
                        <type>
                          <class filter="domain" instance="yes"/>
                        </type>
                        <description>The destination subnet (InetDomain instance).</description>
                      </argument>
                      <argument maturity="stable">
                        <name>default_reject</name>
                        <type>
                          <boolean/>
                        </type>
                        <default>TRUE</default>
                        <description>Enable this parameter to reject all connections outside the specific source
                        range.</description>
                      </argument>
                    </arguments>
                  </metainfo>
                </method>
		"""
		AbstractNAT.__init__(self)
		self.from_domain = from_domain
		self.to_domain = to_domain
		self.default_reject = default_reject
		if from_domain.mask_bits != to_domain.mask_bits:
			raise ValueError, 'OneToOneNAT requires two domains of the same size'
		
	def performTranslation(self, session, addrs, nat_type):
		"""
                <method internal="yes">
                </method>
		"""
		try:
			return self.mapAddress(addrs[nat_type], self.from_domain, self.to_domain, nat_type)
		except ValueError:
			pass
		if self.default_reject:
			raise DACException, 'IP not within the required range.'
		else:
			return addr

	def mapAddress(self, addr, from_domain, to_domain, nat_type):
		"""
                <method internal="yes">
                  <summary>
                    Function to map an address to another subnet.
                  </summary>
                  <description>
                    <para>
                      This function maps the address 'addr' in the domain
                      'from_domain' to another domain 'to_domain'.
                      Returns a SockAddrInet in the destination domain or None
                    </para>
                  </description>
                  <metainfo>
                    <arguments>
                      <argument maturity="stable">
                        <name>from_domain</name>
                        <type></type>
                        <description>source domain</description>
                      </argument>
                      <argument maturity="stable">
                        <name>to_domain</name>
                        <type></type>
                        <description>destination domain</description>
                      </argument>
                      <argument maturity="stable">
                        <name>nat_type</name>
                        <type></type>
                        <description>specifies the NAT type</description>
                      </argument>
                    </arguments>
                  </metainfo>
                </method>
                """
                if addr < from_domain:
                        ip = (addr.ip & ~to_domain.mask) + (to_domain.ip & to_domain.mask)
                        if nat_type == NAT_SNAT:
                                return SockAddrInet(inet_ntoa(ip), 0)
                        elif nat_type == NAT_DNAT:
                                return SockAddrInet(inet_ntoa(ip), addr.port)

class OneToOneMultiNAT(OneToOneNAT):
        """
        <class maturity="stable">
          <summary>
            Class translating addresses between two IP ranges.
          </summary>
          <description>
            <note>
              <para>This class is obsolete, use <link linkend="python.NAT.OneToOneMultiNAT">GeneralNAT</link> instead.</para>
            </note>
            <para>
              This class is similar to <link target="python.NAT.OneToOneNAT">OneToOneNAT</link> as it 1:1 address
               translation between the source and destination subnets. The difference is that the OneToOneMultiNAT class
                supports multiple mappings by using a list of mapping pairs.
            </para>
            <para>
              If the source address
              is outside the given source address range, a <parameter>DACException</parameter> is raised.
              The source and destination subnets must have the same size.
            </para>
          </description>
        </class>
        """
        def __init__(self, mapping, default_reject=TRUE):
                """
                <method maturity="stable">
                  <summary>
                    Constructor to initialize a OneToOneMultiNAT instance.
                  </summary>
                  <description>
                    <para>
                      This constructor initializes an instance of the OneToOneMultiNAT class. Arguments must be
                      <parameter>InetDomain</parameter> instances specifying two non-overlapping IP subnets
                      with the same size.
                    </para>
                  </description>
                  <metainfo>
                    <arguments>
                      <argument maturity="stable">
                        <name>mapping</name>
                        <type>
                          <list>
                            <tuple>
                              <class filter="domain" instance="yes"/>
                              <class filter="domain" instance="yes"/>
                            </tuple>
                          </list>
                        </type>
                        <description>
                          List of <parameter>InetDomain</parameter> pairs in the <parameter>from, to</parameter> format.
                        </description>
                      </argument>
                      <argument maturity="stable">
                        <name>default_reject</name>
                        <type>
                          <boolean/>
                        </type>
                        <default>TRUE</default>
                        <description>Enable this parameter to reject all connections outside the specific source
                        range.</description>
                      </argument>
                    </arguments>
                  </metainfo>
                </method>
		"""
		AbstractNAT.__init__(self)
		self.mapping = mapping
		self.default_reject = default_reject
		for (from_domain, to_domain) in mapping:
			if from_domain.mask_bits != to_domain.mask_bits:
				raise ValueError, 'OneToOneMultiNAT requires two domains of the same size'

	def performTranslation(self, session, addrs, nat_type):
		"""
                <method internal="yes">
                </method>
		"""
		for (from_domain, to_domain) in self.mapping:
			try:
				return self.mapAddress(addrs[nat_type], from_domain, to_domain, nat_type)
			except ValueError:
				pass
		if self.default_reject:
			raise DACException, 'IP not within the required range.'
		else:
			return addr

class RandomNAT(AbstractNAT):
	"""
        <class maturity="stable">
          <summary>
            Class generating a random IP address.
          </summary>
          <description>
            <para>
              This class randomly selects an address from a list of IP addresses.
              This can be used for load-balancing several lines by binding
              each session to a different interface.
            </para>
          </description>
        </class>
        """
        def __init__(self, addresses):
                """
                <method maturity="stable">
                  <summary>
                    Constructor to initialize a RandomNAT instance.
                  </summary>
                  <description>
                    <para>
                      This constructor initializes a RandomNAT instance.
                    </para>
                  </description>
                  <metainfo>
                    <arguments>
                      <argument maturity="stable">
                        <name>addresses</name>
                        <type>
                          <list>
                            <sockaddr/>
                          </list>
                        </type>
                        <description>List of the available interfaces. Each item of the list must be am instance
                        of the <parameter>SockAddr</parameter> (or a derived) class.</description>
                      </argument>
                    </arguments>
                  </metainfo>
                </method>
		"""
		AbstractNAT.__init__(self)
		self.addresses = addresses
	
	def performTranslation(self, session, addrs, nat_type):
		"""
                <method internal="yes">
                </method>
                """
                return choice(self.addresses)

class HashNAT(AbstractNAT):
        """
        <class maturity="stable">
          <summary>
            Class which sets the address from a hash table.
          </summary>
          <description>
           HashNAT statically maps an IP address to
           another using a hash table. The table is indexed by the source IP address, and the
           value is the translated IP address. Both IP addresses are stored in string format.
          </description>
        </class>
        """
        def __init__(self, ip_hash, default_reject=TRUE):
                """
                <method maturity="stable">
                  <summary>
                    Constructor to initialize a HashNAT instance.
                  </summary>
                  <description>
                    <para>
                      This constructor initializes a HashNAT instance.
                    </para>
                  </description>
                  <metainfo>
                    <arguments>
                      <argument maturity="stable">
                        <name>ip_hash</name>
                        <type>
			  <hash>
			    <key>
			      <string/>
			    </key>
			    <value>
			      <string/>
			    </value>
			  </hash>
			</type>
                        <description>The hash storing the IP address.</description>
                      </argument>
                      <argument maturity="stable">
                        <name>default_reject</name>
                        <type>
			  <boolean/>
			</type>
			<default>TRUE</default>
                        <description>Enable this parameter to reject all connections outside the specific source 
                        range.</description>
                      </argument>
                    </arguments>
                  </metainfo>
                </method>
		"""
		AbstractNAT.__init__(self)
		self.ip_hash = ip_hash
		self.default_reject = default_reject

	def performTranslation(self, session, addrs, nat_type):
		"""
                <method internal="yes">
                </method>
		"""
		try:
			ip = self.ip_hash[addrs[nat_type].ip_s]
			if nat_type == NAT_SNAT:
				return SockAddrInet(ip, 0)
			else:
				return SockAddrInet(ip, addr.port)
		except KeyError:
			if self.default_reject:
				raise DACException, 'IP not within the required range.'
			else:
				return addr

