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
Module defining the resolver used to resolve domain names to IP addresses.
</summary>
<description>
This module defines the AbstractResolver interface and various derived classes
to perform name lookups.
</description>
</module>
"""


from Zorp import *
from SockAddr import SockAddrInet
from socket import gethostbyname_ex
import types

# NOTE: This is IPv4 specific

class ResolverPolicy:
        """ 
        <class maturity="stable" type="resolverpolicy"> 
          <summary>
          Class encapsulating a Resolver which can be referenced using its identifier
          </summary> 
          <description>
          <para>Resolvers and resolver policies specify how a Zorp service should
          resolve the domain names in client requests; resolvers are used whenever
          Zorp needs to resolve domain names in order to perform connection
          processing. Such an event occurs when
          <link linkend="python.Router.InbandRouter">InbandRouter</link> is used
          and the Zorp proxy has a DNS name to establish connection to. Names are
          usually resolved using the domain name server (
          <link linkend="python.Resolver.DNSResolver">DNSResolver</link> class),
          or the <link linkend="python.Resolver.HashResolver">HashResolver</link>
          class when the dependence on DNS has to be avoided.</para>
          <para>
          To actually perform name resolution, you have to use a
          <link linkend="python.Resolver.ResolverPolicy">ResolverPolicy</link> instance
          that contains a configured Resolver class. Resolver policies provide a
          way to re-use Resolver instances whithout having to define a Resolver
          for each service individually. </para>
          </description>
          <metainfo>
            <attributes>
            </attributes>
          </metainfo>
        </class>
        """
        def __init__(self, name, resolver):
                """
                <method>
                  <metainfo>
                    <arguments>
                      <argument>
                        <name>name</name>
                        <type>
                          <string/>
                        </type>
                        <description>Name identifying the Resolver policy.
                        </description>
                      </argument>
                      <argument>
                        <name>resolver</name>
                        <type>
                          <class filter="resolver" instance="yes"/>
                        </type>
                        <description>
                        Resolver object which performs name resolution.</description>
                      </argument>
                    </arguments>
                  </metainfo>
                </method>
                """
                self.name = name
                self.resolver = resolver
                if name:
	                if Globals.resolver_policies.has_key(name):
        	                raise ValueError, "Duplicate ResolverPolicy: %s" % name
                        Globals.resolver_policies[name] = self
	
	def resolve(self, host, port):
		"""
		<method internal="yes">
		</method>
		"""
		return self.resolver.resolve(host, port)
                
def getResolverPolicy(name):
	"""
	<function internal="yes">
	</function>
	"""
        if name:
        	if Globals.resolver_policies.has_key(name):
	                return Globals.resolver_policies[name]
		else:
			log(None, CORE_POLICY, 3, "No such resolver policy; policy='%s'", name)
        return None

class AbstractResolver:
        """ 
        <class maturity="stable" abstract="yes"> 
          <summary> Class encapsulating the abstract Resolver interface. 
          </summary> 
          <description>This class encapsulates an interface for application level name resolution. 
          </description> 
          <metainfo> 
            <attributes> 
            </attributes> 
          </metainfo> 
        </class> 
        """
        def __init__(self):
        	"""
		<method internal="yes">
		</method>
		"""
                pass
                
        def resolve(self, host, port):
        	"""
		<method internal="yes">
		</method>
		"""
                raise NotImplementedError

class DNSResolver(AbstractResolver):
        """ 
        <class maturity="stable"> 
          <summary> Class encapsulating DNS-based name resolution. 
          </summary> 
          <description>
          <para>DNSResolver policies query the domain name server used by Zorp in general to resolve domain names. </para>
          <example>
        <title>A simple DNSResolver policy</title>
        <para>
          Below is a simple DNSResolver policy enabled to return
          multiple 'A' records.
          <literallayout>
ResolverPolicy(name="Mailservers", resolver=DNSResolver(multi=TRUE))            
          </literallayout>
        </para>
      </example>
          </description> 
          <metainfo> 
            <attributes> 
            </attributes> 
          </metainfo> 
        </class> 
        """
        def __init__(self, multi=FALSE):
        	"""
        	<method>
		  <summary>
		    Constructor to initialize a DNSResolver instance.
		  </summary>
		  <description>
		    <para>
		      This constructor initializes a DNSResolver instance.
		    </para>
		  </description>
        	  <metainfo>
        	    <arguments>
        	      <argument>
        	        <name>multi</name>
        	        <type>
        	          <boolean/>
        	        </type>
			<default>FALSE</default>
			<description>Enable this attribute to retrieve multiple IP addresses from the DNS server if the 
			domain name has multiple A records.</description>
        	      </argument>
        	    </arguments>
        	  </metainfo>
        	</method>
        	"""
                AbstractResolver.__init__(self)
                self.multi = multi
                
        def resolve(self, host, port):
        	"""
		<method internal="yes">
		</method>
		"""
                try:
			ip_list = gethostbyname_ex(host)[2]
			if self.multi:
			        return map(lambda ip: SockAddrInet(ip, port), ip_list)
			else:
        			return (SockAddrInet(ip_list[0], port),)
		except IOError:
			return None

class HashResolver(AbstractResolver):
	"""<class maturity="stable">
          <summary> Class encapsulating hash-based name resolution. <!--HashResolver policies resolve domain names from a local hash.  -->
          </summary> 
          <description>
          <para>HashResolver policies are used to locally store the IP addresses belonging to a domain name. A domain name (Hostname) 
          and one or more corresponding IP addresses (Addresses) can be stored in a hash. If the domain name to be resolved is 
          not included in the hash, the name resolution will fail. The HashResolver can be used to direct incoming connections to
           specific servers based on the target domain name. </para>
           <example>
           <title>A simple HashResolver policy</title>
           <para>
           The resolver policy below associates the IP addresses <parameter>192.168.1.12</parameter> and <parameter>192.168.1.13</parameter> 
           with the <parameter>mail.example.com</parameter> domain name. 
           </para>
          <synopsis>
ResolverPolicy(name="DMZ", \
	resolver=HashResolver(mapping={"mail.example.com":\
	("192.168.1.12", "192.168.1.13")}))
        </synopsis>
           </example>
          </description>
	<metainfo>
	  <attributes/>
	</metainfo>
	</class>
	"""
	def __init__(self, mapping):
		"""
		<method>
	       <summary>
		    Constructor to initialize a HashResolver instance.
		  </summary>
		  <description>
		    <para>
		      This constructor initializes a HashResolver instance.
		    </para>
		  </description>
		  <metainfo>
		    <arguments>
		      <argument>
		        <name>mapping</name>
		        <type>
                          <hash>
		            <key>
		              <string/>
		            </key>
		            <value>
			      <list>
			        <string format="IP address"/>
                              </list>
		            </value>
		          </hash>
                        </type>
		        <description>
		          Mapping that describes hostname->IP address pairs.
		        </description>
		      </argument>
		    </arguments>
		  </metainfo>
		</method>
		"""
		AbstractResolver.__init__(self)
		self.mapping = mapping
	
	def resolve(self, host, port):
		"""
		<method internal="yes">
		</method>
		"""
		try:
			ip_list = self.mapping[host]
			if type(ip_list) == types.StringType:
				ip_list = (ip_list,)
                        return map(lambda ip: SockAddrInet(ip, port), ip_list)
		except KeyError:
			return None
