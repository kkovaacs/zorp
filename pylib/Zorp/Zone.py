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
    Module defining interface to the Zones.
  </summary>
  <description>
    <para>
      This module defines the <parameter>Zone</parameter> class and other related classes. 
    </para>
    <para>
              Zones are the basis of access control in Zorp. A zone consists of a 
              set of IP addresses or address ranges. For example, a zone can 
              contain an IPv4 subnet. 
            </para>
            <para>
              Zones are organized into a hierarchy created by the 
              Zorp administrator. Children zones inherit the 
              security attributes (set of permitted services etc.) from their 
              parents. The administrative hierarchy often reflects the organization of 
              the company, with zones assigned to the different departments.</para>
              <para>Zone definitions also determine which Zorp services can 
              be started from the zone (<parameter>outbound_services</parameter>) 
              and which services can enter the zone (<parameter>inbound_services</parameter>).</para>
              <para>
              When Zorp has to determine which zone a client belongs to, 
              it selects the most specific zone containing the searched IP address. 
              If an IP address belongs to two different zones, the straitest 
              match is the most specific zone.
              </para>
        <example>
        <title>Finding IP networks</title>
        <para>Suppose there are three zones configured: <parameter>Zone_A</parameter> containing the
            <parameter>10.0.0.0/8</parameter> network, <parameter>Zone_B</parameter> containing the
            <parameter>10.0.0.0/16</parameter> network, and <parameter>Zone_C</parameter> containing
          the <parameter>10.0.0.25</parameter> IP address. Searching for the
          <parameter>10.0.44.0</parameter> network returns <parameter>Zone_B</parameter>, because
          that is the most specific zone matching the searched IP address. Similarly, searching for
            <parameter>10.0.0.25</parameter> returns only <parameter>Zone_C</parameter>.</para>
        <para>This approach is used in the service definitions as well: when a client sends a
          connection request, Zorp looks for the most specific zone containing the IP address of the
          client. Suppose that the clients in <parameter>Zone_A</parameter> are allowed to use HTTP.
          If a client with IP <parameter>10.0.0.50</parameter> (thus belonging to
          <parameter>Zone_B</parameter>) can only use HTTP if <parameter>Zone_B</parameter> is the
          child of <parameter>Zone_A</parameter>, or if a service definition explicitly permits
            <parameter>Zone_B</parameter> to use HTTP.</para>
      </example>
     <example id="inetzone_example">
     <title>Zone examples</title>
     <para>The following example defines a simple zone hierarchy. The following 
     zones are defined:</para>
     <itemizedlist>
     <listitem>
     <para><emphasis>internet</emphasis>: This zone contains every possible IP 
     addresses, if an IP address does not belong to another zone, than it belongs 
     to the <emphasis>internet</emphasis> zone. This zone accepts HTTP requests 
     coming from the <emphasis>office</emphasis> zone, and can access the public 
     HTTP and FTP services of the <emphasis>DMZ</emphasis> zone.</para>
     </listitem>
     <listitem>
     <para><emphasis>office</emphasis>: This zone contains the <parameter>192.168.1.0/32
     </parameter> and <parameter>192.168.2.0/32
     </parameter> networks. The <emphasis>office</emphasis> zone can access the 
     HTTP services of the <emphasis>internet</emphasis> zone, and use FTP to 
     access the <emphasis>DMZ</emphasis> zone. External connections are not 
     permitted to enter the zone (no <parameter>inbound_services</parameter> are defined).</para>
     </listitem>
     <listitem>
     <para><emphasis>management</emphasis>: This zone is separated from the 
     <emphasis>office</emphasis> zone, because it contans an independent subnet <parameter>192.168.3.0/32
     </parameter>. But from the Zorp administrator's view, it is the child zone of 
     the <emphasis>office</emphasis> zone, meaning that it can use (and accept)
      the same services as the <emphasis>office</emphasis> zone: HTTP to the
       <emphasis>internet</emphasis> zone, and FTP to the <emphasis>DMZ</emphasis> zone.</para>
     </listitem>
     <listitem>
     <para><emphasis>DMZ</emphasis>: This zone can accept connections HTTP 
     and FTP connections from other zones, but cannot start external connections.</para>
     </listitem>
     </itemizedlist>
     <synopsis>
InetZone('internet', ['0.0.0.0/0'],
    inbound_services=[
        "office_http_inter"],
    outbound_services=[
        "inter_http_dmz",
        "inter_ftp_dmz"])

InetZone('office', ['192.168.1.0/32', '192.168.2.0/32'],
    outbound_services=[
        "office_http_inter",
        "office_ftp_dmz"])

InetZone('management', ['192.168.3.0/32'],
    admin_parent='office')

InetZone('DMZ', ['10.50.0.0/32'],
    inbound_services=[
        "office_ftp_dmz",
        "inter_http_dmz",
        "inter_ftp_dmz"])</synopsis>
     </example>
  </description>
</module>
"""

from Zorp import *
from Domain import InetDomain, Inet6Domain
from Cache import ShiftCache
from socket import htonl, ntohl
from traceback import print_exc
import types

import kznf.kznfnetlink

#labelset_class = LabelSet;
#zones = {}
root_zone = None

class AbstractZone:
	"""
        <class maturity="stable" abstract="yes" internal="yes">
          <summary>
            Class encapsulating the abstract Zone.
          </summary>
          <description>            
          </description>
          <metainfo>
            <attributes>
              <attribute>
                <name>name</name>
                <type><string/></type>
                <description>The name of the zone.</description>
              </attribute>
              <attribute>
                <name>inbound_services</name>                
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
                <description>
                  A comma-separated list of services permitted to enter the zone.
                </description>
              </attribute>
              <attribute>
                <name>outbound_services</name>               
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
                <description>
                  A comma-separated list of services permitted to leave the zone.
                </description>
              </attribute>
              <attribute>
                <name>admin_parent</name>
                <type><string/></type>
                <description>
                  The parent-zone of this zone in the administrative hierarchy.
                </description>
              </attribute>
              <attribute>
                <name>umbrella</name>
                <type><boolean/></type>
                <description>
                  Enable this option for umbrella zones. Umbrella zones do not 
                  inherit the security attributes of their administrative parents.
                </description>
              </attribute>
            </attributes>
          </metainfo>
        </class>
	"""
	def __init__(self, name, inbound_services=None, outbound_services=None, admin_parent=None, umbrella=0, inherit_name=FALSE):
		"""
                <method maturity="stable">
                  <summary>
                    Constructor to initialize an AbstractZone instance.
                  </summary>
                  <description>
                    <para>
                      This constructor is usually called by derived classes to
                      initialize basic Zone data structures.
                    </para>
                  </description>
                  <metainfo>
                    <arguments>
                      <argument maturity="stable">
                        <name>name</name>
                        <type><string/></type>
                        <description>Name of the zone.</description>
                      </argument>
                      <argument maturity="stable">
                        <name>inbound_services</name>
                        <type><list><string/></list></type>
                        <description>A comma-separated list of services permitted to enter the zone.</description>
                      </argument>
                      <argument maturity="stable">
                        <name>outbound_services</name>
                        <type><list><string/></list></type>
                        <description>A comma-separated list of services permitted to leave the zone..</description>
                      </argument>
                      <argument maturity="stable">
                        <name>admin_parent</name>
                        <type><string/></type>
                        <description>administrative parent name</description>
                      </argument>
                      <argument maturity="stable">
                        <name>umbrella</name>
                        <type><boolean/></type>
                        <description>this is an umbrella zone</description>
                      </argument>
                      <argument maturity="stable">
                        <name>domain</name>
                        <type>Domain instance</type>
                        <description>address domain</description>
                      </argument>
                    </arguments>
                  </metainfo>
                </method>

		""" 
		
		if Globals.zones.has_key(name):
			raise ZoneException, 'Zone %s duplicate name' % name
		Globals.zones[name] = self
		self.name = name
		self.admin_children = []
		self.inherit_name = inherit_name
		self.domain = None
		self.cached_name = None
		self.umbrella = umbrella
		if admin_parent:
			self.admin_parent = Globals.zones[admin_parent]
			self.admin_parent.addAdminChild(self)
		else:
			self.admin_parent = None

                self.inbound_services = {}
                self.outbound_services = {}
                if outbound_services != None:
                        for i in outbound_services:
                                self.outbound_services[i] = 1
				## LOG ##
				# This message reports that this service is an allowed outbound service in that zone.
				##
				log(None, CORE_DEBUG, 5, "Outbound service; zone='%s', service='%s'", (self.name, i))
        
                if inbound_services != None:
                        for i in inbound_services:
                                self.inbound_services[i] = 1
				## LOG ##
				# This message reports that this service is an allowed inbound service in that zone.
				##
				log(None, CORE_DEBUG, 5, "Inbound service; zone='%s', service='%s'", (self.name, i))

	def addAdminChild(self, child):
		"""
                <method internal="yes">
                  <summary>
                    Function to add an administrative child
                  </summary>
                  <description>
                    <para>
                      This function adds 'child' to the set of administrative children.
                    </para>
                  </description>
                  <metainfo>
                    <arguments>
                      <argument maturity="stable">
                        <name>child</name>
                        <type>AbstractZone instance</type>
                        <description>child zone add</description>
                      </argument>
                    </arguments>
                  </metainfo>
                </method>
		"""
		child.setAdminParent(self)
		self.admin_children.append(child)

	def setAdminParent(self, parent):
		"""
                <method internal="yes">
                  <summary>
                    Function to set administrative parent of this zone.
                  </summary>
                  <description>
                    <para>
                      This function sets the administrative parent of this Zone.
                    </para>
                  </description>
                  <metainfo>
                    <arguments>
                      <argument maturity="stable">
                        <name>parent</name>
                        <type>AbstractZone instance</type>
                        <description>parent Zone</description>
                      </argument>
                    </arguments>
                  </metainfo>
                </method>
		"""
		self.admin_parent = parent
		
	def iterAdminChildren(self, fn, parm = None):
		"""
                <method internal="yes">
                  <summary>
                    Function to iterate over the set of administrative children.
                  </summary>
                  <description>
                    <para>
                      This function iterates over the set of administrative
                      children calling the function 'fn' for each item, with
                      parameters 'parm', 'self' and the item.
                    </para>
                    <para>
                     The callback fn may delete items from admin_children, this
                     function uses a local copy of that array.
                    </para>
                  </description>
                  <metainfo>
                    <arguments>
                      <argument maturity="stable">
                        <name>fn</name>
                        <type>function reference</type>
                        <description>function to call</description>
                      </argument>
                      <argument maturity="stable">
                        <name>parm</name>
                        <type>any</type>
                        <description>opaque object passed to fn</description>
                      </argument>
                    </arguments>
                  </metainfo>
                </method>
		""" 
		for x in self.admin_children[:]:
			fn(parm, self, x)

	def __str__(self):
		"""
                <method internal="yes">
                  <summary>
                    Overridden operator to return the textual representation of self.
                  </summary>
                  <description>
                    <para>
                      Called by the Python core to format the object contents when it is
                      written.
                    </para>
                  </description>
                  <metainfo>
                    <arguments/>
                  </metainfo>
                </method>
		"""
		return "RootZone(%s)" % self.name

        def isInboundServicePermitted(self, session):
                """
                <method maturity="stable">
                  <summary>
                    Function to do inbound access control check.
                  </summary>
                  <description>
                    <para>
                      This function is called when a session is connecting to a server to
                      check whether it is permitted.
                    </para>
                    <para>
                      Returns Z_ACCEPT if the service is permitted, Z_REJECT otherwise
                    </para>
                  </description>
                  <metainfo>
                    <arguments>                      
                      <argument maturity="stable">
                        <name>session</name>
                        <type>Session instance</type>
                        <description>session that should be checked</description>
                      </argument>
                      <argument internal="yes">
                        <name>parent</name>
                        <type></type>
                        <description>
                          <para>The parent zone of the destination zone.</para>
                        </description>
                      </argument>
                    </arguments>
                  </metainfo>
                </method>
                """
                if self.inbound_services.has_key(session.service.name) or self.inbound_services.has_key('*'):
                        return Z_ACCEPT
                elif self.admin_parent and not self.umbrella:
               		return self.admin_parent.isInboundServicePermitted(session)
               		
                return Z_REJECT

        def isOutboundServicePermitted(self, session):
                """
                <method maturity="stable">
                  <summary>
                    Function to do outbound access control check.
                  </summary>
                  <description>
                    <para>
                      This function is called when an incoming connection is
                      detected to check whether it is allowable.
                    </para>
                    <para>
                      Returns Z_ACCEPT if the service is permitted, Z_REJECT otherwise
                    </para>
                  </description>
                  <metainfo>
                    <arguments>
                      <argument maturity="stable">
                        <name>session</name>
                        <type>Session instance</type>
                        <description>session that should be checked</description>
                      </argument>
                    </arguments>
                  </metainfo>
                </method>
                """
                if self.outbound_services.has_key(session.service.name) or self.outbound_services.has_key('*'):
                        return Z_ACCEPT
                elif self.admin_parent and not self.umbrella:
               		return self.admin_parent.isOutboundServicePermitted(session)
               		
                return Z_REJECT

	def getName(self):
		"""
                <method internal="yes">
                </method>
		"""
		if self.cached_name:
			return self.cached_name
		if self.inherit_name:
			self.cached_name = self.admin_parent.getName()
		else:
			self.cached_name = self.name
		return self.cached_name

        def buildKZorpMessage(self):
		"""<method internal="yes">
                </method>
                """
                return []

class RootZone(AbstractZone):
	"""
        <class maturity="stable" internal="yes">
          <summary>
            Class encapsulating all address-dependent hierarchies like IPv4 and IPv6.
          </summary>
          <description>
            <para>
              This class encapsulates the top of all address-dependent
              hierarchies. It is used to locate the address hierarchy for
              various address families like IPv4 and IPv6.
            </para>
            <para>
              An instance of this class is created at startup time in the
              global variable named 'root_zone' which is then used when
              looking up the zone of a specific address.
            </para>
          </description>
          <metainfo>
            <attributes/>
          </metainfo>
        </class>
	"""

	def __init__(self, name):
		"""
                <method internal="yes">
                </method>
		"""
		AbstractZone.__init__(self, name)
		self.domains = []
		self.cache = ShiftCache('zone', config.options.zone_cache_shift_threshold)

	def addDomain(self, domain_zone):
		"""
                <method internal="yes">
                </method>
		"""
		self.domains.append(domain_zone)
		
	def findDomain(self, address):
		"""
                <method internal="yes">
                  <summary>
                    Function to find the root Zone of the given address domain.
                  </summary>
                  <description>
                    <para>
                      This function finds the first child in self which uses
                      domain as address domain.
                    </para>
                  </description>
                  <metainfo>
                    <arguments>
                      <argument maturity="stable">
                        <name>domain</name>
                        <type>Domain instance</type>
                        <description>class implementing address range specifics (for example InetDomain for IPv4)</description>
                      </argument>
                    </arguments>
                  </metainfo>
                </method>
		"""
		
		for x in self.domains:
			if x.isMatchingAddress(address):
				return x
			
			
		# we never return self, because RootZone is not a real zone
		raise ZoneException, "No root Zone found for address domain %s" % (address, )

	def addZone(self, zone):
		"""
                <method internal="yes">
                </method>
		"""
		domain_root = self.findDomain(zone.domain)
		domain_root.addZone(zone)

	def findZone(self, address):
		"""
                <method internal="yes">
                  <summary>
                    Function to find the most specific Zone for address.
                  </summary>
                  <description>
                    <para>
                      This function searches the address hierarchy for the most
                      specific Zone containing 'address'.
                    </para>
                  </description>
                  <metainfo>
                    <arguments>                      
                      <argument maturity="stable">
                        <name>address</name>
                        <type>SockAddr instance</type>
                        <description>address we are trying to find</description>
                      </argument>
                    </arguments>
                  </metainfo>
                </method>
		"""

		# FIXME: this is address family specific, should be separated
		# to its own method
		hash = address.ip

                zone = None
                zone = self.cache.lookup(hash)
                if not zone:
        		domain_root = self.findDomain(address)
	        	if domain_root:
                		zone = domain_root.findZone(address)
	                	self.cache.store(hash, zone)
	        	
        	if not zone:
	                raise ZoneException, str(address)

		return zone
		
class Zone(AbstractZone):
	"""
        <class maturity="stable" internal="yes">
          <summary>
            Class encapsulating general peer endpoint addresses.
          </summary>
          <description>
            <para>
              This class encapsulates an address independent zone, a named set of
              client/server endpoints.
              This class differs from RootZone in that it uses a real address
              domain (for IPv4 <link linkend="python.Domain.InetDomain">InetDomain</link> is used), unlike RootZone which
              is a general wrapper for all address types (IPv4, IPv6, SPX etc.)
            </para>
          </description>
          <metainfo>
            <attributes/>
          </metainfo>
        </class>
	"""
	def __init__(self, name, addr, inbound_services = None, outbound_services = None, admin_parent = None, umbrella = 0, domain = None, inherit_name = FALSE):
		"""
                <method maturity="stable">
                  <summary>
                    Constructor to initialize a Zone instance.
                  </summary>
                  <description>
                    <para>
                      This class initializes a Zone instance by calling the
                      inherited constructor, and setting local attributes.
                    </para>
                  </description>
                  <metainfo>
                    <arguments>
                      <argument maturity="stable">
                        <name>name</name>
                        <type><string/></type>
                        <description>name of this zone</description>
                      </argument>
                      <argument maturity="stable">
                        <name>addr</name>
                        <type><list><string/></list></type>
                        <description>
                          a string representing an address range interpreted
                          by the domain class (last argument), *or* a list of
                          strings representing multiple address ranges.
                        </description>
                      </argument>
                      <argument maturity="stable">
                        <name>inbound_services</name>
                        <type><list><string/></list></type>
                        <description>A comma-separated list of services permitted to enter the zone.</description>
                      </argument>
                      <argument maturity="stable">
                        <name>outbound_services</name>
                        <type><list><string/></list></type>
                        <description>
                          A comma-separated list of services permitted to leave the zone.
                        </description>
                      </argument>
                      <argument maturity="stable">
                        <name>admin_parent</name>
                        <type><string/></type>
                        <description>name of the administrative parent</description>
                      </argument>
                      <argument maturity="stable">
                        <name>umbrella</name>
                        <type><boolean/></type>
                        <description>TRUE if this zone is an umbrella zone</description>
                      </argument>
                      <argument maturity="stable">
                        <name>domain</name>
                        <type>Domain instance</type>
                        <description>
                          <para>
                            address domain class parsing 'addr' and performing
                            address comparisons for IPv4 addresses it should be
                            InetDomain
                          </para>
                          <para>
                            Notes If 'addr' is a list of addresses (like
                            ['192.168.1.1', '192.168.1.5']), several subzones
                            are automatically created with administrative
                            parent set to self. This way you can define
                            members with additional privilege easily.
                          </para>
                        </description>
                      </argument>
                    </arguments>
                  </metainfo>
                </method>
		"""
		
		AbstractZone.__init__(self, name, inbound_services, outbound_services, admin_parent, umbrella, inherit_name)
		
		if domain is None:
			raise ValueError, "domain must be defined"
		
		self.domain = domain
		if type(addr) == types.ListType:
			if len(addr) == 1:
				addr = addr[0]
			else:
				i = 0
				while i < len(addr):
	                        	self.subZone("%s-#%u" % (name, i), addr[i], admin_parent=self.name, domain=domain)
	                        	i = i + 1
				addr = None
		
		if addr:
			self.address = domain(addr)
			root_zone.addZone(self)
		else:
			self.address = None

	def subZone(self, name, addr, admin_parent, domain):
		"""
                <method internal="yes">
                  <summary>
                    Function to create a subzone if multiple addresses are specified.
                  </summary>
                  <description>
                    <para>
                      This function is called to create a subzone if multiple
                      addresses are specified. It is called by the Zone constructor.
                    </para>
                  </description>
                </method>
		"""
		return Zone(name, addr, admin_parent=admin_parent, domain=domain, inherit_name=TRUE)


	def __str__(self):
		"""
                <method internal="yes">
                  <summary>
                    Format the Zone as string.
                  </summary>
                  <description>
                    <para>
                      This function is called by the Python core when this object
                      is used as string.
                    </para>
                  </description>
                </method>
		"""
		return "Zone(%s, %s)" % (self.getName(), self.address)


class InetZone(Zone):
	"""
        <class maturity="stable">
          <summary>
            Class encapsulating IPv4 zones.
          </summary>
          <description>
            <para>
              This class encapsulates an IPv4 zone; each zone contains one or
              more IPv4 subnets. An IP address always belongs to the most
              specific zone. 
            </para>
	    <example>
		<title>Determining the zone of an IP address</title>
		<para>
		An IP address always belongs to the most specific zone.
		Suppose that <parameter>Zone A</parameter> includes the IP network <parameter>10.0.0.0/8</parameter> 
		and <parameter>Zone B</parameter> includes the network <parameter>10.0.1.0/24</parameter>. 
		In this case, a client machine with the <parameter>10.0.1.100/32</parameter> IP address 
		belongs to both zones from an IP addressing point of view. But <parameter>Zone B</parameter> is more
		specific (in CIDR terms), so the client machine belongs to <parameter>Zone B</parameter> in Zorp.
		</para>
	    </example>
          </description>
          <metainfo>
            <attributes/>
          </metainfo>
        </class>
	"""
	def __init__(self, name, addr, inbound_services = None, outbound_services = None, admin_parent = None, umbrella = 0, inherit_name = FALSE):
		"""
                <method maturity="stable">
                  <summary>
                    Constructor to initialize an InetZone instance
                  </summary>
                  <description>
                    <para>
                      This constructor initializes an InetZone object.
                    </para>
                  </description>
                  <metainfo>
                    <arguments>
                      <argument maturity="stable">
                        <name>name</name>
                        <type><string/></type>
                        <description>Name of the zone.</description>
                      </argument>
                      <argument maturity="stable">
                        <name>addr</name>
                        <type><list><string/></list></type>
                        <description>
                          A string representing an address range interpreted
                          by the domain class (last argument), *or* a list of
                          strings representing multiple address ranges. <!--FIXME-->
                        </description>
                      </argument>
                      <argument maturity="stable">
                        <name>inbound_services</name>
                        <type><list><string/></list></type>
                        <description>
                          A comma-separated list of services permitted to enter the zone.
                        </description>
                      </argument>
                      <argument maturity="stable">
                        <name>outbound_services</name>
                        <type><list><string/></list></type>
                        <description>A comma-separated list of services permitted to leave the zone.</description>
                      </argument>
                      <argument maturity="stable">
                        <name>admin_parent</name>
                        <type><string/></type>
                        <description>Name of the administrative parent zone. If set, the current zone
                         inherits the lists of permitted inbound and outbound 
                         services from its administrative parent zone.</description>
                      </argument>
                      <argument maturity="stable">
                        <name>umbrella</name>
                        <type><boolean/></type>
                        <description>
                        Enable this option for umbrella zones. Umbrella zones do 
                        not inherit the security attributes (list of permitted 
                        services) of their administrative parents. </description>
                      </argument>
                      <argument internal="yes">
                        <name>inherit_name</name>
                        <type><boolean/></type>
                        <description><!-- FIXME --></description>
                      </argument>
                    </arguments>
                  </metainfo>
                </method>
		"""
		Zone.__init__(self, name, addr, inbound_services, outbound_services, admin_parent, umbrella, InetDomain, inherit_name)
		
	def subZone(self, name, addr, admin_parent, domain):
		"""
                <method internal="yes">
                  <summary>
                    Function to create a subzone if multiple addresses are specified.
                  </summary>
                  <description>
                    <para>
                      This function is called to create a subzone if multiple
                      addresses are specified. It is called by the Zone constructor.
                    </para>
                  </description>
                </method>
		"""
		return InetZone(name, addr, admin_parent=admin_parent, inherit_name=TRUE)

        def buildKZorpMessage(self):
		"""<method internal="yes">
                </method>
                """
                messages = []
                flags = 0
                if self.umbrella:
                        flags = kznf.kznfnetlink.KZF_ZONE_UMBRELLA
                
                if self.admin_parent:
                        parent_name = self.admin_parent.name
                else:
                        parent_name = None

                if self.address:
                        address = ntohl(self.address.ip)
                        mask = ntohl(self.address.mask)
                else:
                        address = None
                        mask = None

                messages.append((kznf.kznfnetlink.KZNL_MSG_ADD_ZONE, kznf.kznfnetlink.create_add_zone_msg(self.getName(), flags, address, mask, self.name, parent_name)))

                for i in self.inbound_services.keys():
                        messages.append((kznf.kznfnetlink.KZNL_MSG_ADD_ZONE_SVC_IN, kznf.kznfnetlink.create_add_zone_svc_msg(self.name, i)))
                for i in self.outbound_services.keys():
                        messages.append((kznf.kznfnetlink.KZNL_MSG_ADD_ZONE_SVC_OUT, kznf.kznfnetlink.create_add_zone_svc_msg(self.name, i)))

                return messages

class InetRootZone(InetZone):
	"""
        <class internal="yes">
          <summary>
            Class encapsulating the top of the IPv4 address hierarchy.
          </summary>
          <description>
            <para>
              This class encapsulates the top of the IPv4 address hierarchy.
              'root_zone' delegates IPv4 specific searches to this class, more
              exactly to the <link
              linkend="python.Zone.InetRootZone.findZone">findZone</link>
              method.
            </para>
          </description>
        </class>
	"""

	def __init__(self, name):
		"""
                <method internal="yes">
                </method>
		"""
		global root_zone

		InetZone.__init__(self, name, None)
		root_zone.addDomain(self)
		self.zones = []
		self.mask_hashes = [None]*33;

	def isMatchingAddress(self, addr):
		"""
                <method internal="yes">
                </method>
		"""
		if type(addr) == types.ClassType and (addr is InetDomain):
			return TRUE
		try:
			if addr.family == AF_INET:
				return TRUE
		except AttributeError:
			pass
		return FALSE

	def addZone(self, zone):
		"""
                <method internal="yes">
                </method>
		"""
		bits = zone.address.mask_bits
		ip = zone.address.ip
		if not self.mask_hashes[bits]:
			self.mask_hashes[bits] = {}
		if self.mask_hashes[bits].has_key(ip):
			raise ZoneException, "Zone with duplicate IP range, %s" % (zone.address)
		self.mask_hashes[bits][zone.address.ip] = zone

	def findZone(self, addr):
		"""
                <method internal="yes">
                  <summary>
                    Function to find the most specific containing Zone of 'addr'
                  </summary>
                  <description>
                    <para>
                      This function returns the most specific Zone containing
                      'addr'
                    </para>
                  </description>
                  <metainfo>
                    <arguments>
                      <argument maturity="stable">
                        <name>addr</name>
                        <type></type>
                        <description>address to look up</description>
                      </argument>
                    </arguments>
                  </metainfo>
                </method>
		"""
		ip = addr.ip
		i = 32
		best = None
		while i >= 0:
			h = self.mask_hashes[i]
			if h:
				try:
					m = htonl(((1 << i) - 1) << (32 - i))
				except OverflowError:
					m = htonl(0x7fffffff << 1)

				try:
					best = h[ip & m]
					break
				except KeyError:
					pass
			i = i - 1
		return best

        def buildKZorpMessage(self):
		"""<method internal="yes">
                </method>
                """
                return []

#class Inet6Zone(Zone):
#	"""A class inherited from Zone using the Inet6Domain address type.
#
#	This is a simple Zone class using Inet6Domain as its address
#	type.
#	
#	"""
#	def __init__(self, name, addr, inbound_services = None, outbound_services = None, admin_parent = None, umbrella = 0):
#		"""Constructor to initialize an Inet6Zone instance
#
#		This constructor initializes an Inet6Zone object instance,
#		and sets its attributes based on arguments.
#
#		Arguments
#
#		  self -- this instance
#		  
#		  name -- name of this zone
#		  
#		  addr -- a string representing an address range,
#		          interpreted by the domain class (last argument),
#		          *or* a list of strings representing multiple
#		          address ranges.
#		  
#		  inbound_services  -- set of permitted inbound services as described by RootZone
#		  
#		  outbound_services -- set of permitted outbound services as described by RootZone
#		  
#		  admin_parent -- name of the administrative parent 
#		  
#		  umbrella  -- TRUE if this zone is an umbrella zone
#		  
#		"""
#		Zone.__init__(self, name, addr, inbound_services, outbound_services, admin_parent, umbrella, Inet6Domain)


root_zone = RootZone("root")
inet_root_zone = InetRootZone("inet_root")
