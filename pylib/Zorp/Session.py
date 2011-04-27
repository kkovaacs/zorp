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
    Module defining interface to the session related classes.
  </summary>
  <description>
    <para>
      This module defines the abstract session interface in a class named
      <parameter>AbstractSession</parameter>, and two descendants <parameter>MasterSession</parameter> 
      and <parameter>StackedSession</parameter>.
    </para>
    <para>
      Sessions are hierarchically stacked into each other just like proxies.
      All sessions except the master session have a parent session from which child sessions inherit variables.
      Child sessions are stacked into their master sessions, so stacked sessions can inherit data from the encapsulating
      proxy instances.
      (Inheritance is implemented using a simple <function>getattr</function> wrapper.) 
    </para>
    <para>
        Instances of the Session classes store the parameters 
         of the client-side and server-side connections in a session object
         (for example, the IP addresses and zone of the server and the client, 
        and the username and group memberships of the user when authentication is used). 
        Other components of Zorp refer to this data
          when making various policy-based decisions.
    </para>
  </description>
  <metainfo/>
</module>
"""

import Zorp
from Zorp import *
from Zone import root_zone
from Cache import ShiftCache

inbound_cache = ShiftCache('inbound_cache', config.options.inbound_service_cache_threshold)
outbound_cache = ShiftCache('outbound_cache', config.options.outbound_service_cache_threshold)

class AbstractSession:
        """
        <class maturity="stable" abstract="yes" internal="yes">
          <summary>
            Class encapsulating an abstract session for different types (master, or stacked).
          </summary>
          <description>
            <para>
              Abstract base class for different session types (master, or stacked),
              both MasterSession and StackedSession are derived from this class.
            </para>
          </description>
          <metainfo>
            <attributes/>
          </metainfo>
        </class>
        """

        def destroy(self):
                """
                <method internal="yes">
                  <summary>
                    Method called at session destruction time.
                  </summary>
                  <description>
                    <para>
                      This method is called when the session is being destroyed.
                      We close filedescriptors here in case no proxy module
                      could be started (because of policy violations, or because
                      the module cannot be found).
                    </para>
                  </description>
                  <metainfo>
                    <arguments/>
                  </metainfo>
                </method>
		"""
		if self.client_stream:
			self.client_stream.close()
		if self.server_stream:
			self.server_stream.close()

class MasterSession(AbstractSession):
	"""
        <class maturity="stable" internal="yes">
          <summary>
            Class encapsulating a master session.
          </summary>
          <description>
            <para>
              This class encapsulates a master session that is on the top of the
              session hierarchy.
            </para>
            <section>
              <title>Referencing attributes exported by parent proxies</title>
              <para>
                When a stacked proxy needs some information exported by its parent,
                it can simply use the by-name references in the
                session structure. For example a proxy named 'pssl' will export an
                attribute named 'pssl' in its session which is inherited in the
                session hierarchy, so a stacked proxy can refer to any pssl
                attributes through this reference:
              </para>                
                <example>
                  <title>Referencing parent proxy attributes by type</title>
                  <programlisting><literallayout>
class MyPsslProxy(PsslProxy):
        class EmbeddedHttpProxy(HttpProxy):
                def config(self):
                        HttpProxy.config(self)                                
                        peer = self.session.pssl.server_peer_certificate.subject
                        
        def config(self):
                PsslProxy.config(self)
                self.stack_proxy = self.EmbeddedHttpProxy
                  </literallayout></programlisting>
                </example>
            </section>
          </description>
          <metainfo>
            <attributes>
              <attribute>
                <name>client_stream</name>
                <type><class filter="stream" instance="yes"/></type>
                <description>Client-side stream.</description>
              </attribute>
              <attribute>
                <name>client_address</name>
                <type><class filter="sockaddr" instance="yes"/></type>
                <description>IP address of the client.</description>
              </attribute>
              <attribute>
                <name>client_local</name>
                <type><class filter="sockaddr" instance="yes"/></type>
                <description>The IP address of the server targeted by the client. </description>
              </attribute>
              <attribute>
                <name>client_zone</name>
                <type><class filter="zone" instance="yes"/></type>
                <description>Zone of the client.</description>
              </attribute>
              <attribute>
                <name>server_stream</name>
                <type><class filter="stream" instance="yes"/></type>
                <description>Server-side stream.</description>
              </attribute>
              <attribute>
                <name>server_address</name>
                <type><class filter="sockaddr" instance="yes"/></type>
                <description>The IP address Zorp connects to. Most often this is 
                the IP address requested by the client, but Zorp can redirect the 
                client requests to different IPs.</description>
              </attribute>
              <attribute>
                <name>server_local</name>
                <type><class filter="sockaddr" instance="yes"/></type>
                <description>Zorp connects the server from this IP address. This 
                is either the IP address of Zorp's external interface, or the 
                IP address of the client (if Forge Port is enabled). The 
                client's original IP address may be modified if SNAT policies 
                are used.</description>
              </attribute>
              <attribute>
                <name>server_zone</name>
                <type><class filter="zone" instance="yes"/></type>
                <description>Zone of the server.</description>
              </attribute>
              <attribute>
                <name>target_address</name>
                <type><class filter="sockaddr" instance="yes"/></type>
                <description>The IP address Zorp connects to. Most often this is 
                the IP address requested by the client, but Zorp can redirect the 
                client requests to different IPs.</description>
              </attribute>
              <attribute>
                <name>target_local</name>
                <type><class filter="sockaddr" instance="yes"/></type>
                <description>Zorp connects the server from this IP address. This 
                is either the IP address of Zorp's external interface, or the 
                IP address of the client (if Forge Port is enabled). The 
                client's original IP address may be modified if SNAT policies 
                are used.</description>
              </attribute>
              <attribute>
                <name>target_zone</name>
                <type><class filter="zone" instance="yes"/></type>
                <description>Zone of the server.</description>
              </attribute>
              <attribute>
                <name>target_address_inband</name>
                <type><boolean/></type>
                <description>destination address is determined by the proxy</description>
              </attribute>
              <attribute>
                <name>target_local_loose</name>
                <type>BOOLEAN</type>
                <description>
                  Allow loosely allocated source ports. (e.g.
                  it is not absoletely necessary to allocate
                  the same port as specified in <parameter>server_local</parameter>parameter>,
                  it is enough if it matches its category.)
                </description>
              </attribute>
              <attribute>
                <name>target_local_random</name>
                <type>BOOLEAN</type>
                <description>
		  Allocate source ports randomly using a cryptographically secure algorithm.
		  <parameter>target_local_loose</parameter> should also be enabled for this.
                </description>
              </attribute>
              <attribute>
                <name>service</name>
                <type><string/></type>
                <description>The name of the service which started this session.</description>
              </attribute>
              <attribute>
                <name>session_id</name>
                <type><string/></type>
                <description>A unique identifier for this session using the
                 following format: <parameter>(Zorp_hostname/service:instance id/proxy)</parameter>.
                </description>
              </attribute>
              <attribute>
                <name>instance_id</name>
                <type><integer/></type>
                <description>The instance identifier of the service (sequence number).</description>
              </attribute>
              <attribute internal="yes">
                <name>started</name>
                <type><boolean/></type>
                <description>Indicates that the instance has been started.</description>
              </attribute>
              <attribute>
                <name>auth_user</name>
                <type><string/></type>
                <description>The username of the authenticated user.</description>
              </attribute>
              <attribute>
                <name>auth_groups</name>
                <type><list><string/></list></type>
                <description>List of groups the authenticated user is member of.</description>
              </attribute>
              <attribute>
                <name>authorized</name>
                <type><boolean/></type>
                <description>Stores whether the session was authorized.</description>
              </attribute>
              <attribute>
                <name>protocol</name>
                <type><integer/></type>
                <description>The protocol used in the client-side connection, 
                represented as an integer.</description>
              </attribute>
              <attribute internal="yes">
                <name>protocol_name</name>
                <type><string/></type>
                <description>The name of the protocol used in the client-side 
                connection.</description>
              </attribute>
            </attributes>
          </metainfo>
        </class>
	"""
	
	def __init__(self):
		"""
                <method internal="yes">
                  <summary>
                    Constructor to initialize a MasterSession instance.
                  </summary>
                  <description>
                    <para>
                      This constructor initializes a new MasterSession instance
                      based on its arguments.
                    </para>
                  </description>
                  <metainfo>
                    <arguments/>
                  </metainfo>
                </method>
		"""
		self.base_session_id = 'svc'
		self.session_id = self.base_session_id
		
		self.client_stream = None
		self.client_address = None
		self.client_local = None
		self.client_zone = None
		
		self.server_stream = None
		self.server_address = None
		self.server_local = None
		self.server_zone = None

		self.target_address = ()
		self.target_local = None
		self.target_zone = ()
		self.target_address_inband = FALSE
		self.target_local_loose = TRUE
		self.target_local_random = FALSE
		
      	        self.auth_user = ""
		self.auth_groups = ()
		self.authorized = FALSE
	
		self.started = 0
		self.service = None
		self.instance_id = 0

		self.setProtocol(0)
		self.proxy = None

	def __del__(self):
		"""
                <method internal="yes">
                  <summary>
                    Function called when the master session is freed.
                  </summary>
                  <description>
                    <para>
                      This function is called when the master session is freed,
                      thus the session ended. We inform our spawner service
                      about this event.
                    </para>
                  </description>
                  <metainfo>
                    <arguments/>
                  </metainfo>
                </method>
                """
                if self.service:
                        self.service.stopInstance(self)


        def setProtocol(self, protocol):
            """
            <method internal="yes">
              <summary>
                Sets the server-side protocol.
              </summary>
              <description>
                This function is called by the dispatcher callbacks to
                specify the protocol that was used to establish the client
                side connection. This function stores this value in the
                current session.
              </description>
              <metainfo>
                <arguments>
                  <argument maturity="stable">
                    <name>protocol</name>
                    <type>INTEGER</type>
                    <description>protocol identifier, one of ZD_PROTO_* constants</description>
                  </argument>
                  
                </arguments>
              </metainfo>
            </method>
            """
            self.protocol = protocol
            try:
                    self.protocol_name = ZD_PROTO_NAME[protocol]
            except KeyError:
                self.protocol_name = "Unknown(%d)" % (self.protocol)



        def setService(self, service):
                """
                <method internal="yes">
                  <summary>
                    Sets the service belonging to this session.
                  </summary>
                  <description>
                    <para>
                      Stores the service reference, and recalculates the session_id.
                      This is called by the Listener after the service is determined.
                    </para>
                  </description>
                  <metainfo>
                    <arguments>
                      <argument maturity="stable">
                        <name>service</name>
                        <type>SERVICE</type>
                        <description>Service instance</description>
                      </argument>
                    </arguments>
                  </metainfo>
                </method>
		"""
		self.service = service
		self.session_id = "%s/%s" % (self.base_session_id, service.name)
		## LOG ##
		# This message reports that the given service is started, because of a new connection.
		##
		log(self.session_id, CORE_SESSION, 5, "Starting service; name='%s'", service.name)

	def setClientAddress(self, addr):
		self.client_address = addr
		self.client_zone = root_zone.findZone(addr)
	
	def setServerAddress(self, addr):
		self.server_address = addr
		self.server_zone = root_zone.findZone(addr)
		
	def setTargetAddress(self, addr):
		"""
                <method internal="yes">
                  <summary>
                    Set the target server address.
                  </summary>
                  <description>
                    <para>
                      This is a compatibility function for proxies that
                      override the routed target.
                    </para>
                  </description>
                  <metainfo>
                    <arguments>
                      <argument maturity="stable">
                        <name>addr</name>
                        <type></type>
                        <description>Server address</description>
                      </argument>
                    </arguments>
                  </metainfo>
                </method>
		"""
		# NOTE: handling SockAddr types is a compatibility hack, as
		# proxies might call setServer with a SockAddr instance
		# instead of a tuple of SockAddrs
		
		if isinstance(addr, SockAddrType):
			self.target_address = (addr,)
		else:
			self.target_address = addr
		self.target_zone = []
		for a in self.target_address:
			self.target_zone.append(root_zone.findZone(a))		

	setServer = setTargetAddress

	def isClientPermitted(self):
		"""
                <method internal="yes">
                  <summary>
                    Function to actually check access control.
                  </summary>
                  <description>
                    <para>
                      This function is called when a connection is established to
                      perform access control checks whether the client is
                      permitted to use the requested service. Its return value
                      specifies the result of the check.
                      Returns Z_ACCEPT for success, and Z_REJECT for failure.
                    </para>
                  </description>
                  <metainfo>
                    <arguments/>
                  </metainfo>
                </method>
                """
                global outbound_cache

                zone_name = self.client_zone.getName()
                cached = outbound_cache.lookup((zone_name, self.service.name))
                if cached == Z_REJECT:
                        ## LOG ##
                        # This message indicates that because of a cached decision this service is not permitted as an outbound service from that zone.
                        # It means that the client from that zone tried to use this service and it is not permitted to do so.
                        # Check that the service is included in the outbound_services set of the Zone.
                        # @see: Zone
                        ##
                        log(self.session_id, CORE_POLICY, 1, "Outbound service not permitted (cached); service='%s', client_zone='%s', client='%s', server_zone='%s', server='%s'", (self.service, self.client_zone, self.client_address, self.server_zone, self.server_address))
                elif cached:
                        return cached

		if self.client_zone.isOutboundServicePermitted(self) != Z_ACCEPT:
			outbound_cache.store((zone_name, self.service.name), Z_REJECT)
			## LOG ##
			# This message indicates that a service going out from the given
			# zone was denied by the policy. Check that the service is included in
			# the outbound_services set of the Zone.
			##
			log(self.session_id, CORE_POLICY, 1, "Outbound service not permitted; service='%s', client_zone='%s', client='%s', server_zone='%s', server='%s'", (self.service, self.client_zone, self.client_address, self.server_zone, self.server_address))
			return Z_REJECT
		outbound_cache.store((zone_name, self.service.name), Z_ACCEPT)
		return Z_ACCEPT

		
	def isServerPermitted(self):
		"""
                <method internal="yes">
                  <summary>
                    Function to actually check access control.
                  </summary>
                  <description>
                    <para>
                      This function is called when a connection is to be
                      established with the server. It performs access control
                      checks whether the connection to the server is permitted by
                      the policy.  Its return value specifies the result of the
                      check.
                      Returns Z_ACCEPT for success, and Z_REJECT for failure.
                    </para>
                  </description>
                  <metainfo>
                    <arguments/>
                  </metainfo>
                </method>
                """
                global inbound_cache
                
                zone_name = self.server_zone.getName()
                cached = inbound_cache.lookup((zone_name, self.service.name))
                if cached == Z_REJECT:
                        ## LOG ##
                        # This message indicates that because of a cached decision this service is not permitted as an inbound service to that zone.
                        # It means that this service tried to connect to a  server in that zone and it is not permitted to do so.
                        # Check that the service is included in the inbound_services set of the Zone.
                        # @see: Zone
                        ##
                        log(self.session_id, CORE_POLICY, 1, "Inbound service not permitted (cached); service='%s', client_zone='%s', client='%s', server_zone='%s', server='%s'", (self.service, self.client_zone, self.client_address, self.server_zone, self.server_address))
                elif cached:
                        return cached

                if self.server_zone.isInboundServicePermitted(self) != Z_ACCEPT:
                        inbound_cache.store((zone_name, self.service.name), Z_REJECT)
                        ## LOG ##
                        # This message indicates that a service trying to enter to the given
                        # zone was denied by the policy. Check that the service is included in
                        # the inbound_services set of the Zone.
                        ##
                        log(self.session_id, CORE_POLICY, 1, "Inbound service not permitted; service='%s', client_zone='%s', client='%s', server_zone='%s', server='%s'", (self.service, self.client_zone, self.client_address, self.server_zone, self.server_address))
                        return Z_REJECT
                inbound_cache.store((zone_name, self.service.name), Z_ACCEPT)
                return Z_ACCEPT
        
        def setServiceInstance(self, instance_id):
                """
                <method internal="yes">
                  <summary>
                    Set service instance number and recalculate session id.
                  </summary>
                  <description>
                    <para>
                      Sets service instance number, and makes up a unique
                      identifier for this session.
                    </para>
                  </description>
                  <metainfo>
                    <arguments>
                      <argument maturity="stable">
                        <name>instance_id</name>
                        <type></type>
                        <description>unique identifier of the service instance</description>
                      </argument>
                    </arguments>
                  </metainfo>
                </method>
                """
                self.instance_id = instance_id
                self.session_id = "%s/%s:%d" % (self.base_session_id, self.name, self.instance_id)
                self.master_session_id = self.session_id

class StackedSession(AbstractSession):
        """
        <class maturity="stable">
          <summary>
            Class encapsulating a subsession.
          </summary>
          <description>
            <para>
              This class represents a stacked session, e.g., a session within the
              session hierarchy. Every subsession inherits session-wide
              parameters from its parent.
            </para>
          </description>
          <metainfo>
            <attributes>
              <attribute maturity="stable">
                <name>owner</name>
                <type>
                  <class filter="AbstractSession" instance="yes"/>
                </type>
                <description>The parent session of the current session.</description>
              </attribute>
              <attribute maturity="stable">
                <name>chainer</name>
                <type>
                  <class filter="chainer" instance="yes"/>
                </type>
                <description>
                  The chainer used to connect to the parent proxy. If unset, the
                  <parameter>server_stream</parameter> parameter must be set.
                </description>
              </attribute>
            </attributes>
          </metainfo>
        </class>
        """

        def __init__(self, owner, chainer = None):
                """
                <method internal="yes">
                  <summary>
                    Constructor to initialize a StackedSession instance.
                  </summary>
                  <description>
                    <para>
                      This constructor initializes a new StackedSession instance
                      based on parameters.
                    </para>
                  </description>
                  <metainfo>
                    <arguments>
                      <argument maturity="stable">
                        <name>owner</name>
                        <type>
                          <class filter="AbstractSession" instance="yes"/>
                        </type>
                        <description>Parent session</description>
                      </argument>
                      <argument maturity="stable">
                        <name>chainer</name>
                        <type>
			  <class filter="chainer" instance="yes"/>
			</type>
                        <description>Chainer used to chain up to parent.</description>
                      </argument>
                    </arguments>
                  </metainfo>
                </method>
                """
                self.owner = owner
                self.chainer = chainer
                
        def __getattr__(self, name):
                """
                <method internal="yes">
                  <summary>
                    Function to perform attribute inheritance.
                  </summary>
                  <description>
                    <para>
                      This function is called by the Python core when an attribute
                      is referenced. It returns variables from the parent session, if
                      not overriden here.
                      Returns The value of the given attribute.
                    </para>
                  </description>
                  <metainfo>
                    <arguments>
                      <argument maturity="stable">
                        <name>name</name>
                        <type></type>
                        <description>Name of the attribute to get.</description>
                      </argument>
                    </arguments>
                  </metainfo>
                </method>
                """
                try:
                        if name != '__dict__':
                                return self.__dict__[name]
                        else:
                                raise KeyError
                except KeyError:
                        return getattr(self.owner, name)

        def setProxy(self, proxy):
                """
                <method internal="yes">
                  <summary>
                    Set the proxy name used in this subsession.
                  </summary>
                  <description>
                    <para>
                      Stores a reference to the proxy class, and modifies
                      the session_id to include the proxy name. This is
                      called by the Listener after the proxy module to
                      use is determined.
                    </para>
                  </description>
                  <metainfo>
                    <arguments>
                      <argument maturity="stable">
                        <name>proxy</name>
                        <type></type>
                        <description>Proxy class, derived from Proxy</description>
                      </argument>
                    </arguments>
                  </metainfo>
                </method>
                """
                self.session_id = "%s/%s:%d/%s" % (self.base_session_id, self.name, self.instance_id, proxy)

