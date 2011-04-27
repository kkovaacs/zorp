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
    The Chainer module defines the classes required to connect to the target servers.
  </summary>
  <description>
	<para>
	Chainers establish a TCP or UDP connection between a proxy and a selected destination.
	The destination is usually a server, but the <link linkend="python.Chainer.SideStackChainer">SideStackChainer
	</link> connects an additional proxy before connecting the server.
	</para>
	
	<section id="chainer_protocol">
	<title>Selecting the network protocol</title>
	<para>The client-side and the server-side connections can use different networking protocols if needed.
	The <parameter>protocol</parameter> attribute of the chainer classes determines the network protocol used in the 
	server-side connection. By default, Zorp uses the same protocol in both connections. 
	The following options are available:</para>
	<!--<inline type="enum" target="zorp.proto.id"/>-->
	<table frame="all">
	<title>
	The network protocol used in the server-side connection
	</title>
	<tgroup cols="2">
	<thead>
		<row><entry>Name</entry><entry>Description</entry>
		</row></thead>
	<tbody>
		<row>
		<entry>ZD_PROTO_AUTO</entry>
		<entry>Use the protocol that is used on the client side.
		</entry>
		</row>
		<row>
		<entry>ZD_PROTO_TCP</entry>
		<entry>Use the TCP protocol on the server side.
		</entry>
		</row>
		<row>
		<entry>ZD_PROTO_UDP</entry>
		<entry>Use the UDP protocol on the server side.
		</entry>
		</row>
	</tbody>
	</tgroup>
	</table>
	</section>
  </description>
  <metainfo>
</metainfo>
</module>
"""

from Zorp import *
from Session import MasterSession
from Stream import Stream
from Session import StackedSession
from SockAddr import SockAddrInet
from NAT import NAT_SNAT, NAT_DNAT
from Cache import TimedCache
from Zone import root_zone
import types

class AbstractChainer:
	"""
        <class maturity="stable" abstract="yes">
          <summary>
            Class encapsulating the abstract chainer.
          </summary>
          <description>
            <para>
		AbstractChainer implements an abstract chainer that establishes a connection between
		the parent proxy and the selected destination. This class serves as a starting point for customized chainer
		classes, but is itself not directly usable. Service definitions should refer to a customized class derived 			from AbstractChainer, or one of the predefined chainer classes, such as <link
		      linkend="python.Chainer.ConnectChainer">ConnectChainer</link> or <link
		      linkend="python.Chainer.FailoverChainer">FailoverChainer</link>.
            </para>
          </description>
          <metainfo>
            <attributes/>
          </metainfo>
        </class>
	"""
	def __init__(self):
		"""
                <method internal="yes">
                </method>
		"""
		pass

	def chainParent(self, session):
		"""
                <method internal="yes">
                  <summary>
                    Function to be called when a proxy wants to connect to its parent.
                  </summary>
                  <description>
                    <para>
                      This function is called to actually perform chaining to the parent.
                    </para>
                  </description>
                  <metainfo>
                    <arguments>                      
                      <argument maturity="stable">
                        <name>session</name>
                        <type>SESSION</type>
                        <description>session we belong to</description>
                      </argument>
                    </arguments>
                  </metainfo>
                </method>
		"""
		raise NotImplementedError

class ConnectChainer(AbstractChainer):
	"""
        <class maturity="stable">
          <summary>
            Class to establish the server-side TCP/IP connection.
          </summary>
          <description>
            <para>
		ConnectChainer is the default chainer class based on AbstractChainer. This class establishes a TCP or UDP
		connection between the proxy and the selected destination address.
            </para>
            <para>
              	ConnectChainer is used by default if no other chainer class is specified in the service definition.
            </para>
            <para>
              ConnectChainer attempts to connect only a single destination address: if the connection establishment
              procedure selects multiple target servers (e.g., a <link linkend="python.Resolver.DNSResolver">DNSResolver</link> with the
              <parameter>multi=TRUE</parameter> parameter or a <link linkend="python.Router.DirectedRouter">DirectedRouter</link> with multiple
              addresses), ConnectChainer will use the first address and ignore all other addresses. Use <link linkend="python.Chainer.FailoverChainer">FailoverChainer</link> to select from the destination from multiple addresses in a failover fashion, and <link linkend="python.Chainer.RoundRobinChainer">RoundRobinChainer</link> to distribute connections 
 in a roundrobin fashion.</para>
            <example>
              <title>A sample ConnectChainer</title>
              <para>The following service uses a ConnectChainer that uses the UDP protocol on the server side.</para>
		<synopsis>
Service(name="demo_service", proxy_class=HttpProxy, chainer=ConnectChainer(protocol=ZD_PROTO_UDP), router=TransparentRouter(overrideable=FALSE, forge_addr=FALSE))
		</synopsis>
            </example>
          </description>
          <metainfo>
            <attributes/>
          </metainfo>
        </class>
	"""
	
	def __init__(self, protocol=ZD_PROTO_AUTO, timeout_connect=None):
		"""
                <method maturity="stable">
                  <summary>
                    Constructor to initialize an instance of the ConnectChainer class.
                  </summary>
                  <description>
                    <para>
                      This constructor creates a new ConnectChainer instance which can be
                      associated with a <link linkend="python.Service">Service</link>.
                    </para>
                  </description>
                  <metainfo>
                    <arguments>
                      <argument maturity="stable">
                        <name>protocol</name>
                        <type>
			  <link id="zorp.proto.id"/>
			</type>
			<default>ZD_PROTO_AUTO</default>
                        <description>
                          Optional parameter that specifies the network protocol used in the connection protocol. By
                          default, the server-side communication uses the same protocol that is
			  used on the client side. See <xref linkend="chainer_protocol"/> for details.
                        </description>
                      </argument>
                      <argument>
                        <name>timeout_connect</name>
                        <type>
                          <integer/>
			</type>
			<default>30000</default>
                        <description>
                          Specifies connection timeout to be used when
                          connecting to the target server.
                        </description>
                      </argument>
                    </arguments>
                  </metainfo>
                </method>
		"""
		AbstractChainer.__init__(self)
		self.protocol = protocol
		if not timeout_connect:
			self.timeout_connect = config.options.timeout_server_connect
		else:
			self.timeout_connect = timeout_connect

	def establishConnection(self, session, local, remote):
		"""
                <method internal="yes">
                  <summary>
                    Function to actually establish a connection.
                  </summary>
                  <description>
                    <para>
                      Internal function to establish a connection with the given
                      local and remote addresses. It is used by derived chainer
                      classes after finding out the destination address to connect
                      to. This function performs access control checks.
                      Returns The stream of the connection to the server
                    </para>
                  </description>
                  <metainfo>
                    <arguments>                      
                      <argument maturity="stable">
                        <name>session</name>
                        <type>SESSION</type>
                        <description>session we belong to
                        </description>
                      </argument>
                      <argument maturity="stable">
                        <name>local</name>
                        <type></type>
                        <description>bind address</description>
                      </argument>
                      <argument maturity="stable">
                        <name>remote</name>
                        <type></type>
                        <description>host to connect to</description>
                      </argument>
                      <argument maturity="stable">
                        <name>protocol</name>
                        <type></type>
                        <description>protocol to connect to</description>
                      </argument>
                    </arguments>
                  </metainfo>
                </method>
		"""
		protocol = self.protocol
		if protocol == 0:
			protocol = session.protocol
		if remote.port == 0:
			remote.port = session.client_local.port
		session.setServerAddress(remote)

		if session.isServerPermitted() == Z_ACCEPT:
			#remote.options = session.client_address.options
			try:
				conn = Attach(session.proxy, protocol, local, remote, tos=session.proxy.server_local_tos, local_loose=session.target_local_loose, timeout=self.timeout_connect, local_random=session.target_local_random)
				session.server_stream = conn.start()
				session.server_local = conn.local
			except IOError:
				session.server_stream = None
			if session.server_stream == None:
				## LOG ##
				# This message indicates that the connection to the server failed.
				##
				log(session.session_id, CORE_SESSION, 3, 
                                    "Server connection failure; server_address='%s', server_zone='%s', server_local='%s', server_protocol='%s'",
                                    (session.server_address, session.server_zone, session.server_local, session.protocol_name))
                                        
			else:
				session.server_stream.name = session.session_id + "/server"
                                session.server_stream.keepalive = session.service.keepalive & Z_KEEPALIVE_SERVER
				## LOG ##
				# This message indicates that the connection to the server succeeded.
				##
				log(session.session_id, CORE_SESSION, 3, 
				    "Server connection established; server_fd='%d', server_address='%s', server_zone='%s', server_local='%s', server_protocol='%s'",
				    (session.server_stream.fd, session.server_address, session.server_zone, session.server_local, session.protocol_name))
				szigEvent(Z_SZIG_CONNECTION_PROPS,
				   (Z_SZIG_TYPE_CONNECTION_PROPS,
				      (session.service.name, session.instance_id, 0, 0, {
				        'server_address': str(session.server_address),
				        'server_local': str(session.server_local),
				        'server_zone': session.server_zone.getName(),
				        }
				 )))

			return session.server_stream
		raise DACException('Server connection is not permitted')
		
	def getNextTarget(self, session):
        	"""<method internal="yes">
                </method>
                """
		return (session.target_local, session.target_address[0])

	def connectTarget(self, session, target_local, target_remote):
        	"""<method internal="yes">
                </method>
                """
		if session.service.snat_policy:
			local = session.service.snat_policy.performTranslation(session, (target_local, target_remote), NAT_SNAT)
		else:
			local = target_local

		if session.service.dnat_policy:
			remote = session.service.dnat_policy.performTranslation(session, (target_local, target_remote), NAT_DNAT)
		else:
			remote = target_remote

		return self.establishConnection(session, local, remote)

	def chainParent(self, session):
		"""
                <method internal="yes">
                  <summary>
                    Function to perform connection establishment.
                  </summary>
                  <description>
                    <para>
                      This function is called by the underlying proxy implementation
                      to actually connect to the server-endpoint of the session.
                      The destination address is 'session.server_address' (which
                      is previously set by the Router used for the service, and
                      optionally overridden by the Proxy). The local address to
                      bind to is determined with the help of a NAT object if one
                      is provided, or allocated dynamically by the kernel.
                    </para>
                  </description>
                  <metainfo>
                    <arguments>
                      <argument maturity="stable">
                        <name>session</name>
                        <type><class/></type>
                        <!-- FIXME <type>AbstractSession instance</type>-->
                        <description>session we belong to</description>
                      </argument>
                    </arguments>
                  </metainfo>
                </method>
		"""
		
		try:
			(target_local, target_remote) = self.getNextTarget(session)
		except ValueError:
			target_local = None
			target_remote = None

		if target_remote == None:
			## LOG ##
			# This message indicates that the connection to the
			# server can not be established, because no server
			# address is set.
			##
			log(session.session_id, CORE_SESSION, 3, "Server connection failure, no destination;")
			return None

		return self.connectTarget(session, target_local, target_remote)


class MultiTargetChainer(ConnectChainer):
	"""<class maturity="stable" abstract="yes">
          <summary>
            Class encapsulating connection establishment with multiple
            target addresses.
          </summary>
          <description>
            <para>
              This class encapsulates a real TCP/IP connection
              establishment, and is used when a top-level proxy wants to
              perform chaining. In addition to ConnectChainer, this class
              adds the capability to perform stateless, simple load balance
              server connections among a set of IP addresses.
            </para>
            <para>
              The same mechanism is used to set multiple server addresses as
              with a single destination address: the Router class sets a list
              of IP addresses in the <parameter>session.target_address</parameter> 
              attribute.
            </para>
          </description>
          <metainfo>
            <attributes>
               <attribute internal="yes">
                 <name>connection_count</name>
                 <type></type>
                 <description>the number of connections established using this chainer
                 </description>
               </attribute>
             </attributes>
          </metainfo>
        </class>
	"""
	def __init__(self, protocol=ZD_PROTO_AUTO, timeout_connect=None):
		"""<method maturity="stable">
                  <summary>
                    Constructor to initialize a MultiTargetChainer instance.
                  </summary>
                  <description>
                    <para>
                      This constructor initializes a MultiTargetChainer class by
                      filling arguments with appropriate values and calling the
                      inherited constructor.
                    </para>
                  </description>
                  <metainfo>
                    <arguments>
                      <argument maturity="stable">
                        <name>self</name>
                        <type><class/></type>
                        <description> this instance</description>
                      </argument>
                      <argument maturity="stable">
                        <name>protocol</name>
                        <type>
			  <link id="zorp.proto.id"/>
			</type>
			<default>ZD_PROTO_AUTO</default>
                        <description>
                          Optional, specifies connection protocol (either
                          ZD_PROTO_TCP or ZD_PROTO_UDP), when not specified
                          defaults to the same protocol as was used on the
                          client side.
                        </description>
                      </argument>
                      <argument>
                        <name>timeout_connect</name>
                        <type>
                          <integer/>
			</type>
			<default>30000</default>
                        <description>
                          Specifies connection timeout to be used when
                          connecting to the target server.
                        </description>
                      </argument>
                    </arguments>
                  </metainfo>
                </method>
		"""
		ConnectChainer.__init__(self, protocol, timeout_connect)
		self.connection_count = 0
		
	def restart(self, session):
	        """<method internal="yes">
                </method>
                """
		session.chainer_restart = TRUE
		
	def getFirstTargetIndex(self, session):
        	"""<method internal="yes">
                </method>
                """
		return self.connection_count % len(session.target_address)
	
	def getNextTarget(self, session):
        	"""<method internal="yes">
                </method>
                """
	
		if not hasattr(session, 'chainer_first_attempt') or session.chainer_restart:
			session.chainer_first_attempt = self.getFirstTargetIndex(session)
			session.chainer_current_host = session.chainer_first_attempt
			session.chainer_restart = FALSE
		else:
			# we made our complete round on targets
			if session.chainer_first_attempt == session.chainer_current_host:
				return (None, None)
				
		target_remote = session.target_address[session.chainer_current_host]			
		session.chainer_current_host = (session.chainer_current_host + 1) % len(session.target_address)
		self.connection_count = self.connection_count + 1
		
		return (session.target_local, target_remote)
		
	def disableTarget(self, session, target_local, target_remote):
        	"""<method internal="yes">
                </method>
                """
		pass

	def chainParent(self, session):
		"""
                <method internal="yes">
                  <summary>
                    Overridden function to perform connection establishment.
                  </summary>
                  <description>
                    <para>
                      This function is called by the actual Proxy implementation
                      to actually connect to the server-endpoint of the session.
                      The destination address is 'session.server_address' (which
                      is previously set by the Router used for the service, and
                      optionally overridden by the Proxy). The local address to
                      bind to is determined with the help of a NAT object if one
                      is provided, or allocated dynamically by the kernel.
                    </para>
                    <para>
                      The failover capability of FailoverChainer is implemented
                      here.
                    </para>
                  </description>
                  <metainfo>
                    <arguments>
                      <argument maturity="stable">
                        <name>session</name>
                        <type>SESSION</type>
                        <description>session we belong to
                        </description>
                      </argument>
                    </arguments>
                  </metainfo>
                </method>
		"""
		stream = None

		(target_local, target_remote) = self.getNextTarget(session)
		while target_remote != None:
			stream = self.connectTarget(session, target_local, target_remote)
			if not stream:
				self.disableTarget(session, target_local, target_remote)
				(target_local, target_remote) = self.getNextTarget(session)
			else:
				return stream

class StateBasedChainer(MultiTargetChainer):
	"""<class maturity="stable" abstract="yes">
          <summary>
            Class encapsulating connection establishment with multiple
            target addresses and keeping down state between connects.
          </summary>
          <description>
            <para>
              This class encapsulates a real TCP/IP connection
              establishment, and is used when a top-level proxy wants to
              perform chaining. In addition to ConnectChainer, this class
              adds the capability to perform stateful, load balance
              server connections among a set of IP addresses.
            </para>
            <note>
            <para>Both the <link linkend="python.Chainer.FailoverChainer">FailoverChainer</link> 
            and <link linkend="python.Chainer.RoundRobinChainer">RoundRobinChainer</link>
             classes are derived from StateBasedChainer.</para>
            </note>
          </description>
          <metainfo>
            <attributes>
               <attribute internal="yes">
                 <name>state</name>
                 <type></type>
                 <description>Down state of target hosts.
                 </description>
               </attribute>
             </attributes>
          </metainfo>
        </class>
	"""
	def __init__(self, protocol=ZD_PROTO_AUTO, timeout_connect=None, timeout_state=None):
		"""<method maturity="stable">
                  <summary>
                    Constructor to initialize a StateBasedChainer instance.
                  </summary>
                  <description>
                    <para>
                      This constructor initializes a StateBasedChainer class by
                      filling arguments with appropriate values and calling the
                      inherited constructor.
                    </para>
                  </description>
                  <metainfo>
                    <arguments>
                      <argument maturity="stable">
                        <name>protocol</name>
                        <type>
			  <link id="zorp.proto.id"/>
			</type>
			<default>ZD_PROTO_AUTO</default>
                        <description>
                          Optional, specifies connection protocol (<parameter>
                          ZD_PROTO_TCP</parameter> or <parameter>ZD_PROTO_UDP
                          </parameter>), when not specified it
                          defaults to the same protocol used on the
                          client side.
                        </description>
                      </argument>
                      <argument>
                        <name>timeout_connect</name>
                        <type>
                          <integer/>
			</type>
			<default>30000</default>
                        <description>
                          Specifies connection timeout to be used when
                          connecting to the target server.
                        </description>
                      </argument>
                      <argument>
                        <name>timeout_state</name>
                        <type>
			  <integer/>
			</type>
			<default>60000</default>
                        <description>
                          The down state of remote hosts is kept for this interval in miliseconds.
                        </description>
                      </argument>
                    </arguments>
                  </metainfo>
                </method>
		"""
		MultiTargetChainer.__init__(self, protocol, timeout_connect)
                if not timeout_state:
                        timeout_state = 60000
		self.state = TimedCache('chainer-state', int((timeout_state + 999) / 1000), update_stamp=FALSE)

	def getNextTarget(self, session):
        	"""<method internal="yes">
                </method>
                """
		while 1:
			(target_local, target_remote) = MultiTargetChainer.getNextTarget(self, session)
			
			if not target_remote:
				# we enumerated all targets
				try:
					session.chainer_targets_enumerated = session.chainer_targets_enumerated + 1
				except AttributeError:
					session.chainer_targets_enumerated = 1
					
				if not self.state or session.chainer_targets_enumerated == 2:
					# we enumerated all our targets twice, once
					# with state held, and then all state
					# cleared, we were not successful, terminate
					# target iteration
	 				log(None, CORE_MESSAGE, 4, "All destinations are down for two full iterations, giving up;")
					return (None, None)

                                ## LOG ##
                                # This message reports that the remote end is down and Zorp stores the
                                # down state of the remote end, so Zorp wont try to connect to it within the
                                # timeout latter.
                                ##
 				log(None, CORE_MESSAGE, 4, "All destinations are down, clearing cache and trying again;")

				# we enumerated all targets, and all of them were
				# down, clear our state and try once more
				self.state.clear()
				self.restart(session)
				continue
			
			is_host_down = self.state.lookup(target_remote.ip_s)
			if not is_host_down:
				return (target_local, target_remote)
			else:
				## LOG ##
                                # This message reports that the remote end is down, but Zorp does not store the
                                # down state of the remote end, so Zorp will try to connect to it next time.
                                ##
				log(session.session_id, CORE_MESSAGE, 4, "Destination is down, skipping; remote='%s'", (target_remote,))
	
	def disableTarget(self, session, target_local, target_remote):
        	"""<method internal="yes">
                </method>
                """
 		## LOG ##
                # This message reports that the remote end is down and Zorp stores the
                # down state of the remote end, so Zorp wont try to connect to it within the
                # timeout latter.
                ##
                log(session.session_id, CORE_MESSAGE, 4, "Destination is down, keeping state; remote='%s'", (target_remote,))
                self.state.store(target_remote.ip_s, 1)
			
class FailoverChainer(StateBasedChainer):
	"""<class maturity="stable">
          <summary>
            Class encapsulating the connection establishment with multiple
            target addresses and keeping down state between connects. 
            FailoverChainer prefers connecting to target hosts in the order
            they were specified.            
          </summary>
          <description>
            <para>
              This class is based on the 
              <link linkend="python.Chainer.StateBasedChainer">StateBasedChainer</link> class and 
              encapsulates a real TCP/IP connection
              establishment, and is used when a top-level proxy wants to
              perform chaining. In addition to ConnectChainer this class
              adds the capability to perform stateful, failover HA
              functionality across a set of IP addresses.
            </para>
            <note>
            <para>Use FailoverChainer if you want to connect to the servers in 
            a predefined order: i.e., connect to the first server, and only 
            connect to the second if the first server is unavailable.</para>
            <para>If you want to distribute connections between the servers 
            (i.e., direct every new connection to a different server to balance 
            the load) use <link linkend="python.Chainer.RoundRobinChainer">RoundRobinChainer
            </link>.</para>
            </note>
            <example>
            <title>A DirectedRouter using FailoverChainer</title>
            <para>The following service definition uses a DirectedRouter class
             with two possible destination addresses. Zorp uses these destinations
              in a failover fashion, targeting the second address only if the first one 
              is unaccessible.</para>
             <synopsis>Service(name="intra_HTTP_inter", router=DirectedRouter(dest_addr=(SockAddrInet('192.168.55.55', 8080), SockAddrInet('192.168.55.56', 8080)), forge_addr=FALSE, forge_port=Z_PORT_ANY, overrideable=FALSE), chainer=FailoverChainer(protocol=ZD_PROTO_AUTO, timeout_state=60000, timeout_connect=30000), max_instances=0, proxy_class=HttpProxy,)</synopsis>
            </example>
          </description>
          <metainfo>
            <attributes>
               <attribute internal="yes">
                 <name>state</name>
                 <type></type>
                 <description>down state of target hosts
                 </description>
               </attribute>
             </attributes>
          </metainfo>
        </class>
	"""
	def __init__(self, protocol=ZD_PROTO_AUTO, timeout=0, timeout_state=None, timeout_connect=None, round_robin=FALSE):
		"""<method maturity="stable">
                  <summary>
                    Constructor to initialize a FailoverChainer instance.
                  </summary>
                  <description>
                    <para>
                      This constructor initializes a FailoverChainer class by
                      filling arguments with appropriate values and calling the
                      inherited constructor.
                    </para>
                  </description>
                  <metainfo>
                    <arguments>
                      <argument maturity="stable">
                        <name>protocol</name>
                        <type>
			  <link id="zorp.proto.id"/>
			</type>
			<default>ZD_PROTO_AUTO</default>
                        <description>
                          Optional, specifies connection protocol (<parameter>
                          ZD_PROTO_TCP</parameter> or <parameter>ZD_PROTO_UDP
                          </parameter>), when not specified it
                          defaults to the protocol used on the
                          client side.
                        </description>
                      </argument>
                      <argument>
                        <name>timeout_state</name>
                        <type>
			  <integer/>
			</type>
			<default>60000</default>
                        <description>
                          The down state of remote hosts is kept for this interval in milliseconds.
                        </description>
                      </argument>
                      <argument>
                        <name>timeout_connect</name>
                        <type>
                          <integer/>
			</type>
			<default>30000</default>
                        <description>
                          Specifies connection timeout to be used when
                          connecting to the target server.
                        </description>
                      </argument>
                      <argument maturity="obsolete">
                        <name>timeout</name>
                        <type>
			  <integer/>
			</type>
			<default>0</default>
                        <description>
                          Obsolete alias for <parameter>timeout_state</parameter>, 
                          specified in seconds.
                        </description>
                      </argument>
                      <argument maturity="obsolete">
                        <name>round_robin</name>
                        <type>
			  <boolean/>
			</type>
			<default>FALSE</default>
                        <description>
                          Obsolete argument to direct FailoverChainer to
                          behave like a 
                          <link linkend="python.Chainer.RoundRobinChainer">RoundRobinChainer</link>.
                        </description>
                      </argument>
                    </arguments>
                  </metainfo>
                </method>
		"""
		if timeout:
			timeout_state = timeout * 1000
		StateBasedChainer.__init__(self, protocol, timeout_connect, timeout_state)
		self.round_robin = round_robin

	def getFirstTargetIndex(self, session):
	       	"""<method internal="yes">
                </method>
                """
		if self.round_robin:
			return StateBasedChainer.getFirstTargetIndex(self, session)
		return 0

class RoundRobinChainer(StateBasedChainer):
	"""<class maturity="stable">
          <summary>
            Class encapsulating the connection establishment with multiple
            target addresses and keeping down state between connects.
          </summary>
          <description>
            <para>
              This class is based on the 
              <link linkend="python.Chainer.StateBasedChainer">StateBasedChainer</link> class and 
              encapsulates a real TCP/IP connection
              establishment, and is used when a top-level proxy wants to
              perform chaining. In addition to ConnectChainer this class
              adds the capability to perform stateful, load balance
              server connections among a set of IP addresses.
            </para>
            <example>
            <title>A DirectedRouter using RoundRobinChainer</title>
            <para>The following service definition uses a RoundRobinChainer class
             with two possible destination addresses. Zorp uses these destinations
              in a roundrobin fashion, alternating between the two destinations.</para>
             <synopsis>Service(name="intra_HTTP_inter", router=DirectedRouter(dest_addr=(SockAddrInet('192.168.55.55', 8080), SockAddrInet('192.168.55.56', 8080)), forge_addr=FALSE, forge_port=Z_PORT_ANY, overrideable=FALSE), chainer=RoundRobinChainer(protocol=ZD_PROTO_AUTO, timeout_state=60000, timeout_connect=30000), max_instances=0, proxy_class=HttpProxy)</synopsis>
            </example>
          </description>
          <metainfo>
            <attributes/>
          </metainfo>
        </class>
	"""
	pass

class SideStackChainer(AbstractChainer):
	"""
        <class maturity="stable">
          <summary>
            Class to pass the traffic to another proxy.
          </summary>
          <description>
            <para>
              This class encapsulates a special chainer. Instead of
              establishing a connection to a server, it creates
              a new proxy instance and connects the server side of the current (parent) proxy
              to the client side of the new (child) proxy. The <parameter>right_class</parameter>
               parameter specifies the child proxy.
            </para>
            <para>
             It is possible to stack multiple proxies side-by-side. The final step of sidestacking is always to specify 
             a regular chainer via the <parameter>right_chainer</parameter> parameter that connects the last proxy to the 
             destination server.
            </para>            
            <tip>
            <para>
            Proxy sidestacking is useful for example to create one-sided SSL connections. 
            See the tutorials of the BalaBit Documentation Page available at  
            <ulink url="http://www.balabit.com/support/documentation/">http://www.balabit.com/support/documentation/</ulink> 
            for details.
            </para>
            </tip>
          </description>
          <metainfo>
            <attributes>
              <attribute maturity="stable">
                <name>right_class</name>
                <type></type>
                <description>The proxy class to connect to the parent proxy. Both built-in and customized classes 
                can be used.</description>
              </attribute>
              <attribute maturity="stable">
                <name>right_chainer</name>
                <type></type>
                <description>The chainer used to connect to the destination of the side-stacked proxy class set in the
		<parameter>right_class</parameter> attribute.
                </description>
              </attribute>
            </attributes>
          </metainfo>
        </class>
	"""
	def __init__(self, right_class, right_chainer = None):
		"""
                <method maturity="stable">
                  <summary>
                    Constructor to initialize an instance of the SideStackChainer class.
                  </summary>
                  <description>
			<para>
                      This constructor creates a new FailoverChainer instance which can be
                      associated with a <link linkend="python.Service.Service">Service</link>.
                    </para>
                  </description>
                  <metainfo>
                    <arguments>
                      <argument maturity="stable">
                        <name>right_class</name>
                        <type>
			  <class filter="proxy"/>
			</type>
                        <description>The proxy class to connect to the parent proxy. Both built-in or customized classes 				can be used.</description>
                      </argument>
                      <argument maturity="stable">
                        <name>right_chainer</name>
                        <type>
			  <class filter="chainer" instance="yes"/>
			</type>
			<default>None</default>
                        <description>The chainer used to connect to the destionation of the side-stacked proxy class set in 				the <parameter>right_class</parameter> attribute.</description>
                      </argument>
                    </arguments>
                  </metainfo>
                </method>
		"""
		AbstractChainer.__init__(self)
		self.right_class = right_class
		if right_chainer == None:
			right_chainer = ConnectChainer()
		self.right_chainer = right_chainer

	def chainParent(self, session):
		"""
                <method internal="yes">
                  <summary>
                    Overridden function to perform chaining.
                  </summary>
                  <description>
                    <para>
                      This function is called by a Proxy instance to establish its
                      server side connection. Instead of connecting to a server
                      this chainer creates another proxy instance and connects
                      this new proxy with the current one.
                    </para>
                  </description>
                  <metainfo>
                    <arguments>
                      <argument maturity="stable">
                        <name>session</name>
                        <type>SESSION</type>
                        <description>session we belong to</description>
                      </argument>
                    </arguments>
                  </metainfo>
                </method>
		"""
		try:
			streams = streamPair(AF_UNIX, SOCK_STREAM)
		except IOError:
			## LOG ##
			# This message indicates that side stacking failed, because Zorp was unable to create a socketPair.
			# It is likely that there is now resource available. Try increase fd limits.
			##
			log(session.session_id, CORE_SESSION, 3, "Side stacking failed, socketPair failed;")
			return None

		try:
			# convert our tuple to an array, to make it possible
			# to modify items
			streams = [streams[0], streams[1]]
			ss = None

			session.server_stream = streams[0]
			session.server_stream.name = session.owner.session_id + "/leftside"
			ss = StackedSession(session, self.right_chainer)
			streams[0] = None
			ss.client_stream = streams[1]
			ss.client_stream.name = ss.session_id + "/rightside"
			ss.server_stream = None
			streams[1] = None
			## LOG ##
			# This message indicates that side stacking was successful.
			##
			log(session.session_id, CORE_SESSION, 4, 
                                "Side-stacking proxy instance; server_fd='%d', client_fd='%d', proxy_class='%s'",
                                (session.server_stream.fd, ss.client_stream.fd, self.right_class.__name__))
			proxy = self.right_class(ss)
			if ProxyGroup(1).start(proxy):
				return ss.client_stream
			else:
				raise RuntimeError, "Error starting proxy in group"
		except:
			## LOG ##
			# This message indicates that side stacking failed. 
			##
			log(session.session_id, CORE_ERROR, 3, "Side-stacking failed; proxy_class='%s'", (self.right_class.__name__))
			if ss:
				ss.destroy()
			if (streams[0] != None):
				streams[0].close()
			if (streams[1] != None):
				streams[1].close()
