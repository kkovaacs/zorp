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
    The Service module defines the classes used to create service definitions.
  </summary>
  <description>
    <para>
      This module defines classes encapsulating service descriptions. Zorp
      services define how incoming connection requests are handled.
      When a connection is accepted by a <link
      linkend="python.Dispatch">Dispatchers</link>, the service bound
      to the Dispatcher creates an instance of itself.
      This instance handles the connection and
      proxies the traffic between the client and the server.
      The instance of the selected service is created using the <link
      linkend="python.Service.Service.startInstance">'startInstance()'</link>
      method.
    </para>
    <para>
    A service does not perform useful activity on its own, it needs
    a <link linkend="python.Dispatch">Dispatcher</link> to bind the
    service to a network interface of the firewall. New instances of the
    service are started as the Dispatcher accepts new connections.
    </para>
    <section>
    <title>Naming services</title>
    <para>
      The name of the service must be a unique identifier; dispatchers refer to this unique ID.      
    </para>
    <para>Use clear, informative, and consistent service names. Include the following information in
            the service name:</para>
          <itemizedlist>
            <listitem>
              <para>Source zones, indicating which clients may use the service (e.g.,
                  <parameter>intranet</parameter>).</para>
            </listitem>
          </itemizedlist>
          <itemizedlist>
            <listitem>
              <para>The protocol permitted in the traffic (e.g.,
              <parameter>HTTP</parameter>).</para>
            </listitem>
          </itemizedlist>
          <itemizedlist>
            <listitem>
              <para>Destination zones, indicating which servers may be accessed using the service
                (e.g., <parameter>Internet</parameter>).</para>
            </listitem>
          </itemizedlist>
          <tip>
            <para>Name the service that allows internal users to browse the Web
                <parameter>intra_HTTP_internet</parameter>. Use dots to indicate child zones, e.g.,
                <parameter> intra.marketing_HTTP_inter</parameter>.</para>
          </tip>
    </section>
    <section>
    <title>Determining the server and client zone</title>
            <para>
               The
              client's IP address identifies a client <link
              linkend="python.Zone">zone</link> and the access control
              information associated by the client zone determines whether a
              service identified by a given name is permitted. Similarly when
              the server side connection is established the same service name
              is used to determine whether the service is permitted to target
              a server in the zone of the server.
            </para>
    </section>
  </description>
</module>
"""

from Stream import Stream
from Session import StackedSession
from Zorp import *
from Chainer import ConnectChainer
from Router import TransparentRouter, DirectedRouter
from Auth import AuthPolicy, getAuthPolicyObsolete, getAuthenticationPolicy
from Resolver import DNSResolver, getResolverPolicy, ResolverPolicy
from NAT import getNATPolicy, NATPolicy, NAT_SNAT, NAT_DNAT

import types, thread, time, socket

import kznf.kznfnetlink

default_snat = None
default_dnat = None
default_auth = None
default_router = None
default_chainer = None

class AbstractService:
	"""
        <class maturity="stable" abstract="yes">
          <summary>
            Class encapsulating the abstract Service properties.
          </summary>
          <description>
            <para>
                AbstractService implements an abstract service. Service
                definitions should be based on a customized class derived from
                AbstractService, or on the predefined
                <link linkend="python.Service.Service">Service</link> class.
            </para>
          </description>
          <metainfo>
            <attributes>
              <attribute>
                <name>name</name>
		<type><string/></type>
                <description>The name of the service.</description>
              </attribute>
            </attributes>
          </metainfo>
        </class>
	"""
	
	def __init__(self, name):
		"""
                <method maturity="stable">
                  <summary>
                    Constructor to initialize an instance of the AbstractService class.
                  </summary>
                  <description>
                    <para>
                      This constructor creates an AbstractService instance and sets the attributes of the instance
                       according to the received arguments. It also registers the Service to the
                       <parameter>services</parameter> hash so that dispatchers can find the service instance.
                    </para>
                  </description>
                  <metainfo>
                    <arguments>
                      <argument maturity="stable">
                        <name>name</name>
                        <type>
                          <string/>
                        </type>
                        <description>The name of the service.</description>
                      </argument>
                    </arguments>
                  </metainfo>
                </method>
                """
                if Globals.services.has_key(name):
                        raise ValueError, "Duplicate service: %s" % name
                Globals.services[name] = self
                self.name = name

        def startInstance(self, session):
                """
                <method internal="yes">
                  <summary>
                    Function to start an instance of this service.
                  </summary>
                  <description>
                    <para>
                      Abstract method to be implemented in derived classes.
                      Should start an instance of the given service. A service
                      instance takes care of the client connection, connects
                      to the server and supervises the traffic going in either
                      direction.
                    </para>
                    <para>
                      Tasks of a service instance are implemented by classes
                      derived from <link linkend="python.Proxy.Proxy">Proxy</link>.
                    </para>
                    <para>
                      This method unconditionally raises a NotImplementedError
                      exception to indicate that it must be overridden by
                      descendant classes like 'Service'.
                    </para>
                  </description>
                  <metainfo>
                    <arguments>
                      <argument maturity="stable">
                        <name>session</name>
                        <type></type>
                        <description>start service within this session</description>
                      </argument>
                    </arguments>
                  </metainfo>
                </method>
                """
                raise NotImplementedError

        def stopInstance(self, session):
                """
                <method internal="yes">
                  <summary>
                    Function called when an instance of this service is ended
                  </summary>
                  <description>
                    <para>
                      This function is called by Session.__del__ and indicates
                      that a given session (instance) of this service is ended.
                    </para>
                  </description>
                  <metainfo>
                    <arguments>
                      <argument maturity="stable">
                        <name>session</name>
                        <type></type>
                        <description>ending session</description>
                      </argument>
                    </arguments>
                  </metainfo>
                </method>
                """
                raise NotImplementedError

        def __str__(self):
                """
                <method internal="yes">
                  <summary>
                    Function to represent this object as a string
                  </summary>
                  <description>
                    <para>
                      This function is called by the Python core when this object
                      is used as-, or casted to a string. It simply returns
                      the service name.
                    </para>
                  </description>
                  <metainfo>
                    <arguments/>
                  </metainfo>
                </method>
                """
                return self.name

class Service(AbstractService):
        """
        <class maturity="stable">
          <summary>
            Class encapsulating a service definition.
          </summary>
          <description>
            <para>
              A service is one of the fundamental objects in Zorp. It
              stores the names of proxy related parameters, and is also
              used for access control purposes to decide what kind
              of traffic is permitted.
            </para>
            <note><para>The Service class transfers application-level (proxy)
             services. To transfer connections on the packet-filter level, 
             use the <link linkend="python.Service.PFService">PFService</link> 
             class.</para></note>
           <example>
           <title>Service example</title>
           <para>The following service transfers HTTP connections. Every
           parameter is left at its default.
           </para>
           <synopsis>
Service(name="demo_http, proxy_class=HttpProxy, router=TransparentRouter(forge_addr=FALSE))
           </synopsis>
           <para>The following service handles HTTP connections. This service
           uses authentication and authorization, and network address translation
           on the client addresses (SNAT).
           </para>
           <synopsis>Service(name="demo_http", proxy_class=HttpProxy, authentication_policy="demo_authentication_policy", authorization_policy="demo_permituser", snat_policy="demo_natpolicy", router=TransparentRouter(overrideable=FALSE, forge_addr=FALSE))</synopsis>
           <para>The following example defines the Zorp classes required for a
           service to work: the client and server zones and the services they
           can accept; the dispatcher that starts the service, and the service itself.
           </para>
           <synopsis>InetZone('internet', ['0.0.0.0/0'],
    inbound_services=[
        "office_http_inter"],
    outbound_services=[])

InetZone('office', ['192.168.1.0/32', '192.168.2.0/32'],
    outbound_services=[
        "office_http_inter"])

def demo_instance() :
    Service(name="office_http_inter", proxy_class=HttpProxy, router=TransparentRouter(forge_addr=FALSE))
    Dispatcher(transparent=TRUE, bindto=DBIface(protocol=ZD_PROTO_TCP, iface="eth0", ip="192.168.1.1", port=50080), service="office_http_inter")</synopsis>
           </example>
          </description>
          <metainfo>
            <attributes>
              <attribute>
                <name>router</name>
                <!--<type>AbstractRouter instance</type>-->
                <type><class/></type>
                <description>A router instance used to determine the
                destination address of the server.
                See <xref linkend="python.Router"/> for details.</description>
              </attribute>
              <attribute>
                <name>chainer</name>
                <!--<type>AbstractChainer instance</type>-->
                <type><class/></type>
                <description>A chainer instance used to connect to
                the destination server.
                See <xref linkend="python.Chainer"/> for details.</description>
              </attribute>
              <attribute>
                <name>snat_policy</name>
                <!--<type>NATPolicy instance</type>-->
                <type><class/></type>
                <description>Name of the NAT policy instance used to translate
                the source addresses of the sessions.
                See <xref linkend="python.NAT"/> for details.</description>
              </attribute>
              <attribute>
                <name>dnat_policy</name>
                <!--<type>NATPolicy instance</type>-->
                <type><class/></type>
                <description>Name of the NAT policy instance used to translate
                the destination addresses of the sessions.
                See <xref linkend="python.NAT"/> for details.</description>
              </attribute>
              <attribute>
                <name>proxy_class</name>
                <!--<type>Proxy instance</type>-->
                <type><class/></type>
                <description>Name of the proxy class instance used to analyze
                the traffic transferred in the session.
                See <xref linkend="python.Proxy"/> for details.</description>
              </attribute>

              <attribute>
                <name>authentication_policy</name>
                <!--<type>AuthenticationPolicy name</type>-->
                <type><class/></type>
                <description>Name of the AuthenticationPolicy instance used to
                authenticate the clients.
                See <xref linkend="python.Auth"/> for details.</description>
              </attribute>
              <attribute>
                <name>authorization_policy</name>
                <!--<type>AuthorizationPolicy name</type>-->
                <type><class/></type>
                <description>Name of the AuthorizationPolicy instance used to
                authorize the clients.
                See <xref linkend="python.Auth"/> for details.</description>
              </attribute>

              <attribute>
                <name>auth_name</name>
                <type><string/></type>
                <description>
                  Authentication name of the service. This string informs the
                  users of the Zorp Authentication Agent about which
                  service they are authenticating for.
                  Default value: the name of the service.
                </description>
              </attribute>
              <attribute>
                <name>resolver_policy</name>
                <!--<type>ResolvePolicy instance</type>-->
                <type></type>
                <description>Name of the ResolvePolicy instance used to resolve
                the destination domain names.
                See <xref linkend="python.Resolver"/> for details.
                Default value: <parameter>DNSResolver</parameter>
                </description>
              </attribute>
              <attribute>
                <name>max_instances</name>
                <type><integer/></type>
                <description>
                  Permitted number of concurrent instances of this service.
                  Usually each service instance handles
                  one connection. The default value is <parameter>0</parameter>,
                  which allows unlimited number of instances.
                </description>
              </attribute>
              <attribute>
                <name>max_sessions</name>
                <type><integer/></type>
                <description>
                  Maximum number of concurrent sessions handled by one thread.
                </description>
              </attribute>
              <attribute>
                <name>num_instances</name>
                <type><integer/></type>
                <description>
                  The current number of running instances of this service.
                </description>
              </attribute>
              <attribute>
                <name>instance_id</name>
		<type><integer/></type>
                <description>The sequence number of the last session started</description>
              </attribute>
              <attribute>
		<name>keepalive</name>
		<type><integer/></type>
		<description>
		  The TCP keepalive option, one of the Z_KEEPALIVE_NONE,
		  Z_KEEPALIVE_CLIENT, Z_KEEPALIVE_SERVER,
		  Z_KEEPALIVE_BOTH values.
		</description>
	      </attribute>
            </attributes>
          </metainfo>
        </class>
	"""

        keepalive = Z_KEEPALIVE_NONE

        def __init__(self, name, proxy_class, router=None, chainer=None, snat_policy=None, snat=None, dnat_policy=None, dnat=None, authentication_policy=None, authorization_policy=None, max_instances=0, max_sessions=0, auth_name=None, resolver_policy=None, auth=None, auth_policy=None, keepalive=None):
		"""
                <method maturity="stable">
                  <summary>
                    Constructor to initialize a Service instance.
                  </summary>
                  <description>
                    <para>
                      This contructor defines a Service with the specified parameters.
                    </para>
                  </description>
                  <metainfo>
                    <arguments>
                      <argument maturity="stable">
                        <name>name</name>
                        <type>
                          <string/>
                        </type>
                        <description>The name identifying the service.</description>
                      </argument>
                      <argument maturity="stable">
                        <name>router</name>
                        <type>
                          <class filter="router" instance="yes"/>
                        </type>
                        <default>None</default>
                        <description>Name of the router instance used to determine
                        the destination address of the server.
                        Defaults to <link linkend="python.Router.TransparentRouter">TransparentRouter</link>
                        if no other router is specified.
                        </description>
                      </argument>
                      <argument maturity="stable">
                        <name>chainer</name>
                        <type>
                          <class filter="chainer" instance="yes"/>
                        </type>
                        <default>None</default>
                        <description>Name of the chainer instance used to connect to
                        the destination server.
                        Defaults to <link linkend="python.Chainer.ConnectChainer">ConnectChainer</link>
                        if no other chainer is specified.</description>
                      </argument>
                      <argument>
                        <name>snat_policy</name>
                        <type>
                          <class filter="natpolicy" existing="yes"/>
                        </type>
                        <default>None</default>
                        <description>Name of the NAT policy instance used to
                        translate the source addresses of
                        the sessions. See <xref linkend="python.NAT"/> for details.</description>
                      </argument>
                      <argument maturity="obsolete">
                        <name>snat</name>
                        <type>
                          <class filter="nat"/>
                        </type>
                        <default>None</default>
                        <description>Obsolete parameter, use <parameter>snat_policy</parameter> instead.
                        </description>
                      </argument>
                      <argument>
                        <name>dnat_policy</name>
                        <type>
                          <class filter="natpolicy" existing="yes"/>
                        </type>
                        <default>None</default>
                        <description>Name of the NAT policy instance used to
                        translate the destination addresses of
                        the sessions. See <xref linkend="python.NAT"/> for details.</description>
                      </argument>
                      <argument maturity="obsolete">
                        <name>dnat</name>
                        <type>
                          <class filter="nat"/>
                        </type>
                        <default>None</default>
                        <description>Obsolete parameter,
                        use <parameter>dnat_policy</parameter> instead.</description>
                      </argument>
                      <argument maturity="stable">
                        <name>proxy_class</name>
                        <type>
                          <class filter="proxy"/>
                        </type>
                        <description>Name of the proxy class instance used to analyze the traffic transferred in
                        the session. See <xref linkend="python.Proxy"/> for details.</description>
                      </argument>
                      <argument>
                        <name>authentication_policy</name>
                        <type>
                          <class filter="authpolicy" existing="yes"/>
                        </type>
                        <default>None</default>
                        <description>Name of the AuthenticationPolicy instance used to authenticate the clients.
                        See <xref linkend="python.Auth"/> for details.</description>
                      </argument>
                      <argument>
                        <name>authorization_policy</name>
                        <type>
                          <class filter="authorizationpolicy" existing="yes"/>
                        </type>
                        <default>None</default>
                        <description>Name of the AuthorizationPolicy instance used to authorize the clients.
                        See <xref linkend="python.Auth"/> for details.</description>
                      </argument>
                      <argument maturity="obsolete">
                        <name>auth</name>
                        <type>
                          <class filter="auth" instance="yes"/>
                        </type>
                        <default>None</default>
                        <description>Obsolete parameter, use <parameter>authentication_policy</parameter> instead.
                        </description>
                      </argument>
                      <argument maturity="obsolete">
                        <name>auth_policy</name>
                        <type>
                          <class filter="authpolicy" existing="yes"/>
                        </type>
                        <default>None</default>
                        <description>Obsolete parameter, use <parameter>authorization_policy</parameter> instead.
                        </description>
                      </argument>
                      <argument>
                        <name>auth_name</name>
                        <type>
                          <string/>
                        </type>
                        <default>None</default>
                        <description>
                         Authentication name of the service. This string informs the
                         users of the Zorp Authentication Agent about which
                         service they are authenticating for. Default value: the name of the service.
                        </description>
                      </argument>
                      <argument maturity="stable">
                        <name>max_instances</name>
                        <type>
                          <integer/>
                        </type>
                        <default>0</default>
                        <description>Permitted number of concurrent instances of this service. Usually each
                        service instance handles one connection. Default value: <parameter>0</parameter> (unlimited).
                        </description>
                      </argument>
       .              <argument>
                        <name>max_sessions</name>
                        <type><integer/></type>
                        <description>
                          Maximum number of concurrent sessions handled by one thread.
                        </description>
                      </argument>
                      <argument>
                        <name>resolver_policy</name>
                        <type>
                          <class filter="resolverpolicy" existing="yes"/>
                        </type>
                        <default>None</default>
                        <description>Name of the ResolvePolicy instance used to resolve the destination domain names.
                        See <xref linkend="python.Resolver"/> for details.
                        Default value: <parameter>DNSResolver</parameter>.
                        </description>
                      </argument>
       .              <argument>
                        <name>keepalive</name>
                        <type><integer/></type>
                        <description>
                          The TCP keepalive option, one of the Z_KEEPALIVE_NONE,
                          Z_KEEPALIVE_CLIENT, Z_KEEPALIVE_SERVER,
                          Z_KEEPALIVE_BOTH values.
                        </description>
                      </argument>
                    </arguments>
                  </metainfo>
                </method>
                """
                AbstractService.__init__(self, name)
                self.proxy_class = proxy_class
                self.router = router or default_router or TransparentRouter()
                self.chainer = chainer or default_chainer or ConnectChainer()
                if (snat or default_snat) and snat_policy:
                        raise ValueError, "Cannot set both snat and snat_policy"
                if (dnat or default_dnat) and dnat_policy:
                        raise ValueError, "Cannot set both dnat and dnat_policy"
                if (auth or default_auth or auth_policy) and authentication_policy:
                        raise ValueError, "Cannot set authentication_policy and auth or auth_policy"

                if snat or default_snat:
                        self.snat_policy = NATPolicy('__%s-snat' % name, snat or default_snat)
                else:
                        self.snat_policy = getNATPolicy(snat_policy)
                if dnat or default_dnat:
                        self.dnat_policy = NATPolicy('__%s-dnat' % name, dnat or default_dnat)
                else:
                        self.dnat_policy = getNATPolicy(dnat_policy)

                if type(auth) == types.StringType:
                        auth_policy = auth
                        auth = None
                if keepalive:
                        self.keepalive = keepalive

                if auth_policy:
                        # one older auth_policy implementation (up to Zorp 3.0)
                        auth_policy = getAuthPolicyObsolete(auth_policy)

                        self.authentication_policy = auth_policy.getAuthenticationPolicy()
                elif auth or default_auth:
                        # even older auth implementation (up to Zorp 2.1)
                        auth_policy = AuthPolicy(None, auth or default_auth)
                        self.authentication_policy = auth_policy.getAuthenticationPolicy()
                else:
                        # current Authentication support
                        self.authentication_policy = getAuthenticationPolicy(authentication_policy)

                        
		self.auth_name = auth_name or name
		
		if resolver_policy:
			self.resolver_policy = getResolverPolicy(resolver_policy)
		else:
			self.resolver_policy = ResolverPolicy(None, DNSResolver())

		self.max_instances = max_instances
		self.max_sessions = max_sessions
		self.num_instances = 0
		self.proxy_group = ProxyGroup(self.max_sessions)
		self.lock = thread.allocate_lock()

	def startInstance(self, session):
		"""
                <method internal="yes">
                  <summary>
                    Start a service instance.
                  </summary>
                  <description>
                    <para>
                      Called by the Listener to create an instance of this
                      service.
                    </para>
                  </description>
                  <metainfo>
                    <arguments>
                      <argument maturity="stable">
                        <name>session</name>
                        <type></type>
                        <description>The session object</description>
                      </argument>
                    </arguments>
                  </metainfo>
                </method>
		"""
		if self.max_instances != 0 and self.num_instances >= self.max_instances:
			raise LimitException
		
		self.lock.acquire()
		self.num_instances = self.num_instances + 1
		self.lock.release()

		session.started = 1
		session.name = self.name
		instance_id = getInstanceId(self.name)

		# NOTE: the instance id calculation is now based in C to create
		# unique session IDs even after policy reload
		# instance_id = self.instance_id
		# self.instance_id = self.instance_id + 1
		
		session.setServiceInstance(instance_id)

		timestamp = str(time.time())

		szigEvent(Z_SZIG_SERVICE_COUNT,
			    (Z_SZIG_TYPE_PROPS,
			       (self.name, {
				 'session_number': instance_id + 1,
				 'sessions_running': self.num_instances,
				 'last_started': timestamp,
				 }
			 )))

		szigEvent(Z_SZIG_CONNECTION_PROPS,
		           (Z_SZIG_TYPE_CONNECTION_PROPS,
		              (self.name, instance_id, 0, 0, {
			        'started': timestamp,
			        'session_id': session.session_id,
		                'proxy_module': self.proxy_class.name,
		                'proxy_class': self.proxy_class.__name__,
		                'client_address': str(session.client_address),
		                'client_local': str(session.client_local),
		                'client_zone': session.client_zone.getName(),
		                }
		         )))


		## LOG ##
		# This message reports that a new proxy instance is started.
		##
		log(session.session_id, CORE_SESSION, 3, "Starting proxy instance; client_fd='%d', client_address='%s', client_zone='%s', client_local='%s', client_protocol='%s'", (session.client_stream.fd, session.client_address, session.client_zone, session.client_local, session.protocol_name))
		ss = StackedSession(session, self.chainer)
		session.client_stream.name = session.session_id + '/' + self.proxy_class.name + '/client'
		
		proxy = self.proxy_class(ss)
		if not self.proxy_group.start(proxy):
			self.proxy_group = ProxyGroup(self.max_sessions)
			if not self.proxy_group.start(proxy):
				raise RuntimeError, "Error starting proxy in group"
		return TRUE

	def stopInstance(self, session):
		"""
                <method internal="yes">
                  <summary>
                    Function called when a session terminates.
                  </summary>
                  <description>
                    <para>
                      This function is called when a session terminates. It
                      decrements concurrent session count.
                    </para>
                  </description>
                  <metainfo>
                    <arguments>
                      <argument maturity="stable">
                        <name>session</name>
                        <type></type>
                        <description>session we belong to</description>
                      </argument>
                    </arguments>
                  </metainfo>
                </method>
		"""
		if session.started:
			self.lock.acquire()
			self.num_instances = self.num_instances - 1
			self.lock.release()

			szigEvent(Z_SZIG_SERVICE_COUNT,
				   (Z_SZIG_TYPE_PROPS,
				    (self.name, {
				      'sessions_running': self.num_instances,
				      }
				 )))

                        szigEvent(Z_SZIG_CONNECTION_STOP, (Z_SZIG_TYPE_CONNECTION_PROPS, (self.name, session.instance_id, 0, 0, {})))

		## LOG ##
		# This message reports that a new proxy instance is stopped.
		##
		log(session.session_id, CORE_SESSION, 4, "Ending proxy instance;")

	def buildKZorpMessage(self):
		"""<method internal="yes">
                </method>
                """	
		return [(kznf.kznfnetlink.KZNL_MSG_ADD_SERVICE, kznf.kznfnetlink.create_add_proxyservice_msg(self.name))];


class PFService(AbstractService):
        """
        <class maturity="stable">
          <summary>
            Class encapsulating a packet-filter service definition.
          </summary>          
          <description>       
          <note><para>The PFService class transfers packet-filter level
             services. To transfer connections on the application-level (proxy), 
             use the <link linkend="python.Service.Service">PFService</link> 
             class.</para></note>   
           <example>
           <title>PFService example</title>
           <para>The following packet-filtering service transfers TCP connections 
           that arrive to port <parameter>5555</parameter>.
           </para>
           <synopsis>PFService(name="intranet_PF5555_internet", router=TransparentRouter(forge_addr=FALSE))</synopsis>
           <para>The following example defines the Zorp classes required for a
           service to work: the client and server zones and the services they
           can accept; the dispatcher that starts the service, and the service itself.
           </para>
           <synopsis>InetZone('internet', ['0.0.0.0/0'],
    inbound_services=[
        "intranet_PF5555_internet"])

InetZone('intranet', [],
    outbound_services=[
        "intranet_PF5555_internet"])

def demo() :    
    PFService(name="intranet_PF5555_internet", router=TransparentRouter(forge_addr=FALSE))
    Dispatcher(transparent=TRUE, bindto=DBIface(protocol=ZD_PROTO_TCP, port=55555, iface="eth0", ip="192.168.0.15"), rule_port="55555", service="intranet_PF5555_internet")</synopsis>
           </example>
          </description>
          <!-- FIXME link to the kzorp chapter -->
          <metainfo>
            <attributes>
              <attribute>
                <name>router</name>
                <!--<type>AbstractRouter instance</type>-->
                <type><class/></type>
                <description>A router instance used to determine the
                destination address of the server.
                See <xref linkend="python.Router"/> for details.</description>
              </attribute>
              <attribute>
                <name>snat_policy</name>
                <!--<type>NATPolicy instance</type>-->
                <type><class/></type>
                <description>Name of the NAT policy instance used to translate
                the source addresses of the sessions.
                See <xref linkend="python.NAT"/> for details.</description>
              </attribute>
              <attribute>
                <name>dnat_policy</name>
                <!--<type>NATPolicy instance</type>-->
                <type><class/></type>
                <description>Name of the NAT policy instance used to translate
                the destination addresses of the sessions.
                See <xref linkend="python.NAT"/> for details.</description>
              </attribute>
             </attributes>
          </metainfo>
        </class>
        
        """
	def __init__(self, name, router=None, snat_policy=None, dnat_policy=None):
		"""
                <method maturity="stable">
                  <summary>
                    Constructor to initialize a PFService instance.
                  </summary>
                  <description>
                    <para>
                      This constructor defines a packetfilter-service with the specified parameters.
                    </para>
                  </description>
                  </method>
                  """
		AbstractService.__init__(self, name)
		self.router = router or default_router or TransparentRouter()
		self.snat_policy = getNATPolicy(snat_policy)
		self.dnat_policy = getNATPolicy(dnat_policy)
		
	def buildKZorpMessage(self):
		"""<method internal="yes">
                </method>
                """
		def addNATMappings(messages, nat_type, nat_policy):
                        if nat_type == NAT_SNAT:
                                msg_type = kznf.kznfnetlink.KZNL_MSG_ADD_SERVICE_NAT_SRC
                        else:
                                msg_type = kznf.kznfnetlink.KZNL_MSG_ADD_SERVICE_NAT_DST
			if nat_policy:
				nat_mapping = nat_policy.getKZorpMapping()
				for mapping in nat_mapping:
					messages.append((msg_type, kznf.kznfnetlink.create_add_service_nat_msg(self.name, mapping)))
				
                if isinstance(self.router, TransparentRouter):
                        flags = kznf.kznfnetlink.KZF_SVC_TRANSPARENT
                        router_target_ip = None
                        router_target_port = None
                elif isinstance(self.router, DirectedRouter):
                        if len(self.router.dest_addr) > 1:
                                raise ValueError, "DirectedRouter with more than one destination address not supported by KZorp"
                        flags = 0
                        router_target_ip = socket.ntohl(self.router.dest_addr[0].ip)
                        router_target_port = self.router.dest_addr[0].port
                else:
                        raise ValueError, "Invalid router type specified for port forwarded service"

                if self.router.forge_addr:
                        flags = flags | kznf.kznfnetlink.KZF_SVC_FORGE_ADDR

		messages = []
		messages.append((kznf.kznfnetlink.KZNL_MSG_ADD_SERVICE, kznf.kznfnetlink.create_add_pfservice_msg(self.name, flags, router_target_ip, router_target_port)))
                if self.snat_policy:
                        addNATMappings(messages, NAT_SNAT, self.snat_policy)
                if self.dnat_policy:
                        addNATMappings(messages, NAT_DNAT, self.dnat_policy)
		return messages
