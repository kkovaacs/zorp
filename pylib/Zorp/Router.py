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
  The Router module defines the classes that select the destination address of the server-side connection.
</summary>
<description>
  <para>
    Routers define the target IP address and port of the destination server, based 
    on information that is available before the Zorp proxy is started. The simplest router (<link
    linkend="python.Router.DirectedRouter">DirectedRouter</link>) selects a
    preset destination as the server address, while the most commonly used <link
    linkend="python.Router.TransparentRouter">TransparentRouter</link> connects to 
    the IP address requested by the client. Other routers may make more complex decisions.
    The destination address selected by the router may be overridden by the proxy and the DNAT classes used in the service.
  </para>
  <section id="router_source_address">
  <title>The source address used in the server-side connection</title>
        <para>
          Routers also define source address and port of the server-side connection. This is the IP address that Zorp
          uses to connect the server. The server sees that the connection originates from this address. The following
          two parameters determine the source address used in the server-side connection:
          </para>
         <para>
        <parameter>forge_addr</parameter>: If set to <parameter>TRUE</parameter>, Zorp uses the client's source address
        as the source of the server-side connection. Otherwise, Zorp uses the IP address of the interface connected to
        the server.
         </para>
         <para>
        <parameter>forge_port</parameter>: This parameter defines the source port that Zorp
          uses in the server-side connection. Specify a port number as an integer value, or use one of the
          following options:</para>
        <!--<inline type="enum" target="enum.zorp.forge_port"/>-->
        <table frame="all">
        <title>
        Options defining the source port of the server-side connection
        </title>
        <tgroup cols="2">
        <thead>
                <row><entry>Name</entry><entry>Description</entry>
                </row></thead>
        <tbody>
                <row>
                <entry>Z_PORT_ANY</entry>
                <entry>Selected a random port between <parameter>1024</parameter>
                and <parameter>65535</parameter>. This is the default behavior of every router.
                </entry>
                </row>
                <row>
                <entry>Z_PORT_GROUP</entry>
                <entry>Select a random port in the same group as the port used by
                the client. The following groups are defined:
                <parameter>0-513</parameter>, <parameter>514-1024</parameter>,
                <parameter>1025-</parameter>.
                </entry>
                </row>
                <row>
                <entry>Z_PORT_EXACT</entry>
                <entry>Use the same port as the client.
                </entry>
                </row>
		<row>
		<entry>Z_PORT_RANDOM</entry>
		<entry>Select a random port using a cryptographically secure function.
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
from SockAddr import SockAddrInet

class AbstractRouter:
        """
        <class maturity="stable" abstract="yes">
          <summary>
            Class encapsulating the abstract router.
          </summary>
          <description>
            <para>
              AbstractRouter implements an abstract router that determines the destination address of 
              the server-side connection. Service definitions should refer to a customized class derived 
              from AbstractRouter, or one of the predefined router classes, such as <link
                      linkend="python.Router.TransparentRouter">TransparentRouter</link> or <link
                      linkend="python.Router.DirectedRouter">DirectedRouter</link>.
                Different implementations of this interface perform Transparent routing
              (directing the client to its original destination), and Directed
              routing (directing the client to a given destination).
            </para>
            <para>
              A proxy can override the destination selected by the router using the
              the <link linkend="python.Proxy.Proxy.setServerAddress">setServerAddress</link> method.
            </para>
          </description>
          <metainfo>
            <attributes>
              <attribute maturity="stable">
                <name>forge_addr</name>
                <type><boolean/></type>
                <description>If set to <parameter>TRUE</parameter>, Zorp uses the
                client's source address as the source of the server-side connection.
                </description>
              </attribute>
              <attribute maturity="stable">
                <name>forge_port</name>
                <!--<type>FORGE_PORT</type>-->
                <type></type>
                <description>
                <para>Defines the source port that Zorp
                 uses in the server-side connection. See <xref linkend="router_source_address"/> for details.</para>
                </description>
              </attribute>
            </attributes>
          </metainfo>
        </class>
        """
        def __init__(self, forge_addr, forge_port):
                """
                <method internal="yes">
                  <metainfo>
                    <arguments>
                      <argument maturity="stable">
                        <name>forge_addr</name>
                        <type>
                          <boolean/>
                        </type>
                        <default>FALSE</default>
                        <description>set to true if the client's source address is to be forged on the server side
                        </description>
                      </argument>
                      <argument maturity="stable">
                        <name>forge_port</name>
                        <type>
                          <choice>
                            <link id="enum.zorp.forge_port"/>
                            <integer/>
                          </choice>
                        </type>
                        <default>Z_PORT_ANY</default>
                        <description>
                <para>Defines the source port that Zorp
                 uses in the server-side connection. See <xref linkend="router_source_address"/> for details.</para>
                        </description>
                      </argument>
                    </arguments>
                  </metainfo>
                </method>
                """
                self.forge_addr = forge_addr
                self.forge_port = forge_port

        def routeConnection(self, session):
                """
                <method internal="yes">
                  <summary>
                    Function called to perform connection routing.
                  </summary>
                  <description>
                    <para>
                    This function is called to determine the destination address
                    of this session, and place it in session.target_address
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
		session.target_local_loose = FALSE
		session.target_local_random = FALSE      # defaults to FALSE, but just in case
		if self.forge_port == Z_PORT_ANY:
			local_port = 0
		elif self.forge_port == Z_PORT_GROUP:
			local_port = session.client_address.port
			session.target_local_loose = TRUE
		elif self.forge_port == Z_PORT_EXACT:
			local_port = session.client_address.port
		elif self.forge_port == Z_PORT_RANDOM:
			local_port = session.client_address.port
			session.target_local_loose = TRUE
			session.target_local_random = TRUE
		elif self.forge_port >= 1 and self.forge_port <= 65535:
			local_port = self.forge_port
		else:
			raise ValueError, "Invalid forge_port value (%d)" % self.forge_port
		
		if self.forge_addr or session.service.snat_policy:
			local_addr = session.client_address.clone(FALSE)
			local_addr.port = local_port
		else:
			if local_port != 0:
				local_addr = session.client_address.clone(FALSE)
				local_addr.ip = 0
				local_addr_port = local_port
			else:
				local_addr = None
		if local_addr:
			session.target_local = local_addr

	
class TransparentRouter(AbstractRouter):
	"""
        <class maturity="stable">
          <summary>
            Class encapsulating a Router which provides transparent services.
          </summary>
          <description>
            <para>
              This class implements transparent routing, which means that
              the destination server is the original destination requested by the client.
            </para>
            <example>
            <title>TransparentRouter example
            </title>
            <para>The following service uses a TransparentRouter that
             connects to the <parameter>8080</parameter> port of the server and
              uses the client's IP address as the source of the server-side
              connection.</para>
            <synopsis>
Service(name="demo_service", proxy_class=HttpProxy, router=TransparentRouter(forced_port=8080, overrideable=FALSE, forge_addr=TRUE))
            </synopsis>
            </example>
          </description>
          <metainfo>
            <attributes>
              <attribute maturity="stable">
                <name>forced_port</name>
                <type></type>
                <description>
                <para>Defines the source port that Zorp
                 uses in the server-side connection.
                 See <xref linkend="router_source_address"/> for details.</para>
                </description>
              </attribute>
              <attribute maturity="stable">
                <name>forge_addr</name>
                <type></type>
                <description>If set to <parameter>TRUE</parameter>, Zorp uses
                the client's source address as the source of the server-side connection.
                </description>
              </attribute>
            </attributes>
          </metainfo>
        </class>
        """
        def __init__(self, forced_port=0, forge_addr=FALSE, overrideable=FALSE, forge_port=Z_PORT_ANY):
                """
                <method maturity="stable">
                  <summary>
                    Constructor to initialize an instance of the TransparentRouter class.
                  </summary>
                  <description>
                    <para>
                      This constructor creates a new TransparentRouter instance which can be
                      associated with a <link linkend="python.Service.Service">Service</link>.
                    </para>
                  </description>
                  <metainfo>
                    <arguments>
                      <argument maturity="stable">
                        <name>forced_port</name>
                        <type>
                          <integer/>
                        </type>
                        <default>0</default>
                        <description>Modify the destination port to this value. Default value: 0
                        (do not modify the target port)</description>
                      </argument>
                      <argument maturity="stable">
                        <name>forge_addr</name>
                        <type>
                          <boolean/>
                        </type>
                        <default>FALSE</default>
                        <description>If set to <parameter>TRUE</parameter>, Zorp uses the client's source address as
                        the source of the server-side connection.
                </description>
                      </argument>
                      <argument maturity="stable">
                        <name>forge_port</name>
                        <type>
                          <choice>
                            <link id="enum.zorp.forge_port"/>
                            <integer/>
                          </choice>
                        </type>
                        <default>Z_PORT_ANY</default>
                <description>
                <para>Defines the source port that Zorp
                 uses in the server-side connection. See <xref linkend="router_source_address"/> for details.</para>
                </description>
                      </argument>
                      <argument maturity="stable">
                        <name>overrideable</name>
                        <type>
                          <boolean/>
                        </type>
                        <default>FALSE</default>
                        <description>If set to <parameter>TRUE</parameter>, 
                         the proxy may override the selected
                         destination. Enable this option when the proxy builds 
                         multiple connections to the destination server, and the proxy
                         knows the address of the destination server, for example, 
                         because it receives a redirect request.
                         This situation is typical for the SQLNet proxy.
                        </description>
                      </argument>
                    </arguments>
                  </metainfo>
                </method>
                """
		AbstractRouter.__init__(self, forge_addr, forge_port)
		self.forced_port = forced_port
		self.overrideable = overrideable

	def routeConnection(self, session):
		"""
                <method internal="yes">
                  <summary>
                    Overridden function to perform routing.
                  </summary>
                  <description>
                    <para>
                      This function sets 'session.target_address' to the transparent
                      destination as stored in 'session.client_local'.
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
		AbstractRouter.routeConnection(self, session)

		addr = session.client_local.clone(FALSE)
		if self.forced_port:
			addr.port = self.forced_port
		session.target_address_inband = self.overrideable
		session.setTargetAddress((addr,))

class DirectedRouter(AbstractRouter):
	"""
        <class maturity="stable">
          <summary>
            Class encapsulating a Router which explicitly defines the target address.
          </summary>
          <description>
            <para>
              This class implements directed routing, which means that the destination 
              address is a preset address for each session.
            </para>
           <example>
            <title>DirectedRouter example
            </title>
            <para>The following service uses a DirectedRouter that
             redirects every connection to the <filename>/var/sample.socket</filename> Unix domain socket.</para>
            <synopsis>
Service(name="demo_service", proxy_class=HttpProxy, router=DirectedRouter(dest_addr=SockAddrUnix('/var/sample.socket'), overrideable=FALSE, forge_addr=FALSE))
            </synopsis>
            <para>The following service uses a DirectedRouter that
             redirects every connection to the <parameter>192.168.2.24:8080</parameter> IP address.</para>
            <synopsis>
Service(name="demo_service", proxy_class=HttpProxy, router=DirectedRouter(dest_addr=SockAddrInet('192.168.2.24', 8080), overrideable=FALSE, forge_addr=FALSE))
            </synopsis>
            </example>
          </description>
          <metainfo>
            <attributes>
              <attribute maturity="stable">
                <name>dest_addr</name>
                <type></type>
                <description>The destination address to connect to.</description>
              </attribute>
            </attributes>
          </metainfo>
        </class>

        """
        def __init__(self, dest_addr, forge_addr=FALSE, overrideable=FALSE, forge_port=Z_PORT_ANY):
                """
                <method maturity="stable">
                  <summary>
                    Constructor to initialize a DirectedRouter.
                  </summary>
                  <description>
                    <para>
                      This constructor initializes an instance of the DirectedRouter class.
                    </para>
                  </description>
                  <metainfo>
                    <arguments>
                      <argument maturity="stable">
                        <name>dest_addr</name>
                        <type>
			  <list>
			    <sockaddr/>
			  </list>
			</type>
                        <description>The destination address to connect to.</description>
                      </argument>
                      <argument maturity="stable">
                        <name>forge_addr</name>
                        <type>
                          <boolean/>
                        </type>
                        <default>FALSE</default>
                    <description>If set to <parameter>TRUE</parameter>, Zorp
                    uses the client's source address as the source of the
                    server-side connection.
                        </description>
                      </argument>
                      <argument maturity="stable">
                        <name>forge_port</name>
                        <type>
                          <choice>
                            <link id="enum.zorp.forge_port"/>
                            <integer/>
                          </choice>
                        </type>
                        <default>Z_PORT_ANY</default>
                        <description>
                        <para>Defines the source port that Zorp
                         uses in the server-side connection.
                         See <xref linkend="router_source_address"/> for details.</para>
                        </description>
                      </argument>
                      <argument maturity="stable">
                        <name>overrideable</name>
                        <type>
                          <boolean/>
                        </type>
                        <default>FALSE</default>
                         <description>If set to <parameter>TRUE</parameter>, 
                         the proxy may override the selected
                         destination. Enable this option when the proxy builds 
                         multiple connections to the destination server, and the proxy
                         knows the address of the destination server, for example, 
                         because it receives a redirect request.
                         This situation is typical for the SQLNet proxy.
                        </description>
                      </argument>
                    </arguments>
                  </metainfo>
                </method>
		"""
		AbstractRouter.__init__(self, forge_addr, forge_port)
		if isinstance(dest_addr, SockAddrType):
			self.dest_addr = (dest_addr,)
		else:
			self.dest_addr = dest_addr
		self.overrideable = overrideable

	def routeConnection(self, session):
		"""
                <method internal="yes">
                  <summary>
                    Overridden function to perform routing.
                  </summary>
                  <description>
                    <para>
                      This function simply sets 'session.target_address' to 'self.dest_addr'
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
		AbstractRouter.routeConnection(self, session)
		session.setTargetAddress(self.dest_addr)
		session.target_address_inband = self.overrideable
		
class InbandRouter(AbstractRouter):
	"""
        <class maturity="stable">
          <summary>
            Class encapsulating the Router which extracts the destination address from the application-level protocol.
          </summary>
          <description>
            <para>
              This class implements inband routing, which means that the destination address will be determined by
              the protocol. Inband routing works only for protocols
              that can send routing information within the protocol, and is mainly used for non-transparent
              proxying. The InbandRouter class currently supports only the HTTP and FTP protocols.
            </para>
           <example>
            <title>InbandRouter example
            </title>
            <para>The following service uses an InbandRouter to extract the destination from the protocol.</para>
            <synopsis>
Service(name="demo_service", proxy_class=HttpProxy, router=InbandRouter(forge_addr=FALSE))
            </synopsis>
            </example>
          </description>
          <metainfo>
            <attributes/>
          </metainfo>
        </class>
	"""
	def __init__(self, forge_addr=FALSE, forge_port=Z_PORT_ANY):
		"""
                <method maturity="stable">
                  <summary>
                    Constructor to initialize a InbandRouter.
                  </summary>
                  <description>
                    <para>
                      This constructor initializes an instance of the InbandRouter class.
                    </para>
                  </description>
                  <metainfo>
                    <arguments>
                      <argument maturity="stable">
                        <name>forge_addr</name>
                        <type>
                          <boolean/>
                        </type>
                        <default>FALSE</default>
                        <description>If set to <parameter>TRUE</parameter>, Zorp uses the client's source address as the                                source of the server-side connection.
                        </description>
                      </argument>
                      <argument maturity="stable">
                        <name>forge_port</name>
                        <type>
                          <choice>
                            <link id="enum.zorp.forge_port"/>
                            <integer/>
                          </choice>
                        </type>
                        <default>Z_PORT_ANY</default>
                        <description>
                        <para>Defines the source port that Zorp
                         uses in the server-side connection.
                         See <xref linkend="router_source_address"/> for details.</para>
                        </description>
                      </argument>
                    </arguments>
                  </metainfo>
                </method>
                """
                AbstractRouter.__init__(self, forge_addr, forge_port)

        def routeConnection(self, session):
                """
                <method internal="yes">
                  <summary>
                    Overridden function to perform routing.
                  </summary>
                  <description>
                    <para>
                      This function does nothing, it simply lets the protocol
                      logic to choose its destination server.
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
		AbstractRouter.routeConnection(self, session)
		session.target_address_inband = TRUE
