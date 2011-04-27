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
<module maturity="obsolete">
  <summary>
    The Listener module defines the classes that accept incoming TCP connections.
  </summary>
  <description>
    <para>
      Listeners bind to a specific IP address and port of the Zorp firewall and wait for incoming connection requests.
      For each accepted connection, the Listener creates a new service instance to handle the TCP traffic arriving in
      the connection. The service started by the listener depends on the type of the listener:
    </para>
        <itemizedlist>
                <listitem>
                        <para>
                        <link linkend="python.Listener.Listener">Listeners</link>
                        start the same service for every connection.
                        </para>
                </listitem>
                <listitem>
                        <para>
                        <link linkend="python.Listener.ZoneListener">ZoneListeners</link>
                        start different services based on the zone the client belongs to.
                        </para>
                </listitem>
                <listitem>
                        <para><link linkend="python.Listener.CSZoneListener">CSZoneListeners</link>
                        start different services based on the zones the client and the destination server belong to.
                        </para>
                </listitem>
        </itemizedlist>
        <note>
        <para>
        Only one listener can bind to an IP address/port pair.
        </para>
        </note>
        <section id="listener_service_selection">
        <title>Zone-based service selection</title>
              <para>
              Listeners can start only a predefined service. Use ZoneListeners or CSZoneListeners to start different
               services for different connections. ZoneListener assigns different services to different client zones;
                CSZoneListener assigns different services to different client-server zone pairs.
                Define the zones and the related services in the <parameter>services</parameter> parameter.
                The <parameter>*</parameter> wildcard matches all client or server zones.
            </para>
            <note>
              <para>
                The server zone may be modified by the proxy, the router, the chainer, or the NAT policy used in the
                 service. To select the service, CSZoneListener determines the server zone from the original destination
                  IP address of the incoming client request. Similarly, the client zone is determined from the source IP
                   address of the original client request.
              </para>
            </note>
            <para>
              To accept connections from the child zones of the selected client
              zones, set the <parameter>follow_parent</parameter> attribute
              to <parameter>TRUE</parameter>. Otherwise, the listener accepts
              traffic only from the client zones explicitly listed in the
              <parameter>services</parameter> attribute of the listener.
            </para>
            </section>
  </description>
</module>
"""

from Dispatch import *

class Listener(Dispatcher):
        """
        <class maturity="stable">
          <summary>
            Class encapsulating the default Listener.
          </summary>
          <description>
            <para>
              Listeners listen for incoming TCP connections on a port and start a session
              and a service for accepted connections.
            </para>
            <example>
                <title>Listener example</title>
                <para>The following example defines a transparent listener that
                starts the service called <parameter>demo_http_service</parameter>
                for connections received on the <parameter>192.168.2.1</parameter>
                 IP address.</para>
                <synopsis>
Listener(bindto=SockAddrInet('192.168.2.1', 50080), service="demo_http_service", transparent=TRUE, backlog=255, threaded=FALSE)
                </synopsis>
            </example>
          </description>
          <metainfo>
            <attributes/>
          </metainfo>
        </class>
        """
        def __init__(self, bindto, service, **kw):
                """
                <method maturity="stable">
                  <summary>
                    Constructor to initialize an instance of the Listener class.
                  </summary>
                  <description>
                    <para>
                      This constructor creates a new Listener instance which can be
                      associated with a <link linkend="python.Service.Service">Service</link>.
                    </para>
                  </description>
                  <metainfo>
                    <arguments>
                      <argument>
                        <name>bindto</name>
                        <type>
                          <sockaddr existing="yes"/>
                        </type>
                        <description>An existing <link linkend="python.SockAddr">socket address</link> containing the IP address and port number where the Listener accepts connections.</description>
                      </argument>
                      <argument>
                        <name>service</name>
                        <type>
                          <service/>
                        </type>
                        <description>Name of the service to start.</description>
                      </argument>
                      <argument>
                        <name>transparent</name>
                        <type>
                          <boolean/>
                        </type>
                        <description>Set this parameter to <parameter>TRUE</parameter> if the listener
                        starts a transparent service.</description>
                      </argument>
                      <argument>
                        <name>backlog</name>
                        <type>
                          <integer/>
                        </type>
                        <description>
                        This parameter sets the queue size (maximum number) of TCP connections that are established
                        by the kernel, but not yet accepted by Zorp. This queue stores the connections that successfully
                         performed the three-way TCP handshake with the Zorp host, until the
                         listener sends the <emphasis>Accept</emphasis> package.</description>
                      </argument>
                      <argument>
                        <name>threaded</name>
                        <type>
                          <boolean/>
                        </type>
                        <description>Set this parameter to <parameter>TRUE</parameter> to start a new thread for every
                         client request. The proxy threads started by the listener will start from the listener's thread
                          instead of the main Zorp thread. Zorp accepts incoming connections faster and optimizes queuing
                           if this option is enabled. This improves user experience, but significantly increases the
                            memory consumption of Zorp. Use it only if Zorp has to transfer a very high number of
                             concurrent connections.
                             </description>
                      </argument>
                      <argument>
                        <name>mark_tproxy</name>
                        <type>
                          <boolean/>
                        </type>
                        <description>Set this parameter to <parameter>TRUE</parameter> to mark all connections
                        accepted by the Listener with the <parameter>-m tproxy</parameter> IPtables label.</description>
                      </argument>
                    </arguments>
                  </metainfo>
                </method>
                """

                Dispatcher.__init__(self, convertSockAddrToDB(bindto, ZD_PROTO_TCP), service, **kw)

class ZoneListener(ZoneDispatcher):
        """
        <class maturity="stable">
          <summary>
            Class encapsulating a Listener which selects a service based on the client zone.
          </summary>
          <description>
            <para>
              ZoneListeners are similar to Listeners, but select a service based on the zone of the client.
              See <xref linkend="listener_service_selection"/> for details.
            </para>
          </description>
          <metainfo>
            <attributes/>
          </metainfo>
        </class>
        """
        def __init__(self, bindto, services, **kw):
                """
                <method maturity="stable">
                  <summary>
                    Constructor to initialize an instance of the ZoneListener class.
                  </summary>
                  <description>
                    <para>
                      This constructor creates a new ZoneListener instance which can be
                      associated with a <link linkend="python.Service.Service">Service</link>.
                    </para>
                  </description>
                  <metainfo>
                    <arguments>
                      <argument>
                        <name>bindto</name>
                        <type>
                          <sockaddr existing="yes"/>
                        </type>
                        <description>An existing <link linkend="python.SockAddr">socket address</link> containing the IP address and port number where the Listener accepts connections.</description>
                      </argument>
                      <argument maturity="stable">
                        <name>services</name>
                        <type>
                          <hash>
                            <key>
                                <zone/>
                            </key>
                            <value>
                                <service/>
                            </value>
                          </hash>
                        </type>
                       <description>Client zone - service name pairs using the <parameter>("zone":"service")</parameter> format; specifying the service to start when the listener accepts a connection from the given
                        client zone.</description>
                      </argument>
                      <argument>
                        <name>transparent</name>
                        <type>
                          <boolean/>
                        </type>
                        <description>Set this parameter to <parameter>TRUE</parameter> if the listener
                        starts a transparent service.</description>
                      </argument>
                      <argument>
                        <name>backlog</name>
                        <type>
                          <integer/>
                        </type>
                        <description>This parameter sets the queue size (maximum number) of TCP connections that are
                         established by the kernel, but not yet accepted by Zorp. This queue stores the connections that
                          successfully performed the three-way TCP handshake with the Zorp host, until the listener
                          sends the <emphasis>Accept</emphasis> package.</description>
                      </argument>
                      <argument>
                        <name>threaded</name>
                        <type>
                          <boolean/>
                        </type>
                        <description>Set this parameter to <parameter>TRUE</parameter> to start a new thread for every
                         client request. The proxy threads started by the listener will start from the listener's thread
                          instead of the main Zorp thread. Zorp accepts incoming connections faster and optimizes queuing
                           if this option is enabled. This improves user experience, but significantly increases the
                            memory consumption of Zorp. Use it only if Zorp has to transfer a very high number of
                             concurrent connections.
                             </description>
                      </argument>
                      <argument>
                        <name>follow_parent</name>
                        <type>
                          <boolean/>
                        </type>
                        <description>Set this parameter to <parameter>TRUE</parameter> if the listener handles also the
                         connections coming from the child zones of the selected client zones. Otherwise, the listener
                          accepts traffic only from the client zones explicitly listed in the <parameter>services
                          </parameter> parameter.</description>
                      </argument>
                      <argument>
                        <name>mark_tproxy</name>
                        <type>
                          <boolean/>
                        </type>
                        <description>Set this parameter to <parameter>TRUE</parameter> to mark all connections accepted by
                         the Listener with the <parameter>-m tproxy</parameter> IPtables label.</description>
                      </argument>
                    </arguments>
                  </metainfo>
                </method>
                """
                ZoneDispatcher.__init__(self, convertSockAddrToDB(bindto, ZD_PROTO_TCP), services, **kw)

class CSZoneListener(CSZoneDispatcher):
        """
        <class maturity="stable">
          <summary>
            Class encapsulating a Listener which selects a service based on the client and the server zone.
          </summary>
          <description>
            <para>
              CSZoneListeners are similar to Listeners, but select a service based on the zone of the client and
              the destination server. See <xref linkend="listener_service_selection"/> for details.
            </para>
            <example>
                <title>CSZoneListener example</title>
                <para>The following example defines a CSZonelistener that
                starts the service called <parameter>internet_HTTP_DMZ</parameter>
                for connections received on the <parameter>192.168.2.1</parameter>
                 IP address, but only if the connection comes from the
                 <parameter>internet</parameter> zone and the destination is
                 in the <parameter>DMZ</parameter> zone.</para>
                <synopsis>
Listener(bindto=SockAddrInet('192.168.2.1', 50080), services={("internet", "DMZ"):"internet_HTTP_DMZ"}, transparent=TRUE, backlog=255, threaded=FALSE, follow_parent=FALSE)
                </synopsis>
            </example>
          </description>
          <metainfo>
            <attributes/>
          </metainfo>
        </class>
        """

        def __init__(self, bindto, services, **kw):
                """
                <method maturity="stable">
                  <summary>
                    Constructor to initialize a CSZoneListener instance.
                  </summary>
                  <description>
                    <para>
                      This constructor creates a new CSZoneListener instance which can be
                      associated with a <link linkend="python.Service.Service">Service</link>.
                    </para>
                  </description>
                  <metainfo>
                    <arguments>
                      <argument>
                        <name>bindto</name>
                        <type>
                          <sockaddr existing="yes"/>
                        </type>
                        <description>An existing <link linkend="python.SockAddr">socket address</link> containing the IP address and port number where the Listener accepts connections.</description>
                      </argument>
                      <argument>
                        <name>services</name>
                        <type>
                          <hash>
                            <key>
                              <tuple>
                                <zone/>
                                <zone/>
                              </tuple>
                            </key>
                            <value>
                                <service/>
                            </value>
                          </hash>
                        </type>
                        <guitype>HASH;STRING_zone,STRING_zone;STRING_service</guitype>
                         <description>Client zone - server zone - service name pairs using the <parameter>(("client_zone","server_zone"):"service")</parameter> format; specifying the service to start when the listener accepts a connection from the given
                        client zone.</description>
                        </argument>
                      <argument>
                        <name>transparent</name>
                        <type>
                          <boolean/>
                        </type>
                        <description>Set this parameter to <parameter>TRUE</parameter> if the listener starts a
                         transparent service.</description>
                      </argument>
                      <argument>
                        <name>backlog</name>
                        <type>
                          <integer/>
                        </type>
                        <description>This parameter sets the queue size (maximum number) of TCP connections that are
                         established by the kernel, but not yet accepted by Zorp. This queue stores the connections that
                          successfully performed the
                           three-way TCP handshake with the Zorp host, until the dispatcher sends the <emphasis>Accept
                           </emphasis> package.</description>
                      </argument>
                      <argument>
                        <name>threaded</name>
                        <type>
                          <boolean/>
                        </type>
                        <description>Set this parameter to <parameter>TRUE</parameter> to start a new thread for every
                         client request. The proxy threads started by the listener will start from the listener's thread
                          instead of the main Zorp thread. Zorp accepts incoming connections faster and optimizes queuing
                           if this option is enabled. This improves user experience, but significantly increases the
                            memory consumption of Zorp. Use it only if Zorp has to transfer a very high number of
                             concurrent connections.
                             </description>
                      </argument>
                      <argument>
                        <name>follow_parent</name>
                        <type>
                          <boolean/>
                        </type>
                        <description>Set this parameter to <parameter>TRUE</parameter> if the listener handles also the
                         connections coming from the child zones of the selected client zones. Otherwise, the listener
                          accepts traffic only from the explicitly listed client zones.</description>
                      </argument>
                      <argument>
                        <name>mark_tproxy</name>
                        <type>
                          <boolean/>
                        </type>
                        <description>Set this parameter to <parameter>TRUE</parameter> to mark all connections accepted by
                         the Listener with the <parameter>-m tproxy</parameter> IPtables label.</description>
                      </argument>
                    </arguments>
                  </metainfo>
                </method>
                """
                CSZoneDispatcher.__init__(self, convertSockAddrToDB(bindto, ZD_PROTO_TCP), services, **kw)
