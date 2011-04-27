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
  The Receiver module defines the classes that accept incoming UDP connections.
</summary>
<description>
    <para>
      Receivers are identical to <link linkend="python.Listener">Listeners</link>, but they accept UDP connections.
    </para>
</description>
</module>  
"""

from Dispatch import *

class Receiver(Dispatcher):
	"""
        <class maturity="stable">
          <summary>
            Class encapsulating the default Receiver.
          </summary>
          <description>
		<para>
              Receivers listen for incoming UDP connections on a port and start a session
              and a service for accepted connections.
            </para>
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
                    Constructor to initialize an instance of the Receiver class.
                  </summary>
                  <description>
                    <para>
                      This constructor creates a new Receiver instance which can be
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
                        <description>An existing <link linkend="python.SockAddr">socket address</link> containing the IP address and port number where the Receiver accepts connections.</description>
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
                        <description>Set this parameter to <parameter>TRUE</parameter> if the receiver 
                        starts a transparent service.</description>
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
                      <argument>
                        <name>session_limit</name>
                        <type> 
                          <integer/> 
                        </type> 
                        <description>Specifies the maximum number of proxies permitted to start in a single poll loop.
                        </description>
                      </argument>
                    </arguments>
                  </metainfo>
                </method>
		"""
		Dispatcher.__init__(self, convertSockAddrToDB(bindto, ZD_PROTO_UDP), service, **kw)

class ZoneReceiver(ZoneDispatcher):
        """<class maturity="stable">
        <summary>
             Class encapsulating a Receiver which selects a service based on the client zone. 
             See <xref linkend="listener_service_selection"/> for details.
        </summary>
        <metainfo>
          <attributes/>
        </metainfo>
        </class>
        """

	def __init__(self, bindto, services, **kw):
                """
                <method maturity="stable">
                  <summary>
                    Constructor to initialize an instance of the ZoneReceiver class.
                  </summary>
                  <description>
                    <para>
                      This constructor creates a new ZoneReceiver instance which can be
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
                        <description>An existing <link linkend="python.SockAddr">socket address</link> containing the IP address and port number where the 
			Receiver accepts connections.</description>
                      </argument>
                      <argument>
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
                        <description>Client zone - service name pairs using the <parameter>("zone":"service")</parameter> format; specifying the service to start when the receiver accepts a connection from the given
			client zone.</description>
                      </argument>
                      <argument>
                        <name>transparent</name>
                        <type>
                          <boolean/>
                        </type>
                        <description>Set this parameter to <parameter>TRUE</parameter> if the receiver 
                        starts a transparent service.</description>
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
                        <description>Set this parameter to <parameter>TRUE</parameter> to mark all connections accepted by
                         the Listener with the <parameter>-m tproxy</parameter> IPtables label.</description>
                      </argument>
                      <argument>
                        <name>session_limit</name>
                        <type>  
                          <integer/>  
                        </type>  
                        <description>Specifies the maximum number of proxies permitted to start in a single poll loop.
                        </description>
                      </argument>
                    </arguments>
                  </metainfo>
                </method>
		"""
		ZoneDispatcher.__init__(self, convertSockAddrToDB(bindto, ZD_PROTO_UDP), services, **kw)

class CSZoneReceiver(CSZoneDispatcher):
	"""
	<class maturity="stable">
          <summary>
             Class encapsulating a Receiver which selects a service based on the client and the server zone.
             See <xref linkend="listener_service_selection"/> for details.
          </summary>
          <description>
            <para>
              CSZoneReceivers are similar to Receivers, but select a service based on the zone of the 
              client and the destination server. See <xref linkend="listener_service_selection"/> for details.
            </para>
            <note>
              <para>
                The server zone may be modified by the proxy, the router, the chainer, or the NAT policy used in the
                 service. To select the service, CSZoneListener determines the server zone from the original destination
                  IP address of the incoming client request. Similarly, the client zone is determined from the source IP
                   address of the original client request.
              </para>
            </note>
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
                    Constructor to initialize a CSZoneReceiver instance.
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
                        <description>An existing <link linkend="python.SockAddr">socket address</link> containing the IP address and port number where the 
			Receiver accepts connections.</description>
                      </argument>
                      <argument maturity="stable">
                        <name>service</name>
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
                        <description>Client zone - server zone - service name pairs using the <parameter>(("client_zone","server_zone"):"service")</parameter> format; specifying the service to start when the receiver accepts a connection from the given
			client zone.</description>
                      </argument>
                      <argument>
                        <name>transparent</name>
                        <type>
                          <boolean/>
                        </type>
                        <description>Set this parameter to <parameter>TRUE</parameter> if the receiver starts a
                         transparent service.</description>
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
                        <description>Set this parameter to <parameter>TRUE</parameter> to mark all connections accepted 
                        by the Listener with the <parameter>-m tproxy</parameter> IPtables label.</description>
                      </argument>
                      <argument>
                        <name>session_limit</name>
                        <type>  
                          <integer/>  
                        </type>  
                        <type>Integer</type>
                        <description>Specifies the maximum number of proxies permitted to start in a single poll loop.
                        </description>
                      </argument>
                    </arguments>
                  </metainfo>
                </method>
		"""
		CSZoneDispatcher.__init__(self,  convertSockAddrToDB(bindto, ZD_PROTO_UDP), services, **kw)
