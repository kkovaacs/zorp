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
## $Id: Plug.py,v 1.32 2004/06/15 12:28:47 sasa Exp $
##
## Author  : Bazsi
## Auditor : kisza
## Last audited version: 1.10
## Notes:
##
############################################################################

"""<module maturity="stable">
  <summary>
    Proxy for transferring data without protocol inspection.
  </summary>
  <description>
    <para>
      This module defines an interface to the Plug proxy. Plug is a simple TCP or
      UDP circuit, which means that transmission takes place without protocol
      verification.
    </para>
    <section>
      <title>Proxy behavior</title>
      <para>
        This class implements a general plug proxy, and is capable of optionally
        disabling data transfer in either direction. Plug proxy reads
        connection on the client side, then creates another connection at the 
        server side. Arriving responses are sent back to the client. However, it is not a protocol proxy, therefore PlugProxy does not implement any protocol analysis. It offers protection to clients and servers from lower level (e.g.: IP) attacks. It is mainly used to allow traffic pass the firewall for which there is no protocol proxy available.
      </para>
      <para>
        By default plug copies all data in both directions. To change
        this behavior, set the <parameter>copy_to_client</parameter> or <parameter>copy_to_server</parameter> attribute
        to FALSE.
      </para>
    <para>
      Plug supports the use of secondary sessions as described in <xref linkend="secondary_sessions">secondary sessions</xref>.
      </para>
      <note>
          <para>
            Copying of out-of-band data is not supported.
          </para>
      </note>
      </section>
    <section>
      <title>Related standards</title>
        <para>
          Plug proxy is not a protocol specific proxy module, therefore
          it is not specified in standards.
        </para>
    </section>
  </description>
  <metainfo>
    <constants>
      <constantgroup maturity="stable" id="const.plug.log">
        <description>
          Log level defined in Plug module 
        </description>
        <item>
          <name>PLUG_DEBUG</name>
          <value>"plug.debug"</value>
        </item>
      </constantgroup>
    </constants>
  </metainfo>
</module>
"""

from Zorp import *
from Proxy import Proxy

PLUG_DEBUG = "plug.debug"

class AbstractPlugProxy(Proxy):
	"""<class maturity="stable" abstract="yes">
          <summary>
            Class encapsulating the abstract Plug proxy.
          </summary>
          <description>
	  <para>An abstract proxy class for transferring data.</para>
          </description>
          <metainfo>
            <attributes>
              <attribute maturity="stable">
                <name>copy_to_server</name>
                <type>
                  <boolean/>
                </type>
                <default>TRUE</default>
                <conftime>
                  <write/>
                </conftime>
                <runtime>
                  <read/>
                </runtime>
                <description>
                  Allow data transfer in the client->server direction.
                </description>
              </attribute>
              <attribute maturity="stable">
                <name>copy_to_client</name>
                <type>
                  <boolean/>
                </type>
                <default>TRUE</default>
                <conftime>
                  <write/>
                </conftime>
                <runtime>
                  <read/>
                </runtime>
                <description>
                  Allow data transfer in the server->client direction.
                </description>
              </attribute>
              <attribute maturity="stable">
                <name>bandwidth_to_client</name>
                <type>
                  <integer/>
                </type>
                <default>n/a</default>
                <conftime/>
                <runtime>
                  <read/>
                </runtime>
                <description>
                  Read-only variable containing the bandwidth currently used in server->client direction.
                </description>
              </attribute>
              <attribute maturity="stable">
                <name>bandwidth_to_server</name>
                <type>
                  <integer/>
                </type>
                <default>n/a</default>
                <conftime/>
                <runtime>
                  <read/>
                </runtime>
                <description>
                  Read-only variable containing the bandwidth currently used in client->server direction.
                </description>
              </attribute>
              <attribute maturity="stable">
                <name>packet_stats_interval_time</name>
                <type>
                  <integer/>
                </type>
                <default>0</default>
                <conftime>
                  <write/>
                </conftime>
                <runtime>
                  <read/>
                </runtime>
                <description>
                  The time in milliseconds between two successive packetStats() events.
		  It can be useful when the Quality of Service for the connection is influenced dynamically.
                  Set to 0 to turn packetStats() off.
                </description>
              </attribute>
              <attribute maturity="stable">
                <name>packet_stats_interval_packet</name>
                <type>
                  <integer/>
                </type>
                <default>0</default>
                <conftime>
                  <write/>
                </conftime>
                <runtime>
                  <read/>
                </runtime>
                <description>
                  The number of passing packages between two successive packetStats() events.  
		  It can be useful when the Quality of Service for the connection is influenced dynamically.
                  Set to 0 to turn packetStats() off.
                </description>
              </attribute>
              <attribute maturity="stable">
                <name>stack_proxy</name>
		<type>
		  <link id="action.zorp.stack"/>
		</type>
                <conftime>
                  <write/>
                </conftime>
                <runtime>
                  <read/>
                </runtime>
                <description>
                   Proxy class to stack into the connection. All data is passed to the specified proxy.
                </description>
              </attribute>
              <attribute maturity="stable">
                <name>timeout</name>
                <type>
                  <integer/>
                </type>
                <default>60000</default>
                <conftime>
                  <write/>
                </conftime>
                <runtime>
                  <read/>
                </runtime>
                <description>
                  I/O timeout in milliseconds.
                </description>
              </attribute>
              <attribute maturity="stable">
                <name>shutdown_soft</name>
                <type>
                  <boolean/>
                </type>
                <default>FALSE</default>
                <conftime>
                  <write/>
                </conftime>
                <runtime>
                  <read/>
                </runtime>
                <description>
                  If enabled, the two sides of a connection are closed separately. (E.g.: if the server closes the connection the client side connection is held until it is verified that no further data arrives, for example from a stacked proxy.) It is automatically enabled when proxies are stacked into the connection.
                </description>
              </attribute>
              <attribute maturity="stable">
                <name>buffer_size</name>
                <type>
                  <integer/>
                </type>
                <default>1500</default>
                <conftime>
                  <write/>
                </conftime>
                <runtime>
                  <read/>
                </runtime>
                <description>
                  Size of the buffer used for copying data.
                </description>
              </attribute>
              <attribute maturity="stable">
                <name>secondary_sessions</name>
                <type>
                  <integer/>
                </type>
                <default>10</default>
                <conftime>
                  <read/>
                  <write/>
                </conftime>
                <runtime>
                  <read/>
                </runtime>
                <description>
                  Maximum number of allowed secondary sessions within a single proxy instance. See <xref linkend="secondary_sessions"/> for details.
                </description>
              </attribute>
              <attribute maturity="stable">
                <name>secondary_mask</name>
                <type>
                  <secondary_mask/>
                </type>
                <default>0xf</default>
                <conftime>
                  <read/>
                  <write/>
                </conftime>
                <runtime>
                  <read/>
                </runtime>
                <description>
                  Specifies which connections can be handled by the same proxy instance. See <xref linkend="secondary_sessions"/> for details.
                </description>
              </attribute>
            </attributes>
          </metainfo>
        </class>
        """
	name = "plug"
	def __init__(self, session):
		"""<method internal="yes">
                  <summary>
                    Constructor initializing a PlugProxy instance.
                  </summary>
                  <description>
                    <para>
                      This constructor creates and sets up a PlugProxy instance.
                    </para>
                  </description>
                  <metainfo>
                    <arguments>
                      <argument maturity="stable">
                        <name>session</name>
                        <type>SESSION</type>
                        <description>
                          session this instance belongs to
                        </description>
                      </argument>
                    </arguments>
                  </metainfo>
                </method>
                """
		self.stack_proxy = None
		Proxy.__init__(self, session)

	def requestStack(self):
		"""<method internal="yes">
                  <summary>
                    Function returning the stacked proxy class.
                  </summary>
                  <description>
                    <para>
		      This callback is called by the underlying C proxy to query
		      if something is to be stacked into it. It should return
		      the proxy class to be used.
		      Returns the class of the proxy to stack.
                    </para>
                  </description>
                  <metainfo>
                    <arguments/>
                  </metainfo>
                </method>
                """
		return self.stack_proxy

	def packetStats(self, client_bytes, client_pkts, server_bytes, server_pkts):
		"""<method maturity="stable">
                  <summary>
                    Function called when the packet_stats_interval is elapsed.
                  </summary>
                  <description>
                    <para>
                     This function is called whenever the time interval set in packet_stats_interval elapses, or a given number of
                     packets were transmitted. This event receives packet
                     statistics as parameters.
                    </para>
                    <para>
                     This function can be used in managing the Quality of Service of the connections; e.g.: to terminate connections with excessive
                     bandwidth requirements (for instance to limit the impact of
                     a covert channel opened when using plug instead of a                    protocol specific proxy).
                     </para>
                  </description>
                  <metainfo>
                    <arguments>
                      <argument maturity="stable">
                        <name>client_bytes</name>
                        <type></type>
                        <description>
                          Number of bytes transmitted to the client.
                        </description>
                      </argument>
                      <argument maturity="stable">
                        <name>client_pkts</name>
                        <type></type>
                        <description>
                          Number of packets transmitted to the client.
                        </description>
                      </argument>
                      <argument maturity="stable">
                        <name>server_bytes</name>
                        <type></type>
                        <description>
                          Number of bytes transmitted to the server.
                        </description>
                      </argument>
                      <argument maturity="stable">
                        <name>server_pkts</name>
                        <type></type>
                        <description>
                          Number of packets transmitted to the server.
                       </description>
                      </argument>
                    </arguments>
                  </metainfo>
                </method>
                """
		raise NotImplementedError


class PlugProxy(AbstractPlugProxy):
	"""<class maturity="stable">
          <summary>
            Class encapsulating the default Plug proxy.
          </summary>
          <description>
            <para>
              A default PlugProxy based on AbstractPlugProxy.
            </para>
          </description>
          <metainfo>
            <attributes/>
          </metainfo>
        </class>
        """
	pass

