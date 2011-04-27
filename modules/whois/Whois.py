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
## $Id: Whois.py,v 1.10 2004/06/15 12:28:48 sasa Exp $
##
## Author  : Bazsi
## Auditor :
## Last audited version: 1.1
## Notes:
##
############################################################################

"""<module maturity="stable">
  <summary>
    Proxy for the Whois information lookup protocol.
  </summary>
  <description>
    <para>
      WHOIS is a protocol providing information about domain and IP owners.
    </para>
    <section>
      <title>The Whois protocol</title>
      <para>
        Whois is a netwide service to the Internet users maintained by
        DDN Network Information Center (NIC). 
      </para>
      <para>
        The protocol follows a very simple method. First the client
        opens a TCP connection to the server at the port 43 and
        sends a one line REQUEST closed with &lt;CRLF&gt;.
        This request can contain only ASCII characters.
        The server sends the result back and closes the connection.
      </para>
    </section>
    <section>
      <title>Proxy behavior</title>
      <para>
        WhoisProxy is a module build for parsing messages of the WHOIS protocol. It reads and parses the REQUESTs on the client side and sends them to the server if the local security policy permits. Arriving RESPONSEs are not parsed as they do not have any fixed structure or syntax. 
      </para>
      <example>
        <title>Example WhoisProxy logging all whois requests</title>
        <literallayout>
class MyWhoisProxy(AbstractWhoisProxy):
	def whoisRequest(self, request):
		log(None, CORE_DEBUG, 3, "Whois request: '%s'" % (request))
		return Z_ACCEPT
        </literallayout>
      </example>
    </section>
    <section>
      <title>Related standards</title>
        <para>
          <itemizedlist>
          <listitem>
            <para>
              The NICNAME/WHOIS protocol is described in RFC 954.
            </para>
          </listitem>
          </itemizedlist>
        </para>
    </section>
  </description>
  <metainfo>
    <attributes/>
  </metainfo>
</module>
"""

from Zorp import *
from Proxy import Proxy

class AbstractWhoisProxy(Proxy):
	"""<class maturity="stable" abstract="yes">
          <summary>
            Class encapsulating the abstract Whois proxy.
          </summary>
          <description>
            <para>
              This class implements the WHOIS protocol as specified in RFC 954.
            </para>
          </description>
          <metainfo>
            <attributes>
              <attribute maturity="stable">
                <name>timeout</name>
                <type>
                  <integer/>
                </type>
                <default>30000</default>
                <conftime>
                  <read/>
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
                <name>max_line_length</name>
                <type>
                  <integer/>
                </type>
                <default>132</default>
                <conftime>
                  <read/>
                  <write/>
                </conftime>
                <runtime>
                  <read/>
                </runtime>
                <description>
                  Maximum number of characters allowed in a single line.
                </description>
              </attribute>
              <attribute maturity="stable">
                <name>max_request_length</name>
                <type>
                  <integer/>
                </type>
                <default>128</default>
                <conftime>
                  <read/>
                  <write/>
                </conftime>
                <runtime>
                  <read/>
                </runtime>
                <description>
                  Maximum allowed length of a Whois request.
                </description>
              </attribute>
              <attribute maturity="stable">
                <name>request</name>
                <type>
                  <string/>
                </type>
                <default/>
                <conftime/>
                <runtime>
                  <read/>
                  <write/>
                </runtime>
                <description>
                  The Whois request.
                </description>
              </attribute>
              <attribute maturity="stable">
                <name>response_header</name>
                <type>
                  <string/>
                </type>
                <default/>
                <conftime>
                  <read/>
                  <write/>
                </conftime>
                <runtime>
                  <read/>
                  <write/>
                </runtime>
                <description>
                  Prepend this string to each Whois response.
                </description>
              </attribute>
              <attribute maturity="stable">
                <name>response_footer</name>
                <type>
                  <string/>
                </type>
                <default/>
                <conftime>
                  <read/>
                  <write/>
                </conftime>
                <runtime>
                  <read/>
                  <write/>
                </runtime>
                <description>
                  Append this string to each Whois response.
                </description>
              </attribute>
            </attributes>
          </metainfo>
        </class>
        """
	name = "whois"
	def __init__(self, session):
		"""<method maturity="stable" internal="yes">
                  <summary>
                    Constructor to initialize a WhoisProxy instance.
                  </summary>
                  <description>
                  <para>
                    This constructor creates and set up a WhoisProxy instance.
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
		Proxy.__init__(self, session)

	def whoisRequest(self, request):
		"""<method>
		<summary>
	          Function to process whois requests.
	        </summary>
	        <description>
	          <para>
			This function is called by the Whois proxy to process the 
			requests. It can also be used to change specific
			attributes of the request.
	          </para>
	        </description>
	        <metainfo>
	          <arguments/>
	        </metainfo>
	        </method>
	        """
	        """
		Arguments
		  self -- this instance
		  request -- request contents, same as self.request

                FIXME: xml-isation
		"""
		return Z_ACCEPT

class WhoisProxy(AbstractWhoisProxy):
	"""<class maturity="stable">
          <summary>
            Default proxy class based on AbstractWhoisProxy.
          </summary>
          <description>
            <para>
              A default proxy class based on AbstractWhoisProxy.
            </para>
          </description>
          <metainfo>
            <attributes/>
          </metainfo>
        </class>
        """
	pass

