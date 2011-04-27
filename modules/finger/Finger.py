############################################################################
##
##  COPYRIGHTHERE
##
## $Id: Finger.py,v 1.19 2004/06/15 12:28:47 sasa Exp $
##
## Author  : Bazsi
## Auditor : 
## Last audited version:
## Notes:
##
############################################################################

"""<module maturity="stable">
<summary>
  Proxy for the Finger User Information Protocol.
</summary>
<description>
  <para>
    The Finger module defines the classes constituting the proxy for the Finger protocol.
  </para>
  <section>
    <title>The Finger protocol</title>
    <para>
      Finger is a request/response based User Information Protocol using port TCP/79. 
      The client opens a connection to the remote machine to initiate a request. 
      The client sends a one line query based on the Finger query specification and 
      waits for the answer. A remote user information program (RUIP) processes the
      query, returns the result and closes the connection. The response is a series 
      of lines consisting of printable ASCII closed carriage return-line feed 
      (CRLF, ASCII13, ASCII10). After receiving the answer the client closes 
      the connection as well.
    </para>
    <para>
      The following queries can be used:
      <itemizedlist>
        <listitem>
          <para>
            &lt;CRLF&gt; This is a simple query listing all users logged in to the remote machine.
          </para>
        </listitem>
        <listitem>
          <para>
            USERNAME&lt;CRLF&gt; A query to request all available information about the user USERNAME.
          </para>
        </listitem>
        <listitem>
          <para>
            USERNAME@HOST1&lt;CRLF&gt; Request the RUIP to forward the
            query to HOST1. The response to this query is all information about the user USERNAME available at the remote computer HOST1.
          </para>
        </listitem>
        <listitem>
          <para>
            USERNAME@HOST1@HOST2&lt;CRLF&gt; Request HOST1 to forward the query to HOST2. The response to this query is all information about the user USERNAME available at the remote computer HOST2.
          </para>
        </listitem>
      </itemizedlist>
    </para>
  </section>
  <section>
    <title>Proxy behavior</title>
      <para>
        Finger is a module built for parsing messages of the Finger protocol.
        It reads the QUERY at the client side, parses it and - if the local security policy permits - sends it to the server. When the RESPONSE arrives
        it processes the RESPONSE and sends it back to the client. It is possible to prepend and/or append a string to the response. Requests can also be manipulated in various ways using the
        <emphasis><link linkend="python.Finger.AbstractFingerProxy.fingerRequest">fingerRequest</link></emphasis>
        function, which is called by the proxy if it is defined.
      </para>
      <para>
        Length of the username, the line and the hostname can be limited by setting
        various attributes. Finger proxy also has the capability
        of limiting the number of hosts in a request, e.g.: <command>finger user@domain@server</command> normally results in fingering 'user@domain' performed by
        the host 'server'. By default, the proxy removes everything
        after and including the first '@' character. This behavior can be modified by setting the max_hop_count attribute to a non-zero value.
      </para>
      <example>
        <title>Controlling the number of max hops</title>
        <literallayout>
def MyFingerProxy(FingerProxy):
	def config(self):
		FingerProxy.config(self)
		self.max_hop_count = 2
		self.timeout = 30
        </literallayout>
      </example>
  </section>
  <section>
    <title>Related standards</title>
      <para>
        <itemizedlist>
          <listitem>
            <para>
              The Finger User Information Protocol is described in RFC 1288.
            </para>
          </listitem>
        </itemizedlist>
      </para>
  </section>
</description>
<metainfo>
</metainfo>
</module>
"""

from Zorp import *
from Proxy import Proxy

class AbstractFingerProxy(Proxy):
	"""<class maturity="stable" abstract="yes">
        <summary> 
          Class encapsulating the abstract Finger proxy.
        </summary>
        <description>
          <para>
            This proxy implements the Finger protocol as specified in RFC 1288.
          </para>
        </description>
        <metainfo>
          <attributes>
            <attribute maturity="stable">
              <name>max_hop_count</name>
              <type>
                <integer/>
              </type>
              <default>0</default>
              <conftime>
                <read/>
                <write/>
              </conftime>
              <runtime>
                <read/>
              </runtime>
              <description>
                  Maximum number of '@' characters in the request. Any text after the last allowed '@' character is stripped from the request.
              </description>
            </attribute>
            <attribute maturity="stable">
              <name>max_hostname_length</name>
              <type>
                <integer/>
              </type>
              <default>30</default>
              <conftime>
                <read/>
                <write/>
              </conftime>
              <runtime>
                <read/>
              </runtime>
              <description>
                Maximum number of characters in a single name of the hostname chain.
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
                Maximum number of characters in a single line in requests and responses.
              </description>
            </attribute>
            <attribute maturity="stable">
              <name>max_username_length</name>
              <type>
                <integer/>
              </type>
              <default>8</default>
              <conftime>
                <read/>
                <write/>
              </conftime>
              <runtime>
                <read/>
              </runtime>
              <description>
                Maximum length of the username in a request.
              </description>
            </attribute>
            <attribute maturity="stable">
              <name>request_detailed</name>
              <type>
                <integer/>
              </type>
              <default>n/a</default>
              <conftime/>
              <runtime>
                <read/>
                <write/>
              </runtime>
              <description>
                Indicates if multi-line formatting request (/W prefix) was sent by the client (-l parameter). Request for multi-line formatting can be added/removed by the proxy during the <link linkend="python.Finger.AbstractFingerProxy.fingerRequest">fingerRequest</link> event.
              </description>
            </attribute>
            <attribute maturity="stable">
              <name>request_hostnames</name>
              <type>
                <string/>
              </type>
              <default>n/a</default>
              <conftime/>
              <runtime>
                <read/>
                <write/>
              </runtime>
              <description>
                The hostname chain. The hostname chain can be modified by the proxy during the <link linkend="python.Finger.AbstractFingerProxy.fingerRequest">fingerRequest</link> event.
              </description>
            </attribute>
            <attribute maturity="stable">
              <name>request_username</name>
              <type>
                <string/>
              </type>
              <default>n/a</default>
              <conftime/>
              <runtime>
                <read/>
                <write/>
              </runtime>
              <description>
                The username to be queried. The username can be modified by the proxy during the <link linkend="python.Finger.AbstractFingerProxy.fingerRequest">fingerRequest</link> event.
              </description>
            </attribute>
            <attribute maturity="stable">
              <name>response_header</name>
              <type>
                <string/>
              </type>
              <default>""</default>
              <conftime/>
                <read/>
                <write/>
              <runtime>
                <read/>
                <write/>
              </runtime>
              <description>
                String to be prepended by the proxy to each finger response.
              </description>
            </attribute>
            <attribute maturity="stable">
              <name>response_footer</name>
              <type>
                <string/>
              </type>
              <default></default>
              <conftime>
                <read/>
                <write/>
              </conftime>
              <runtime>
                <read/>
                <write/>
              </runtime>
              <description>
                String to be appended by the proxy to each finger response.
              </description>
            </attribute>
            <attribute maturity="stable">
              <name>strict_username_check</name>
              <type>
                <boolean/>
              </type>
              <default>TRUE</default>
              <conftime>
                <read/>
                <write/>
              </conftime>
              <runtime>
                <read/>
              </runtime>
              <description>
                If enabled (TRUE), only requests for usernames containing alphanumeric characters and underscore [a-zA-Z0-9_] are allowed.
              </description>
            </attribute>
            <attribute maturity="stable">
              <name>timeout</name>
              <type>
                <integer/>
              </type>
              <default>n/a</default>
              <conftime>
                <read/>
                <write/>
              </conftime>
              <runtime>
                <read/>
              </runtime>
              <description>
                Timeout value for the request in milliseconds.
              </description>
            </attribute>
          </attributes>
        </metainfo>
        </class>
	"""
	name = "finger"

        def __init__(self, session):
                """<method internal="yes">
                <summary>
                  Constructor to initialize a FingerProxy instance.
                </summary>
                <description>
                  <para>
                    This constructor creates and set up a FingerProxy instance.
                  </para>
                </description>
                <metainfo>
                  <arguments>
                    <argument internal="yes">
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

	def fingerRequest(self, username, hostname):
		"""<method>
                <summary>
                  Function processing finger requests.
                </summary>
                <description>
                  <para>
                    This function is called by the Finger proxy to process 
                    requests. It can also modify request-specific
                    attributes.
                  </para>
                </description>
                <metainfo>
                  <arguments>
                    <argument maturity="stable">
                      <name>username</name>
                      <type></type>
                      <description>
                        Username to be fingered.
                      </description>
                    </argument>
                    <argument maturity="stable">
                      <name>hostname</name>
                      <type></type>
                      <description>
                        Destination hosts of the finger request.
                      </description>
                    </argument>
                  </arguments>
                </metainfo>
                </method>
		"""
		return Z_ACCEPT

	def config(self):
		"""<method internal="yes">
                </method>
                """
		pass

class FingerProxy(AbstractFingerProxy):
	"""<class maturity="stable">
        <summary>
          Class encapsulating the default Finger proxy.
        </summary>
        <description>
          <para>
           Simple FingerProxy based on AbstractFingerProxy. 
          </para>
        </description>
        <metainfo>
          <attributes/>
        </metainfo>
        </class>
        """
	pass
