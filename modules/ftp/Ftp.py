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
## $Id: Ftp.py,v 1.94 2004/07/19 16:56:01 sasa Exp $
##
## Author  : sasa
## Auditor :  
## Last audited version: 
## Notes:
##
############################################################################

"""<module maturity="stable">
<summary>
  Proxy for the File Transfer Protocol.
</summary>
<description>
  <para>
    The Ftp module defines the classes constituting the proxy for the File Transfer Protocol (FTP).
  </para>
  <section>
    <title>The FTP protocol</title>
    <para>
      File Transfer Protocol (FTP) is a protocol to transport files via a reliable TCP 
    connection between a client and a server.
      FTP uses two reliable TCP connections to transfer files:
      a simple TCP connection (usually referred to as the Control Channel) to transfer control information and a secondary TCP connection (usually
      referred to as the Data Channel) to perform the data transfer. It
      uses a command/response based approach, i.e. the client issues a command
      and the server responds with a 3-digit status code and associated
      status information in text format. The Data Channel can be initiated either from
      the client or the server; the Control Channel is always started from the client. 
    </para>
    <para>
      The client is required to authenticate itself before other commands
      can be issued. This is performed using the USER and PASS commands 
      specifying username and password, respectively.
    </para>
    <section>
      <title>Protocol elements</title>
      <para>
        The basic protocol is as follows: the client issues a request (also called
        command in FTP terminology) and the server responds with the result.
        Both commands and responses are line based: commands are sent as complete lines starting with a keyword identifying the operation to
        be performed. A response spans one or more lines, each specifying the
        same 3-digit status code and possible explanation.
      </para>
    </section>
    <section>
      <title>Data transfer</title>
      <para>
        Certain commands (for example RETR, STOR or LIST) also have a data
        attachment which is transferred to the peer. Data attachments are
        transferred in a separate TCP connection. This connection is
        established on-demand on a random, unprivileged port when a data transfer 
        command is issued.
      </para>
      <para>
        Endpoint information of this data channel is exchanged via the
        PASV and PORT commands, or their newer equivalents (EPSV and EPRT).
      </para>
      <para>
        The data connection can either be initiated by the client (passive
        mode) or the server (active mode). In passive mode (PASV or EPSV
        command) the server opens a listening socket and sends back the
        endpoint information in the PASV response. In active mode (PORT or
        EPRT command) the client opens a listening socket and sends its
        endpoint information as the argument of the PORT command.
	The source port of the server is usually either 20, or the port number of the Command Channel minus one.
      </para>
      <example>
        <title>FTP protocol sample</title>
        <literallayout>
220 FTP server ready
USER account
331 Password required.
PASS password
230 User logged in.
SYST
215 UNIX Type: L8
PASV
227 Entering passive mode (192,168,1,1,4,0)
LIST
150 Opening ASCII mode data connection for file list
226-Transferring data in separate connection complete.
226 Quotas off
QUIT
221 Goodbye
        </literallayout>
      </example>
    </section>
  </section>
  <section id="ftp_proxy_behavior">
    <title>Proxy behavior</title>
      <para>
        FtpProxy is a module built for parsing commands of the Control Channel in the FTP protocol. It reads the REQUEST at the client side, parses it and - if the local security policy permits - sends it to the server.
        The proxy parses the arriving RESPONSES and sends them to the client if the policy permits that. FtpProxy uses a PlugProxy to transfer the data arriving in the Data Channel. The proxy is capable of manipulating commands and stacking further proxies (e.g.: <link linkend="python.Mime.MimeProxy">MimeProxy</link>) into the Data Channel. Both transparent and non-transparent modes are supported.
      </para>
      <para>
        The default low-level proxy implementation (AbstractFtpProxy) denies all requests by default. Different commands and/or responses can be enabled by using one of the several predefined proxy classes which are suitable for most tasks. Alternatively, use of the commands can be permitted individually using different attributes. This is detailed in the following two sections.
      </para>
      <section id="ftp_commands">
        <title>Configuring policies for FTP commands and responses</title>
          <para>
            Changing the default behavior of commands can be done by 
            using the hash attribute <parameter>request</parameter>, indexed by the command name (e.g.: USER or PWD). There is a similar attribute for responses called <parameter>response</parameter>, indexed by the command name and the response code. 
	     The possible values of these hashes are shown in the tables below. See <xref linkend="proxy_policies"/> for details. When looking up entries of the <parameter>response</parameter> attribute hash, the lookup precedence described in <xref linkend="proxy_response_codes"/> is used.
	    <inline type="actiontuple" target="action.ftp.req"/>
	    <inline type="actiontuple" target="action.ftp.rsp"/>
          </para>
          <example>
            <title>Customizing FTP to allow only anonymous sessions</title>
              <para>
	      This example calls a function called pUser (defined in the example) whenever a USER command is received. All other commands are accepted. The parameter of the USER command (i.e. the username) is examined: if it is 'anonymous' or 'Anonymous', the connection is accepted, otherwise it is rejected.
	      </para>
	      <literallayout>
class AnonFtp(FtpProxy):
	def config(self):
		self.request["USER"] = (FTP_REQ_POLICY, self.pUser)
		self.request["*"] = (FTP_REQ_ACCEPT)

	def pUser(self,command):
		if self.request_parameter == "anonymous" or self.request_parameter == "Anonymous":
			return FTP_REQ_ACCEPT
		return FTP_REQ_REJECT
              </literallayout>
          </example>
        <para>
          All responses are rejected by default, even though this is not permitted by
          RFC 959. Therefore, the FtpProxy sends an "500 Error parsing answer"
          to the client. The responses can be either enabled one by one, or all of them at once by using ("*","*") in the policy.
        </para> 
      </section>
      <section id="ftp_features">
        <title>Configuring policies for FTP features and FTPS support</title>
          <para>
            FTP servers send the list of supported features to the clients. For example, proftpd supports the following features: <parameter>LANG en, MDTM, UTF8, AUTH TLS, PBSZ, PROT, REST STREAM, SIZE</parameter>. Zorp can change the default behavior of Ftp features using the hash attribute <parameter>feature</parameter>, indexed by the name of the feature (e.g.: UTF8 or AUTH TLS).
	     The possible actions are shown in the table below. See <xref linkend="proxy_policies"/> for details.</para>
	     <para>The built-in Ftp proxies of Zorp permit the use of every feature by default.</para>
	     <inline type="actiontuple" target="action.ftp.feat"/>
	    <section id="configuring-ftps">
	    <title>Enabling FTPS connections</title>
	        <para>For FTPS connections to operate correctly, the FTP server and client applications must comply to the <emphasis>FTP Security Extensions (RFC 2228)</emphasis> and <emphasis>Securing FTP with TLS (RFC 4217)</emphasis> RFCs.</para>
	        <para>For FTPS connections, the <parameter>AUTH TLS, PBSZ, PROT</parameter> features must be accepted. Also, STARTTLS support must be properly configured. See <xref linkend="configuring-ssl"/> for details.</para>
	        <para>If the proxy is configured to disable encryption between Zorp and the client, the proxy automatically removes the <parameter>AUTH TLS, PBSZ, PROT</parameter> features from the list sent by the server.</para>
	        <para>If STARTTLS connections are accepted on the client side (<parameter>self.ssl.client_security=SSL_ACCEPT_STARTTLS</parameter>), but TLS-forwarding is disabled on the server side, the proxy automatically inserts the <parameter>AUTH TLS, PBSZ, PROT</parameter> features into the list sent by the server. These features are inserted even if encryption is explicitly disabled on the server side or the server does not support the <parameter>FEAT</parameter> command, making one-sided STARTTLS support feasible.</para>
	        <warning>
	            <!-- Copied to ftp_inband_authentication as well -->
	            <para>When using <link linkend="python.Router.InbandRouter">inband routing</link> with the FTPS protocol, Zorp compares the server's certificate to its hostname. The subject_alt_name parameter (or the Common Name parameter if the subject_alt_name parameter is empty) of the server's certificate must contain the hostname or the IP address (as resolved from the Zorp host) of the server (e.g., <parameter>ftp.example.com</parameter>).</para>
	            <para>Alternatively, the Common Name or the <parameter>subject_alt_name</parameter> parameter can contain a generic hostname, e.g., <parameter>*.example.com</parameter>.</para>
	            <para>Note that if the Common Name of the certificate contains a generic hostname, do not specify a specific hostname or an IP address in the <parameter>subject_alt_name parameter</parameter>.</para>
	        </warning>
	        <note>
	            <itemizedlist>
	                <listitem>
	                    <para>The Zorp Ftp proxy does not support the following FTPS-related commands: <parameter>REIN, CCC, CDC</parameter>.</para>
	                </listitem>
	                <listitem>
	                   <para>STARTTLS is supported in nontransparent scenarios as well.</para>
	                </listitem>
	            </itemizedlist>
	        </note>
	        <example id="example_ftps">
	            <title>Configuring FTPS support</title>
                    <para>This example is a standard FtpProxy with FTPS support enabled.</para>
                   <literallayout>
class FtpsProxy(FtpProxy):
	def config(self):
		self.ssl.client_connection_security = SSL_ACCEPT_STARTTLS
		self.ssl.server_connection_security = SSL_FORWARD_STARTTLS
                   </literallayout>
                </example>
	    </section>
      </section>
      <section id="ftp_stacking">
      <title>Stacking</title>
      <para>
      The available stacking modes for this proxy module are listed in the following table. For additional information on stacking, see <xref linkend="proxy_stacking"/>.
      </para>
      <inline type="actiontuple" target="action.ftp.stk"/>
      </section>
      <section id="ftp_inband_authentication">
          <title>Configuring inband authentication</title>
          <para>Starting with Zorp 3.3FR1, the Ftp proxy supports <link linkend="python.Auth.InbandAuthentication">inband authentication</link> as well to use the built-in authentication method of the FTP and FTPS protocols to authenticate the client. The authentication itself is performed by the ZAS backend configured for the service.</para>
          <para>If the client uses different usernames on ZAS and the remote server (e.g., he uses his own username to authenticate to ZAS, but anonymous on the target FTP server), the client must specify the usernames and passwords in the following format:</para>
          <para>Username:</para>
          <synopsis>&lt;ftp user&gt;@&lt;proxy user&gt;@&lt;remote site&gt;[:&lt;port&gt;]</synopsis>
          <para>Password:</para>
          <synopsis>&lt;ftp password&gt;@&lt;proxy password&gt;</synopsis>
          <para>Alternatively, all the above information can be specified as the username:</para>
          <synopsis>&lt;ftp user&gt;@&lt;proxy user&gt;@&lt;remote site&gt;[:&lt;port&gt;]:&lt;ftp password&gt;@&lt;proxy password&gt;</synopsis>
          <warning>
	            <!-- Copied to configuring-ftps as well -->
	            <para>When using <link linkend="python.Router.InbandRouter">inband routing</link> with the FTPS protocol, Zorp compares the server's certificate to its hostname. The subject_alt_name parameter (or the Common Name parameter if the subject_alt_name parameter is empty) of the server's certificate must contain the hostname or the IP address (as resolved from the Zorp host) of the server (e.g., <parameter>ftp.example.com</parameter>).</para>
	            <para>Alternatively, the Common Name or the <parameter>subject_alt_name</parameter> parameter can contain a generic hostname, e.g., <parameter>*.example.com</parameter>.</para>
	            <para>Note that if the Common Name of the certificate contains a generic hostname, do not specify a specific hostname or an IP address in the <parameter>subject_alt_name parameter</parameter>.</para>
	        </warning>
      </section>
  </section>
  <section id="ftp_standards">
    <title>Related standards</title>
      <para>
        <itemizedlist>
          <listitem>
            <para>
              The File Transfer Protocol is described in RFC 959.
            </para>
          </listitem>
          <listitem>
            <para>
              FTP Security Extensions including the FTPS protocol and securing FTP with TLS are described in RFC 2228 and RFC 4217.
            </para>
          </listitem>
        </itemizedlist>
      </para>
  </section>
</description>
<metainfo>
  <enums>
    <enum maturity="stable" id="enum.ftp.data">
      <description>
        Data flow control hashes.
      </description>
      <item><name>FTP_DATA_KEEP</name></item>
      <item><name>FTP_DATA_PASSIVE</name></item>
      <item><name>FTP_DATA_ACTIVE</name></item>
    </enum>
    <enum maturity="stable" id="enum.ftp.req">
      <description>
        Ftp proxyrequest control hashes.
      </description>
      <item><name>FTP_REQ_ACCEPT</name></item>
      <item><name>FTP_REQ_REJECT</name></item>
      <item><name>FTP_REQ_ABORT</name></item>
      <item><name>FTP_REQ_POLICY</name></item>
    </enum>
    <enum maturity="stable" id="enum.ftp.rsp">
      <description>
        Ftp proxy response control hashes.
      </description>
      <item><name>FTP_RSP_ACCEPT</name></item>
      <item><name>FTP_RSP_REJECT</name></item>
      <item><name>FTP_RSP_ABORT</name></item>
      <item><name>FTP_RSP_POLICY</name></item>
    </enum>
    <enum internal="yes" id="enum.ftp.active">
      <description>
        Ftp proxy data port controll hashes.
      </description>
      <item><name>FTP_ACTIVE_MINUSONE</name></item>
      <item><name>FTP_ACTIVE_TWENTY</name></item>
      <item><name>FTP_ACTIVE_RANDOM</name></item>
    </enum>
    <enum maturity="stable" id="enum.ftp.stk">
      <description>
	Stacking policy.
      </description>
      <item><name>FTP_STK_DATA</name></item>
      <item><name>FTP_STK_NONE</name></item>
    </enum>
    <enum maturity="stable" id="enum.ftp.feat">
      <description>
        Ftp feature control hash settings.
      </description>
      <item><name>FTP_FEATURE_ACCEPT</name></item>
      <item><name>FTP_FEATURE_DROP</name></item>
      <item><name>FTP_FEATURE_INSERT</name></item>
    </enum>
  </enums>
  <constants>
    <constantgroup maturity="stable" id="const.ftp.log">
      <description>
        Ftp logging types, printed in to log messages
      </description>
      <item><name>FTP_DEBUG</name><value>"ftp.debug"</value></item>
      <item><name>FTP_ERROR</name><value>"ftp.error"</value></item>
      <item><name>FTP_POLICY</name><value>"ftp.policy"</value></item>
    </constantgroup>
  </constants>
  <actiontuples>
    <actiontuple maturity="stable" id="action.ftp.req" action_enum="enum.ftp.req">
      <description>
	Action codes for commands in FTP
      </description>
      <tuple action="FTP_REQ_ACCEPT">
	<args/>
	<description>
	  Allow the request to pass.
	</description>
      </tuple>
      <tuple action="FTP_REQ_REJECT">
	<args>
          <string/>
        </args>
	<description>
	  Reject the request with the error message specified in the
	  second optional parameter.
	</description>
      </tuple>
      <tuple action="FTP_REQ_POLICY">
	<args>METHOD</args>
	<description>
	  Call the function specified to make a decision about the event. The function receives two parameters: 'self', and 'command'. See <xref linkend="proxy_policies"/> for details.
	</description>
      </tuple>
      <tuple action="FTP_REQ_ABORT">
	<args/>
	<description>
	  Terminate the connection.
	</description>
       </tuple>
    </actiontuple>  
    <actiontuple maturity="stable" id="action.ftp.rsp" action_enum="enum.ftp.rsp">
      <description>
	Action codes for responses in FTP
      </description>
      <tuple action="FTP_RSP_ACCEPT">
	<args/>
	<description>
	  Allow the response to pass.
	</description>
      </tuple>
      <tuple action="FTP_RSP_REJECT">
	<args>
          <string/>
        </args>
	<description>
	  Modify the response to a general failure with error message
	  specified in the optional second parameter.
	</description>
      </tuple>
      <tuple action="FTP_RSP_POLICY">
	<args>METHOD</args>
	<description>
	  Call the function specified to make a decision about the event. The function receives three parameters:
	  'self', 'command', and 'answer'.
	  See <xref linkend="proxy_policies"/> for details.
	</description>
      </tuple>
      <tuple action="FTP_RSP_ABORT">
	<args/>
	<description>
	  Terminate the connection.
	</description>
      </tuple>
    </actiontuple>
    <actiontuple maturity="stable" id="action.ftp.stk" action_enum="enum.ftp.stk">
      <description>
	Stacking policy.
      </description>
      <tuple action="FTP_STK_DATA">
	<args>
	  <link id="action.zorp.stack"/>
        </args>
	<description>Pass the data to the stacked proxy or program.</description>
      </tuple>
      <tuple action="FTP_STK_NONE">
	<args/>
	<description>No proxy stacked.</description>
      </tuple>
    </actiontuple>
    <actiontuple maturity="stable" id="action.ftp.feat" action_enum="enum.ftp.feat">
      <description>
	Policy about enabling FTP features.
      </description>
      <tuple action="FTP_FEATURE_ACCEPT">
	<args/>
	<description>Forward the availability of the feature from the server to the client.</description>
      </tuple>
      <tuple action="FTP_FEATURE_DROP">
	<args/>
	<description>Remove the feature from the feature list sent by the server.</description>
      </tuple>
      <tuple action="FTP_FEATURE_INSERT">
	<args/>
	<description>Add the feature into the list of available features.</description>
      </tuple>
    </actiontuple>
  </actiontuples>
</metainfo></module>
"""

from Zorp import *
from Plug import PlugProxy
from Proxy import Proxy, proxyLog
from SockAddr import SockAddrInet, SockAddrInetRange
from Session import StackedSession
from Stream import Stream

FTP_DATA_KEEP    = 0
FTP_DATA_PASSIVE = 1
FTP_DATA_ACTIVE  = 2

FTP_REQ_ACCEPT = 1
FTP_REQ_REJECT = 3
FTP_REQ_ABORT  = 4
FTP_REQ_POLICY = 6

FTP_RSP_ACCEPT = 1
FTP_RSP_REJECT = 3
FTP_RSP_ABORT  = 4
FTP_RSP_POLICY = 6

FTP_DEBUG  = "ftp.debug"
FTP_ERROR  = "ftp.error"
FTP_POLICY = "ftp.policy"

FTP_ACTIVE_MINUSONE = 0
FTP_ACTIVE_TWENTY   = 1
FTP_ACTIVE_RANDOM   = 2

FTP_STK_NONE   = 1
FTP_STK_DATA   = 2
FTP_STK_POLICY = 6

FTP_FEATURE_ACCEPT = 1
FTP_FEATURE_DROP   = 2
FTP_FEATURE_INSERT = 3

class ParseInbandAuthError(Exception):
        """<class internal="yes"/>"""
	pass

class AbstractFtpProxy(Proxy):
	"""<class maturity="stable" abstract="yes">
        <summary>
          Class encapsulating the abstract FTP proxy.
        </summary>
        <description>
          <para>
            This proxy implements the FTP protocol as specified in RFC 959. All traffic and commands are denied by default. Consequently, either customized Ftp proxy classes derived from the abstract class should be used, or one of the predefined classes (e.g.: <link linkend="python.Ftp.FtpProxy">FtpProxy</link>, <link linkend="python.Ftp.FtpProxyRO">FtpProxyRO</link>, etc.).
          </para>
        </description>
        <metainfo>
          <attributes>
            <attribute maturity="stable">
              <name>request_stack</name>
              <type>
                <hash>
                  <key>
                    <string/>
                  </key>
                  <value>
                    <link id="action.ftp.stk"/>
                  </value>
                </hash>
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
                Hash containing the stacking policy for the FTP commands. The hash
                is indexed by the FTP command (e.g. RETR, STOR). See also <xref linkend="proxy_stacking"/>.
              </description>
            </attribute>
            <attribute maturity="stable">
              <name>data_port_min</name>
              <type>
                <integer/>
              </type>
              <default>40000</default>
              <conftime>
                <read/>
                <write/>
              </conftime>
              <runtime>
                <read/>
              </runtime>
              <description>
                On the proxy side, ports equal to or above the value of <parameter>data_port_min</parameter> can be allocated as the data channel.
              </description>
            </attribute>
            <attribute maturity="stable">
              <name>data_port_max</name>
              <type>
                <integer/>
              </type>
              <default>41000</default>
              <conftime>
                <read/>
                <write/>
              </conftime>
              <runtime>
                <read/>
              </runtime>
              <description>
                On the proxy side, ports equal to or below the value of <parameter>data_port_max</parameter> can be allocated as the data channel.
              </description>
            </attribute>
            <attribute maturity="stable">
              <name>data_mode</name>
              <type>
                <link id="enum.ftp.data"/>
              </type>
              <default>FTP_DATA_KEEP</default>
              <conftime>
                <read/>
                <write/>
              </conftime>
              <runtime>
                <read/>
              </runtime>
              <description>
                The type of the FTP connection on the server side can be manipulated: leave it as the client requested (FTP_DATA_KEEP), or force passive (FTP_DATA_PASSIVE) or active (FTP_DATA_ACTIVE) connection.
              </description>
            </attribute>
            <attribute maturity="stable">
              <name>masq_address_client</name>
              <type>
                <string/>
              </type>
              <default>""</default>
              <conftime>
                <read/>
                <write/>
              </conftime>
              <runtime>
                <read/>
              </runtime>
              <description>
                IP address of the firewall appearing on the client side. If its value is set, Zorp sends this IP regardless of its true IP (where it is binded). This attribute may be used when network address translation is performed before Zorp.
              </description>
            </attribute>
            <attribute maturity="stable">
              <name>masq_address_server</name>
              <type>
                <string/>
              </type>
              <default>""</default>
              <conftime>
                <read/>
                <write/>
              </conftime>
              <runtime>
                <read/>
              </runtime>
              <description>
                IP address of the firewall appearing on the server side. If its value is set, Zorp sends this IP regardless of its true IP (where it is binded). This attribute may be used when network address translation is performed before Zorp.
              </description>
            </attribute>
            <attribute maturity="stable">
              <name>max_line_length</name>
              <type>
                <integer/>
              </type>
              <default>255</default>
              <conftime>
                <read/>
                <write/>
              </conftime>
              <runtime>
                <read/>
              </runtime>
              <description>
                Maximum length of a line that the proxy is allowed to transfer. Requests/responses exceeding this limit are dropped.
             </description>
            </attribute>
            <attribute maturity="stable">
              <name>max_username_length</name>
              <type>
                <integer/>
              </type>
              <default>32</default>
              <conftime>
                <read/>
                <write/>
              </conftime>
              <runtime>
                <read/>
              </runtime>
              <description>
                Maximum length of the username.
              </description>
            </attribute>
            <attribute maturity="stable">
              <name>max_password_length</name>
              <type>
                <integer/>
              </type>
              <default>64</default>
              <conftime>
                <read/>
                <write/>
              </conftime>
              <runtime>
                <read/>
              </runtime>
              <description>
                Maximum length of the password.
              </description>
            </attribute>
            <attribute maturity="stable">
              <name>max_hostname_length</name>
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
                Maximum length of hostname. Used only in non-transparent mode.
              </description>
            </attribute>
            <attribute maturity="stable">
              <name>password</name>
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
                The password to be sent to the server.
              </description>
            </attribute>
            <attribute maturity="stable">
              <name>permit_unknown_command</name>
              <type>
                <boolean/>
              </type>
              <default>FALSE</default>
              <conftime>
                <read/>
                <write/>
              </conftime>
              <runtime>
                <read/>
              </runtime>
              <description>
                Enable the transmission of unknown commands.
              </description>
            </attribute>
            <attribute maturity="stable">
              <name>permit_empty_command</name>
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
                Enable transmission of lines without commands.
              </description>
            </attribute>
            <attribute maturity="stable">
              <name>request</name>
              <type>
                <hash>
                  <key>
                    <string/>
                  </key>
                  <value>
                    <link id="enum.ftp.req"/>
                  </value>
                </hash>
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
                Normative policy hash for FTP requests indexed by command name (e.g.: "USER", "PWD" etc.).
                See also <xref linkend="proxy_policies"/>.
              </description>
            </attribute>
            <attribute maturity="stable">
              <name>response</name>
              <type>
                <hash>
                  <key>
                    <tuple>
                      <string/>
                      <string/>
                    </tuple>
                  </key>
                  <value>
                    <link id="enum.ftp.rsp"/>
                  </value>
                </hash>
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
                Normative policy hash for FTP responses indexed by command name and answer code
                (e.g.: "USER","331"; "PWD","200" etc.). See also <xref linkend="proxy_policies"/>.
              </description>
            </attribute>
            <attribute maturity="stable">
              <name>request_command</name>
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
                When a request is evaluated on the policy level, this variable contains the
                requested command.
              </description>
            </attribute>
            <attribute maturity="stable">
              <name>request_parameter</name>
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
                When a request is evaluated on the policy level, this variable contains
                the parameters of the requested command.
              </description>
            </attribute>
            <attribute maturity="stable">
              <name>response_status</name>
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
                When a response is evaluated on the policy level, this variable contains the answer code.
              </description>
            </attribute>
            <attribute maturity="stable">
              <name>response_parameter</name>
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
                When a response is evaluated on the policy level, this variable contains answer parameters.
              </description>
            </attribute>
            <attribute maturity="stable">
              <name>response_strip_msg</name>
              <type>
                <boolean/>
              </type>
              <default>FALSE</default>
              <conftime>
                <read/>
                <write/>
              </conftime>
              <runtime>
                <read/>
              </runtime>
              <description>
                Strip the response message and only send the response code.
              </description>
            </attribute>
            <attribute maturity="stable">
              <name>target_port_range</name>
              <type>
                <string/>
              </type>
              <default>21</default>
              <conftime>
                <read/>
                <write/>
              </conftime>
              <runtime>
                <read/>
              </runtime>
              <description>
                The port where the client can connect through a
                non-transparent FtpProxy.
              </description>
            </attribute>
            <attribute maturity="stable">
              <name>timeout</name>
              <type>
                <integer/>
              </type>
              <default>300000</default>
              <conftime>
                <read/>
                <write/>
              </conftime>
              <runtime>
                <read/>
              </runtime>
              <description>
                General I/O timeout in milliseconds. When there is no specific
                timeout for a given operation, this value is used.
              </description>
            </attribute>
            <attribute maturity="stable">
              <name>buffer_size</name>
              <type>
                <integer/>
              </type>
              <default>4096</default>
              <conftime>
                <read/>
                <write/>
              </conftime>
              <runtime>
                <read/>
              </runtime>
              <description>
                Buffer size for data transfer in bytes.
              </description>
            </attribute>
            <attribute maturity="stable">
              <name>transparent_mode</name>
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
                Specifies if the proxy works in transparent (TRUE)
                or non-transparent (FALSE) mode.
              </description>
            </attribute>
            <attribute maturity="stable">
              <name>username</name>
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
                The username authenticated to the server.
              </description>
            </attribute>
            <attribute maturity="stable">
              <name>valid_chars_username</name>
              <type>
                <string/>
              </type>
              <default>a-zA-Z0-9._@</default>
              <conftime>
                <read/>
                <write/>
              </conftime>
              <runtime>
                <read/>
              </runtime>
              <description>
                List of the characters accepted in usernames.
              </description>
            </attribute>
            <attribute maturity="stable">
              <name>active_connection_mode</name>
              <type>
                <link id="enum.ftp.active"/>
              </type>
              <default>FTP_ACTIVE_MINUSONE</default>
              <conftime>
                <read/>
                <write/>
              </conftime>
              <runtime>
                <read/>
              </runtime>
              <description>
                In active mode the server connects the client. By default this must be from Command Channel port minus one (FTP_ACTIVE_MINUSONE). Alternatively, connection can also be performed either from port number 20 (FTP_ACTIVE_TWENTY) or from a random port (FTP_ACTIVE_RANDOM).  
              </description>
            </attribute>
            <attribute>
              <name>strict_port_checking</name>
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
                <write/>
              </runtime>
              <description>
                 If enabled Zorp will strictly check the foreign
                 port: in active mode the server must be connected on port 20, while in any other situation the foreign port must be above 1023.
              </description>
            </attribute>
            <attribute>
              <name>permit_client_bounce_attack</name>
              <type>
                <boolean/>
              </type>
              <default>FALSE</default>
              <conftime>
                <read/>
                <write/>
              </conftime>
              <runtime>
                <read/>
                <write/>
              </runtime>
              <description>
                If enabled the IP addresses of data channels will not need
                to match with the IP address of the control channel,
                permitting the use of FXP while increasing the security
                risks.
              </description>
            </attribute>
            <attribute>
              <name>permit_server_bounce_attack</name>
              <type>
                <boolean/>
              </type>
              <default>FALSE</default>
              <conftime>
                <read/>
                <write/>
              </conftime>
              <runtime>
                <read/>
                <write/>
              </runtime>
              <description>
                If enabled the IP addresses of data channels will not need
                to match with the IP address of the control channel,
                permitting the use of FXP while increasing the security
                risks.
              </description>
            </attribute>
            <attribute maturity="stable">
              <name>max_continuous_line</name>
              <type>
                <integer/>
              </type>
              <default>100</default>
              <conftime>
                <read/>
                <write/>
              </conftime>
              <runtime>
                <read/>
              </runtime>
              <description>
                Maximum number of answer lines for a command.
              </description>
            </attribute>
            <attribute maturity="stable">
              <name>hostname</name>
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
                The hostname of the FTP server to connect to, when inband routing is used.
              </description>
            </attribute>
            <attribute maturity="stable">
              <name>hostport</name>
              <type>
                <integer/>
              </type>
              <default/>
              <conftime/>
              <runtime>
                <read/>
                <write/>
              </runtime>
              <description>
                The port of the FTP server to connect to, when inband routing is used.
              </description>
            </attribute>
            <attribute maturity="stable">
              <name>proxy_username</name>
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
                The username to be used for proxy authentication given by the user, when inband authentication is used.
              </description>
            </attribute>
            <attribute maturity="stable">
              <name>proxy_password</name>
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
                The password to be used for proxy authentication given by the user, when inband authentication is used.
              </description>
            </attribute>
            <attribute maturity="stable">
              <name>feature</name>
              <type>
                <link id="enum.ftp.feat"/>
              </type>
              <default/>
              <conftime>
                <read/>
                <write/>
              </conftime>
              <runtime>
                <read/>
              </runtime>
              <description>
                A policy hash for FTP features, indexed by the name of the feature.
              </description>
            </attribute>
            <attribute internal="yes">
              <name>auth</name>
              <type>
                <FIXME_OBJECT/>
              </type>
              <default>n/a</default>
              <conftime>
                <write/>
              </conftime>
              <runtime>
                <read/>
              </runtime>
              <description>
              </description>
            </attribute>
            <attribute maturity="stable">
              <name>features</name>
              <type>
                <hash>
                  <key>
                    <string/>
                  </key>
                  <value>
                    <link id="action.ftp.feat"/>
                  </value>
                </hash>
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
                Hash containing the filtering policy for FTP features.
              </description>
            </attribute>
          </attributes></metainfo>
        </class>
        """
	name = "ftp"
	auth_inband_supported = TRUE

	def __init__(self, session):
		"""<method internal="yes">
                  <summary>
                    Constructor to initialize an FtpProxy instance
                  </summary>
                  <description>
                    <para>
                      This constructor initializes an FtpProxy instance by
                      calling the inherited __init__ constructor
                      with appropriate parameters, and setting up
                      local attributes based on arguments.
                    </para>
                  </description>
                  <metainfo>
                    <arguments>
                      <argument maturity="stable">
                        <name>session</name>
                        <type>SESSION</type>
                        <description>
                          this session object
                        </description>
                      </argument>
                    </arguments>
                  </metainfo>
                </method>
                """
		self.restrict_client_connect = TRUE
		self.restrict_server_connect = FALSE
		self.data_port_min = 40000
		self.data_port_max = 41000
		self.request_stack = {}
		self.strict_port_checking = TRUE
		self.permit_client_bounce_attack = FALSE
		self.permit_server_bounce_attack = FALSE
		Proxy.__init__(self, session)

	def __destroy__(self):
		"""
                <method internal="yes">
                </method>
                """
		Proxy.__destroy__(self)
		try:
			del self.session.ftp_data_stop
		except AttributeError:
			pass
	
	def bounceCheck(self, remote, side, connect):
		"""<method maturity="stable" internal="yes">
                  <summary>
                    Bounce check method for ftp.
                  </summary>
                  <description>
                    <para>
                      This function is called by the proxy to decide whether an incoming connection
                      is mounting a bounce attack on this FTP service. The current behavior
                      is to only allow data connections from the peers and not from anyone else, but this
                      can be controlled by the permit_bounce_attack attribute.
                    </para>
                  </description>
                  <metainfo>
                    <arguments/>
                  </metainfo>
                </method>
                """
		if side == 0:
			ret = (remote.ip == self.session.client_address.ip) or self.permit_client_bounce_attack
			if ret and self.strict_port_checking:
				if remote.port < 1024:
					## LOG ##
					# This message indicates that the remote port is bellow 1024 and due to the
					# violation Zorp is closing connection.
					##
					proxyLog(self, FTP_POLICY, 3, "Client foreign port below 1024; port='%d'" % remote.port)
					ret = FALSE
		elif side == 1:
			ret = (remote.ip == self.session.server_address.ip) or self.permit_server_bounce_attack
			if ret and self.strict_port_checking:
				if connect:
					if remote.port < 1024:
						## LOG ##
						# This message indicates that the remote port is bellow 1024 and due to the
						# violation Zorp is closing connection.
						##
						proxyLog(self, FTP_POLICY, 3, "Server foreign port below 1024 in passive mode; port='%d'" % remote.port)
						ret = FALSE
				else:
					if remote.port != 20 and remote.port != self.session.server_address.port - 1:
						## LOG ##
						# This message indicates that the server's remote port is not control_port-1 or 20 and due to the
						# violation Zorp is closing connection.
						##
						proxyLog(self, FTP_POLICY, 3, "Server foreign port is not good in active mode; port='%d', control_port='%d'" % (remote.port, self.session.server_address.port))
						ret = FALSE
		else:
			## LOG ##
			# This message indicates an internal error, please contact the BalaBit QA team.
			##
			proxyLog(self, FTP_POLICY, 3, "Unknown side when calling bounceCheck; side='%d'" % side)
			ret = FALSE

		return ret
		

	def loadAnswers(self):
		"""<method internal="yes">
                  <summary>
                    This function can be called by derived classes to initialize internal hashtables.
                  </summary>
                  <description>
                    This function fills in the self.answers hash so that commonly used request/answer combinations are accepted.
                  </description>
                  <metainfo>
                    <arguments/>
                  </metainfo>
                </method>
                """
		self.response["*", "421"]    = (FTP_RSP_ABORT, "421 Logoff")
		self.response["*", "500"]    = (FTP_RSP_ACCEPT)

		self.response["Null", "120"] = (FTP_RSP_ACCEPT)
		self.response["Null", "220"] = (FTP_RSP_ACCEPT)

		self.response["ABOR", "225"] = (FTP_RSP_ACCEPT)
		self.response["ABOR", "226"] = (FTP_RSP_ACCEPT)
		self.response["ABOR", "501"] = (FTP_RSP_ACCEPT)
		self.response["ABOR", "502"] = (FTP_RSP_ACCEPT)

		self.response["ACCT", "202"] = (FTP_RSP_ACCEPT)
		self.response["ACCT", "230"] = (FTP_RSP_ACCEPT)
		self.response["ACCT", "501"] = (FTP_RSP_ACCEPT)
		self.response["ACCT", "503"] = (FTP_RSP_ACCEPT)
		self.response["ACCT", "530"] = (FTP_RSP_ACCEPT)

		self.response["ALLO", "200"] = (FTP_RSP_ACCEPT)
		self.response["ALLO", "202"] = (FTP_RSP_ACCEPT)
		self.response["ALLO", "501"] = (FTP_RSP_ACCEPT)
		self.response["ALLO", "504"] = (FTP_RSP_ACCEPT)
		self.response["ALLO", "530"] = (FTP_RSP_ACCEPT)

		self.response["APPE", "110"] = (FTP_RSP_ACCEPT)
		self.response["APPE", "125"] = (FTP_RSP_ACCEPT)
		self.response["APPE", "150"] = (FTP_RSP_ACCEPT)
		self.response["APPE", "226"] = (FTP_RSP_ACCEPT)
		self.response["APPE", "250"] = (FTP_RSP_ACCEPT)
		self.response["APPE", "425"] = (FTP_RSP_ACCEPT)
		self.response["APPE", "426"] = (FTP_RSP_ACCEPT)
		self.response["APPE", "450"] = (FTP_RSP_ACCEPT)
		self.response["APPE", "451"] = (FTP_RSP_ACCEPT)
		self.response["APPE", "452"] = (FTP_RSP_ACCEPT)
		self.response["APPE", "501"] = (FTP_RSP_ACCEPT)
		self.response["APPE", "502"] = (FTP_RSP_ACCEPT)
		self.response["APPE", "530"] = (FTP_RSP_ACCEPT)
		self.response["APPE", "551"] = (FTP_RSP_ACCEPT)
		self.response["APPE", "552"] = (FTP_RSP_ACCEPT)
		self.response["APPE", "532"] = (FTP_RSP_ACCEPT)
		self.response["APPE", "534"] = (FTP_RSP_ACCEPT)
		self.response["APPE", "535"] = (FTP_RSP_ACCEPT)
		self.response["APPE", "550"] = (FTP_RSP_ACCEPT)
		self.response["APPE", "553"] = (FTP_RSP_ACCEPT)

		self.response["AUTH", "234"] = (FTP_RSP_ACCEPT)
		self.response["AUTH", "334"] = (FTP_RSP_ACCEPT)
		self.response["AUTH", "431"] = (FTP_RSP_ACCEPT)
		self.response["AUTH", "501"] = (FTP_RSP_ACCEPT)
		self.response["AUTH", "502"] = (FTP_RSP_ACCEPT)
		self.response["AUTH", "504"] = (FTP_RSP_ACCEPT)
		self.response["AUTH", "534"] = (FTP_RSP_ACCEPT)

		self.response["CDUP", "200"] = (FTP_RSP_ACCEPT)
		self.response["CDUP", "250"] = (FTP_RSP_ACCEPT)
		self.response["CDUP", "501"] = (FTP_RSP_ACCEPT)
		self.response["CDUP", "502"] = (FTP_RSP_ACCEPT)
		self.response["CDUP", "530"] = (FTP_RSP_ACCEPT)
		self.response["CDUP", "550"] = (FTP_RSP_ACCEPT)

		self.response["CWD", "250"]  = (FTP_RSP_ACCEPT)
		self.response["CWD", "501"]  = (FTP_RSP_ACCEPT)
		self.response["CWD", "502"]  = (FTP_RSP_ACCEPT)
		self.response["CWD", "530"]  = (FTP_RSP_ACCEPT)
		self.response["CWD", "550"]  = (FTP_RSP_ACCEPT)

		self.response["DELE", "250"] = (FTP_RSP_ACCEPT)
		self.response["DELE", "450"] = (FTP_RSP_ACCEPT)
		self.response["DELE", "550"] = (FTP_RSP_ACCEPT)
		self.response["DELE", "501"] = (FTP_RSP_ACCEPT)
		self.response["DELE", "502"] = (FTP_RSP_ACCEPT)
		self.response["DELE", "530"] = (FTP_RSP_ACCEPT)

		self.response["EPRT", "200"] = (FTP_RSP_ACCEPT)
		self.response["EPRT", "501"] = (FTP_RSP_ACCEPT)
		self.response["EPRT", "522"] = (FTP_RSP_ACCEPT)

		self.response["EPSV", "229"] = (FTP_RSP_ACCEPT)
		self.response["EPSV", "501"] = (FTP_RSP_ACCEPT)

		self.response["FEAT", "221"] = (FTP_RSP_ACCEPT)
		self.response["FEAT", "502"] = (FTP_RSP_ACCEPT)

		self.response["HELP", "211"] = (FTP_RSP_ACCEPT)
		self.response["HELP", "214"] = (FTP_RSP_ACCEPT)
		self.response["HELP", "501"] = (FTP_RSP_ACCEPT)
		self.response["HELP", "502"] = (FTP_RSP_ACCEPT)

		self.response["LIST", "125"] = (FTP_RSP_ACCEPT)
		self.response["LIST", "150"] = (FTP_RSP_ACCEPT)
		self.response["LIST", "226"] = (FTP_RSP_ACCEPT)
		self.response["LIST", "250"] = (FTP_RSP_ACCEPT)
		self.response["LIST", "425"] = (FTP_RSP_ACCEPT)
		self.response["LIST", "426"] = (FTP_RSP_ACCEPT)
		self.response["LIST", "451"] = (FTP_RSP_ACCEPT)
		self.response["LIST", "450"] = (FTP_RSP_ACCEPT)
		self.response["LIST", "501"] = (FTP_RSP_ACCEPT)
		self.response["LIST", "502"] = (FTP_RSP_ACCEPT)
		self.response["LIST", "530"] = (FTP_RSP_ACCEPT)
		self.response["LIST", "534"] = (FTP_RSP_ACCEPT)
		self.response["LIST", "535"] = (FTP_RSP_ACCEPT)

		self.response["MDTM", "213"] = (FTP_RSP_ACCEPT)
		self.response["MDTM", "501"] = (FTP_RSP_ACCEPT) #Hmmm.
		self.response["MDTM", "550"] = (FTP_RSP_ACCEPT)

		self.response["MKD", "257"]  = (FTP_RSP_ACCEPT)
		self.response["MKD", "501"]  = (FTP_RSP_ACCEPT)
		self.response["MKD", "502"]  = (FTP_RSP_ACCEPT)
		self.response["MKD", "530"]  = (FTP_RSP_ACCEPT)
		self.response["MKD", "550"]  = (FTP_RSP_ACCEPT)

		self.response["MLST", "250"] = (FTP_RSP_ACCEPT)
		self.response["MLST", "425"] = (FTP_RSP_ACCEPT)
		self.response["MLST", "426"] = (FTP_RSP_ACCEPT)
		self.response["MLST", "451"] = (FTP_RSP_ACCEPT)
		self.response["MLST", "450"] = (FTP_RSP_ACCEPT)
		self.response["MLST", "501"] = (FTP_RSP_ACCEPT)
		self.response["MLST", "502"] = (FTP_RSP_ACCEPT)
		self.response["MLST", "530"] = (FTP_RSP_ACCEPT)
		self.response["MLST", "534"] = (FTP_RSP_ACCEPT)
		self.response["MLST", "535"] = (FTP_RSP_ACCEPT)
		self.response["MLST", "550"]  = (FTP_RSP_ACCEPT)

		self.response["MLSD", "125"] = (FTP_RSP_ACCEPT)
		self.response["MLSD", "150"] = (FTP_RSP_ACCEPT)
		self.response["MLSD", "226"] = (FTP_RSP_ACCEPT)
		self.response["MLSD", "250"] = (FTP_RSP_ACCEPT)
		self.response["MLSD", "425"] = (FTP_RSP_ACCEPT)
		self.response["MLSD", "426"] = (FTP_RSP_ACCEPT)
		self.response["MLSD", "451"] = (FTP_RSP_ACCEPT)
		self.response["MLSD", "450"] = (FTP_RSP_ACCEPT)
		self.response["MLSD", "501"] = (FTP_RSP_ACCEPT)
		self.response["MLSD", "502"] = (FTP_RSP_ACCEPT)
		self.response["MLSD", "530"] = (FTP_RSP_ACCEPT)
		self.response["MLSD", "534"] = (FTP_RSP_ACCEPT)
		self.response["MLSD", "535"] = (FTP_RSP_ACCEPT)

		self.response["MODE", "200"] = (FTP_RSP_ACCEPT)
		self.response["MODE", "501"] = (FTP_RSP_ACCEPT)
		self.response["MODE", "504"] = (FTP_RSP_ACCEPT)
		self.response["MODE", "530"] = (FTP_RSP_ACCEPT)

		self.response["NLST", "125"] = (FTP_RSP_ACCEPT)
		self.response["NLST", "150"] = (FTP_RSP_ACCEPT)
		self.response["NLST", "226"] = (FTP_RSP_ACCEPT)
		self.response["NLST", "250"] = (FTP_RSP_ACCEPT)
		self.response["NLST", "425"] = (FTP_RSP_ACCEPT)
		self.response["NLST", "426"] = (FTP_RSP_ACCEPT)
		self.response["NLST", "450"] = (FTP_RSP_ACCEPT)
		self.response["NLST", "451"] = (FTP_RSP_ACCEPT)
		self.response["NLST", "501"] = (FTP_RSP_ACCEPT)
		self.response["NLST", "502"] = (FTP_RSP_ACCEPT)
		self.response["NLST", "530"] = (FTP_RSP_ACCEPT)
		self.response["NLST", "534"] = (FTP_RSP_ACCEPT)
		self.response["NLST", "535"] = (FTP_RSP_ACCEPT)
		self.response["NLST", "550"] = (FTP_RSP_ACCEPT)

		self.response["NOOP", "200"] = (FTP_RSP_ACCEPT)

		self.response["PASS", "202"] = (FTP_RSP_ACCEPT)
		self.response["PASS", "230"] = (FTP_RSP_ACCEPT)
		self.response["PASS", "332"] = (FTP_RSP_ACCEPT)
		self.response["PASS", "501"] = (FTP_RSP_ACCEPT)
		self.response["PASS", "503"] = (FTP_RSP_ACCEPT)
		self.response["PASS", "530"] = (FTP_RSP_ACCEPT)

		self.response["PASV", "227"] = (FTP_RSP_ACCEPT)
		self.response["PASV", "501"] = (FTP_RSP_ACCEPT)
		self.response["PASV", "502"] = (FTP_RSP_ACCEPT)
		self.response["PASV", "530"] = (FTP_RSP_ACCEPT)

		self.response["PBSZ", "200"] = (FTP_RSP_ACCEPT)
		self.response["PBSZ", "501"] = (FTP_RSP_ACCEPT)
		self.response["PBSZ", "503"] = (FTP_RSP_ACCEPT)
		self.response["PBSZ", "530"] = (FTP_RSP_ACCEPT)

		self.response["PORT", "200"] = (FTP_RSP_ACCEPT)
		self.response["PORT", "501"] = (FTP_RSP_ACCEPT)
		self.response["PORT", "530"] = (FTP_RSP_ACCEPT)

		self.response["PROT", "200"] = (FTP_RSP_ACCEPT)
		self.response["PROT", "431"] = (FTP_RSP_ACCEPT)
		self.response["PROT", "501"] = (FTP_RSP_ACCEPT)
		self.response["PROT", "503"] = (FTP_RSP_ACCEPT)
		self.response["PROT", "504"] = (FTP_RSP_ACCEPT)
		self.response["PROT", "530"] = (FTP_RSP_ACCEPT)
		self.response["PROT", "534"] = (FTP_RSP_ACCEPT)
		self.response["PROT", "536"] = (FTP_RSP_ACCEPT)

		self.response["PWD", "257"]  = (FTP_RSP_ACCEPT)
		self.response["PWD", "501"]  = (FTP_RSP_ACCEPT)
		self.response["PWD", "502"]  = (FTP_RSP_ACCEPT)
		self.response["PWD", "550"]  = (FTP_RSP_ACCEPT)

		self.response["QUIT", "221"] = (FTP_RSP_ACCEPT)

		self.response["REIN", "120"] = (FTP_RSP_ACCEPT)
		self.response["REIN", "220"] = (FTP_RSP_ACCEPT)
		self.response["REIN", "502"] = (FTP_RSP_ACCEPT)

		self.response["REST", "350"] = (FTP_RSP_ACCEPT)
		self.response["REST", "501"] = (FTP_RSP_ACCEPT)
		self.response["REST", "502"] = (FTP_RSP_ACCEPT)
		self.response["REST", "530"] = (FTP_RSP_ACCEPT)

		self.response["RETR", "110"] = (FTP_RSP_ACCEPT)
		self.response["RETR", "125"] = (FTP_RSP_ACCEPT)
		self.response["RETR", "150"] = (FTP_RSP_ACCEPT)
		self.response["RETR", "226"] = (FTP_RSP_ACCEPT)
		self.response["RETR", "250"] = (FTP_RSP_ACCEPT)
		self.response["RETR", "425"] = (FTP_RSP_ACCEPT)
		self.response["RETR", "426"] = (FTP_RSP_ACCEPT)
		self.response["RETR", "450"] = (FTP_RSP_ACCEPT)
		self.response["RETR", "451"] = (FTP_RSP_ACCEPT)
		self.response["RETR", "452"] = (FTP_RSP_ACCEPT)
		self.response["RETR", "501"] = (FTP_RSP_ACCEPT)
		self.response["RETR", "530"] = (FTP_RSP_ACCEPT)
		self.response["RETR", "532"] = (FTP_RSP_ACCEPT)
		self.response["RETR", "534"] = (FTP_RSP_ACCEPT)
		self.response["RETR", "535"] = (FTP_RSP_ACCEPT)
		self.response["RETR", "550"] = (FTP_RSP_ACCEPT)
		self.response["RETR", "553"] = (FTP_RSP_ACCEPT)

		self.response["RMD", "250"]  = (FTP_RSP_ACCEPT)
		self.response["RMD", "501"]  = (FTP_RSP_ACCEPT)
		self.response["RMD", "502"]  = (FTP_RSP_ACCEPT)
		self.response["RMD", "530"]  = (FTP_RSP_ACCEPT)
		self.response["RMD", "550"]  = (FTP_RSP_ACCEPT)

		self.response["RNFR", "350"] = (FTP_RSP_ACCEPT)
		self.response["RNFR", "450"] = (FTP_RSP_ACCEPT)
		self.response["RNFR", "501"] = (FTP_RSP_ACCEPT)
		self.response["RNFR", "502"] = (FTP_RSP_ACCEPT)
		self.response["RNFR", "530"] = (FTP_RSP_ACCEPT)
		self.response["RNFR", "550"] = (FTP_RSP_ACCEPT)

		self.response["RNTO", "250"] = (FTP_RSP_ACCEPT)
		self.response["RNTO", "501"] = (FTP_RSP_ACCEPT)
		self.response["RNTO", "502"] = (FTP_RSP_ACCEPT)
		self.response["RNTO", "530"] = (FTP_RSP_ACCEPT)
		self.response["RNTO", "532"] = (FTP_RSP_ACCEPT)
		self.response["RNTO", "553"] = (FTP_RSP_ACCEPT)

		self.response["SITE", "200"] = (FTP_RSP_ACCEPT)
		self.response["SITE", "202"] = (FTP_RSP_ACCEPT)
		self.response["SITE", "501"] = (FTP_RSP_ACCEPT)
		self.response["SITE", "530"] = (FTP_RSP_ACCEPT)

		self.response["SIZE", "213"] = (FTP_RSP_ACCEPT)
		self.response["SIZE", "550"] = (FTP_RSP_ACCEPT)

		self.response["SMNT", "202"] = (FTP_RSP_ACCEPT)
		self.response["SMNT", "250"] = (FTP_RSP_ACCEPT)
		self.response["SMNT", "501"] = (FTP_RSP_ACCEPT)
		self.response["SMNT", "502"] = (FTP_RSP_ACCEPT)
		self.response["SMNT", "530"] = (FTP_RSP_ACCEPT)
		self.response["SMNT", "550"] = (FTP_RSP_ACCEPT)

		self.response["STAT", "211"] = (FTP_RSP_ACCEPT)
		self.response["STAT", "212"] = (FTP_RSP_ACCEPT)
		self.response["STAT", "213"] = (FTP_RSP_ACCEPT)
		self.response["STAT", "450"] = (FTP_RSP_ACCEPT)
		self.response["STAT", "501"] = (FTP_RSP_ACCEPT)
		self.response["STAT", "502"] = (FTP_RSP_ACCEPT)
		self.response["STAT", "530"] = (FTP_RSP_ACCEPT)

		self.response["STOR", "110"] = (FTP_RSP_ACCEPT)
		self.response["STOR", "125"] = (FTP_RSP_ACCEPT)
		self.response["STOR", "150"] = (FTP_RSP_ACCEPT)
		self.response["STOR", "226"] = (FTP_RSP_ACCEPT)
		self.response["STOR", "250"] = (FTP_RSP_ACCEPT)
		self.response["STOR", "425"] = (FTP_RSP_ACCEPT)
		self.response["STOR", "426"] = (FTP_RSP_ACCEPT)
		self.response["STOR", "450"] = (FTP_RSP_ACCEPT)
		self.response["STOR", "451"] = (FTP_RSP_ACCEPT)
		self.response["STOR", "452"] = (FTP_RSP_ACCEPT)
		self.response["STOR", "501"] = (FTP_RSP_ACCEPT)
		self.response["STOR", "530"] = (FTP_RSP_ACCEPT)
		self.response["STOR", "532"] = (FTP_RSP_ACCEPT)
		self.response["STOR", "534"] = (FTP_RSP_ACCEPT)
		self.response["STOR", "535"] = (FTP_RSP_ACCEPT)
		self.response["STOR", "550"] = (FTP_RSP_ACCEPT)
		self.response["STOR", "551"] = (FTP_RSP_ACCEPT)
		self.response["STOR", "552"] = (FTP_RSP_ACCEPT)
		self.response["STOR", "553"] = (FTP_RSP_ACCEPT)

		self.response["STOU", "110"] = (FTP_RSP_ACCEPT)
		self.response["STOU", "125"] = (FTP_RSP_ACCEPT)
		self.response["STOU", "150"] = (FTP_RSP_ACCEPT)
		self.response["STOU", "226"] = (FTP_RSP_ACCEPT)
		self.response["STOU", "250"] = (FTP_RSP_ACCEPT)
		self.response["STOU", "425"] = (FTP_RSP_ACCEPT)
		self.response["STOU", "426"] = (FTP_RSP_ACCEPT)
		self.response["STOU", "450"] = (FTP_RSP_ACCEPT)
		self.response["STOU", "451"] = (FTP_RSP_ACCEPT)
		self.response["STOU", "452"] = (FTP_RSP_ACCEPT)
		self.response["STOU", "501"] = (FTP_RSP_ACCEPT)
		self.response["STOU", "530"] = (FTP_RSP_ACCEPT)
		self.response["STOU", "532"] = (FTP_RSP_ACCEPT)
		self.response["STOU", "534"] = (FTP_RSP_ACCEPT)
		self.response["STOU", "535"] = (FTP_RSP_ACCEPT)
		self.response["STOU", "551"] = (FTP_RSP_ACCEPT)
		self.response["STOU", "552"] = (FTP_RSP_ACCEPT)
		self.response["STOU", "553"] = (FTP_RSP_ACCEPT)

		self.response["STRU", "200"] = (FTP_RSP_ACCEPT)
		self.response["STRU", "501"] = (FTP_RSP_ACCEPT)
		self.response["STRU", "504"] = (FTP_RSP_ACCEPT)
		self.response["STRU", "530"] = (FTP_RSP_ACCEPT)

		self.response["SYST", "215"] = (FTP_RSP_ACCEPT)
		self.response["SYST", "501"] = (FTP_RSP_ACCEPT)
		self.response["SYST", "502"] = (FTP_RSP_ACCEPT)

		self.response["TYPE", "200"] = (FTP_RSP_ACCEPT)
		self.response["TYPE", "501"] = (FTP_RSP_ACCEPT)
		self.response["TYPE", "504"] = (FTP_RSP_ACCEPT)
		self.response["TYPE", "530"] = (FTP_RSP_ACCEPT)

		self.response["USER", "230"] = (FTP_RSP_ACCEPT)
		self.response["USER", "232"] = (FTP_RSP_ACCEPT)
		self.response["USER", "331"] = (FTP_RSP_ACCEPT)
		self.response["USER", "332"] = (FTP_RSP_ACCEPT)
		self.response["USER", "336"] = (FTP_RSP_ACCEPT)
		self.response["USER", "501"] = (FTP_RSP_ACCEPT)
		self.response["USER", "530"] = (FTP_RSP_ACCEPT)

	def loadMinimalCommands(self):
		"""<method internal="yes">
                  <summary>
                    This function enable some minimal command set
                  </summary>
                  <description>
                    <para>
                      This function loads a minimal set of commands, for various subclass
                    </para>
                  </description>
                  <metainfo>
                    <arguments/>
                  </metainfo>
                </method>
                """
		self.request["ABOR"] = (FTP_REQ_ACCEPT)
		self.request["ACCT"] = (FTP_REQ_ACCEPT)
		self.request["AUTH"] = (FTP_REQ_ACCEPT)
		self.request["CDUP"] = (FTP_REQ_ACCEPT)
		self.request["CWD"]  = (FTP_REQ_ACCEPT)
		self.request["EPRT"] = (FTP_REQ_ACCEPT)
		self.request["EPSV"] = (FTP_REQ_ACCEPT)
		self.request["FEAT"] = (FTP_REQ_ACCEPT)
		self.request["LIST"] = (FTP_REQ_ACCEPT)
		self.request["MODE"] = (FTP_REQ_ACCEPT)
		self.request["MDTM"] = (FTP_REQ_ACCEPT)
		self.request["MLST"] = (FTP_REQ_ACCEPT)
		self.request["MLSD"] = (FTP_REQ_ACCEPT)
		self.request["NLST"] = (FTP_REQ_ACCEPT)
		self.request["NOOP"] = (FTP_REQ_ACCEPT)
		self.request["PASV"] = (FTP_REQ_ACCEPT)
		self.request["PASS"] = (FTP_REQ_ACCEPT)
		self.request["PBSZ"] = (FTP_REQ_ACCEPT)
		self.request["PORT"] = (FTP_REQ_ACCEPT)
		self.request["PROT"] = (FTP_REQ_ACCEPT)
		self.request["PWD"]  = (FTP_REQ_ACCEPT)
		self.request["QUIT"] = (FTP_REQ_ACCEPT)
		self.request["REST"] = (FTP_REQ_ACCEPT)
		self.request["RETR"] = (FTP_REQ_ACCEPT)
		self.request["SIZE"] = (FTP_REQ_ACCEPT)
		self.request["STAT"] = (FTP_REQ_ACCEPT)
		self.request["STRU"] = (FTP_REQ_ACCEPT)
		self.request["SYST"] = (FTP_REQ_ACCEPT)
		self.request["TYPE"] = (FTP_REQ_ACCEPT)

		self.request["CLNT"] = (FTP_REQ_REJECT)
		self.request["XPWD"] = (FTP_REQ_REJECT)
		self.request["MACB"] = (FTP_REQ_REJECT)
		self.request["OPTS"] = (FTP_REQ_REJECT)

	def requestStack(self):
		"""<method internal="yes">
                </method>
                """
		try:
			stack_proxy = self.request_stack[self.request_command]
		except:
			try:
				stack_proxy = self.request_stack["*"]
			except:
				stack_proxy =  (FTP_STK_NONE, None)
		
		if type(stack_proxy) == type(()):
			while 1:
				stack_type = stack_proxy[0]
				if stack_type == FTP_STK_NONE:
					return (FTP_STK_NONE, None)
				elif stack_type == FTP_STK_POLICY:
					# call function
					stack_proxy = stack_proxy[1]()
				else:
					return stack_proxy
		else:
			return (FTP_STK_NONE, None)
                
		return stack_proxy


	def parseInbandAuth(self, command, parameter):
		"""<method internal="yes">
                  <summary>
                    This method should be called when inband authentication is used, to parse the data embedded in USER and PASS commands.
                  </summary>
                  <description>
                    This method fills in self.username, self.proxy_username, self.proxy_password, self.hostname, self.hostport and self.password
                    from the USER and PASS command parameters passed to it. It will leave any unspecified fields untouched.
                  </description>
                  <metainfo>
                    <arguments/>
                  </metainfo>
                </method>
                """
		def parseUser(self, parameter):
			self.need_proxy_pass = True
			self.need_ftp_pass = True
			ats = parameter.count('@')

			if ats == 0:
				# client configured for transparent/proxy-less operation
				raise ParseInbandAuthError, "USER parameter is required to include at least the username and the hostname in nontransparent mode"
			elif ats == 1:
				# old-style: USER: user@host[:port]  PASS: ftp_pass
				self.username, hostname_port = parameter.split('@')
				# no proxy authentication is done in this case
				self.need_proxy_pass = False
			elif ats == 2:
				# USER: user@proxyUser@host[:port]  PASS: pass@proxyPass
				self.username, self.proxy_username, hostname_port = parameter.split('@')
				# in this case, the PASS parameter includes the two passwords, therefore both need_* fields are left True
			elif ats == 3:
				# USER: user@proxyUser@host[:port]:pass@proxyPass  PASS doesn't matter
				self.username, self.proxy_username, hostname_port_pass, self.proxy_password = parameter.split('@')
				self.need_proxy_pass = False
                                self.proxy_auth_needed = 1              # tell C code to do authentication
				self.hostname, rest = hostname_port_pass.split(':', 1)
				try:
					port_s, self.password = rest.split(':', 1)
					try:
						hostport = int(port_s)
						if hostport < 1 or hostport > 65535:
							self.password = rest
						else:
							self.hostport = hostport
					except ValueError:
						self.password = rest
				except ValueError:
					self.password = rest
				self.need_ftp_pass = False
			else:
				# none of the above forms allow @-s except as separators
				raise ParseInbandAuthError, "too many \"@\"-s in USER parameter"
			
			if ats in (1, 2):
				try:
					self.hostname, port_s = hostname_port.split(':')
				except ValueError:
					self.hostname = hostname_port
				else:
					try:
						self.hostport = int(port_s)
					except ValueError:
						raise ParseInbandAuthError, "non-numeric port in USER parameter"

		def parsePass(self, parameter):
			if self.need_proxy_pass:
				try:
					self.password, self.proxy_password = parameter.split('@', 1)
                                        self.proxy_auth_needed = 1              # tell C code to do authentication
				except ValueError:
					raise ParseInbandAuthError, "proxy and FTP server passwords must be given in either "\
						"USER or PASS parameter in nontransparent mode"
			elif self.need_ftp_pass:
					self.password = parameter

                        # repeated PASS-es until another USER have no effect
                        self.need_proxy_pass = False
                        self.need_ftp_pass = False

		command = command.upper()
		try:
			if command == 'USER':
				parseUser(self, parameter)
			elif command == 'PASS':
				parsePass(self, parameter)
			else:
                                proxyLog(self, FTP_POLICY, 3, "Error parsing inband authorization token, " \
                                         "unknown command; command='%s'" % command)
                                return FALSE
                except ParseInbandAuthError, e:
                        proxyLog(self, FTP_POLICY, 3, "Error parsing inband authorization token; " \
                                 "command='%s', parameter='%s', error='%s'" % (command, parameter, e.args[0]))
                        return FALSE
		except ValueError, e:
                        proxyLog(self, FTP_POLICY, 3, "Error parsing inband authorization token, " \
                                 "input does not match the supported format; " \
                                 "command='%s', parameter='%s'" % (command, parameter))
                        return FALSE

                return TRUE

class FtpProxy(AbstractFtpProxy):
	"""<class maturity="stable">
          <summary>
            Default Ftp proxy based on AbstractFtpProxy.
          </summary>
          <description>
            <para>
              A permitting Ftp proxy based on the AbstractFtpProxy, allowing all commands, responses, and features, including unknown ones. The connection is terminated if a response with the answer code <parameter>421</parameter> is received.
            </para>
          </description>
          <metainfo>
            <attributes/>
          </metainfo>
        </class>
        """
	def config(self):
		"""<method internal="yes">
                  <summary>
                    Configuration for FtpProxy.
                  </summary>
                  <description>
                    <para>
                      Enables all commands by setting permit_unknown_commands to
                      TRUE and adding two wildcard entries to the commands
                      and answers hash.
                    </para>
                  </description>
                  <metainfo>
                    <arguments/>
                  </metainfo>
                </method>
                """
		self.request["*"] = (FTP_REQ_ACCEPT)
		self.response["*","421"]    = (FTP_RSP_ABORT, "421 Logoff")
		self.response["*", "*"] = (FTP_RSP_ACCEPT)
		self.features["*"] = (FTP_FEATURE_ACCEPT)
		self.permit_unknown_command = TRUE

class FtpProxyAnonRO(AbstractFtpProxy):
	"""<class maturity="stable">
          <summary>
            FTP proxy based on AbstractFtpProxy, only allowing read-only access to anonymous users.
          </summary>
          <description>
            <para>
              FTP proxy based on AbstractFtpProxy, enabling read-only access (i.e. only downloading) to anonymous users (uploads and usernames other than 'anonymous' or 'ftp' are disabled). Commands and return codes are strictly checked, unknown commands and responses are rejected. Every feature is accepted.
            </para>
	    <para>The ABOR; ACCT; AUTH; CDUP; CWD; EPRT; EPSV; FEAT; LIST; MODE; MDTM; NLST; NOOP; PASV; PASS; PORT; PWD; QUIT; REST; RETR; SIZE; STAT; STRU; SYST; TYPE; and USER commands are permitted, the CLNT; XPWD; MACB; OPTS commands are rejected.</para>
          </description>
          <metainfo>
            <attributes/>
          </metainfo>
        </class>
        """
	def pUser(self,command):
		"""<method internal="yes">
                </method>
                """
		if self.request_parameter == "ftp" or self.request_parameter == "anonymous":
			return FTP_REQ_ACCEPT
		return FTP_REQ_REJECT

	def config(self):
		"""<method internal="yes">
                  <summary>
                    Configuration for FtpProxyAnonRO
                  </summary>
                  <description>
                    <para>
                      It enables a minimal set of commands for a working anonymous Download-Only FTP proxy, and sets permit_unknown_commands to FALSE.
                    </para> 
                  </description>
                  <metainfo>
                    <arguments/>
                  </metainfo>
                </method>
                """
		AbstractFtpProxy.loadMinimalCommands(self)
		self.request["USER"] = (FTP_REQ_POLICY, self.pUser)

		self.request["*"]    = (FTP_REQ_REJECT)

		AbstractFtpProxy.loadAnswers(self)
		self.response["*","*"] = (FTP_RSP_REJECT)
		self.features["*"] = (FTP_FEATURE_ACCEPT)
		self.permit_unknown_command = FALSE

class FtpProxyRO(AbstractFtpProxy):
	"""<class maturity="stable">
          <summary>
            FTP proxy based on AbstractFtpProxy, allowing read-only access to any user.
          </summary>
          <description>
            <para>
              FTP proxy based on AbstractFtpProxy, enabling read-only access to any user. Commands and return codes are strictly checked, unknown commands and responses are rejected. Every feature is accepted.
            </para>
            <para>The ABOR; ACCT; AUTH; CDUP; CWD; EPRT; EPSV; FEAT; LIST; MODE; MDTM; NLST; NOOP; PASV; PASS; PORT; PWD; QUIT; REST; RETR; SIZE; STAT; STRU; SYST; TYPE; and USER commands are permitted, the CLNT; XPWD; MACB; OPTS commands are rejected.</para>
          </description>
          <metainfo>
            <attributes/>
          </metainfo>
        </class>
        """
	def config(self):
		"""<method internal="yes">
                  <summary>
                    Configuration for FtpProxyRO
                  </summary>
                  <description>
                    <para>
                      It enables a minimal set of commands for a working Download-Only FTP proxy, and sets permit_unknown_commands to FALSE.
                    </para>
                  </description>
                  <metainfo>
                    <arguments/>
                  </metainfo>
                </method>
                """
		AbstractFtpProxy.loadMinimalCommands(self)

		self.request["USER"] = (FTP_REQ_ACCEPT)
		self.request["*"]    = (FTP_REQ_REJECT)

		AbstractFtpProxy.loadAnswers(self)
		self.response["*","*"] = (FTP_RSP_REJECT)
		self.features["*"] = (FTP_FEATURE_ACCEPT)
		self.permit_unknown_command = FALSE

class FtpProxyAnonRW(AbstractFtpProxy):
	"""<class maturity="stable">
          <summary>
            FTP proxy based on AbstractFtpProxy, allowing full read-write access, but only to anonymous users.
          </summary>
          <description>
            <para>
              FTP proxy based on AbstractFtpProxy, enabling full read-write access to anonymous users (the 'anonymous' and 'ftp' usernames are permitted). Commands and return codes are strictly checked, unknown commands and responses are rejected. Every feature is accepted.
            </para>
	    <para>The ABOR; ACCT; APPE; CDUP; CWD; DELE; EPRT; EPSV; LIST; MKD; MODE; MDTM; NLST; NOOP; PASV; PASS; PORT; PWD; QUIT; RMD; RNFR; RNTO; REST; RETR; SIZE; STAT; STOR; STOU; STRU; SYST; TYPE; USER and FEAT commands are permitted, the AUTH; CLNT; XPWD; MACB; OPTS commands are rejected.</para>
          </description>
          <metainfo>
            <attributes/>
          </metainfo>
        </class>
        """
	def pUser(self,command):
		"""<method internal="yes">
                </method>
                """
		if self.request_parameter == "ftp" or self.request_parameter == "anonymous":
			return FTP_REQ_ACCEPT
		return FTP_REQ_REJECT

	def config(self):
		"""<method internal="yes">
                  <summary>
                    Configuration for FtpProxyAnonRO
                  </summary>
                  <description>
                    <para>
                      It enables a minimal set of commands for a working Anonymous
                      FTP proxy, and sets permit_unknown_commands to FALSE.
                    </para>
		   
                  </description>
                  <metainfo>
                    <arguments/>
                  </metainfo>
                </method>
                """
		AbstractFtpProxy.loadMinimalCommands(self)

		self.request["APPE"] = (FTP_REQ_ACCEPT)
		self.request["DELE"] = (FTP_REQ_ACCEPT)
		self.request["MKD"]  = (FTP_REQ_ACCEPT)
		self.request["RMD"]  = (FTP_REQ_ACCEPT)
		self.request["RNFR"] = (FTP_REQ_ACCEPT)
		self.request["RNTO"] = (FTP_REQ_ACCEPT)
		self.request["STOR"] = (FTP_REQ_ACCEPT)
		self.request["STOU"] = (FTP_REQ_ACCEPT)

		self.request["USER"] = (FTP_REQ_POLICY, self.pUser)

		self.request["*"]    = (FTP_REQ_REJECT)

		AbstractFtpProxy.loadAnswers(self)
		self.response["*","*"] = (FTP_RSP_REJECT)
		self.features["*"] = (FTP_FEATURE_ACCEPT)
		self.permit_unknown_command = FALSE

class FtpProxyRW(AbstractFtpProxy):
	"""<class maturity="stable">
          <summary>
            FTP proxy based on AbstractFtpProxy, allowing full read-write access to any user.
          </summary>
          <description>
            <para>
              FTP proxy based on AbstractFtpProxy, enabling full read-write access to any user. Commands and return codes are strictly checked, unknown commands and responses are rejected. Every feature is accepted.
            </para>
            <para>The ABOR; ACCT; AUTH; CDUP; CWD; EPRT; EPSV; FEAT; LIST; MODE; MDTM; NLST; NOOP; PASV; PASS; PORT; PWD; QUIT; REST; RETR; SIZE; STAT; STRU; SYST; TYPE; and USER commands are permitted, the CLNT; XPWD; MACB; OPTS commands are rejected.</para>
          </description>
          <metainfo>
            <attributes/>
          </metainfo>
        </class>
        """
	def config(self):
		"""<method internal="yes">
                  <summary>
                    Configuration for FtpProxyRW
                  </summary>
                  <description>
                    <para>
                      It enables a minimal set of commands for a working FTP proxy, and sets <parameter>permit_unknown_commands</parameter> to FALSE.  
                    </para>
                  </description>
                  <metainfo>
                    <arguments/>
                  </metainfo>
                </method>
                """
		AbstractFtpProxy.loadMinimalCommands(self)

		self.request["APPE"] = (FTP_REQ_ACCEPT)
		self.request["DELE"] = (FTP_REQ_ACCEPT)
		self.request["MKD"]  = (FTP_REQ_ACCEPT)
		self.request["RMD"]  = (FTP_REQ_ACCEPT)
		self.request["RNFR"] = (FTP_REQ_ACCEPT)
		self.request["RNTO"] = (FTP_REQ_ACCEPT)
		self.request["STOR"] = (FTP_REQ_ACCEPT)
		self.request["STOU"] = (FTP_REQ_ACCEPT)
		self.request["USER"] = (FTP_REQ_ACCEPT)
		self.request["ALLO"] = (FTP_REQ_ACCEPT)

		self.request["*"]    = (FTP_REQ_REJECT)

		AbstractFtpProxy.loadAnswers(self)
		self.response["*","*"] = (FTP_RSP_REJECT)
		self.features["*"] = (FTP_FEATURE_ACCEPT)
		self.permit_unknown_command = FALSE

class FtpProxyMinimal(FtpProxyRO):
	"""<class maturity="obsolete">
          <summary>
            Alias FtpProxyRO
          </summary>
          <description/>
          <metainfo>
            <attributes/>
          </metainfo>
        </class>
        """
	pass

