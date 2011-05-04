############################################################################
##
## Copyright (c) 2000, 2001, 2002, 2003, 2004, 2005 BalaBit IT Ltd, Budapest, Hungary
## All rights reserved.
##
##
## $Id: Pssl.py,v 1.28 2004/09/23 13:26:46 bazsi Exp $
##
## Author  : Bazsi
## Auditor : 
## Last audited version: 
## Notes:
##
############################################################################

"""<module maturity="obsolete">
  <summary>
    Compatibility proxy for the Secure Socket Layer protocols.
  </summary>
  <description>
    <para>
      This proxy is a compatibility wrapper for core SSL functionality. The documentation of the attributes was left intact for reference, but you should update your configuration to use the common SSL framework available for every proxy. See <xref linkend="configuring-ssl"/> for details.
    </para>
    <note>
    <para>
     This documentation describes the now-obsolete Pssl proxy available in the commercial
     version of Zorp. For the documentation of the SSL proxy available in the
     open-source Zorp GPL, see the <filename>modules/Pssl.py</filename> file.
    </para>
    </note>
     <section>
      <title>Proxy behavior</title>
      <para>
        PsslProxy is a module built for inspecting SSL/TLS connections. SSL/TLS connections initiated from the client are terminated on the firewall; and two separate SSL/TLS connections are built: one between the client and the firewall, and one between the firewall and the server. If both connections are accepted by the local security policy (the certificates are valid, and only the allowed encryption algorithms are used), PsslProxy stacks a proxy to inspect the protocol embedded into the secure channel. The PsslProxy functions as a PlugProxy if no protocol proxy is stacked.
      </para>
      <para>
      Several configuration examples and considerations are discussed in the 
	Technical White Paper and Tutorial <emphasis>Proxying secure channels - the Secure Socket Layer</emphasis>, available at the BalaBit Documentation Page <ulink url="http://www.balabit.com/support/documentation/">http://www.balabit.com/support/documentation/</ulink>.
      </para>
      <section>
        <title>General behavior</title>
        <para>
            The proxy starts its operation by inspecting the values set in the
            <parameter>handshake_seq</parameter> attribute. When this attribute is set to
            PSSL_HSO_CLIENT_SERVER the client side, otherwise (PSSL_HSO_SERVER_CLIENT) the
            server side handshake is performed first.
        </para>
        <para>
          As part of the handshake process the proxy checks if SSL is enabled on the given side (<parameter>client_need_ssl</parameter> and <parameter>server_need_ssl</parameter> attributes). It is not necessary for SSL to be enabled on both sides - the proxy can handle one-sided SSL connections as well (e.g.: the firewall communicates in an unencrypted channel with the client, but in a secure channel with the server). If SSL is not enabled, the handshake is skipped for that side.
        </para>
        <para>
          When SSL is needed, the proxy will cooperate with the policy layer
          to have all required parameters (keys, certificates, etc.) set up.
          This is achieved using decision points in the hash named
          <parameter>handshake_hash</parameter> which is explained later in detail.
        </para>
        <para>
          The SSL handshake is slightly different for the client (in this case
          the proxy behaves as an SSL server) and the server (when the proxy
          behaves as an SSL client).
        </para>
      </section>
      <section>
        <title>Client side (SSL server) behavior</title>
        <para>
          As an SSL server the first thing to present to an SSL client is
          a certificate/key pair, thus a call to the 'setup_key' callback
          is made. It is expected that by the time this callback returns
          the attributes <parameter>client_local_privatekey</parameter> and
          <parameter>client_local_certificate</parameter> are filled appropriately.
        </para>
        <para>
          If peer authentication is enabled (by setting the attribute
          <parameter>client_verify_type</parameter>) a list of trusted CA certificates must be
          set up (stored in the hash <parameter>client_local_ca_list</parameter>). The list can be set up
          by the 'setup_ca_list' function call. Peer certificates are verified against the trusted CA list and their associated revocation lists. Revocations can be set up
          in the 'setup_crl_list' callback.
        </para>
        <para>
          At the end of the verification another callback named
          'verify_cert' is called which can either ACCEPT or DENY the
          certificate possibly overriding the verification against the local
          CA database.
        </para>
      </section>
      <section>
        <title>Server side (SSL client) behavior</title>
        <para>
          Server side handshake is similar to the client side handshake
          previously described. The difference is the order of certificate
          verification. On the server side the proxy verifies the server
          certificate first and then sends its own certificate for
          verification. This is unlike the client side where the local
          certificate is sent first, and then the peer's certificate is verified.
        </para>
        <para>
          So the callbacks are called in this order: 'setup_ca_list' and
          'setup_crl_list' to set up CA and CRL information, 'verify_cert'
          to finalize certificate validation, and 'setup_key' to optionally
          provide a local certificate/key pair.
        </para>
      </section>
      <section>
        <title>Handshake callbacks</title>
        <para>
          As described earlier, the proxy provides a way to customize the
          SSL handshake process. This is done using the <parameter>client_handshake</parameter>
          and <parameter>server_handshake</parameter> hashes. These hashes are indexed by  the keywords listed below.
        </para>
        <para>
          The tuple can be separated to two parts: 1) tuple type, 2)
          parameters for the given type. For now only 'PSSL_HS_POLICY' is
          valid as tuple type, and it requires a function reference as
          parameter.
        </para>
        <para>
          The following keys are accepted as indexes:
        </para>
        <itemizedlist>
          <listitem>
            <para>
              setup_key --  This function is called when the proxy needs the private key/certificate pair to be set up. All attributes filled in the earlier phases can be used to decide which key/certificate to use. The function expects two parameters: self, side.
            </para>
          </listitem>
          <listitem>
            <para>
              setup_ca_list -- This function is called when the proxy needs the trusted CA list to be set up.  The function expects two parameters: self, side.
            </para>
          </listitem>
          <listitem>
            <para>
              setup_crl_list -- This function is called when the proxy needs the CRL list to be set up. This function gets a single string parameter which contains the name of the CA  whose CRL is to be filled up. The function expects three parameters: self, side, ca_name.
            </para>
          </listitem>
          <listitem>
            <para>
              verify_cert -- This function is called to finalize the verification process. 
              The function expects two parameters: self, side.
            </para>
          </listitem>
        </itemizedlist>
        <para>
          The function arguments as referenced above are defined as:
        </para>
        <itemizedlist>
          <listitem>
            <para>
              self -- The proxy instance.
            </para>
          </listitem>
          <listitem>
            <para>
              side -- The side where handshake is being
              performed.
            </para>
          </listitem>
          <listitem>
            <para>
              ca_name -- Name of an X.509 certificate.
            </para>
          </listitem>
        </itemizedlist>
        <para>
          The functions return one of the 'PSSL_HS_*' constants.
          Generally if the function returns 'PSSL_HS_ACCEPT' the handshake
          continues, otherwise the handshake is aborted. As an exception,
          'verify_cert' may return 'PSSL_HS_VERIFIED' in which case the
          certificate is accepted without further verification.
        </para>
      </section>
      <section>
        <title>X.509 Certificates</title>
        <para>
          An X.509 certificate is a public key with a subject name specified
          as an X.500 DN (distinguished name) signed by a certificate issuing authority (CA). X.509 certificates are represented as Python policy objects having the following attributes:
        </para>
        <itemizedlist>
          <listitem>
            <para>
              subject -- Subject of the certificate.
            </para>
          </listitem>
          <listitem>
            <para>
              issuer -- Issuer of the certificate (i.e. the CA that signed it).
            </para>
          </listitem>
          <listitem>
            <para>
              serial -- Serial number of the certificate.
            </para>
          </listitem>
          <listitem>
            <para>
              blob -- The certificate itself as a string in PEM format.
            </para>
          </listitem>
        </itemizedlist>
	
	<para>
	Zorp uses X.509 certificates to provide a convenient and efficient way to
	manage and distribute certificates and keys used by the various components and proxies of the managed Zorp
	hosts. It is mainly aimed at providing certificates required for the secure communication between the different
	parts of the firewall system, e.g. Zorp hosts and ZMS engine (the actual communication is realized by agents).	
	</para>
	<para>
	Certificates of trusted CAs (and their accompanying CRLs) are used in Zorp to validate the certificates of servers accessed by the clients. The hashes and structures below are used by the various certificate-related attributes of the Zorp Pssl proxy, particularly the ones of <parameter>certificate</parameter> type.
	</para>
	
      <section>
        <title>X.509 Certificate Names</title>
        <para>
          A certificate name behaves as a string, and contains a DN in
          the following format (also known as one-line format):
        </para>
        <para>
          /RDN=value/RDN=value/.../RDN=value/
        </para>
        <para>
          The word RDN stands for relative distinguished name. For example the DN
          below:
        </para>
        <para>
          cn=Root CA, ou=CA Group, o=Foo Ltd, l=Bar, st=Foobar State, c=US
        </para>
        <para>
          becomes:
        </para>
        <para>
          /C=US/ST=Foobar State/L=Bar/O=Foo Ltd/OU=CA Group/CN=Root CA/
        </para>
        <para>
          The format and representation of certificate names may change in
          future releases.
        </para>
      </section>
      <section>
        <title>X.509 Certificate Revocation List</title>
        <para>
          A certifying authority may revoke the issued
          certificates. A revocation means that the serial number and the
          revocation date is added to the list of revoked certificates.
          Revocations are published on a regular basis. This list is called
          the Certificate Revocation List, also known as CRL. A CRL always
          has an issuer, a date when the list was published, and the
          expected date of its next update.
        </para>
      </section>
      <section>
        <title>X.509 Certificate hash</title>
        <para>
          The proxy stores trusted CA certificates in a Certificate hash. This hash can be indexed by two different types. If an
          integer index is used, the slot specified by this value is looked
          up; if a string index is used, it is interpreted as a one-line DN
          value, and the appropriate certificate is looked up. Each slot in
          this hash contains an X.509 certificate.
        </para>
      </section>
      <section>
        <title>X.509 CRL hash</title>
        <para>
          Similarly to the certificate hash, a separate hash for storing
          Certificate Revocation Lists was defined. A CRL contains revocation lists
          associated to CAs.
        </para>
      </section>
      <section id="certificate_verification">
      <title>Certificate verification options
      </title>
      <para>
      Zorp is able to automatically verify the certificates received. The types of accepted certificates can be controlled separately on the client and the server side using the <parameter>client_verify_type</parameter> and the <parameter>server_verify_type</parameter> attributes. These attributes offer an easy way to restrict encrypted access only to sites having trustworthy certificates. The available options are  summarized in the following table.
      </para>
      <inline type="enum" target="enum.pssl.verify"/>
      <para>
      The <parameter>server_check_subject</parameter> can be used to compare the domain name
      provided in the <parameter>Subject</parameter> field of the server certificate to 
      application level information about the server. Currently it can compare the <parameter>Subject</parameter> field to the domain name of the HTTP request in HTTPS
       communication. If the <parameter>server_check_subject</parameter> is set to
        <parameter>TRUE</parameter> and <parameter>server_verify_type</parameter> is
	 <parameter>SSL_VERIFY_REQUIRED_UNTRUSTED</parameter> or  <parameter>SSL_VERIFY_REQUIRED_TRUSTED</parameter>, the HTTP proxy stacked into SSL 
	 will deny access to the page and return an error if the <parameter>Subject</parameter> field does not match the domain name of the URL.
      </para>
      </section>
     </section>
      <section>
        <title>Setting the allowed SSL/TLS protocol</title>
        <para>
          As there are different and sometimes incompatible releases of the
          SSL protocol, it is possible to specify which SSL/TLS version is
          allowed to pass the firewall. The attributes
          <parameter>client_ssl_method</parameter> and
          <parameter>server_ssl_method</parameter> can be used for this
          purpose. Specify the appropriate '<link
          linkend="enum.pssl.method">PSSL_METHOD_*</link>' constant to allow
          the selected protocol. Only one constant can be specified. Zorp
          currently supports the SSL versions 2 and 3 and the TLS v1
          protocols.
	 <inline type="enum" target="enum.pssl.method"/>	 
        </para>	
	<warning>
	 <para>
	 The OpenSSL implementation of the SSL protocol (used by Zorp) has an important feature regarding method selection: it allows automatical fallbacks if one side 
	 does not support the selected method. That means that even if <parameter>PSSL_METHOD_SSLv3</parameter> is specified, the communication might fall back to SSLv2 if one f the communicating parties does not support v3. To explicitly deny a protocol, set the appropriate <parameter>client_disable_proto_*</parameter> or <parameter>server_disable_proto_*</parameter> attribute to <parameter>TRUE</parameter>. In Zorp SSLv2 is disabled by default.
	 </para>
	 </warning>
      </section>
      <section>
        <title>SSL cipher selection</title>
        <para>
          The cipher algorithms used for key exchange and mass symmetric
          encryption are specified by the attributes <parameter>client_ssl_ciphers</parameter>
          and <parameter>server_ssl_ciphers</parameter>. These attributes contain a cipher
          specification as specified by the OpenSSL manuals, see the manual
          page ciphers(ssl) for further details.
        </para>
        <para>
          The default set of ciphers can be set by using the following predefined
         variables.
	  <inline type="enum" target="enum.pssl.ciphers"/>
        </para>
        <para>
          Cipher specifications as defined above are sorted by key length,
          the cipher providing the best key length will be the most preferred.
        </para>
      </section>      
    </section>
    <section>
      <title>Related standards</title>
      <itemizedlist>
      <listitem>
      <para>
        The SSL protocol is defined by Netscape Ltd. at http://wp.netscape.com/eng/ssl3/ssl-toc.html
      </para>
      </listitem>
      <listitem>
      <para>
        The TLS protocol is defined in RFC 2246.
      </para>
      </listitem>
      </itemizedlist>
    </section>
  </description>
  <metainfo>
    <enums>
      <enum maturity="stable" id="enum.ssl.verify">
        <description>
          SSL protocol verification hashes
        </description>
        <item>
          <name>SSL_VERIFY_NONE</name>
        </item>
        <item>
          <name>SSL_VERIFY_OPTIONAL</name>
        </item>
        <item>
          <name>SSL_VERIFY_REQUIRED_UNTRUSTED</name>
        </item>
        <item>
          <name>SSL_VERIFY_REQUIRED_TRUSTED</name>
        </item>
      </enum>
      <enum maturity="stable" id="enum.pssl.verify">
        <description>
          Certificate verification settings
        </description>
        <item>
          <name>PSSL_VERIFY_NONE</name>
	  <description>Automatic certificate verification is disabled.</description>
        </item>
<!--        <item>
          <name>PSSL_VERIFY_OPTIONAL</name>
	  <description>Certificate is optional, all certificates are accepted.</description>
        </item>-->
        <item>
          <name>PSSL_VERIFY_OPTIONAL_UNTRUSTED</name>
	  <description>Certificate is optional, if present, both trusted and untrusted certificates are accepted.</description>
        </item>
        <item>
          <name>PSSL_VERIFY_OPTIONAL_TRUSTED</name>
	  <description>Certificate is optional, but if a certificate is present, only  certificates signed by a trusted CA are accepted.</description>
        </item>
        <item>
          <name>PSSL_VERIFY_REQUIRED_UNTRUSTED</name>
	  <description>Valid certificate is required, both trusted and untrusted certificates are accepted.</description>
        </item>
        <item>
          <name>PSSL_VERIFY_REQUIRED_TRUSTED</name>
	  <description>Certificate is required, only valid certificates signed by a trusted CA are accepted.</description>
        </item>
      </enum>
      <enum maturity="stable" id="enum.pssl.method">
        <description>
          Constants for SSL/TLS protocol selection
        </description>
        <item>
          <name>PSSL_METHOD_SSLV23</name>
	  <description>
           Permit the use of SSLv2 and v3.
          </description>
        </item>
        <item>
          <name>PSSL_METHOD_SSLV2</name>
	  <description>
           Permit the use of SSLv2 exclusively.
          </description>
        </item>
        <item>
          <name>PSSL_METHOD_SSLV3</name>
	  <description>
		Permit the use of SSLv3 exclusively.
	  </description>
        </item>
        <item>
          <name>PSSL_METHOD_TLSV1</name>
	  <description>
		Permit the use of TLSv1 exclusively.
	  </description>
        </item>
        <item>
          <name>PSSL_METHOD_ALL</name>
	  <description>
           Permit the use of all the supported (SSLv2, SSLv3, and TLSv1) protocols.
          </description>
        </item>
      </enum>
      <enum maturity="stable" id="enum.pssl.ciphers">
        <description>
          Constants for cipher selection
        </description>
        <item>
          <name>PSSL_CIPHERS_ALL</name>
	  <description>
	   Permit the use of all supported ciphers, including the 40 and 56 bit exportable ciphers.
	  </description>
        </item>
        <item>
          <name>PSSL_CIPHERS_HIGH</name>
	  <description>
		Permit only the use of ciphers which use at least 128 bit long keys.
	  </description>
        </item>
        <item>
          <name>PSSL_CIPHERS_MEDIUM</name>
	  <description>
		Permit only the use of ciphers which use 128 bit long keys.
	  </description>
        </item>
        <item>
          <name>PSSL_CIPHERS_LOW</name>
	  <description>
		Permit only the use of ciphers which use keys shorter then 128 bits.
	  </description>
        </item>
      </enum>
      <enum maturity="stable" id="enum.pssl.hso">
        <description>
          handshake order
        </description>
        <item>
          <name>PSSL_HSO_CLIENT_SERVER</name>
        </item>
        <item>
          <name>PSSL_HSO_SERVER_CLIENT</name>
        </item>
      </enum>
    </enums>
    <constants>
      <constantgroup maturity="stable" id="const.pssl.log">
        <description>
          pssl proxy printed log messages
        </description>
        <item>
          <name>PSSL_ERROR</name>
          <value>'pssl.error'</value>
        </item>
        <item>
          <name>PSSL_DEBUG</name>
          <value>'pssl.debug'</value>
        </item>
      </constantgroup>
      <constantgroup maturity="stable" id="const.pssl.hs">
        <description>
          handshake policy decisions
        </description>
        <item>
          <name>PSSL_HS_ACCEPT</name>
          <value>0</value>
        </item>
        <item>
          <name>PSSL_HS_REJECT</name>
          <value>1</value>
        </item>
        <item>
          <name>PSSL_HS_POLICY</name>
          <value>6</value>
        </item>
        <item>
          <name>PSSL_HS_VERIFIED</name>
          <value>10</value>
        </item>
      </constantgroup>
    </constants>
  </metainfo>
</module>
"""

from Zorp import *
from Proxy import proxyLog
from Proxy import SSL_VERIFY_NONE, SSL_VERIFY_OPTIONAL, \
        SSL_VERIFY_OPTIONAL_UNTRUSTED, SSL_VERIFY_OPTIONAL_TRUSTED, \
        SSL_VERIFY_REQUIRED_UNTRUSTED, SSL_VERIFY_REQUIRED_TRUSTED, \
        SSL_HSO_CLIENT_SERVER, SSL_HSO_SERVER_CLIENT, SSL_HS_ACCEPT, \
        SSL_HS_REJECT, SSL_HS_POLICY, SSL_HS_VERIFIED, SSL_METHOD_SSLV23, \
        SSL_METHOD_SSLV2, SSL_METHOD_SSLV3, SSL_METHOD_TLSV1, SSL_METHOD_ALL, \
        SSL_CIPHERS_ALL, SSL_CIPHERS_HIGH, SSL_CIPHERS_MEDIUM, SSL_CIPHERS_LOW, \
        SSL_NONE, SSL_FORCE_SSL, SSL_ACCEPT_STARTTLS, SSL_FORWARD_STARTTLS
from Plug import *

import re
import os
import types
import thread
import string
import fcntl

PSSL_ERROR	= 'pssl.error'
PSSL_DEBUG	= 'pssl.debug'
PSSL_INFO	= 'pssl.info'
PSSL_VIOLATION  = 'pssl.violation'

PSSL_VERIFY_NONE = SSL_VERIFY_NONE
PSSL_VERIFY_OPTIONAL = SSL_VERIFY_OPTIONAL
PSSL_VERIFY_OPTIONAL_UNTRUSTED = SSL_VERIFY_OPTIONAL_UNTRUSTED
PSSL_VERIFY_OPTIONAL_TRUSTED = SSL_VERIFY_OPTIONAL_TRUSTED
PSSL_VERIFY_REQUIRED_UNTRUSTED = SSL_VERIFY_REQUIRED_UNTRUSTED
PSSL_VERIFY_REQUIRED_TRUSTED = SSL_VERIFY_REQUIRED_TRUSTED

PSSL_HSO_CLIENT_SERVER = SSL_HSO_CLIENT_SERVER
PSSL_HSO_SERVER_CLIENT = SSL_HSO_SERVER_CLIENT

PSSL_HS_ACCEPT = SSL_HS_ACCEPT
PSSL_HS_REJECT = SSL_HS_REJECT
PSSL_HS_POLICY = SSL_HS_POLICY
PSSL_HS_VERIFIED = SSL_HS_VERIFIED

PSSL_METHOD_SSLV23 = SSL_METHOD_SSLV23
PSSL_METHOD_SSLV2 = SSL_METHOD_SSLV2
PSSL_METHOD_SSLV3 = SSL_METHOD_SSLV3
PSSL_METHOD_TLSV1 = SSL_METHOD_TLSV1
PSSL_METHOD_ALL = SSL_METHOD_ALL

PSSL_CIPHERS_ALL = SSL_CIPHERS_ALL
PSSL_CIPHERS_HIGH = SSL_CIPHERS_HIGH
PSSL_CIPHERS_MEDIUM = SSL_CIPHERS_MEDIUM
PSSL_CIPHERS_LOW = SSL_CIPHERS_LOW

PSSL_NONE = SSL_NONE
PSSL_FORCE_SSL = SSL_FORCE_SSL
PSSL_ACCEPT_STARTTLS = SSL_ACCEPT_STARTTLS
PSSL_FORWARD_STARTTLS = SSL_FORWARD_STARTTLS

class AbstractPsslProxy(AbstractPlugProxy):
	"""<class maturity="obsolete" abstract="yes">
          <summary>
            Class encapsulating the abstract Pssl proxy.
          </summary>
          <description>
            <para>
              This proxy is a compatibility wrapper for core SSL functionality. The documentation was left intact for reference, but SSL attributes should be used in each protocol proxy instead of this wrapper.
              This abstract class encapsulates a plug proxy which uses SSL/TLS on both or either sides, making it possible for any protocol
              proxy to analyze protocol streams embedded into SSL/TLS. AbstractPsslProxy serves as a starting point for customized proxy classes and is itself not directly usable. Service definitions should refer to a customized class derived from AbstractPsslProxy, or the predefined PsslProxy class.
            </para>
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
		  <read/>
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
		  <read/>
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
                <name>packet_stats_interval</name>
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
                  The number of passing packages between two successive packetStats() events.
                  Set to 0 to turn packetStats() off.
                </description>
              </attribute>
              <attribute maturity="stable">
                <name>stack_proxy</name>
		<type>
		  <link id="action.zorp.stack"/>
		</type>
		<conftime>
		  <read/>
		  <write/>
		</conftime>
		<runtime>
		  <read/>
		  <write/>
		</runtime>
                <description>
                  The proxy class to stack into the connection to inspect the embedded protocol. See also <xref linkend="proxy_stacking"/>.
                </description>
              </attribute>
              <attribute maturity="stable">
                <name>timeout</name>
		<type>
		  <integer/>
		</type>
		<default>600000</default>
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
                <name>handshake_timeout</name>
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
                  SSL handshake timeout in milliseconds.
                </description>
              </attribute>
              <attribute maturity="stable">
                <name>permit_invalid_certificates</name>
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
                  Accept any kind of verification failure when UNTRUSTED verify_type is set.
		  E.g.: accept expired, self-signed, etc. certificates. 
                </description>
              </attribute>
              <attribute maturity="stable">
                <name>handshake_seq</name>
		<type>
		  <link id="enum.pssl.hso"/>
		</type>
		<default>PSSL_HSO_CLIENT_SERVER</default>
		<conftime>
		  <read/>
		  <write/>
		</conftime>
		<runtime>
		  <read/>
		</runtime>
                <description>
                  Handshake order. PSSL_HSO_CLIENT_SERVER performs the client side handshake first, PSSL_HSO_SERVER_CLIENT the server side.
                </description>
              </attribute>
              <attribute maturity="stable">
                <name>client_need_ssl</name>
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
                  Enable SSL on the client side of the proxy.
                  This requires setting up a client private key and a certificate.
                </description>
              </attribute>
              <attribute internal="yes">
                <name>client_handshake</name>
                <type>HASH:empty:RW:R</type>
                <default>empty</default>
                <conftime>
                  <read/>
                  <write/>
                </conftime>
                <runtime>
                  <read/>
                </runtime>
                <description>
                  Specifies policy callbacks for various SSL handshake phases.
                </description>
              </attribute>
              <attribute maturity="stable">
                <name>client_verify_type</name>
		<type>
		  <link id="enum.pssl.verify"/>
		</type>
		<default>PSSL_VERIFY_REQUIRED_TRUSTED</default>
		<conftime>
		  <read/>
		  <write/>
		</conftime>
		<runtime>
		  <read/>
		</runtime>
                <description>
                  Verification setting of the peer certificate on the client side.
                </description>
              </attribute>
              <attribute maturity="stable">
                <name>client_verify_depth</name>
                <type>
                  <integer/>
                </type>
                <default>4</default>
                <conftime>
                  <read/>
                  <write/>
                </conftime>
                <runtime>
                  <read/>
                </runtime>
                <description>
                  The longest accepted CA verification chain.
                </description>
              </attribute>
              <attribute maturity="stable">
                <name>client_local_privatekey</name>
		<type>
		  <certificate key="yes" cert="no"/>
		</type>
		<default>empty</default>
		<conftime>
		  <read/>
		  <write/>
		</conftime>
		<runtime>
		  <read/>
		  <write/>
		</runtime>
                <description>
                  The private key of the firewall on the client side. Specified as a string in PEM format.
                </description>
              </attribute>
              <attribute maturity="stable">
                <name>client_local_privatekey_passphrase</name>
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
                  Passphrase used to access <parameter>client_local_privatekey</parameter>.
                </description>
              </attribute>
              <attribute maturity="stable" internal="yes">
                <name>client_local_certificate</name>
                <type>X509:empty:RW:RW</type>
                <default>empty</default>
                <conftime>
                  <read/>
                  <write/>
                </conftime>
                <runtime>
                  <read/>
                  <write/>
                </runtime>
                <description>
                  The certificate associated to <parameter>client_local_privatekey</parameter> to be used on the client side.
                </description>
              </attribute>
              <attribute maturity="stable" internal="yes">
                <name>client_peer_certificate</name>
                <type>X509:empty:R:R</type>
                <default>empty</default>
                <conftime>
                  <read/>
                </conftime>
                <runtime>
                  <read/>
                </runtime>
                <description>
                  The certificate returned by the peer on the client side.
                </description>
              </attribute>
              <attribute maturity="stable" internal="yes">
                <name>client_local_ca_list</name>
                <type>HASH;INTEGER;X509:empty:RW:RW</type>
                <default>empty</default>
                <conftime>
                  <read/>
                  <write/>
                </conftime>
                <runtime>
                  <read/>
                  <write/>
                </runtime>
                <description>
                  A hash of trusted certificates. The items in this hash are used to verify client certificates.
                </description>
              </attribute>
              <attribute maturity="stable" internal="yes">
                <name>client_local_crl_list</name>
                <type>HASH;INTEGER;X509_CRL:empty:RW:RW</type>
                <default>empty</default>
                <conftime>
                  <read/>
                  <write/>
                </conftime>
                <runtime>
                  <read/>
                  <write/>
                </runtime>
                <description>
                  A hash of Certificate Revocation Lists, associated to CA certificates in <parameter>client_local_ca_list</parameter>.
                </description>
              </attribute>
              <attribute maturity="stable">
                <name>client_ssl_method</name>
		<type>
		  <link id="enum.pssl.method"/>
		</type>
		<default>PSSL_METHOD_ALL</default>
		<conftime>
		  <read/>
		  <write/>
		</conftime>
		<runtime>
		  <read/>
		</runtime>
                <description>
                  Specifies the allowed SSL/TLS protocols on the client side.
                </description>
              </attribute>
              <attribute maturity="stable">
                <name>client_disable_proto_sslv2</name>
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
                  Specifies that SSLv2 should be disabled even if the method selection would otherwise support SSLv2.
                </description>
              </attribute>
              <attribute maturity="stable">
                <name>client_disable_proto_sslv3</name>
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
                  Specifies that SSLv3 should be disabled even if the method selection would otherwise support SSLv3.
                </description>
              </attribute>
              <attribute maturity="stable">
                <name>client_disable_proto_tlsv1</name>
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
                  Specifies that TLSv1 should be disabled even if the method selection would otherwise support TLSv1.
                </description>
              </attribute>
              <attribute maturity="stable">
                <name>client_ssl_cipher</name>
		<type>
		  <link id="enum.pssl.ciphers"/>
		</type>
		<default>PSSL_CIPHERS_ALL</default>
		<conftime>
		  <read/>
		  <write/>
		</conftime>
		<runtime>
		  <read/>
		</runtime>
                <description>
                  Specifies the allowed ciphers on the client side.
                </description>
              </attribute>
              <attribute maturity="stable">
                <name>client_enable_renegotiation</name>
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
                  If set to TRUE, the client can request the renegotiation of the SSL connection.
                </description>
              </attribute>
              <attribute maturity="stable">
                <name>server_need_ssl</name>
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
                  Enable SSL on the server side of the proxy.
                  This requires setting up a private key and a certificate on Zorp.
                </description>
              </attribute>
              <attribute maturity="stable" internal="yes">
                <name>server_handshake</name>
                <type>HASH:empty:RW:R</type>
                <default>empty</default>
                <conftime>
                  <read/>
                  <write/>
                </conftime>
                <runtime>
                  <read/>
                </runtime>
                <description>
                  Specifies policy callbacks for various SSL handshake phases.
                </description>
              </attribute>
              <attribute maturity="stable">
                <name>server_verify_type</name>
		<type>
		  <link id="enum.pssl.verify"/>
		</type>
		<default>PSSL_VERIFY_REQUIRED_TRUSTED</default>
		<conftime>
		  <read/>
		  <write/>
		</conftime>
		<runtime>
		  <read/>
		</runtime>
                <description>
                  Verification settings of the peer certificate on the server side.
                </description>
              </attribute>
              <attribute maturity="stable">
                <name>server_verify_depth</name>
                <type>
                  <integer/>
                </type>
                <default>4</default>
                <conftime>
                  <read/>
                  <write/>
                </conftime>
                <runtime>
                  <read/>
                </runtime>
                <description>
                  The longest accepted CA verification chain.
                </description>
              </attribute>
              <attribute maturity="stable">
                <name>server_local_privatekey</name>
		<type>
		  <certificate key="yes" cert="no"/>
		</type>
		<default>empty</default>
		<conftime>
		  <read/>
		  <write/>
		</conftime>
		<runtime>
		  <read/>
		  <write/>
		</runtime>
                <description>
                  The private key of the firewall on the server side,                  specified as a string in PEM format.
                  Server side key and certificate are optional.
                </description>
              </attribute>
              <attribute maturity="stable">
                <name>server_local_privatekey_passphrase</name>
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
                  Passphrase used to access <parameter>server_local_privatekey</parameter>.
                </description>
              </attribute>
              <attribute maturity="stable" internal="yes">
                <name>server_local_certificate</name>
                <type>X509:empty:RW:RW</type>
                <default>empty</default>
                <conftime>
                  <read/>
                  <write/>
                </conftime>
                <runtime>
                  <read/>
                  <write/>
                </runtime>
                <description>
                  The certificate to be used on the server side, associated with <parameter>server_local_privatekey</parameter>.
                </description>
              </attribute>
              <attribute maturity="stable" internal="yes">
                <name>server_peer_certificate</name>
                <type>X509:empty:R:R</type>
                <default>empty</default>
                <conftime>
                  <read/>
                </conftime>
                <runtime>
                  <read/>
                </runtime>
                <description>
                  The certificate returned by the peer on the server side.
                </description>
              </attribute>
              <attribute maturity="stable" internal="yes">
                <name>server_local_ca_list</name>
                <type>HASH;INTEGER;X509:empty:RW:RW</type>
                <default>empty</default>
                <conftime>
                  <read/>
                  <write/>
                </conftime>
                <runtime>
                  <read/>
                  <write/>
                </runtime>
                <description>
                  Hash of trusted certificates. The items in this hash are used to verify server certificates.
                </description>
              </attribute>
              <attribute maturity="stable" internal="yes">
                <name>server_peer_ca_list</name>
                <type>HASH;INTEGER;X509:empty:RW:RW</type>
                <default>empty</default>
                <conftime>
                  <read/>
                  <write/>
                </conftime>
                <runtime>
                  <read/>
                  <write/>
                </runtime>
                <description>
                  Hash of names of trusted CAs as returned by the server to aid the selection of a local certificate.
                </description>
              </attribute>
              <attribute maturity="stable" internal="yes">
                <name>server_local_crl_list</name>
                <type>HASH;INTEGER;X509_CRL:empty:RW:RW</type>
                <default>empty</default>
                <conftime>
                  <read/>
                  <write/>
                </conftime>
                <runtime>
                  <read/>
                  <write/>
                </runtime>
                <description>
                  Hash of Certificate Revocation Lists, associated to CA certificates in <parameter>server_local_ca_list</parameter>.
                </description>
              </attribute>
              <attribute maturity="stable">
                <name>server_ssl_method</name>
		<type>
		  <link id="enum.pssl.method"/>
		</type>
		<default>PSSL_METHOD_ALL</default>
		<conftime>
		  <read/>
		  <write/>
		</conftime>
		<runtime>
		  <read/>
		</runtime>
                <description>
                  Specifies the SSL/TLS protocols allowed on the server side.
                </description>
              </attribute>
              <attribute maturity="stable">
                <name>server_disable_proto_sslv2</name>
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
                  Specifies that SSLv2 should be disabled even if the method selection would otherwise support SSLv2.
                </description>
              </attribute>
              <attribute maturity="stable">
                <name>server_disable_proto_sslv3</name>
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
                  Specifies that SSLv3 should be disabled even if the method selection would otherwise support SSLv3.
                </description>
              </attribute>
              <attribute maturity="stable">
                <name>server_disable_proto_tlsv1</name>
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
                  Specifies that TLSv1 should be disabled even if the method selection would otherwise support TLSv1.
                </description>
              </attribute>
              <attribute maturity="stable">
                <name>server_ssl_cipher</name>
		<type>
		  <link id="enum.pssl.ciphers"/>
		</type>
		<default>PSSL_CIPHERS_ALL</default>
		<conftime>
		  <read/>
		  <write/>
		</conftime>
		<runtime>
		  <read/>
		</runtime>
                <description>
                  Specifies the ciphers allowed on the server side.
                </description>
              </attribute>
              <attribute maturity="stable">
                <name>server_check_subject</name>
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
                  Specifies
                  whether the Subject of the
                  server side certificate is
                  checked against application
                  layer information
                  (e.g.: whether it matches the
                  hostname in the URL). See also <xref linkend="certificate_verification"/>. 
                </description>
              </attribute>
              <attribute maturity="stable">
                <name>server_enable_renegotiation</name>
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
                  If set to TRUE, the server can request the renegotiation of the SSL connection.
                </description>
              </attribute>
            </attributes>
          </metainfo>
        </class>
        """
	name = "plug"

        compat_attributes = frozenset(( \
                'handshake_timeout', \
                'permit_invalid_certificates', \
                'handshake_seq', \
                'client_handshake', \
                'client_verify_type', \
                'client_verify_depth', \
                'client_local_privatekey', \
                'client_local_privatekey_passphrase', \
                'client_local_certificate', \
                'client_peer_certificate', \
                'client_local_ca_list', \
                'client_local_crl_list', \
                'client_ssl_method', \
                'client_disable_proto_sslv2', \
                'client_disable_proto_sslv3', \
                'client_disable_proto_tlsv1', \
                'client_ssl_cipher', \
                'server_handshake', \
                'server_verify_type', \
                'server_verify_depth', \
                'server_local_privatekey', \
                'server_local_privatekey_passphrase', \
                'server_local_certificate', \
                'server_peer_certificate', \
                'server_local_ca_list', \
                'server_peer_ca_list', \
                'server_local_crl_list', \
                'server_ssl_method', \
                'server_disable_proto_sslv2', \
                'server_disable_proto_sslv3', \
                'server_disable_proto_tlsv1', \
                'server_ssl_cipher', \
                'server_check_subject', \
                'client_cert_file', \
                'client_key_file', \
                'client_keypair_files', \
                'client_keypair_generate', \
                'client_ca_directory', \
                'client_crl_directory', \
                'client_cagroup_directories', \
                'client_trusted_certs_directory', \
                'server_cert_file', \
                'server_key_file', \
                'server_keypair_files', \
                'server_keypair_generate', \
                'server_ca_directory', \
                'server_crl_directory', \
                'server_cagroup_directories', \
                'server_trusted_certs_directory', \
                'key_generator', \
                'client_cert', \
                'client_key', \
                'server_cert', \
                'server_key' ))

        compat_value_ssl_enabled = { \
                FALSE: PSSL_NONE, \
                TRUE: PSSL_FORCE_SSL
        }

        compat_value_ssl_enabled_rev = { \
                PSSL_NONE: FALSE, \
                PSSL_FORCE_SSL: TRUE
        }

	def __init__(self, session):
		"""<method internal="yes">
        	  <summary>
                    Constructor to initialize a PsslProxy instance.
                  </summary>
                  <description>
                    <para>
                      Sets attributes based on arguments, and calls the inherited
                      constructor.
                    </para>
                  </description>
                  <metainfo>
                    <attributes>
                      <attribute maturity="stable">
                        <name>session</name>
                        <type>Session</type>
                        <description>
                          the reference of the owning session
                        </description>
                      </attribute>
                      <attribute maturity="stable">
                        <name>type</name>
                        <type></type>
                        <description>
                          type of this session, must indicate STREAM session, since SSL is supported only on TCP streams
                        </description>
                      </attribute>
                    </attributes>
                  </metainfo>
                </method>
                """
		self.stack_proxy = None
		AbstractPlugProxy.__init__(self, session)

	def __pre_config__(self):
		"""<method internal="yes">
                </method>
                """
		AbstractPlugProxy.__pre_config__(self)
		self.ssl.key_generator = self.key_generator
		self.ssl.client_connection_security = PSSL_FORCE_SSL
		self.ssl.server_connection_security = PSSL_FORCE_SSL

	def requestStack(self):
		"""<method internal="yes">
                  <summary>
                    Function used to query whether to stack anything to Pssl.
                  </summary>
                  <description>
                    <para>
                      Callback called by the underlying C proxy to query if
                      something is to be stacked.
                    </para>
                  </description>
                  <metainfo>
                    <arguments/>
                  </metainfo>
                </method>
                """
		return self.stack_proxy

        def __setattr__(self, name, value):
                if name == "client_need_ssl":
                        setattr(self.ssl, "client_connection_security", self.compat_value_ssl_enabled[value])
                elif name == "server_need_ssl":
                        setattr(self.ssl, "server_connection_security", self.compat_value_ssl_enabled[value])
                elif name in self.compat_attributes:
                        setattr(self.ssl, name, value)
                else:
                        super(AbstractPsslProxy, self).__setattr__(name, value)

        def __getattr__(self, name):
                if name == "client_need_ssl":
                        value = getattr(self.ssl, "client_connection_security")
                        value = self.compat_value_ssl_enabled_rev[value]
                elif name == "server_need_ssl":
                        value = getattr(self.ssl, "server_connection_security")
                        value = self.compat_value_ssl_enabled_rev[value]
                elif name in self.compat_attributes:
                        value = getattr(self.ssl, name)
                else:
                        value = super(AbstractPsslProxy, self).getattr(name)
                return value

class PsslProxy(AbstractPsslProxy):
	"""<class maturity="stable">
          <summary>
            Default Pssl proxy based on AbstractPsslProxy.
          </summary>
          <description>
            <para>
              This proxy is a compatibility wrapper for core SSL functionality. The documentation was left intact for reference, but SSL attributes should be used in each protocol proxy instead of this wrapper.
              PsslProxy is a default class for proxying SSL/TLS connections based on AbstractPsslProxy.
            </para>
          </description>
          <metainfo>
            <attributes>
              <attribute maturity="stable">
                <name>client_cert_file</name>
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
                  File containing the client side certificate.
                </description>
              </attribute>
              <attribute maturity="stable">
                <name>client_key_file</name>
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
                  File containing the client side private key.
                </description>
              </attribute>
              <attribute state="stable">
                <name>client_keypair_files</name>
		<type>
		  <certificate cert="yes" key="yes"/>
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
                  A tuple of two file names containing the certificate and
                  key files. Using <parameter>client_keypair_files</parameter> is alternative to using
                  the <parameter>client_cert_file</parameter> and <parameter>client_key_file</parameter> attributes.
                </description>
              </attribute>
              <attribute state="stable">
                <name>client_keypair_generate</name>
		<type>
		  <boolean/>
		</type>
		<default>FALSE</default>
		<conftime>
		  <read/>
		  <write/>
		</conftime>
		<runtime/>
                <description>
                  Enables keybridging towards the clients. (Specifies whether to generate new certificates.)
                </description>
              </attribute>
              <attribute maturity="stable">
                <name>client_ca_directory</name>
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
                  Directory where the trusted CA certificates are stored.
                </description>
              </attribute>
              <attribute maturity="stable">
                <name>client_crl_directory</name>
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
                  Directory where the CRLs associated with trusted CAs are stored.
                </description>
              </attribute>
              <attribute state="stable">
                <name>client_cagroup_directories</name>
                <type>
                  <cagroup/>
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
                  A tuple of the trusted CA certificate directory and
                  the corresponding CRL directory.
                </description>
              </attribute>
              <attribute state="stable">
                <name>client_trusted_certs_directory</name>
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
                  A directory where trusted IP - certificate assignments are
                  stored.  When a specific IP address introduces itself with the
                  certificate stored in this directory, it is accepted regardless of
                  its expiration or issuer CA. Each file in the directory should
                  contain a certificate in PEM format and have the name of the IP
                  address.
                </description>
              </attribute>
              <attribute maturity="stable">
                <name>server_cert_file</name>
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
                  File containing the server side certificate.
                </description>
              </attribute>
              <attribute maturity="stable">
                <name>server_key_file</name>
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
                  File containing the server side private key.
                </description>
              </attribute>
              <attribute state="stable">
                <name>server_keypair_files</name>
                <type>
                  <certificate cert="yes" key="yes"/>
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
                  A tuple of two file names containing the certificate and key
                  files. Using <parameter>client_keypair_files</parameter> is alternative to use the
                  <parameter>client_cert_file</parameter> and <parameter>client_key_file</parameter> attributes.
                </description>
              </attribute>
              <attribute state="stable">
                <name>server_keypair_generate</name>
                <type>
                  <boolean/>
                </type>
                <default>FALSE</default>
                <conftime>
                  <read/>
                  <write/>
                </conftime>
                <runtime/>
                <description>
                  Enables keybridging towards the server. (Specifies whether to generate new certificates.)
                </description>
              </attribute>
              <attribute maturity="stable">
                <name>server_ca_directory</name>
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
                  Directory where the trusted CA certificates are stored.
                </description>
              </attribute>
              <attribute maturity="stable">
                <name>server_crl_directory</name>
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
                  Directory where the CRLs associated with the trusted CAs are stored.
                </description>
              </attribute>
              <attribute state="stable">
                <name>server_cagroup_directories</name>
                <type>
                  <cagroup/>
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
                  A tuple of the trusted CA certificate directory and the corresponding
                  CRL directory.
                </description>
              </attribute>
              <attribute state="stable">
                <name>server_trusted_certs_directory</name>
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
                  A directory where trusted IP:port - certificate assignments are
                  stored. When a specific IP address introduces itself with the
                  certificate stored in this directory, it is accepted regardless
                  of its expiration or issuer CA. Each file in the directory should
                  contain a certificate in PEM format and should be named as
                  'IP:PORT'.
                </description>
              </attribute>
              <attribute state="stable" global="yes">
                <name>key_generator</name>
                <type>
                  <class filter="x509keymanager" instance="yes"/>
                </type>
                <conftime>
                  <read/>
                  <write/>
                </conftime>
                <runtime/>
                <description>
                  An instance of a X509KeyManager or derived class to generate keys
                  automatically based on the keys on one of the other peers. Use
                  X509KeyBridge to generate certificates automatically with a 
                  firewall hosted local CA.
                </description>
              </attribute>
              <attribute maturity="obsolete">
                <name>client_cert</name>
                <type></type>
                <description>
                  Alias for Zorp 0.8 compatibility
                  same as client_cert_file
                </description>
              </attribute>
              <attribute maturity="obsolete">
                <name>client_key</name>
                <type></type>
                <description>
                  Alias for Zorp 0.8 compatibility
                  same as client_key_file
                </description>
              </attribute>
              <attribute maturity="obsolete">
                <name>server_cert</name>
                <type></type>
                <description>
                  Alias for Zorp 0.8 compatibility
                  same as server_cert_file
                </description>
              </attribute>
              <attribute maturity="obsolete">
                <name>server_key</name>
                <type></type>
                <description>
                  Alias for Zorp 0.8 compatibility
                  same as server_key_file
                </description>
              </attribute>
            </attributes>
          </metainfo>
        </class>
        """
	key_generator = None



