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
  <summary>The Proxy module defines the abstract proxy class.</summary>
  <description>
    <para>
      This module encapsulates the ZorpProxy component
      implemented by the Zorp core. The Proxy module provides a common framework for
      protocol-specific proxies, implementing the functions that are used by all proxies.
      Protocol-specific proxy modules are derived from the Proxy module, and are
      described in <xref linkend="chapter_Proxies"/>.
    </para>
    <para>
        Starting with Zorp 3.3FR1, the Proxy module provides a common SSL/TLS framework for the Zorp proxies as well. This SSL framework replaces and extends the functionality of the Pssl proxy, providing support for STARTTLS as well. The Pssl proxy has become obsolete, but still provides a compatibility layer for older configuration files, but you are recommended to update your configuration to use the new SSL framework as soon as possible. The SSL framework is described in <xref linkend="chapter_ssl"/>.
    </para>
    <note>
        <para>STARTTLS support is currently available only for the Ftp proxy to support FTPS sessions.</para>
    </note>
    <inline type="enum" target="enum.ssl.verify"/>
    <inline type="enum" target="enum.ssl.method"/>
    <inline type="enum" target="enum.ssl.ciphers"/>
    <inline type="enum" target="enum.ssl.hso"/>
    <inline type="enum" target="enum.ssl.client_connection_security"/>
    <inline type="enum" target="enum.ssl.server_connection_security"/>
    <inline type="const" target="const.ssl.log"/>
    <inline type="const" target="const.ssl.hs"/>
  </description>
  <metainfo>
    <enums>
      <enum maturity="stable" id="enum.ssl.verify">
        <description>
          Certificate verification settings
        </description>
        <item>
          <name>SSL_VERIFY_NONE</name>
          <description>Automatic certificate verification is disabled.</description>
        </item>
<!--        <item>
          <name>SSL_VERIFY_OPTIONAL</name>
          <description>Certificate is optional, all certificates are accepted.</description>
        </item>-->
        <item>
          <name>SSL_VERIFY_OPTIONAL_UNTRUSTED</name>
          <description>Certificate is optional, if present, both trusted and untrusted certificates are accepted.</description>
        </item>
        <item>
          <name>SSL_VERIFY_OPTIONAL_TRUSTED</name>
          <description>Certificate is optional, but if a certificate is present, only  certificates signed by a trusted CA are accepted.</description>
        </item>
        <item>
          <name>SSL_VERIFY_REQUIRED_UNTRUSTED</name>
          <description>Valid certificate is required, both trusted and untrusted certificates are accepted.</description>
        </item>
        <item>
          <name>SSL_VERIFY_REQUIRED_TRUSTED</name>
          <description>Certificate is required, only valid certificates signed by a trusted CA are accepted.</description>
        </item>
      </enum>
      <enum maturity="stable" id="enum.ssl.method">
        <description>
          Constants for SSL/TLS protocol selection
        </description>
        <item>
          <name>SSL_METHOD_SSLV23</name>
          <description>
           Permit the use of SSLv2 and v3.
          </description>
        </item>
        <item>
          <name>SSL_METHOD_SSLV2</name>
          <description>
           Permit the use of SSLv2 exclusively.
          </description>
        </item>
        <item>
          <name>SSL_METHOD_SSLV3</name>
          <description>
                Permit the use of SSLv3 exclusively.
          </description>
        </item>
        <item>
          <name>SSL_METHOD_TLSV1</name>
          <description>
                Permit the use of TLSv1 exclusively.
          </description>
        </item>
        <item>
          <name>SSL_METHOD_ALL</name>
          <description>
           Permit the use of all the supported (SSLv2, SSLv3, and TLSv1) protocols.
          </description>
        </item>
      </enum>
      <enum maturity="stable" id="enum.ssl.ciphers">
        <description>
          Constants for cipher selection
        </description>
        <item>
          <name>SSL_CIPHERS_ALL</name>
          <description>
           Permit the use of all supported ciphers, including the 40 and 56 bit exportable ciphers.
          </description>
        </item>
        <item>
          <name>SSL_CIPHERS_HIGH</name>
          <description>
                Permit only the use of ciphers which use at least 128 bit long keys.
          </description>
        </item>
        <item>
          <name>SSL_CIPHERS_MEDIUM</name>
          <description>
                Permit only the use of ciphers which use 128 bit long keys.
          </description>
        </item>
        <item>
          <name>SSL_CIPHERS_LOW</name>
          <description>
                Permit only the use of ciphers which use keys shorter then 128 bits.
          </description>
        </item>
      </enum>
      <enum maturity="stable" id="enum.ssl.hso">
        <description>
          Handshake order.
        </description>
        <item>
          <name>SSL_HSO_CLIENT_SERVER</name>
          <description>
                Perform the SSL-handshake with the client first.
          </description>
        </item>
        <item>
          <name>SSL_HSO_SERVER_CLIENT</name>
          <description>
                Perform the SSL-handshake with the server first.
          </description>
        </item>
      </enum>
      <enum maturity="stable" id="enum.ssl.client_connection_security">
        <description>
          Client connection security type.
        </description>
        <item>
          <name>SSL_NONE</name>
          <description>
                Disable encryption between Zorp and the peer.
          </description>
        </item>
        <item>
          <name>SSL_FORCE_SSL</name>
          <description>
                Require encrypted communication between Zorp and the peer.
          </description>
        </item>
        <item>
          <name>SSL_ACCEPT_STARTTLS</name>
          <description>
                Permit STARTTLS sessions. Currently supported only in the Ftp proxy.
          </description>
        </item>
      </enum>
      <enum maturity="stable" id="enum.ssl.server_connection_security">
        <description>
          Server connection security type.
        </description>
        <item>
          <name>SSL_NONE</name>
          <description>
                Disable encryption between Zorp and the peer.
          </description>
        </item>
        <item>
          <name>SSL_FORCE_SSL</name>
          <description>
                Require encrypted communication between Zorp and the peer.
          </description>
        </item>
        <item>
          <name>SSL_FORWARD_STARTTLS</name>
          <description>
                Forward STARTTLS requests to the server. Currently supported only in the Ftp proxy.
          </description>
        </item>
      </enum>
    </enums>
    <constants>
      <constantgroup maturity="stable" id="const.ssl.log">
        <description>
          Verbosity level of the log messages
        </description>
        <item>
          <name>SSL_ERROR</name>
          <description>
                Log only errors of the SSL framework.
          </description>
        </item>
        <item>
          <name>SSL_DEBUG</name>
          <description>
                Enable verbose logging of the SSL framework.
          </description>
        </item>
      </constantgroup>
      <constantgroup maturity="stable" id="const.ssl.hs">
        <description>
          Handshake policy decisions
        </description>
        <item>
          <name>SSL_HS_ACCEPT</name>
          <value>0</value>
          <description>
                Accept the connection.
          </description>
        </item>
        <item>
          <name>SSL_HS_REJECT</name>
          <value>1</value>
          <description>
                Reject the connection.
          </description>
        </item>
        <item>
          <name>SSL_HS_POLICY</name>
          <value>6</value>
          <description>
                Use a policy to decide about the connection.
          </description>
        </item>
        <item>
          <name>SSL_HS_VERIFIED</name>
          <value>10</value>
          <description>
                <!--FIXME-->
          </description>
        </item>
      </constantgroup>
    </constants>
  </metainfo>
</module>
"""

from Zorp import *
from Stream import Stream
from SockAddr import SockAddrInet, getHostByName
from Session import StackedSession, MasterSession
from Stack import getStackingProviderBackend
from Keybridge import *

import string, os, sys, traceback, re, types

SSL_ERROR      = 'core.error'
SSL_DEBUG      = 'core.debug'
SSL_INFO       = 'core.info'
SSL_VIOLATION  = 'core.violation'

SSL_VERIFY_NONE                = 0
SSL_VERIFY_OPTIONAL            = 1
SSL_VERIFY_OPTIONAL_UNTRUSTED  = 1
SSL_VERIFY_OPTIONAL_TRUSTED    = 2
SSL_VERIFY_REQUIRED_UNTRUSTED  = 3
SSL_VERIFY_REQUIRED_TRUSTED    = 4

# handshake order
SSL_HSO_CLIENT_SERVER   = 0
SSL_HSO_SERVER_CLIENT   = 1

# handshake policy decisions
SSL_HS_ACCEPT           = 1
SSL_HS_REJECT           = 3
SSL_HS_POLICY           = 6
SSL_HS_VERIFIED         = 10

SSL_METHOD_SSLV23       = "SSLv23"
SSL_METHOD_SSLV2        = "SSLv2"
SSL_METHOD_SSLV3        = "SSLv3"
SSL_METHOD_TLSV1        = "TLSv1"
SSL_METHOD_ALL          = "SSLv23"

SSL_CIPHERS_ALL         = "ALL:!aNULL:@STRENGTH"

SSL_CIPHERS_HIGH        = "HIGH:!aNULL:@STRENGTH"
SSL_CIPHERS_MEDIUM      = "HIGH:MEDIUM:!aNULL:@STRENGTH"
SSL_CIPHERS_LOW         = "HIGH:MEDIUM:LOW:EXPORT:!aNULL:@STRENGTH"

# connection security settings
SSL_NONE                = 0
SSL_FORCE_SSL           = 1
SSL_ACCEPT_STARTTLS     = 2
SSL_FORWARD_STARTTLS    = 3

def proxyLog(self, type, level, msg, args=None):
        """
        <function maturity="stable">
          <summary>
            Function to send a proxy-specific message to the system log.
          </summary>
          <description>
            <para>
              This function sends a message into the system log. All messages start with the
              <parameter>session_id</parameter> that uniquely identifies the connection.
            </para>
          </description>
          <metainfo>
            <arguments>
              <argument maturity="stable">
                <name>type</name>
                <type>
                  <string/>
                </type>
                <description>
                  The class of the log message.
                </description>
              </argument>
              <argument maturity="stable">
                <name>level</name>
                <type>
                  <integer/>
                </type>
                <description>
                  Verbosity level of the log message.
                </description>
              </argument>
              <argument maturity="stable">
                <name>msg</name>
                <type>
                  <string/>
                </type>
                <description>
                  The text of the log message.
                </description>
              </argument>
            </arguments>
          </metainfo>
        </function>
        """
        ## NOLOG ##
        log(self.session.session_id, type, level, msg, args)

class Proxy(BuiltinProxy):
        """
        <class maturity="stable" abstract="yes">
          <summary>
            Class encapsulating the abstract Zorp proxy.
          </summary>
          <description>
            <para>
              This class serves as the abstact base class for all proxies implemented
              in Zorp. When an instance of the Proxy class is created, it loads and starts a protocol-specific proxy.
              Proxies operate in their own threads, so this constructor returns immediately.
            </para>
          </description>
          <metainfo>
            <attributes>
              <attribute maturity="stable" internal="yes">
                <name>session</name>
                <type>Session instance</type>
                <description>The session inspected by the proxy.</description>
              </attribute>
              <attribute maturity="stable" internal="yes">
                <name>name</name>
                <type>
                  <string/>
                </type>
                <description>The protocol-specific proxy class inspecting the traffic.</description>
              </attribute>
              <attribute maturity="stable" global="yes">
                <name>auth_inband_defer</name>
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
                Set this parameter to <parameter>TRUE</parameter> to enable the protocol-specific proxy to perform
                inband authentication. This has effect only if the <link linkend="python.Auth">AuthenticationPolicy</link> used in
                the service requests InbandAuthentication.
                </description>
              </attribute>
              <attribute>
                <name>language</name>
                <type>
                  <string/>
                </type>
                <default>en</default>
                <conftime>
                  <read/>
                  <write/>
                </conftime>
                <runtime>
                  <read/>
                </runtime>
                <description>
                  Determines the language used for user-visible error messages.
                  Supported languages: <parameter>en</parameter> - English;
                  <parameter>de</parameter> -  German; <parameter>hu</parameter> - Hungarian.
                </description>
              </attribute>

              <!-- SSL attributes -->
              <attribute maturity="stable">
                <name>ssl.handshake_timeout</name>
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
                <name>ssl.permit_invalid_certificates</name>
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
                <name>ssl.handshake_seq</name>
                <type>
                  <link id="enum.ssl.hso"/>
                </type>
                <default>SSL_HSO_CLIENT_SERVER</default>
                <conftime>
                  <read/>
                  <write/>
                </conftime>
                <runtime>
                  <read/>
                </runtime>
                <description>
                  Handshake order. SSL_HSO_CLIENT_SERVER performs the client side handshake first, SSL_HSO_SERVER_CLIENT the server side.
                </description>
              </attribute>
              <attribute maturity="stable">
                <name>ssl.client_connection_security</name>
                <type>
                  <link id="enum.ssl.client_connection_security"/>
                </type>
                <default>SSL_NONE</default>
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
                <name>ssl.client_handshake</name>
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
                <name>ssl.client_verify_type</name>
                <type>
                  <link id="enum.ssl.verify"/>
                </type>
                <default>SSL_VERIFY_REQUIRED_TRUSTED</default>
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
                <name>ssl.client_verify_depth</name>
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
                <name>ssl.client_local_privatekey</name>
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
                <name>ssl.client_local_privatekey_passphrase</name>
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
                  Passphrase used to access <parameter>ssl.client_local_privatekey</parameter>.
                </description>
              </attribute>
              <attribute maturity="stable" internal="yes">
                <name>ssl.client_local_certificate</name>
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
                  The certificate associated to <parameter>ssl.client_local_privatekey</parameter> to be used on the client side.
                </description>
              </attribute>
              <attribute maturity="stable" internal="yes">
                <name>ssl.client_peer_certificate</name>
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
                <name>ssl.client_local_ca_list</name>
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
                <name>ssl.client_local_crl_list</name>
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
                  A hash of Certificate Revocation Lists, associated to CA certificates in <parameter>ssl.client_local_ca_list</parameter>.
                </description>
              </attribute>
              <attribute maturity="stable">
                <name>ssl.client_ssl_method</name>
                <type>
                  <link id="enum.ssl.method"/>
                </type>
                <default>SSL_METHOD_ALL</default>
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
                <name>ssl.client_disable_proto_sslv2</name>
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
                <name>ssl.client_disable_proto_sslv3</name>
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
                <name>ssl.client_disable_proto_tlsv1</name>
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
                <name>ssl.client_ssl_cipher</name>
                <type>
                  <link id="enum.ssl.ciphers"/>
                </type>
                <default>SSL_CIPHERS_ALL</default>
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
                <name>ssl.server_connection_security</name>
                <type>
                  <link id="enum.ssl.server_connection_security"/>
                </type>
                <default>SSL_NONE</default>
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
                <name>ssl.server_handshake</name>
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
                <name>ssl.server_verify_type</name>
                <type>
                  <link id="enum.ssl.verify"/>
                </type>
                <default>SSL_VERIFY_REQUIRED_TRUSTED</default>
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
                <name>ssl.server_verify_depth</name>
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
                <name>ssl.server_local_privatekey</name>
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
                  The private key of the firewall on the server side, specified as a string in PEM format.
                  Server side key and certificate are optional.
                </description>
              </attribute>
              <attribute maturity="stable">
                <name>ssl.server_local_privatekey_passphrase</name>
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
                  Passphrase used to access <parameter>ssl.server_local_privatekey</parameter>.
                </description>
              </attribute>
              <attribute maturity="stable" internal="yes">
                <name>ssl.server_local_certificate</name>
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
                  The certificate to be used on the server side, associated with <parameter>ssl.server_local_privatekey</parameter>.
                </description>
              </attribute>
              <attribute maturity="stable" internal="yes">
                <name>ssl.server_peer_certificate</name>
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
                <name>ssl.server_local_ca_list</name>
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
                <name>ssl.server_peer_ca_list</name>
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
                <name>ssl.server_local_crl_list</name>
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
                <name>ssl.server_ssl_method</name>
                <type>
                  <link id="enum.ssl.method"/>
                </type>
                <default>SSL_METHOD_ALL</default>
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
                <name>ssl.server_disable_proto_sslv2</name>
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
                <name>ssl.server_disable_proto_sslv3</name>
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
                <name>ssl.server_disable_proto_tlsv1</name>
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
                <name>ssl.server_ssl_cipher</name>
                <type>
                  <link id="enum.ssl.ciphers"/>
                </type>
                <default>SSL_CIPHERS_ALL</default>
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
                <name>ssl.server_check_subject</name>
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

              <!-- FIXME: SSL attributes -->

              <attribute maturity="stable">
                <name>ssl.client_cert_file</name>
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
                  File containing the client-side certificate.
                </description>
              </attribute>
              <attribute maturity="stable">
                <name>ssl.client_key_file</name>
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
                  File containing the client-side private key.
                </description>
              </attribute>
              <attribute state="stable">
                <name>ssl.client_keypair_files</name>
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
                  key files. Using <parameter>ssl.client_keypair_files</parameter> is an alternative to using
                  the <parameter>ssl.client_cert_file</parameter> and <parameter>ssl.client_key_file</parameter> attributes.
                </description>
              </attribute>
              <attribute state="stable">
                <name>ssl.client_keypair_generate</name>
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
                <name>ssl.client_ca_directory</name>
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
                <name>ssl.client_crl_directory</name>
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
                <name>ssl.client_cagroup_directories</name>
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
                <name>ssl.client_trusted_certs_directory</name>
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
                <name>ssl.server_cert_file</name>
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
                  File containing the server-side certificate.
                </description>
              </attribute>
              <attribute maturity="stable">
                <name>ssl.server_key_file</name>
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
                  File containing the server-side private key.
                </description>
              </attribute>
              <attribute state="stable">
                <name>ssl.server_keypair_files</name>
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
                  files. Using <parameter>ssl.server_keypair_files</parameter> is an alternative to using the
                  <parameter>ssl.server_cert_file</parameter> and <parameter>ssl.server_key_file</parameter> attributes.
                </description>
              </attribute>
              <attribute state="stable">
                <name>ssl.server_keypair_generate</name>
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
                <name>ssl.server_ca_directory</name>
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
                <name>ssl.server_crl_directory</name>
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
                <name>ssl.server_cagroup_directories</name>
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
                <name>ssl.server_trusted_certs_directory</name>
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
              <attribute state="stable">
                <name>ssl.key_generator</name>
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

            </attributes>
          </metainfo>
        </class>
        """
        name = None
        module = None
        auth_inband_defer = FALSE
        auth_inband_supported = FALSE
        auth_server_supported = FALSE

        def __init__(self, session):
                """
                <method internal="yes">
                  <summary>
                    Constructor to initialize an instance of the Proxy class.
                  </summary>
                  <description>
                    <para>
                      This constructor creates a new Proxy instance
                      which creates an instance of the protocol-specific proxy class.
                    </para>
                  </description>
                  <metainfo>
                    <arguments>
                      <argument maturity="stable">
                        <name>name</name>
                        <type></type>
                        <description>The protocol-specific proxy class inspecting the traffic.</description>
                      </argument>
                      <argument maturity="stable">
                        <name>session</name>
                        <type>SESSION</type>
                        <description>The session inspected by the proxy.</description>
                      </argument>
                    </arguments>
                  </metainfo>
                </method>
                """
                # NOTE: circular reference, it is resolved in the __destroy__ method
                self.session = session
                self.session.proxy = self
                setattr(self.session, self.name, self)

                self.server_fd_picked = FALSE
                self.proxy_started = FALSE
                session.setProxy(self.name)

                ## LOG ##
                # This message reports that a new proxy instance was started.
                ##
                log(session.session_id, CORE_SESSION, 5, "Proxy starting; class='%s', proxy='%s'", (self.__class__.__name__, self.name))
                if session.owner:
                        parent = session.owner.proxy
                else:
                        parent = None
                if not self.module:
                        self.module = self.name

                super(Proxy, self).__init__(self.name, self.module, session.session_id, session.client_stream, parent)

        def __del__(self):
                """
                <method internal="yes">
                  <summary>
                    Destructor to deinitialize a Proxy instance.
                  </summary>
                  <description>
                    <para>
                      This destructor is called when this object instance is
                      freed. It simply sends a message about this event to the
                      log.
                    </para>
                  </description>
                  <metainfo>
                    <arguments/>
                  </metainfo>
                </method>
                """

                ## LOG ##
                # This message reports that this proxy instance was ended.
                ##
                log(self.session.session_id, CORE_SESSION, 5, "Proxy ending; class='%s', module='%s'", (self.__class__.__name__, self.name))

        def __pre_startup__(self):
                """
                <method internal="yes">
                </method>
                """
                pass


        def __pre_config__(self):
                """
                <method internal="yes">
                  <summary>
                    Function called by the proxy core to perform internal proxy initialization.
                  </summary>
                  <description>
                    <para>
                      This function is similar to config() to perform initialization
                      of internal proxy related data. It is not meant as a user
                      interface, currently it is used to perform outband authentication.
                    </para>
                  </description>
                  <metainfo>
                    <arguments/>
                  </metainfo>
                </method>
                """
                if not self.session.auth_user and self.session.service.authentication_policy:
                        self.session.service.authentication_policy.performAuthentication(self.session)

                # hack: decrease timeout for UDP sessions
                if (self.session.protocol == ZD_PROTO_UDP) and self.timeout > 60000:
                        self.timeout = 60000
                self.language = config.options.language

                self.ssl.client_trusted_certs_directory = ''
                self.ssl.server_trusted_certs_directory = ''
                self.ssl.client_keypair_generate = FALSE
                self.ssl.server_keypair_generate = FALSE
                self.ssl.client_certificate_trusted = FALSE
                self.ssl.server_certificate_trusted = FALSE

                self.ssl.client_handshake["verify_cert_ext"] = (SSL_HS_POLICY, self.verifyTrustedCertClient)
                self.ssl.server_handshake["verify_cert_ext"] = (SSL_HS_POLICY, self.verifyTrustedCertServer)

        def __post_config__(self):
                """<method internal="yes">
                </method>
                """
                if self.ssl.client_keypair_generate == TRUE and self.ssl.server_keypair_generate == TRUE:
                        raise ValueError, 'client_keypair_generate and server_keypair_generate are both enabled. '\
                                'Key generation cannot work on both sides at the same time.'

                if self.ssl.client_connection_security > SSL_NONE:
                        if hasattr(self.ssl, "client_cert") and type(self.ssl.client_cert) == types.StringType:
                                self.ssl.client_cert_file = self.ssl.client_cert
                        if hasattr(self.ssl, "client_key") and type(self.ssl.client_key) == types.StringType:
                                self.ssl.client_key_file = self.ssl.client_key

                        if hasattr(self.ssl, "client_keypair_files"):
                                self.ssl.client_cert_file = self.ssl.client_keypair_files[0]
                                self.ssl.client_key_file = self.ssl.client_keypair_files[1]

                        if hasattr(self.ssl, "client_cagroup_directories"):
                                self.ssl.client_ca_directory = self.ssl.client_cagroup_directories[0]
                                self.ssl.client_crl_directory = self.ssl.client_cagroup_directories[1]

                        if hasattr(self.ssl, "client_cert_file"):
                                proxyLog(self, SSL_DEBUG, 6, "Compatibility feature, processing client_cert_file; value='%s'" % self.ssl.client_cert_file)
                                self.ssl.client_local_certificate = self.readPEM(self.ssl.client_cert_file)

                        if hasattr(self.ssl, "client_key_file"):
                                proxyLog(self, SSL_DEBUG, 6, "Compatibility feature, processing client_key_file; value='%s'" % self.ssl.client_key_file)
                                self.ssl.client_local_privatekey = self.readPEM(self.ssl.client_key_file)

                        if hasattr(self.ssl, "client_ca_directory"):
                                proxyLog(self, SSL_DEBUG, 6, "Compatibility feature, processing client_ca_directory; value='%s'" % self.ssl.client_ca_directory)
                                self.readHashDir(self.ssl.client_local_ca_list, self.ssl.client_ca_directory)

                        if hasattr(self.ssl, "client_crl_directory"):
                                proxyLog(self, SSL_DEBUG, 6, "Compatibility feature, processing client_crl_directory; value='%s'" % self.ssl.client_crl_directory)
                                self.readHashDir(self.ssl.client_local_crl_list, self.ssl.client_crl_directory)

                        if self.ssl.client_keypair_generate:
                                if self.ssl.handshake_seq != SSL_HSO_SERVER_CLIENT:
                                        raise ValueError, "For client-side keypair generation, the handshake order"\
                                                " must be SSL_HSO_SERVER_CLIENT."
                                else:
                                        self.ssl.client_handshake["setup_key"] = (SSL_HS_POLICY, self.generateKeyClient)

                if self.ssl.server_connection_security > SSL_NONE:
                        if hasattr(self.ssl, "server_cert") and type(self.ssl.server_cert) == types.StringType:
                                self.ssl.server_cert_file = self.ssl.server_cert
                        if hasattr(self.ssl, "server_key") and type(self.ssl.server_key) == types.StringType:
                                self.ssl.server_key_file = self.ssl.server_key

                        if hasattr(self.ssl, "server_keypair_files"):
                                self.ssl.server_cert_file = self.ssl.server_keypair_files[0]
                                self.ssl.server_key_file = self.ssl.server_keypair_files[1]

                        if hasattr(self.ssl, "server_cagroup_directories"):
                                self.ssl.server_ca_directory = self.ssl.server_cagroup_directories[0]
                                self.ssl.server_crl_directory = self.ssl.server_cagroup_directories[1]

                        if hasattr(self.ssl, "server_cert_file"):
                                proxyLog(self, SSL_DEBUG, 6, "Compatibility feature, processing server_cert_file; value='%s'" % self.ssl.server_cert_file)
                                self.ssl.server_local_certificate = self.readPEM(self.ssl.server_cert_file)

                        if hasattr(self.ssl, "server_key_file"):
                                proxyLog(self, SSL_DEBUG, 6, "Compatibility feature, processing server_key_file; value='%s'" % self.ssl.server_key_file)
                                self.ssl.server_local_privatekey = self.readPEM(self.ssl.server_key_file)

                        if hasattr(self.ssl, "server_ca_directory"):
                                proxyLog(self, SSL_DEBUG, 6, "Compatibility feature, processing server_ca_directory; value='%s'" % self.ssl.server_ca_directory)
                                self.readHashDir(self.ssl.server_local_ca_list, self.ssl.server_ca_directory)

                        if hasattr(self.ssl, "server_crl_directory"):
                                proxyLog(self, SSL_DEBUG, 6, "Compatibility feature, processing server_crl_directory; value='%s'" % self.ssl.server_crl_directory)
                                self.readHashDir(self.ssl.server_local_crl_list, self.ssl.server_crl_directory)

                        if self.ssl.server_keypair_generate:
                                if self.ssl.handshake_seq != SSL_HSO_CLIENT_SERVER:
                                        raise ValueError, "For server-side keypair generation, the handshake order"\
                                                " must be SSL_HSO_CLIENT_SERVER."
                                else:
                                        self.ssl.server_handshake["setup_key"] = (SSL_HS_POLICY, self.generateKeyServer)

        def config(self):
                """
                <method maturity="stable">
                  <summary>
                    Function called by the proxy core to initialize the proxy instance.
                  </summary>
                  <description>
                    <para>
                      This function is called during proxy startup. It sets the attributes of the proxy instance according
                       to the configuration of the proxy.
                    </para>
                  </description>
                  <metainfo>
                    <arguments/>
                  </metainfo>
                </method>
                """
                pass

        def __destroy__(self):
                """
                <method internal="yes">
                  <summary>
                    Function called by the proxy core when the session is to be freed.
                  </summary>
                  <description>
                    <para>
                      This function is called when the proxy module is to be freed. It
                      simply sends a message about this event to the log.
                    </para>
                  </description>
                  <metainfo>
                    <arguments/>
                  </metainfo>
                </method>
                """
                # NOTE: if C proxy was started but the chaining process was
                # not completed then the server side of the connection is
                # still hanging there unpicked. Close it.

                if self.proxy_started and self.session.server_stream and not self.server_fd_picked:
                        self.session.server_stream.close()

                # free circular reference between session & proxy
                session = self.session
                del self.session.proxy
                delattr(self.session, self.name)

                ## LOG ##
                # This message reports that this proxy instance was destroyed and freed.
                ##
                log(self.session.session_id, CORE_DEBUG, 6, "Proxy destroy; class='%s', module='%s'", (self.__class__.__name__, self.name))
                # free possible circular references in __dict__ by removing all elements
                self.__dict__.clear()
                self.session = session

        def stackProxy(self, client_stream, server_stream, proxy_class, stack_info):
                """
                <method internal="yes">
                  <summary>
                    Function to embed (stack) a proxy into the current proxy instance.
                  </summary>
                  <description>
                    <para>
                      This function stacks a new proxy into the current proxy instance. The function receives the
                      downstream filedescriptors and the protocol-specific proxy class to embed.
                      The way the underlying proxy decides which proxy_class
                      to use is proxy specific.
                    </para>
                  </description>
                  <metainfo>
                    <arguments>
                      <argument maturity="stable">
                        <name>client_stream</name>
                        <type></type>
                        <description>The client-side data stream.</description>
                      </argument>
                      <argument maturity="stable">
                        <name>server_stream</name>
                        <type></type>
                        <description>The server-side data stream.</description>
                      </argument>
                      <argument maturity="stable">
                        <name>proxy_class</name>
                        <type></type>
                        <description>The protocol-specific proxy class to embed into the current proxy instance.
                        </description>
                      </argument>
                    </arguments>
                  </metainfo>
                </method>
                """

                ## LOG ##
                # This message reports that Zorp is about to stack a new proxy under the current proxy, as a child proxy.
                ##
                proxyLog(self, CORE_DEBUG, 7, "Stacking child proxy; client_fd='%d', server_fd='%d', class='%s'", (client_stream.fd, server_stream.fd, proxy_class.__name__))

                subsession = StackedSession(self.session)
                subsession.stack_info = stack_info
                session_id = string.split(self.session.session_id, '/')
                if len(session_id):
                        session_id[len(session_id)-1] = proxy_class.name
                        session_id = string.join(session_id, '/')
                else:
                        # hmm, funny session_id ...
                        session_id = self.session.session_id
                subsession.client_stream = client_stream
                subsession.client_stream.name = "%s/client_upstream" % (session_id)
                subsession.server_stream = server_stream
                subsession.server_stream.name = "%s/server_upstream" % (session_id)
                try:
                        proxy = proxy_class(subsession)
                        if ProxyGroup(1).start(proxy):
                                return proxy
                        else:
                                raise RuntimeError, "Error starting proxy in group"

                except:
                        ## LOG ##
                        # This message indicates that an error occurred during child proxy stacking.
                        # The stacking failed and the subsession is destroyed.
                        ##
                        proxyLog(self, CORE_ERROR, 2, "Error while stacking child proxy; error='%s', error_desc='%s', " % (sys.exc_info()[0], sys.exc_info()[1]))
                        subsession.destroy()
                        raise

                return None

        def stackCustom(self, args):
                """
                <method maturity="stable" internal="yes">
                  <summary>
                    Function to perform custom stacking.
                  </summary>
                  <description>
                    <para>
                      This function is called by the underlying C proxy to
                      stack a Stackin Provider (<parameter>Z_STACK_PROVIDER</parameter>), or to perform a customized
                       stacking (<parameter>Z_STACK_CUSTOM</parameter>) stacking.
                    </para>
                  </description>
                  <metainfo>
                    <arguments>
                      <argument maturity="stable">
                        <name>args</name>
                        <type></type>
                        <description>A tuple of custom stacking arguments.</description>
                      </argument>
                    </arguments>
                  </metainfo>
                </method>
                """

                ## LOG ##
                # This message reports that Zorp is about to stack a new proxy under the current proxy, as a child proxy.
                ##
                proxyLog(self, CORE_DEBUG, 7, "Stacking custom child; args='%s'", (str(args)))
                stack_info = None
                if isinstance(args[0], str):
                        # this is a Z_STACK_PROVIDER stacking,
                        # args[0] is provider name,
                        # args[1] is stack_info argument
                        stack_backend = getStackingProviderBackend(args[0])
                        stack_info = args[1]
                else:
                        # this is a Z_STACK_CUSTOM stacking
                        # args[0] is an AbstractStackingBackend instance
                        # args[1] is optional stack_info
                        stack_backend = args[0]
                        stack_info = args[1]
                return stack_backend.stack(stack_info)


        def setServerAddress(self, host, port):
                """
                <method maturity="stable">
                  <summary>
                    Function called by the proxy instance to set the
                    address of the destination server.
                  </summary>
                  <description>
                    <para>
                      The proxy instance calls this function to set the
                      address of the destination server.
                      This function attempts to resolve the hostname of the server using the DNS;
                      the result is stored in the <parameter>session.server_address</parameter> parameter.
                      The address of the server may be modified later by the router of the service. See
                      <xref linkend="python.Router"/> for details.
                    </para>
                    <note>
                    <para>
                    The <parameter>setServerAddress</parameter> function has effect
                     only when <link linkend="python.Router.InbandRouter">InbandRouter</link>
                      is used.
                    </para>
                    </note>
                  </description>
                  <metainfo>
                    <arguments>
                      <argument>
                        <name>host</name>
                        <type><string/></type>
                        <description>The host name of the server.</description>
                      </argument>
                      <argument>
                        <name>port</name>
                        <type><integer/></type>
                        <description>The Port number of the server.</description>
                      </argument>
                    </arguments>
                  </metainfo>
                </method>
                """
                # resolve host, port and store it in session.server_address
                # may raise an exception
                if self.session.target_address_inband:
                        target = self.session.service.resolver_policy.resolve(host, port)
                        if not target:
                                ## LOG ##
                                # This message indicates that the given hostname
                                # could not be resolved.  It could happen if the
                                # hostname is invalid or nonexistent, or it if your
                                # resolve setting are not well configured.  Check
                                # your "/etc/resolv.conf"
                                ##
                                proxyLog(self, CORE_ERROR, 3, "Error resolving hostname; host='%s'", (host,))
                                return FALSE
                        self.session.setTargetAddress(target)
                return TRUE

        def connectServer(self):
                """
                <method maturity="stable">
                  <summary>
                    Function called by the proxy instance to establish the
                    server-side connection.
                  </summary>
                  <description>
                    <para>
                      This function is called to establish the server-side connection.
                      The function either connects a proxy to the destination server,
                      or an embedded proxy to its parent proxy. The proxy may set the
                       address of the destination server using the <function>setServerAddress</function>
                        function.
                    </para>
                    <para>
                      The <function>connectServer</function> function calls the chainer
                      specified in the service definition to connect to the remote server
                      using the host name and port parameters.
                    </para>
                    <para>
                      The <function>connectServer</function> function returns the descriptor
                       of the server-side data stream.
                    </para>
                  </description>
                  <metainfo>
                    <arguments/>
                  </metainfo>
                </method>
                """
                try:
                        if self.session.chainer == None:
                        
                                # we have no chainer, the server side fd
                                # should be available by now, used in stacked
                                # proxies

                                if self.session.server_stream == None:
                                        raise InternalException, "No chainer and server_stream is None"
                                if self.server_fd_picked:
                                        ## LOG ##
                                        # This message indicates an internal
                                        # error condition, more precisely a
                                        # non-toplevel proxy tried to
                                        # connect to the server side
                                        # multiple times, which is not
                                        # supported. Please report this
                                        # event to the Zorp QA team (at
                                        # devel@balabit.com).
                                        ##
                                        log(self.session.session_id, CORE_ERROR, 1, "Internal error, stacked proxy reconnected to server multiple times;")
                                        return None
                                self.server_fd_picked = TRUE
                        else:
                                self.server_fd_picked = TRUE
                                self.session.server_stream = None
                                self.session.server_local = self.session.owner.server_local
                                self.session.chainer.chainParent(self.session)
                except ZoneException, s:
                        ## LOG ##
                        # This message indicates that no appropriate zone was found for the server address.
                        # @see: Zone
                        ##
                        log(self.session.session_id, CORE_POLICY, 1, "Zone not found; info='%s'", (s,))
                except DACException, s:
                        ## LOG ##
                        # This message indicates that an DAC policy violation occurred.
                        # It is likely that the new connection was not permitted as an inbound_service in the given zone.
                        # @see: Zone
                        ##
                        log(self.session.session_id, CORE_POLICY, 1, "DAC policy violation; info='%s'", (s,))
                        self.notifyEvent("core.dac_exception", [])
                except MACException, s:
                        ## LOG ##
                        # This message indicates that a MAC policy violation occurred.
                        ##
                        log(self.session.session_id, CORE_POLICY, 1, "MAC policy violation; info='%s'", (s,))
                except AAException, s:
                        ## NOLOG ##
                        log(self.session.session_id, CORE_POLICY, 1, "Authentication failure; info='%s'", (s,))
                except LimitException, s:
                        ## NOLOG ##
                        log(self.session.session_id, CORE_POLICY, 1, "Connection over permitted limits; info='%s'", (s,))
                except LicenseException, s:
                        ## NOLOG ##
                        log(self.session.session_id, CORE_POLICY, 1, "Attempt to use an unlicensed component, or number of licensed hosts exceeded; info='%s'", (s,))
                except:
                        traceback.print_exc()

                return self.session.server_stream
        
        def userAuthenticated(self, entity,
                              auth_info=''):
                """
                <method maturity="stable">
                  <summary>
                    Function called when inband authentication is successful.
                  </summary>
                  <description>
                    <para>
                      The proxy instance calls this function to
                      indicate that the inband authentication was successfully
                      performed. The name of the client is stored in the
                      <parameter>entity</parameter> parameter.
                    </para>
                  </description>
                  <metainfo>
                  <arguments>
                      <argument maturity="stable">
                        <name>entity</name>
                        <type></type>
                        <description>Username of the authenticated client.</description>
                      </argument>
                    </arguments>
                  </metainfo>
                </method>
                """
                self.session.auth_user = entity
                self.session.auth_info = auth_info
                ## LOG ##
                # This message reports that the user authentication was successful.
                ##
                proxyLog(self, CORE_AUTH, 3, "User authentication successful; entity='%s', auth_info='%s'", (entity, auth_info))

                szigEvent(Z_SZIG_CONNECTION_PROPS,
                           (Z_SZIG_TYPE_CONNECTION_PROPS,
                              (self.session.service.name, self.session.instance_id, 0, 0, {
                                'auth_user': entity,
                                'auth_info': auth_info,
                                'auth_groups': str(groups),
                                }
                         )))

        def readPEM(self, filename):
                """<method internal="yes">
                </method>
                """
                proxyLog(self, CORE_DEBUG, 6, "Reading PEM file; filename='%s'" % filename)
                f = open(filename, 'r')
                res = f.read()
                f.close()
                return res

        hash_pattern = re.compile("[0-9a-fA-F]*\.(r){0,1}[0-9]")

        def readHashDir(self, hash, directory):
                """<method internal="yes">
                </method>
                """
                try:
                        files = os.listdir(directory)
                        i = 0
                        for file in files:
                                if self.hash_pattern.match(file):
                                        try:
                                                hash[i] = self.readPEM(directory + '/' + file)
                                        except (TypeError, ValueError), s:
                                                proxyLog(self, SSL_ERROR, 3, "Error adding CA certificate; reason='%s'" % (s,))
                                        i = i+1
                except OSError, e:
                        proxyLog(self, SSL_ERROR, 3, "Error reading CA or CRL directory; dir='%s', error='%s'", (directory, e.strerror))

        def verifyTrustedCert(self, side, verify_results, trusted_certs_dir, blob):
                """<method internal="yes">
                </method>
                """
                if trusted_certs_dir:
                        if side == 1:
                                f = '%s/%s:%d' % (self.ssl.server_trusted_certs_directory, self.session.server_address.ip_s, self.session.server_address.port)
                        elif side == 0:
                                f = '%s/%s' % (self.ssl.client_trusted_certs_directory, self.session.client_address.ip_s)
                else:
                        return SSL_HS_ACCEPT

                proxyLog(self, SSL_DEBUG, 6, "Testing trusted certificates; f='%s'", (f,))
                if blob and os.access(f, os.R_OK):
                        if self.readPEM(f) == blob:
                                proxyLog(self, SSL_INFO, 4, "Trusting peer certificate; stored_cert='%s'", f)
                                return SSL_HS_VERIFIED
                        else:
                                proxyLog(self, SSL_VIOLATION, 2, "Peer certificate differs from trusted cert; stored_cert='%s'", f)
                                return SSL_HS_REJECT

                return SSL_HS_ACCEPT

        def verifyTrustedCertClient(self, side, verify_results):
                """<method internal="yes">
                </method>
                """
                res = self.verifyTrustedCert(side, verify_results, self.ssl.client_trusted_certs_directory, self.ssl.client_peer_certificate.blob)
                if res == SSL_HS_VERIFIED or (res == SSL_HS_ACCEPT and verify_results[0]):
                        self.ssl.client_certificate_trusted = TRUE
                return res

        def verifyTrustedCertServer(self, side, verify_results):
                """<method internal="yes">
                </method>"""
                res = self.verifyTrustedCert(side, verify_results, self.ssl.server_trusted_certs_directory, self.ssl.server_peer_certificate.blob)
                if res == SSL_HS_VERIFIED or (res == SSL_HS_ACCEPT and verify_results[0]):
                        self.ssl.server_certificate_trusted = TRUE
                return res

        def generateKeyClient(self, side):
                """<method internal="yes">
                </method>
                """
                # client side, we need to look up the server key
                if not getattr(self.ssl, "server_peer_certificate", None):
                        proxyLog(self, SSL_ERROR, 4, "Unable to generate certificate for the client, no server certificate present, using configured certificate;")
                        return SSL_HS_ACCEPT

                if hasattr(self.ssl, "key_generator"):
                        proxyLog(self, SSL_DEBUG, 4, "Generating key for the client; trusted='%d'", self.ssl.server_certificate_trusted)
                        if self.ssl.server_certificate_trusted:
                                (self.ssl.client_local_certificate, self.ssl.client_local_privatekey) = \
                                    self.ssl.key_generator.getKeypair({'bridge-trusted-key': self.ssl.server_peer_certificate.blob})
                        else:
                                (self.ssl.client_local_certificate, self.ssl.client_local_privatekey) = \
                                    self.ssl.key_generator.getKeypair({'bridge-untrusted-key': self.ssl.server_peer_certificate.blob})
                        return SSL_HS_ACCEPT
                else:
                        proxyLog(self, SSL_ERROR, 4, "Unable to generate key for the client, no key generator configured;")
                        return SSL_HS_REJECT

        def generateKeyServer(self, side):
                """<method internal="yes">
                </method>
                """
                # server side, we need to look up the client key
                if not getattr(self.ssl, "client_peer_certificate", None):
                        proxyLog(self, SSL_ERROR, 4, "Unable to generate certificate for the server, no client certificate present, using configured certificate;")
                        return SSL_HS_ACCEPT

                if hasattr(self.ssl, "key_generator"):
                        proxyLog(self, SSL_DEBUG, 4, "Generating key for the server; trusted='%d'", self.ssl.server_certificate_trusted)
                        if self.ssl.client_certificate_trusted:
                                (self.ssl.server_local_certificate, self.ssl.server_local_privatekey) = \
                                    self.ssl.key_generator.getKeypair({'bridge-trusted-key': self.ssl.client_peer_certificate.blob})
                        else:
                                (self.ssl.server_local_certificate, self.ssl.server_local_privatekey) = \
                                    self.ssl.key_generator.getKeypair({'bridge-untrusted-key': self.ssl.client_peer_certificate.blob})
                        return SSL_HS_ACCEPT
                else:
                        proxyLog(self, SSL_ERROR, 4, "Unable to generate key for the server, no key generator configured;")
                        return SSL_HS_REJECT
