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
    Module defining interface to the authentication databases.
  </summary>
  <description>
    <para>
      This module contains classes related to authentication databases. Together
      with the <link linkend="python.Auth">Auth</link> module it implements the
      Authentication and Authorization framework of Zorp. See
      <xref linkend="authentication_overview"/> and <xref linkend="zorp_authentication"/>
       for details.
    </para>
  </description>
</module>

"""
import Zorp
from Zorp import *

Z_AUTH_UNKNOWN    = 0
Z_AUTH_GETMETHODS = 1
Z_AUTH_METHODS    = 2
Z_AUTH_SETMETHOD  = 3
Z_AUTH_REQUEST    = 4
Z_AUTH_RESPONSE   = 5
Z_AUTH_ACCEPT     = 6
Z_AUTH_ABORT      = 7
Z_AUTH_REJECT     = 8



class AuthenticationProvider:
        """
        <class type="authprov">
          <summary>A database-independent class used by Zorp to connect to an 
          authentication backend.
          </summary>
          <description>
          <para>
          The authentication provider is an intermediate layer that mediates 
          between Zorp and the <emphasis>authentication backend</emphasis> (e.g., a user database) 
          during connection authentication
           - Zorp itself does not directly communicate with the database.            
          </para>
           <example>
            <title>A sample authentication provider</title>
            <para>The following example defines an authentication provider that
            uses the <link linkend="python.AuthDB.ZAS2AuthenticationBackend">ZAS2AuthenticationBackend</link> backend.</para>
            <synopsis>
AuthenticationProvider(name="demo_authentication_provider", backend=ZAS2AuthenticationBackend(serveraddr=SockAddrInet('192.168.10.10', 1317), use_ssl=TRUE, ssl_verify_depth=3, pki_cert=("/etc/key.d/ZAS_certificate/cert.pem", "/etc/key.d/ZAS_certificate/key.pem"), pki_ca=("/etc/ca.d/groups/demo_trusted_group/certs/", "/etc/ca.d/groups/demo_trusted_group/crls/")))
            </synopsis>
            </example>
          </description>
          <metainfo>
            <attributes/>
          </metainfo>
        </class>
        """
        def __init__(self, name, backend):
                """
                <method maturity="stable">
                  <summary>
                    Constructor to initialize an AbstractAuthorizationBackend instance.
                  </summary>
                  <description>
                    <para>
                      This constructor initializes an AbstractAuthorizationBackend instance.
                    </para>
                  </description>
                  <metainfo>
                    <arguments>                      
                      <argument maturity="stable">
                        <name>name</name>
                        <type>
                          <string/>
                        </type>
                        <description>Name of the ZAS instance.</description>
                      </argument>
                      <argument maturity="stable">
                        <name>backend</name>
                        <type>
                          <class filter="authdb" instance="yes"/>
                        </type>
                        <description>Type of the database backend used by the ZAS instance.</description>
                      </argument>
                    </arguments>
                  </metainfo>
                </method>
                """
                if Globals.authentication_providers.has_key(name):
                        raise ValueError, "Duplicate authorization provider: %s" % name
                Globals.authentication_providers[name] = self
                self.name = name
                self.backend = backend

def getAuthenticationProviderBackend(name):
        """
        <function internal="yes">
        </function>
        """
        if name:
                if Globals.authentication_providers.has_key(name):
                        return Globals.authentication_providers[name].backend
                else:
                        log(None, CORE_POLICY, 3, "No such authentication provider; provider='%s'", (name))
        return None

class AbstractAuthenticationBackend:
        """
        <class maturity="stable" abstract="yes" type="authdb">
          <summary>
            Class encapsulating the abstract authentication backend like ZAS.
          </summary>
          <description>
            <para>
              This is an abstract class to encapsulate an authentication
              backend, which is responsible for checking authentication
              credentials against a backend database. In actual configurations, use one of the derived classes like <link
              linkend="python.AuthDB.ZAS2AuthenticationBackend">ZAS2AuthenticationBackend</link>.
            </para>
            <para>
              The interface defined here is used by various authentication
              methods like <link
              linkend="python.Auth.ZAAuthentication">ZAAuthentication</link> and <link
              linkend="python.Auth.InbandAuthentication">InbandAuthentication</link>.
            </para>
          </description>
          <metainfo>
            <attributes/>
          </metainfo>
        </class>
        """
        def __init__(self):
                """
                <method internal="yes">
                  <summary>
                    Constructor to initialize an AbstractAuthorizationBackend instance.
                  </summary>
                  <description>
                    <para>
                      This constructor initializes an AbstractAuthorizationBackend instance.
                    </para>
                  </description>
                  <metainfo>
                    <arguments/>
                  </metainfo>
                </method>
                """
                pass

        def startSession(self, session_id, session):
                """
                <method internal="yes">
                  <summary>
                    Method to be called when an authentication session starts.
                  </summary>
                  <description>
                    <para>
                      This method is called when an authentication session
                      identified by 'session_id' starts. 'session_id' can be used
                      to associate data with this session, as each subsequent
                      calls to AbstractAuthorization methods will get this value.
                    </para>
                  </description>
                  <metainfo>
                    <arguments>                      
                      <argument maturity="stable">
                        <name>session_id</name>
                        <type></type>
                        <description>session identifier represented as a string</description>
                      </argument>
                    </arguments>
                  </metainfo>
                </method>
                """
                pass

        def stopSession(self, session_id):
                """
                <method internal="yes">
                  <summary>
                    Method to be called when an authentication session ends.
                  </summary>
                  <description>
                    <para>
                      This method is called when an authentication session is ended.
                      It's a placeholder for freeing up any resources associated to
                      a given session.
                    </para>
                  </description>
                  <metainfo/>
                </method>
                """
                pass

        def getMethods(self, session_id, entity):
                """
                <method internal="yes">
                  <summary>
                    Function returning the allowed set of methods.
                  </summary>
                  <description>
                    <para>
                      This function calculates and returns the set of allowed methods
                      a user is allowed to authenticate with. We return an empty
                      set here, overridden methods should return something more
                      interesting.
                      Returns return a tuple. First value is Z_AUTH_*, the second is a array of applicable methods. (if any)
                    </para>
                  </description>
                  <metainfo>
                    <arguments>                      
                      <argument maturity="stable">
                        <name>session_id</name>
                        <type></type>
                        <description>authentication session id </description>
                      </argument>
                      <argument maturity="stable">
                        <name>entity</name>
                        <type></type>
                        <description>username</description>
                      </argument>
                    </arguments>
                  </metainfo>
                </method>
                """
                return ()

        def setMethod(self, session_id, method):
                """
                <method internal="yes">
                  <summary>
                    Function to set the authentication Method.
                  </summary>
                  <description>
                    This function should return a challenge for a given entity
                    using the given method, or None if challenge is not
                    applicable for the given method.
                    Returns return a tuple. First value is one of Z_AUTH*, second value is a string containing the challenge, or None if not applicable
                  </description>
                  <metainfo>
                    <arguments>
                      <argument maturity="stable">
                        <name>session_id</name>
                        <type></type>
                        <description>authentication session id</description>
                      </argument>
                      <argument maturity="stable">
                        <name>entity</name>
                        <type></type>
                        <description>username</description>
                      </argument>
                      <argument maturity="stable">
                        <name>method</name>
                        <type></type>
                        <description>authentication method</description>
                      </argument>
                    </arguments>
                  </metainfo>
                </method>
                """
                raise NotImplementedError

        def converse(self, session_id, credentials):
                """
                <method internal="yes">
                  <summary>
                    Function checking the presented credentials of an entity.
                  </summary>
                  <description>
                    <para>
                      This function is called to check the credentials presented
                      by the client for validity. It should return either TRUE, if
                      the credentials for the given challenge  method  username
                      are valid.
                      Returns return a tuple. First value is one of Z_AUTH_*, second is depending on the first.
                    </para>
                  </description>
                  <metainfo>
                    <arguments>
                      <argument maturity="stable">
                        <name>session_id</name>
                        <type></type>
                        <description>authentication session id</description>
                      </argument>
                      <argument maturity="stable">
                        <name>entity</name>
                        <type></type>
                        <description>username</description>
                      </argument>
                      <argument maturity="stable">
                        <name>challenge</name>
                        <type></type>
                        <description>a previously issued challenge (might be None or an empty string)</description>
                      </argument>
                      <argument maturity="stable">
                        <name>credentials</name>
                        <type></type>
                        <description>response for the given challenge</description>
                      </argument>
                    </arguments>
                  </metainfo>
                </method>
                """
                raise NotImplementedError



