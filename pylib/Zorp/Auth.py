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
## $Id: Auth.py,v 1.69 2004/05/07 12:57:53 bazsi Exp $
##
## Author  : Bazsi
## Auditor : kisza
## Last audited version: 1.3
## Notes:
##
############################################################################
"""
<module maturity="stable">
  <summary>
    Module defining interface to the Authentication module.
  </summary>
  <description>
    <para>
      This module contains classes related to authentication and authorization.
      Together with the <link linkend="python.AuthDB">AuthDB</link> module it implements
      the Authentication and Authorization framework of Zorp.
    </para>
      <para>User authentication verifies the identity of the user trying to access a particular network
    service. When performed on the connection level, that enables the full auditing of the network
    traffic. Authentication is often used in conjunction with authorization, allowing
    access to a service only to clients who have the right to do so.</para>
    
    <section id="authentication_overview">    
        <title>Authentication and authorization basics</title>
    <para>Authentication is a method to ensure that certain services (access to a server, etc.) can
      be used only by the clients allowed to access the service. The process generally called as
      authentication actually consists of three distinct steps: </para>
    <itemizedlist>
      <listitem>
        <para><emphasis>Identification</emphasis>: Determining the clients identity (e.g.:
          requesting a username).</para>
      </listitem>
      <listitem>
        <para><emphasis>Authentication</emphasis>: Verifying the clients identity (e.g.: requesting
          a password that only the real client knows).</para>
      </listitem>
      <listitem>
        <para><emphasis>Authorization</emphasis>: Granting access to the service (e.g.: verifying
          that the authenticated client is allowed to access the service).</para>
        <note>
          <para>It is important to note that although authentication and authorization are usually
            used together, they can also be used independently. Authentication verifies the identity
            of the client. There are situations where authentication is sufficient, because all
            users are allowed to access the services, only the event and the user's identity has to
            be logged. On the other hand, authorization is also possible without authentication, for
            example if access to a service is time-limited (e.g.: it can only be accessed outside
            the normal work-hours, etc.). In such situations authentication is not needed.</para>
        </note>
      </listitem>
    </itemizedlist>
    </section>
    <section id="zorp_authentication">
     <title>Authentication and authorization in Zorp</title>
        <para>
            Zorp can authenticate and authorize access to the Zorp services.
            The aim of authentication is to identify the user and the associated group memberships.            
            When the client initiates a connection, it actually tries to use a Zorp service. 
            Zorp checks if an <emphasis>authentication
            policy</emphasis> is associated to the service. If an authentication policy is present, 
            Zorp contacts the <emphasis>authentication 
            provider</emphasis> specified in the authentication policy. The type of 
            authentication (the authentication class used, e.g., InbandAuthentication)
             is also specified in the authentication policy. The authentication provider 
            connects to an <emphasis>authentication backend</emphasis> (e.g., a user database) to perform the 
            authentication of the client - Zorp itself does not directly communicate with the database.</para>
            <para>If the authentication is successful, Zorp verifies that the client is allowed to access 
            the service (by evaluating the <emphasis>authorization policy</emphasis> and the identity and 
            group memberships of the client). If the client is authorized to access the service, 
            the server-side connection is built. The client is automatically authorized if no 
            authorization policy is assigned to the service.</para>
            <para>
            Currently only one authentication provider, the Zorp Authentication Server (ZAS) is available
             via the <link linkend="python.AuthDB.ZAS2AuthenticationBackend">ZAS2AuthenticationBackend</link> class.
             Authentication providers are actually configured instances of the authentication backends, and it is 
             independent from the database that the backend connects to. The 
             authentication backend is that ties the authentication provider to 
             the server storing the user data.
            For details on using ZAS, see the <emphasis>Connection authentication and authorization</emphasis> 
            chapter of the <emphasis>Zorp Administrator's Guide</emphasis>. 
            </para>
            <para>
              The aim of authentication is to identify
              the user and resolve group memberships. The results are stored in
              the in the <parameter>auth_user</parameter> and <parameter>auth_groups</parameter> attributes of the
              <link linkend="python.Session">session</link> object.
              Note that apart from the information required for authentication, Zorp also sends session information 
              (e.g., the IP address of the client) to the authentication provider. 
            </para>
            <para>Zorp provides the following authentication classes:</para>
            <itemizedlist>
                <listitem>
                 <para><link linkend="python.Auth.InbandAuthentication">InbandAuthentication</link>: Use the built-in authentication
                 of the protocol to authenticate the client on the Zorp. </para>
                </listitem>
                <listitem>
                 <para><link linkend="python.Auth.ServerAuthentication">ServerAuthentication</link>: Enable the client to connect to
                 the target server, and extract its authentication information from the protocol.</para>
                </listitem>
                <listitem>
                 <para><link linkend="python.Auth.ZAAuthentication">ZAAuthentication</link>: Outband authentication using the
                 Zorp Authentication Agent.</para>
                </listitem>
            </itemizedlist>
           <para>If the authentication is successful, Zorp verifies that the client is allowed to access the service
           (by evaluating the authorization policy). If the client is authorized to access the service, the server-side connection
           is built. The client is automatically authorized if no authorization policy is assigned to the service.</para>
           <para>Each Zorp service can use an authorization policy to determine whether a client is allowed to access the service.
           If the authorization is based on the identity of the client, it takes place only after a successful authentication -
            identity-based authorization can be performed only if the client's identity is known and has been verified. The actual
            authorization is performed by Zorp, based on the authentication information received from ZAS or extracted from the protocol.
            </para>
            <para>Zorp provides the following authorization classes:</para>
            <itemizedlist>
                <listitem>
                 <para><link linkend="python.Auth.PermitUser">PermitUser</link>: Authorize listed users.</para>
                </listitem>
                <listitem>
                 <para><link linkend="python.Auth.PermitGroup">PermitGroup</link>: Authorize users belonging to the specified groups.</para>
                </listitem>
                <listitem>
                 <para><link linkend="python.Auth.PermitTime">PermitTime</link>: Authorize connections in a specified time interval.</para>
                </listitem>
                <listitem>
                 <para><link linkend="python.Auth.BasicAccessList">BasicAccessList</link>: Combine other authorization policies
                 into a single rule.</para>
                </listitem>
                <listitem>
                 <para><link linkend="python.Auth.PairAuthorization">PairAuthorization</link>: Authorize only user pairs.</para>
                </listitem>
                <listitem>
                 <para><link linkend="python.Auth.NEyesAuthorization">NEyesAuthorization</link>: Have another client authorize every connection.</para>
                </listitem>
            </itemizedlist>
            </section>        
  </description>
</module>
"""

import Zorp
from Zorp import *
from Cache import TimedCache, LockedCache

import types, threading, time

## Authentication
#####################################################

class AuthenticationPolicy:
        """
        <class maturity="stable" type="authenticationpolicy">
          <summary>A policy determining how the user is authenticated to access
            the service.
          </summary>
          <description>
           Authentication policies determine how the user is authenticated to access
            the service. The <parameter>authentication_policy</parameter> attribute
            of a service can reference an instance of the AuthenticationPolicy class.
            <example>
            <title>A simple authentication policy</title>
            <para>The following example defines an authentication policy that can
            be referenced in service definitions. This policy uses inband authentication and references
            an  <link linkend="python.AuthDB.AuthenticationProvider">authentication provider</link>.</para>
            <synopsis>
AuthenticationPolicy(name="demo_authentication_policy", cache=None, authentication=InbandAuthentication(), provider="demo_authentication_provider")
            </synopsis>
           <para>
            To use the authentication policy, include it in the definition of the service:</para>
            <synopsis>
Service(name="office_http_inter", proxy_class=HttpProxy, authentication_policy="demo_authentication_policy", authorization_policy="demo_authorization_policy")
            </synopsis>
            </example>
            <example>
            <title>Caching authentication decisions</title>
            <para>The following example defines an authentication policy that caches
             the authentication decisions for ten minutes (600 seconds). For details on authentication caching, see
            see <xref linkend="python.Auth.AuthCache"/>).</para>
            <synopsis>
AuthenticationPolicy(name="demo_authentication_policy", cache=AuthCache(timeout=600, update_stamp=TRUE, service_equiv=TRUE, cleanup_threshold=100), authentication=InbandAuthentication(), provider="demo_authentication_provider")
            </synopsis>
            </example>
          </description>
          <metainfo>
            <attributes>
            </attributes>
          </metainfo>
        </class>
        """
        def __init__(self, name, provider, authentication, cache = None):
                """
                <method maturity="stable">
                  <summary>Constructor to initialize an instance of the AuthenticationPolicy class.
                  </summary>
                  <description>
                  </description>
                  <metainfo>
                  <arguments>
                      <argument>
                        <name>name</name>
                        <type>
                          <string/>
                        </type>
                        <description>Name identifying the AuthenticationPolicy instance.</description>
                      </argument>
                      <argument>
                        <name>provider</name>
                        <type>
                          <class filter="authprov" instance="yes"/>
                        </type>
                        <description>The authentication provider object used in the authentication process.
                        See <xref linkend="authentication_overview"/> for details.</description>
                      </argument>
                      <argument>
                        <name>authentication</name>
                        <type>
                          <class filter="authentication" instance="yes"/>
                        </type>
                        <default>None</default>
                        <description>The authentication method used in the authentication process. See <xref linkend="authentication_overview"/> for details.</description>
                      </argument>
                      <argument>
                        <name>cache</name>
                        <type>
                          <class filter="authcache|none" instance="yes"/>
                        </type>
                        <default>None</default>
                        <description>Caching method used to store authentication results.</description>
                      </argument>
                    </arguments>
                  </metainfo>
                </method>
                """
                if Globals.authentication_policies.has_key(name):
                        raise ValueError, 'Duplicate AuthenticationPolicy: %s' % name
                Globals.authentication_policies[name] = self

                self.name = name
                self.provider = getAuthenticationProviderBackend(provider)
                self.authentication = authentication
                self.cache = cache
                self.name = name

        def performAuthentication(self, session):
                """
                <method internal="yes">
                </method>
                """
                entity = None
                if self.cache:
                        entity = self.cache.lookup(session)

                if not entity:
                        res = self.authentication.performAuth(self.provider, session)
                else:
                        res = TRUE
                        session.proxy.userAuthenticated(entity[0], entity[1], 'cached')

                return res

        def authorized(self, session):
                """
                <method internal="yes">
                </method>
                """
                entity = (session.auth_user, session.auth_groups)
                if self.cache:
                        self.cache.store(session, entity)

        def unauthorized(self, session):
                """
                <method internal="yes">
                </method>
                """
                if self.cache:
                        self.cache.store(session, None)


def getAuthenticationPolicy(name):
        """<function internal="yes">
        </function>"""
        if name:
                if Globals.authentication_policies.has_key(name):
                        return Globals.authentication_policies[name]
                else:
                        log(None, CORE_POLICY, 3, "No such authentication policy; policy='%s'", (name))
        return None

class AbstractAuthentication:
        """
        <class maturity="stable" type="authentication" abstract="yes">
          <summary>
            Class encapsulating the abstract authentication interface.
          </summary>
          <description>
            <para>
              This class encapsulates interfaces for inband and outband
              authentication procedures. Service definitions  should refer to a customized class
              derived from AbstractAuthentication, or one of the predefined authentication classes, such as
              <link
              linkend="python.Auth.InbandAuthentication">InbandAuthentication</link>
              or <link
              linkend="python.Auth.ZAAuthentication">ZAAuthentication</link>.
            </para>
          </description>
          <metainfo>
            <attributes>
              <attribute internal="yes">
                <name>authentication_provider</name>
                <type>AuthenticationProvider instance</type>
                <description>The authentication provider object used in the authentication process. See <xref linkend="authentication_overview"/> for details.</description>
              </attribute>
            </attributes>
          </metainfo>
        </class>
        """
        def __init__(self, authentication_provider=None, auth_cache=None):
                """
                <method maturity="stable">
                  <summary>
                    Constructor to initialize an AbstractAuthentication instance.
                  </summary>
                  <description>
                    <para>
                      This constructor initializes an instance of the AbstractAuthentication
                      class.
                    </para>
                  </description>
                  <metainfo>
                    <arguments>                      
                      <argument maturity="obsolete">
                        <name>authentication_provider</name>
                        <type>
                          <class filter="authprov" instance="yes"/>
                        </type>
                        <default>None</default>
                        <description>The authentication provider object used in the authentication process. See <xref linkend="authentication_overview"/> for details.
                        </description>
                      </argument>
                      <argument maturity="obsolete">
                        <name>auth_cache</name>
                        <type>
                          <class filter="authcache|none" instance="yes"/>
                        </type>
                        <default>None</default>
                        <description>Caching method used to store authentication results.</description>
                      </argument>
                    </arguments>
                  </metainfo>
                </method>
                """
                # for compatibility
                self.cache = auth_cache
                self.authentication_provider = authentication_provider

        def performAuth(self, provider, session):
                """
                <method internal="yes">
                  <summary>
                     Function called to initiate authentication before
                     the session is started.
                  </summary>
                  <description>
                    <para>
                      This function is called to initiate
                      authentication before a session is started. It
                      should raise AAException if the authentication
                      was not successful. This function is running in
                      the context of the proxy thread, and blocks the
                      proxy until it returns.
                    </para>
                  </description>
                  <metainfo>
                    <arguments>
                      <argument maturity="stable">
                        <name>session</name>
                        <type>SESSION</type>
                        <description>the session object which is to be started</description>
                      </argument>
                    </arguments>
                  </metainfo>
                </method>
                """
                raise AAException, 'Outband authentication not implemented'

class InbandAuthentication(AbstractAuthentication):
        """
        <class maturity="stable" type="authentication">
          <summary>
            Class encapsulating the inband authentication interface.
          </summary>
          <description>
            <para>
              This class encapsulates inband authentication. Inband
              authentication is performed by the proxy using the
              rules of the application-level protocol. Only the authentication methods
               supported by the particular protocol can be used during inband authentication.
               <link
              linkend="python.Auth.AuthenticationPolicy">Authentication policies</link> can refer to instances of the
              InbandAuthentication class using the <parameter>auth</parameter> parameter.
            </para>
            <warning>
              <para>Inband authentication is currently supported only for the Http and Ftp proxy classes. </para>
            </warning>
          </description>
          <metainfo>
            <attributes/>
          </metainfo>
        </class>
        """

        def __init__(self, authentication_provider=None, auth_cache=None):
                """
                <method maturity="stable">
                  <summary>
                    Constructor to initialize an InbandAuthentication instance.
                  </summary>
                  <description>
                    <para>
                      This constructor initializes an instance of the InbandAuthentication class.
                    </para>
                  </description>
                  <metainfo>
                    <arguments>
                      <argument maturity="obsolete">
                        <name>authentication_provider</name>
                        <type>
                          <class filter="authprov" instance="yes"/>
                        </type>
                        <default>None</default>
                        <description>The authentication provider object to authenticate against</description>
                      </argument>
                      <argument maturity="obsolete">
                        <name>auth_cache</name>
                        <type>
                          <class filter="authcache|none" instance="yes"/>
                        </type>
                        <default>None</default>
                        <description>The authentication cache object which stores successful authentications.</description>
                      </argument>
                    </arguments>
                  </metainfo>
                </method>
                """
                AbstractAuthentication.__init__(self, authentication_provider, auth_cache)

        def performAuth(self, provider, session):
                """
                <method internal="yes">
                </method>
                """
                if not session.proxy.auth_inband_defer:
                        if session.proxy.auth_inband_supported:
                                session.proxy.auth = provider
                        else:
                                raise AAException, 'Inband authentication not supported by the underlying proxy'
                return TRUE

class ServerAuthentication(AbstractAuthentication):
        """
        <class maturity="stable" type="authentication">
          <summary>
            Class encapsulating the server authentication interface.
          </summary>
          <description>
            <para>
              This class encapsulates server authentication: Zorp authenticates the
              user based on the response of the server to the user's authentication request.
              Server authentication is a kind of inband authentication, it is performed within the application
              protocol, but the target server checks the credentials of the user instead of Zorp.
              This authentication method is useful when the
              server can be trusted for authentication purposes, but you need to
              include an authorization decision in the service definition.
            </para>
          </description>
          <metainfo>
            <attributes/>
          </metainfo>
        </class>
        """

        def __init__(self):
                """
                <method maturity="stable">
                  <summary>
                    Constructor to initialize a ServerAuthentication instance.
                  </summary>
                  <description>
                    <para>
                      This constructor initializes an instance of the ServerAuthentication class.
                    </para>
                  </description>
                  <metainfo>
                    <arguments/>
                  </metainfo>
                </method>
                """
                AbstractAuthentication.__init__(self)

        def performAuth(self, provider, session):
                """
                <method internal="yes">
                </method>
                """
                if session.proxy.auth_server_supported:
                        session.proxy.auth_server = TRUE
                        if provider:
                                session.proxy.auth = provider
                else:
                        raise AAException, 'Server authentication not supported by the underlying proxy'
                return TRUE


#####################################################
## AuthCache
#####################################################

class AuthCache:
        """
        <class type="authcache">
          <summary>
            Class encapsulating the authentication cache.
          </summary>
          <description>
            <para>
              This class encapsulates an authentication cache which associates
              usernames with client IP addresses. The association between a username
              and an IP address is valid only until the specified timeout.
              Caching the authentication results means that the users
              do not need to authenticate themselves for every request: it is
              assumed that the same user is using the computer within the timeout. E.g.: once
              authenticated for an HTTP service, the client can browse
              the web for <guilabel>Timeout</guilabel> period, but has to authenticate again to
                use FTP.
            </para>
            <para>
            To use a single authorization cache for every service request of a client, set
            the <parameter>service_equiv</parameter> attribute to <parameter>TRUE</parameter>.
            That way Zorp does not make difference between the different services (protocols) used
                by the client: after a successful authentication the user can use all available services
                without having to perform another authentication. E.g.: if this option is enabled in the
                example above, the client does not have to re-authenticate for starting an FTP
                connection.
            </para>
          </description>
          <metainfo>
            <attributes>
              <attribute internal="yes">
                <name>name</name>
                <type>String</type>
                <description>Name of the authentication cache.</description>
              </attribute>
              <attribute internal="yes">
                <name>cache</name>
                <type>AbstractCache instance</type>
                <description>TimedCache object where the information is stored.</description>
              </attribute>
              <attribute internal="yes">
                <name>service_equiv</name>
                <type>Boolean</type>
                <description>If enabled, then a single authentication of a user applies to every service from that client.</description>
              </attribute>
            </attributes>
          </metainfo>
        </class>
        """

        def __init__(self, name=None, timeout=600, update_stamp=TRUE, service_equiv=FALSE, cleanup_threshold=100):
                """
                <method maturity="stable">
                  <summary>
                    Constructor to initialize an instance of the AuthCache class.
                  </summary>
                  <description>
                    <para>
                      This constructor initializes and registers an AuthCache
                      instance that can be referenced in authentication
                      policies.
                    </para>
                  </description>
                  <metainfo>
                    <arguments>
                      <argument maturity="obsolete">
                        <name>name</name>
                        <type>
                          <string/>
                        </type>
                        <default>None</default>
                        <description>
                          The name of the authentication cache, this will be
                          used to identify this authentication cache when
                          the obsolete AuthPolicy construct is used. Setting
                          this value is not required if
                          AuthenticationPolicy is used.
                        </description>
                      </argument>
                      <argument>
                        <name>timeout</name>
                        <type>
                          <integer/>
                        </type>
                        <default>600</default>
                        <description>
                          Timeout while an authentication is assumed to be valid.
                        </description>
                      </argument>
                      <argument>
                        <name>update_stamp</name>
                        <type>
                          <boolean/>
                        </type>
                        <default>TRUE</default>
                        <description>
                          If set to <parameter>TRUE</parameter>, then cached authentications increase
                          the validity period of the authentication cache. Otherwise, the authentication
                          cache expires according to the timeout value set in
                          <xref linkend="Auth___init___timeout"/><!-- FIXME ambiguous link, should point to
                          previous attribute-->.
                        </description>
                      </argument>
                      <argument>
                        <name>service_equiv</name>
                        <type>
                          <boolean/>
                        </type>
                        <default>FALSE</default>
                        <description>If enabled, then a single authentication of a user applies to every service from that client.</description>
                      </argument>
                      <argument>
                        <name>cleanup_threshold</name>
                        <type>
                          <integer/>
                        </type>
                        <default>100</default>
                        <description>
                          When the number of entries in the cache reaches the value of
                          <parameter>cleanup_threshold</parameter>, old entries are automatically
                          deleted.
                        </description>
                      </argument>
                    </arguments>
                  </metainfo>
                </method>
                """
                if name:
                        self.name = name
                        cache_name = 'authcache(%s)' % self.name
                else:
                        cache_name = 'authcache(noname)'
                self.cache = LockedCache(TimedCache(cache_name, timeout, update_stamp, cleanup_threshold))
                self.service_equiv = service_equiv
                if name:
                        if Globals.auth_caches.has_key(name):
                                raise ValueError, "Duplicate AuthCache name: %s" % name
                        Globals.auth_caches[name] = self


        def makeKey(self, session):
                """
                <method internal="yes">
                </method>
                """
                if self.service_equiv:
                        return session.client_address.ip_s
                else:
                        return (session.client_address.ip_s, session.service.name)

        def lookup(self, session):
                """
                <method internal="yes">
                </method>
                """
                return self.cache.lookup(self.makeKey(session))

        def store(self, session, entity):
                """
                <method internal="yes">
                </method>
                """
                return self.cache.store(self.makeKey(session), entity)

def getAuthCacheByName(name):
        """<function internal="yes">
        </function>"""
        if name:
                if Globals.auth_caches.has_key(name):
                        return Globals.auth_caches[name]
                else:
                        log(None, CORE_POLICY, 3, "No such authentication cache; cache='%s'", (name))
        return None


#####################################################
## Authorization
#####################################################


#####################################################
## Compatibility
#####################################################

class AuthPolicy:
        """
        <class maturity="obsolete" type="authpolicy">
          <summary>
            Class encapsulating the authentication and authorization (AA) policy. 
          </summary>
          <description>
            <para>
              This class encapsulates authentication and authorization
              policy, which can be associated with Zorp services. This
              class is obsolete, please use           
               <link linkend="python.Auth.AuthenticationPolicy">AuthenticationPolicy
            </link> and <link linkend="python.Auth.AuthorizationPolicy">AuthorizationPolicy</link>
             instead.
            </para>
            <para>
              A user will not be able to use a given service if it
              cannot fulfill the authentication and authorization
              requirements this class poses.
            </para>
            <para>
              Both an authentication (for example SatyrAuthentication) and an
              authorization (for example BasicAccessList) can be set, tough
              both of them is optional.
            </para>
          </description>
          <metainfo>
            <attributes>
              <attribute>
                <name>name</name>
                <type><string/></type>
                <description>
                  Name of the authentication policy, this value is
                  used when associating authentication policies to
                  services.
                </description>
              </attribute>
              <attribute>
                <name>authentication</name>
                <type><class filter="AbstractAuthentication"/></type>
                <description>
                  Authentication object which performs authentication
                  and stores its result to make it possible to perform
                  authorization.
                </description>
              </attribute>
 -->
            </attributes>
          </metainfo>
        </class>
        """

        def __init__(self, name, authentication=None, authorization=None, auth_cache=None):
                """
                <method maturity="stable">
                  <summary>
                    Constructor to initialize an AuthPolicy instance.
                  </summary>
                  <description>
                    <para>
                      This constructor creates a new AuthPolicy instance which
                      can be associated with a Zorp service to perform
                      authentication and authorization.
                    </para>
                  </description>
                  <metainfo>
                    <arguments>
                      <argument>
                        <name>name</name>
                        <type>
                          <string/>
                        </type>
                        <description>
                          Name of the authentication policy, this value is
                          used when associating authentication policies to
                          services.
                        </description>
                      </argument>
                      <argument>
                        <name>authentication</name>
                        <type>
                          <class filter="authentication" instance="yes"/>
                        </type>
                        <default>None</default>
                        <description>
                          Authentication object which performs authentication
                          and stores its result to make it possible to perform
                          authorization.
                        </description>
                      </argument>
 -->
                    </arguments>
                  </metainfo>
                </method>
                """
                self.name = name
                self.authentication = authentication
                self.auth_cache = auth_cache

                # FIXME: this is a hack for compatibility and might be removed as soon
                # as SatyrAuthentication.cache is removed.
                if not auth_cache and hasattr(authentication, 'cache'):
                        self.auth_cache = authentication.cache

                if type(self.auth_cache) == types.StringType:
                        self.auth_cache = getAuthCacheByName(self.auth_cache)

                if name:
                        if Globals.auth_policies.has_key(name):
                                raise ValueError, "Duplicate AuthPolicy name: %s" % name
                        Globals.auth_policies[name] = self

        def getAuthenticationPolicy(self):
                if Globals.authentication_policies.has_key('__%s-authentication' % self.name):
                        return Globals.authentication_policies['__%s-authentication' % self.name]
                else:
                        return AuthenticationPolicy('__%s-authentication' % self.name, self.authentication.authentication_provider, self.authentication, self.auth_cache)

        def getAuthorizationPolicy(self):
                if self.authorization:
                        if Globals.authorization_policies.has_key('__%s-authorization' % self.name):
                                Globals.authorization_policies['__%s-authorization' % self.name]
                        else:
                                return AuthorizationPolicy('__%s-authorization' % self.name, self.authorization)
                return None

def getAuthPolicyObsolete(name):
        """<function/>"""
        if name:
                if Globals.auth_policies.has_key(name):
                        return Globals.auth_policies[name]
                else:
                        log(None, CORE_POLICY, 3, "No such AuthPolicy; policy='%s'", (name))
        return None
