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
<module>
<summary>The Stack module defines the classes used to connect to a stacking provider.
</summary>
<description>
  <para>Zorp is capable of stacking, that is, handing over parts of the traffic to other modules for 
  further inspection (e.g., to other proxies to inspect embedded protocols, to 
  content vectoring modules for virus filtering, etc.). The Stack module defines the 
  classes required for this functionality.
  </para>
  <para>
  Stacking in Zorp services is performed using <link linkend="python.Stack.StackingProvider">
  StackingProvider policies</link>, which reference the host that performs the stacked operations
    using the <link linkend="python.Stack.RemoteStackingBackend">
  RemoteStackingBackend</link> class. 
  </para>
</description>
<metainfo/>
</module>
"""

from Zorp import *
import Globals

class StackingProvider:
        """
        <class type="stackingprov">
          <summary>This is a policy class that is used to reference a configured 
          stacking provider in service definitions.
          </summary>
          <description>
            <para>Instances of the StackingProvider class are policies that define
            which remote stacking backend a particular service uses to inspect 
            the contents of the traffic.
            </para>
            <example>
            <title>A simple StackingProvider class</title>
            <para>The following class creates a simple stacking provider that 
            can be referenced in service definitions. The remote host that 
            provides the stacking services is located under the 
            <parameter>192.168.12.12</parameter> IP address.
            </para>
            <synopsis>StackingProvider(name="demo_stackingprovider", backend=RemoteStackingBackend(addrs=(SockAddrInet('192.168.12.12', 1318),)))</synopsis>
            </example>
            <example>
            <title>Using a StackingProvider in an FTP proxy</title>
            <para>The following classes define a stacking provider that 
            can be accesses a local ZCV instance using a domain socket. 
            This service provider is then used to filter FTP traffic. 
            The configuration of the ZCV (i.e., what modules it uses to filter 
            the traffic is not discussed here).
            </para>
            <synopsis>class StackingFtpProxy(FtpProxy):
    def config(self):
        FtpProxy.config(self)
        self.request_stack["RETR"]=(FTP_STK_DATA, (Z_STACK_PROVIDER, "demo_stackingprovider", "default_rulegroup"))        

StackingProvider(name="demo_stackingprovider_socket", backend=RemoteStackingBackend(addrs=(SockAddrUnix('/var/run/zcv/zcv.sock'),)))</synopsis>
            </example>
          </description>
          <metainfo>
          </metainfo>
        </class>
        """
        def __init__(self, name, backend):
                """
                <method maturity="stable">
                  <summary>Constructor to initialize an instance of the StackingProvider class.
                  </summary>
                  <description>
                    <para>This constructor creates a StackingProvider instance 
                    and sets the attributes of the instance according to the received arguments.
                    </para>
                  </description>
                  <metainfo>
                    <arguments>
                      <argument maturity="stable">
                        <name>name</name>
                        <type>
                          <string/>
                        </type>
                        <description>Name of the Stacking provider policy. This 
                        name can be referenced in the service definitions.</description>
                      </argument>
                      <argument maturity="stable">
                        <name>backend</name>
                        <type>
                          <class filter="stackingbackend" instance="yes"/>
                        </type>
                        <description>A configured <link linkend="python.Stack.RemoteStackingBackend">
                        RemoteStackingBackend</link> class containing the address
                        of the remote stacking backend, e.g.,
                        <parameter>RemoteStackingBackend(addrs=(SockAddrInet('192.168.2.3', 1318),))</parameter> or                        <parameter>RemoteStackingBackend(addrs=(SockAddrUnix('/var/run/zcv/zcv.sock'),)).
                        </parameter>.
                         </description>
                      </argument>
                    </arguments>
                  </metainfo>
                </method>
                """

                if Globals.stacking_providers.has_key(name):
                        raise ValueError, "Duplicate Stacking provider: %s" % name
                Globals.stacking_providers[name] = self
                self.name = name
                self.backend = backend

def getStackingProviderBackend(name):
        """
        <function internal="yes"/>"""
        if name:
                if Globals.stacking_providers.has_key(name):
                        return Globals.stacking_providers[name].backend
                else:
                        log(None, CORE_POLICY, 3, "No such stacking provider; provider='%s'", (name))
        return None

class AbstractStackingBackend:
        """        
        <class maturity="stable" abstract="yes" type="stackingbackend">
          <summary>This is an abstract class, currently without any functionality.
          </summary>
          <description>
            <para>This is an abstract class, currently without any functionality.
            </para>
          </description>
          <metainfo>
            <attributes/>
          </metainfo>
        </class>
        """
        def __init__(self):
                """
                <method internal="yes"/>"""
                pass

        def stack(self):
                """
                <method internal="yes"/>"""
                raise IOError, "Unimplemented stacking method"

class RemoteStackingBackend(AbstractStackingBackend):
        """
        <class type="stackingbackend">
          <summary>Constructor to initialize an instance of the RemoteStackingBackend class.
          </summary>
          <description>
            <para>
            This class contains the address of the host that performs the stacked
             operations. It is typically used to access the Zorp Content Vectoring
              Server (ZCV) to perform virus filtering in the traffic. The remote 
              backend can be accessed using the TCP protocol or a local socket, 
              e.g., <parameter>RemoteStackingBackend(addrs=(SockAddrInet('192.168.2.3', 1318),))</parameter> or                        <parameter>RemoteStackingBackend(addrs=(SockAddrUnix('/var/run/zcv/zcv.sock'),)).
                        </parameter>.
            </para>
          </description>
          <metainfo>
            <attributes/>
          </metainfo>
        </class>
        """
        def __init__(self, addrs):
                """
                <method>
                  <summary>
                  </summary>
                  <description>
                    <para>
                    </para>
                  </description>
                  <metainfo>
                    <arguments>
                      <argument maturity="stable">
                        <name>addrs</name>
                        <type>
                          <list>
                            <sockaddr/>
                          </list>
                        </type>
                        <description>The address of the remote backend in
                        <link linkend="python.SockAddr.SockAddrInet">SockAddrInet</link> or
                        <link linkend="python.SockAddr.SockAddrUnix">SockAddrUnix</link>
                         format. Separate addresses with commas to list more than one address
                         for a backend. Zorp will connect to these addresses in a 
                         failover fashion.</description>
                      </argument>
                    </arguments>
                  </metainfo>
                </method>
                """
                AbstractStackingBackend.__init__(self)
                self.addrs = addrs
                self.current_host = 0

        def stack(self, stack_info):
                """
                <method internal="yes"/>"""
                for i in range(len(self.addrs)):
                        addr = self.addrs[self.current_host]
                        self.current_host = (self.current_host + 1) % len(self.addrs)

                        try:
                                return performStackRemote(addr, stack_info)
                        except IOError:
                                log(None, CORE_ERROR, 3, "Error performing stack handshake with peer; addr='%s'", str(addr))
                log(None, CORE_DEBUG, 6, "Could not finish handshake with any of the stacking peers;")
                return None

