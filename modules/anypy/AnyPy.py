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
## $Id: AnyPy.py,v 1.12 2003/12/08 17:44:20 bazsi Exp $
##
## Author  : Bazsi
## Auditor : kisza
## Last audited version: 1.2
## Notes:
##
############################################################################

"""<module internal="yes" type="internal">
<!-- FIXME: reindent -->
<summary>
   Module defining interface to the AnyPy proxy. 
</summary>
  <description>
    <para>
      This module defines an interface to the AnyPy proxy as implemented in Zorp.
      AnyPy is basically a Python proxy which means that the proxy behaviour is
      defined in Python by the administrator.
    </para>
  <section>
    <title>Related standards</title>
    <para>
    </para>
  </section>
  </description>
  <metainfo>
    <attributes/>
  </metainfo>
</module>"""

from Proxy import Proxy

# policy verdicts
ANYPY_UNSPEC     = 0 # policy doesn't specify it, do something sensible 
ANYPY_ACCEPT     = 1
ANYPY_DENY       = 2
ANYPY_REJECT     = 3 # continue and tell the client that we didn't do it 
ANYPY_ABORT      = 4 # abort the connection 
ANYPY_DROP       = 5 # continue and don't do it 
ANYPY_POLICY     = 6 # Policy level will decide what to do 
ANYPY_ERROR      = 7 # Error occured try to nice fail 

class AbstractAnyPyProxy(Proxy):
	"""<class internal="yes" abstract="yes">
        <summary>
          Class encapsulating in AnyPy proxy.
        </summary>
          <description>
            <para>
              This class encapsulates AnyPy, a proxy module calling a Python
              function to do all of its work. It can be used for defining proxies
              for protocols not directly supported by Zorp.
            </para>
            <section>
              <title>Note</title>
              <para>
                Your code will be running as the proxy to transmit protocol elements,
                you'll have to take care and be security conscious not to
                make security vulnerabilities.
              </para>
            </section>
          </description>
        <metainfo>
          <attributes/>
        </metainfo>
        </class>
        """
	name = "anypy"
	def __init__(self, session):
		"""<method maturity="stable">
                <summary>
                  Constructor to initialize an AnyPy instance.
                </summary>
                <description>
                  <para>
                    This constructor initializes a new AnyPy instance
                    based on arguments and calls the inherited constructor.
                  </para>
                </description>
                  <metainfo>
                    <arguments>
                      <argument maturity="stable">
                        <name>session</name>
                        <type>SESSION</type>
                        <description>
                          session we belong to
                        </description>
                      </argument>
                    </arguments>
                  </metainfo>
                </method>
                """
		Proxy.__init__(self, session)

	def proxyThread(self):
		"""<method maturity="stable">
                <summary>
                  Function called by the low level proxy core to perform transferring requests.
                </summary>
                <description>
                  <para>
                    This function is called by the proxy module to perform
                    transferring requests. It may use the
                    'self.session.client_stream' and
                    'self.session.server_stream' streams to
                    read data from and write data to.
                  </para>
                </description>
                <metainfo>
                  <arguments/>
                </metainfo>
                </method>
		"""
		raise NotImplementedError

class AnyPyProxy(AbstractAnyPyProxy):
	"""<class internal="yes">
        <summary>
          Class encapsulating the default AnyPy proxy.
        </summary>
        <metainfo>
          <attributes/>
        </metainfo>
        </class>
        """
	pass

