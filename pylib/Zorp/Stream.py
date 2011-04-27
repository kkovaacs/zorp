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
    Module defining interface to the streaming component.
  </summary>
  <description>
    <para>
      This module defines the Stream class, encapsulating file descriptors and
      related functions.
    </para>
  </description>
</module>
"""

G_IO_STATUS_ERROR = 0
G_IO_STATUS_NORMAL = 1
G_IO_STATUS_EOF = 2
G_IO_STATUS_AGAIN = 3

class Stream:
	"""
        <class maturity="stable">
          <summary>
            Class encapsulating the file descriptor and related functions.
          </summary>
          <description>
            <para>
              This class encapsulates a full-duplex data tunnel, represented by
              a UNIX file descriptor. Proxies communicate with its peers through
              instances of this class. The <parameter>client_stream</parameter> 
              and <parameter>server_stream</parameter>
              attributes of the <link
              linkend="python.Session">Session</link> class contain a
              Stream instance.
            </para>
          </description>
          <metainfo>
            <attributes>
              <attribute>
                <name>fd</name>
                <type><integer/></type>
                <description>The file descriptor associated to the stream.</description>
              </attribute>
              <attribute>
                <name>name</name>
                <type><string/></type>
                <description>The name of the stream.</description>
              </attribute>
              <attribute>
                <name>bytes_recvd</name>
                <type><integer/></type>
                <description>The number of bytes received in the stream.</description>
              </attribute>
              <attribute>
                <name>bytes_sent</name>
                <type><integer/></type>
                <description>The number of bytes sent in the stream.</description>
              </attribute>
            </attributes>
          </metainfo>
        </class>
	"""
	
	def __init__(self, fd, name):
		"""
                <method maturity="stable">
                  <summary>
                    Constructor to initialize a stream.
                  </summary>
                  <description>
                    <para>
                      This constructor initializes a Stream instance setting its
                      attributes according to arguments.
                    </para>
                  </description>
                  <metainfo>
                    <arguments>
                      <argument>
                        <name>fd</name>
                        <type><integer/></type>
                        <description>The file descriptor associated to the stream.</description>
                      </argument>
                      <argument>
                        <name>name</name>
                        <type><string/></type>
                        <description>The name of the stream.</description>
                      </argument>
                    </arguments>
                  </metainfo>
                </method>
		"""
		pass

	def read(self, count):
		"""
                <method maturity="stable" internal="yes">
                  <summary>
                    Method to read up to count bytes from the stream.
                  </summary>
                  <description>
                    <para>
                      This method reads up to count bytes from the stream
                      and returns it as a <string/>.
                    </para>
                  </description>
                  <metainfo>
                    <arguments>
                      <argument maturity="stable">
                        <name>count</name>
                        <type><integer/></type>
                        <description>maximum number of bytes to read</description>
                      </argument>
                    </arguments>
                  </metainfo>
                </method>
		"""
		pass
		
	def write(self, buf):
		"""
                <method maturity="stable" internal="yes">
                  <summary>
                    Method to write the contents of a buffer to the stream.
                  </summary>
                  <description>
                    <para>
                      This method writes the contents of the given buffer to
                      the stream.
                    </para>
                  </description>
                  <metainfo>
                    <arguments>
                      <argument maturity="stable">
                        <name>buf</name>
                        <type><string/></type>
                        <description>buffer to write</description>
                      </argument>
                    </arguments>
                  </metainfo>
                </method>

		"""

