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
## $Id: Telnet.py,v 1.21 2004/07/28 14:36:07 sasa Exp $
##
## Author  : hidden
## Auditor :
## Last audited version:
## Notes:
##
############################################################################

"""<module maturity="stable">
  <summary>
    Proxy for the Telnet protocol.
  </summary>
  <description>
    <para>
      The Telnet module defines the classes constituting the proxy for the TELNET protocol.
    </para>
    <section>
      <title>The Telnet protocol</title>
      <para>
        The Telnet protocol was designed to remotely login to computers via the
        network. Although its main purpose is to access a remote standard terminal, it can be used for many other functions as well.
      </para>
      <para>
        The protocol follows a simple scenario. The client
        opens a TCP connection to the server at the port 23. The server 
        authenticates the client and opens a terminal. At the end of the session
        the server closes the connection. All data is sent in plain text format whithout any encryption.
      </para>
      <section>
        <title>The network virtual terminal</title>
        <para>
          The communication is based on the network virtual terminal (NVT).
          Its goal is to map a character terminal so neither the "server" nor 
          "user" hosts need to keep information about the characteristics 
          of each other's terminals and terminal handling conventions.
          NVT uses 7 bit code ASCII characters as the display device. An end of line
          is transmitted as a CRLF (carriage return followed by a line feed).
          NVT ASCII is used by many other protocols as well.
        </para>
        <para>
          NVT defines three mandatory control codes which must be understood by
          the participants: NULL, CR (Carriage Return), which moves the printer to the left 
          margin of the current line and LF (Line Feed), which moves the printer to the next 
          line keeping the current horizontal position.
        </para>
        <para>
          NVT also contains some optional commands which are useful. These are the following:
	</para>
	  <itemizedlist>
	   <listitem>
	    <para>
            <emphasis>BELL</emphasis> is an audible or visual sign. 
            </para>
	  </listitem>
	  <listitem>
	    <para>
	    <emphasis>BS</emphasis> (Back Space) moves the printer back one position and deletes a character.
	    </para>
	  </listitem>
	  <listitem>
	    <para>
            <emphasis>HT</emphasis> (Horizontal Tab) moves the printer to the next horizontal tabular stop.
	    </para>
	  </listitem>
	  <listitem>
	  <para>
          <emphasis>VT</emphasis> Vertical Tab moves the printer to the next vertical tabular stop.
	  </para>
	  </listitem>
	  <listitem>
	  <para> 
          <emphasis>FF</emphasis> (Form Feed) moves the printer to the top of the next page.
        </para>
	</listitem>
	</itemizedlist>
      </section>
      <section>
        <title>Protocol elements</title>
        <para>
          The protocol uses several commands that control the method and various details of the
          interaction between the client and the server. These commands can be either mandatory commands or extensions.
          During the session initialization the client and the server negotiates the connection parameters with these
          commands. Sub-negotiation is a process during the protocol which is for exchanging extra parameters of 
          a command (e.g.: sending the window size). The commands of the protocol are:
          <table>
            <title>Telnet protocol commands</title>
            <tgroup cols="2">
              <thead>
                <row>
                  <entry>Request/Response</entry>
                  <entry>Description</entry>
                </row>
              </thead>
              <tbody>
                <row>
                  <entry>SE</entry>
                  <entry>End of sub-negotiation parameters.</entry>
                </row>
                <row>
                  <entry>NOP</entry>
                  <entry>No operation.</entry>
                </row>
                <row>
                  <entry>DM</entry>
                  <entry>Data mark - Indicates the position of Sync event within the data stream.</entry>
                </row>
                <row>
                  <entry>BRK</entry>
                  <entry>Break - Indicates that a break or attention key was hit.</entry>
                </row>
                <row>
                  <entry>IP</entry>
                  <entry>Suspend, interrupt or abort the process.</entry>
                </row>
                <row>
                  <entry>AO</entry>
                  <entry>Abort output - Run a command without sending the output back to the client.</entry>
                </row>
                <row>
                  <entry>AYT</entry>
                  <entry>Are you there - Request a visible evidence that the AYT command has been received.</entry>
                </row>
                <row>
                  <entry>EC</entry>
                  <entry>Erase character - Delete the character last received from the stream.</entry>
                </row>
                <row>
                  <entry>EL</entry>
                  <entry>Erase line - Erase a line without a CRLF.</entry>
                </row>
                <row>
                  <entry>GA</entry>
                  <entry>Go Ahead - Instruct the other machine to start the transmission.</entry>
                </row>
                <row>
                  <entry>SB</entry>
                  <entry>Sub-negotiation starts here.</entry>
                </row>
                <row>
                  <entry>WILL</entry>
                  <entry>Will (option code) - Indicates the desire to begin performing the indicated option, or confirms that it is being performed.</entry>
                </row>
                <row>
                  <entry>WONT</entry>
                  <entry>Will not (option code) - Indicates the refusal to perform,               or continue performing, the indicated option.</entry>
                </row>
                <row>
                  <entry>DO</entry>
                  <entry>Do (option code) - Indicates the request that the                        other party perform, or confirmation that                                 the other party is expected to perform, the                                 indicated option.</entry>
                </row>
                <row>
                  <entry>DONT</entry>
                  <entry>Do not (option code) - Indicates the request that the other party stop performing the indicated option, or confirmation that its performing               is no longer expected. </entry>
                </row>
                <row>
                  <entry>IAC</entry>
                  <entry>Interpret as command.</entry>
                </row>
              </tbody>
            </tgroup>
          </table>
        </para>

      </section>
    </section>
    <section>
      <title>Proxy behavior</title>
      <para>
        TelnetProxy is a module built for parsing TELNET protocol commands and the negotiation process.
        It reads and parses COMMANDs on the client side, and sends them to the server if the local security policy permits. Arriving RESPONSEs are parsed as well and sent to the client if the local security policy permits.
        It is possible to manipulate options by using TELNET_OPT_POLICY. It is also 
        possible to accept or deny certain options and suboptions.
      </para>
      <para>
      The Telnet shell itself cannot be controlled, thus the commands issued by the users cannot be monitored or modified.
      </para>
      <section>
        <title>Default policy</title>
        <para>
          The low level abstract Telnet proxy denies every option and suboption negotiation
          sequences by default. The different options can be enabled either manually in a derived proxy class, or the predefined TelnetProxy class can be used. 
        </para>
      </section>
      <section id="telnet_policies">
        <title>Configuring policies for the TELNET protocol</title>
        <para>
          The Telnet proxy can enable/disable the use of the options and their suboptions within the session. Changing the default policy
          can be done using the <parameter>option</parameter> multi-dimensional hash, 
          indexed by the option and the suboption (optional). If the suboption is specified, the lookup precedence described in <xref linkend="proxy_response_codes"/> is used.
	  The possible action codes are listed in the table below.</para>
	  <inline type="actiontuple" target="action.telnet.opt"/>

        <example>
          <title>Example for disabling the Telnet X Display Location option</title>
          <literallayout>
class MyTelnetProxy(TelnetProxy):
	def config(self):
		TelnetProxy.config(self)
		self.option[TELNET_X_DISPLAY_LOCATION] = (TELNET_OPT_REJECT)
          </literallayout>
        </example>
	
	<para>
	Constants have been defined for the easier use of TELNET options and suboptions. These are listed in <xref linkend="telnet_options"/>.
	</para>
      
      <section>
        <title>Policy callback functions</title>
        <para>
          Policy callback functions can be used to make decisions based on the
          content of the suboption negotiation sequence. For example, the  suboption negotiation sequences of the Telnet
          Environment option transfer environment
          variables. The low level proxy implementation parses these variables, and
          passes their name and value to the callback function one-by-one. These
          values can also be manipulated during transfer, by changing the <parameter>current_var_name</parameter> and
          <parameter>current_var_value</parameter> attributes of the proxy class.
        </para>
        <example>
          <title>Rewriting the DISPLAY environment variable</title>
          <literallayout>
class MyRewritingTelnetProxy(TelnetProxy):
	def config(self):
		TelnetProxy.config()
		self.option[TELNET_ENVIRONMENT, TELNET_SB_IS] = (TELNET_OPTION_POLICY, self.rewriteVar)

	def rewriteVar(self, option, name, value):
		if name == "DISPLAY":
			self.current_var_value = "rewritten_value:0"
		return TELNET_OPTION_ACCEPT
          </literallayout>
        </example>
      </section>
      <section>
      <title>
      Option negotiation
      </title>
      <para>
      In the Telnet protocol, options and the actual commands are represented on one byte. In order to be able to use a command in a session, the option (and its suboptions if there are any) corresponding to the command has to be negotiated between the client and the server. Usually the command and the option is represented by the same value, e.g.: the <parameter>TELNET_STATUS</parameter> command and option are both represented by the value "5". However, this is not always the case. The <parameter>negotiation</parameter> hash is indexed by the code of the command, and contains the code of the option to be negotiated for the given command (or the <parameter>TELNET_NEG_NONE</parameter> when no negotation is needed). </para>
      <para>Currently the only command where the code of the command differs from the related option is <literallayout>self.negotiation["239"] = int(TELNET_EOR)</literallayout>.
      </para>
      </section>
     </section>
    </section>
    <section>
      <title>Related standards</title>
          <para>
              The Telnet protocol is described in RFC 854. The different options of the protocol are described in various other RFCs, listed in <xref linkend="telnet_options"/>.
            </para>
   </section>
  </description>
  <appendix id="telnet_app_options">
  <title>TELNET appendix</title>
  	<para>
	The constants defined for the easier use of TELNET options and suboptions are listed in the table below. Suboptions are listed directly under the option they refer to. All suboptions have the TELNET_SB prefix. The RFC describing the given option is also shown in the table.
	</para>
	<table frame="all" id="telnet_options">
<title>TELNET options and suboptions</title>
<tgroup cols="3">
<thead><row><entry>Name</entry><entry>Constant value of option/suboption</entry><entry>Detailed in RFC #</entry></row></thead>
<tbody>

<row><entry>TELNET_BINARY</entry><entry>0</entry><entry>856</entry></row>

<row><entry>TELNET_ECHO</entry><entry>1</entry><entry>857</entry></row>

<row><entry>TELNET_SUPPRESS_GO_AHEAD</entry><entry>3</entry><entry>858</entry></row>

<row><entry>TELNET_STATUS</entry><entry>5</entry><entry>859 </entry></row>
<row><entry>TELNET_SB_STATUS_SB_IS</entry><entry>0</entry></row>
<row><entry>TELNET_SB_STATUS_SB_SEND</entry><entry>1</entry></row>

<row><entry>TELNET_TIMING_MARK</entry><entry>6</entry><entry>860</entry></row>

<row><entry>TELNET_RCTE</entry><entry>7</entry><entry>726</entry></row>

<row><entry>TELNET_NAOCRD</entry><entry>10</entry><entry>652</entry></row>
<row><entry>TELNET_SB_NAOCRD_DR</entry><entry>0</entry></row>
<row><entry>TELNET_SB_NAOCRD_DS</entry><entry>1</entry></row>

<row><entry>TELNET_NAOHTS</entry><entry>11</entry><entry>653</entry></row>
<row><entry>TELNET_SB_NAOHTS_DR</entry><entry>0</entry></row>
<row><entry>TELNET_SB_NAOHTS_DS</entry><entry>1</entry></row>

<row><entry>TELNET_NAOHTD</entry><entry>12</entry><entry>654</entry></row>
<row><entry>TELNET_SB_NAOHTD_DR</entry><entry>0</entry></row>
<row><entry>TELNET_SB_NAOHTD_DS</entry><entry>1</entry></row>

<row><entry>TELNET_NAOFFD</entry><entry>13</entry><entry>655</entry></row>
<row><entry>TELNET_SB_NAOFFD_DR</entry><entry>0</entry></row>
<row><entry>TELNET_SB_NAOFFD_DS</entry><entry>1</entry></row>

<row><entry>TELNET_NAOVTS</entry><entry>14</entry><entry>656</entry></row>
<row><entry>TELNET_SB_NAOVTS_DR</entry><entry>0</entry></row>
<row><entry>TELNET_SB_NAOVTS_DS</entry><entry>1</entry></row>

<row><entry>TELNET_NAOVTD</entry><entry>15</entry><entry>657</entry></row>
<row><entry>TELNET_SB_NAOVTD_DR</entry><entry>0</entry></row>
<row><entry>TELNET_SB_NAOVTD_DS</entry><entry>1</entry></row>

<row><entry>TELNET_NAOLFD</entry><entry>16</entry><entry>658</entry></row>
<row><entry>TELNET_SB_NAOLFD_DR</entry><entry>0</entry></row>
<row><entry>TELNET_SB_NAOLFD_DS</entry><entry>1</entry></row>

<row><entry>TELNET_EXTEND_ASCII</entry><entry>17</entry><entry>698</entry></row>

<row><entry>TELNET_LOGOUT</entry><entry>18</entry><entry>727</entry></row>

<row><entry>TELNET_BM</entry><entry>19</entry><entry>735</entry></row>
<row><entry>TELNET_SB_BM_DEFINE</entry><entry>1</entry></row>
<row><entry>TELNET_SB_BM_ACCEPT</entry><entry>2</entry></row>
<row><entry>TELNET_SB_BM_REFUSE</entry><entry>3</entry></row>
<row><entry>TELNET_SB_BM_LITERAL</entry><entry>4</entry></row>
<row><entry>TELNET_SB_BM_CANCEL</entry><entry>5</entry></row>

<row><entry>TELNET_DET</entry><entry>20</entry><entry>1043, 732</entry></row>
<row><entry>TELNET_SB_DET_DEFINE</entry><entry>1</entry></row>
<row><entry>TELNET_SB_DET_ERASE</entry><entry>2</entry></row>
<row><entry>TELNET_SB_DET_TRANSMIT</entry><entry>3</entry></row>
<row><entry>TELNET_SB_DET_FORMAT</entry><entry>4</entry></row>
<row><entry>TELNET_SB_DET_MOVE_CURSOR</entry><entry>5</entry></row>
<row><entry>TELNET_SB_DET_SKIP_TO_LINE</entry><entry>6</entry></row>
<row><entry>TELNET_SB_DET_SKIP_TO_CHAR</entry><entry>7</entry></row>
<row><entry>TELNET_SB_DET_UP</entry><entry>8</entry></row>
<row><entry>TELNET_SB_DET_DOWN</entry><entry>9</entry></row>
<row><entry>TELNET_SB_DET_LEFT</entry><entry>10</entry></row>
<row><entry>TELNET_SB_DET_RIGHT</entry><entry>11</entry></row>
<row><entry>TELNET_SB_DET_HOME</entry><entry>12</entry></row>
<row><entry>TELNET_SB_DET_LINE_INSERT</entry><entry>13</entry></row>
<row><entry>TELNET_SB_DET_LINE_DELETE</entry><entry>14</entry></row>
<row><entry>TELNET_SB_DET_CHAR_INSERT</entry><entry>15</entry></row>
<row><entry>TELNET_SB_DET_CHAR_DELETE</entry><entry>16</entry></row>
<row><entry>TELNET_SB_DET_READ_CURSOR</entry><entry>17</entry></row>
<row><entry>TELNET_SB_DET_CURSOR_POSITION</entry><entry>18</entry></row>
<row><entry>TELNET_SB_DET_REVERSE_TAB</entry><entry>19</entry></row>
<row><entry>TELNET_SB_DET_TRANSMIT_SCREEN</entry><entry>20</entry></row>
<row><entry>TELNET_SB_DET_TRANSMIT_UNPROTECTED</entry><entry>21</entry></row>
<row><entry>TELNET_SB_DET_TRANSMIT_LINE</entry><entry>22</entry></row>
<row><entry>TELNET_SB_DET_TRANSMIT_FIELD</entry><entry>23</entry></row>
<row><entry>TELNET_SB_DET_TRANSMIT_REST_SCREEN</entry><entry>24</entry></row>
<row><entry>TELNET_SB_DET_TRANSMIT_REST_LINE</entry><entry>25</entry></row>
<row><entry>TELNET_SB_DET_TRANSMIT_REST_FIELD</entry><entry>26</entry></row>
<row><entry>TELNET_SB_DET_TRANSMIT_MODIFIED</entry><entry>27</entry></row>
<row><entry>TELNET_SB_DET_DATA_TRANSMIT</entry><entry>28</entry></row>
<row><entry>TELNET_SB_DET_ERASE_SCREEN</entry><entry>29</entry></row>
<row><entry>TELNET_SB_DET_ERASE_LINE</entry><entry>30</entry></row>
<row><entry>TELNET_SB_DET_ERASE_FIELD</entry><entry>31</entry></row>
<row><entry>TELNET_SB_DET_ERASE_REST_SCREEN</entry><entry>32</entry></row>
<row><entry>TELNET_SB_DET_ERASE_REST_LINE</entry><entry>33</entry></row>
<row><entry>TELNET_SB_DET_ERASE_REST_FIELD</entry><entry>34</entry></row>
<row><entry>TELNET_SB_DET_ERASE_UNPROTECTED</entry><entry>35</entry></row>
<row><entry>TELNET_SB_DET_FORMAT_DATA</entry><entry>36</entry></row>
<row><entry>TELNET_SB_DET_REPEAT</entry><entry>37</entry></row>
<row><entry>TELNET_SB_DET_SUPPRESS_PROTECTION</entry><entry>38</entry></row>
<row><entry>TELNET_SB_DET_FIELD_SEPARATOR</entry><entry>39</entry></row>
<row><entry>TELNET_SB_DET_FN</entry><entry>40</entry></row>
<row><entry>TELNET_SB_DET_ERROR</entry><entry>41</entry></row>

<row><entry>TELNET_SUPDUP</entry><entry>21</entry><entry>736, 734</entry></row>

<row><entry>TELNET_SUPDUP_OUTPUT</entry><entry>22</entry><entry>749</entry></row>

<row><entry>TELNET_SEND_LOCATION</entry><entry>23</entry><entry>779</entry></row>

<row><entry>TELNET_TERMINAL_TYPE</entry><entry>24</entry><entry>1091</entry></row>
<row><entry>TELNET_SB_TERMINAL_TYPE_IS</entry><entry>0</entry></row>
<row><entry>TELNET_SB_TERMINAL_TYPE_SEND</entry><entry>1</entry></row>

<row><entry>TELNET_EOR</entry><entry>25</entry><entry>885</entry></row>

<row><entry>TELNET_TUID</entry><entry>26</entry><entry>927</entry></row>

<row><entry>TELNET_OUTMRK</entry><entry>27</entry><entry>933</entry></row>

<row><entry>TELNET_TTYLOC</entry><entry>28 946</entry></row>

<row><entry>TELNET_3270_REGIME</entry><entry>29</entry><entry>1041</entry></row>
<row><entry>TELNET_SB_3270_REGIME_IS</entry><entry>0</entry></row>
<row><entry>TELNET_SB_3270_REGIME_ARE</entry><entry>1</entry></row>

<row><entry>TELNET_X3_PAD</entry><entry>30</entry><entry>1053</entry></row>
<row><entry>TELNET_SB_X3_PAD_SET</entry><entry>0</entry></row>
<row><entry>TELNET_SB_X3_PAD_RESPONSE_SET</entry><entry>1</entry></row>
<row><entry>TELNET_SB_X3_PAD_IS</entry><entry>2</entry></row>
<row><entry>TELNET_SB_X3_PAD_RESPONSE_IS</entry><entry>3</entry></row>
<row><entry>TELNET_SB_X3_PAD_SEND</entry><entry>4</entry></row>

<row><entry>TELNET_NAWS</entry><entry>31</entry><entry>1073</entry></row>

<row><entry>TELNET_TERMINAL_SPEED</entry><entry>32</entry><entry>1079</entry></row>
<row><entry>TELNET_SB_TERMINAL_SPEED_IS</entry><entry>0</entry></row>
<row><entry>TELNET_SB_TERMINAL_SPEED_SEND</entry><entry>1</entry></row>

<row><entry>TELNET_TOGGLE_FLOW_CONTROL</entry><entry>33</entry><entry>1372</entry></row>
<row><entry>TELNET_SB_TOGGLE_FLOW_CONTROL_OFF</entry><entry>0</entry></row>
<row><entry>TELNET_SB_TOGGLE_FLOW_CONTROL_ON</entry><entry>1</entry></row>
<row><entry>TELNET_SB_TOGGLE_FLOW_CONTROL_RESTART_ANY </entry><entry>2</entry></row>
<row><entry>TELNET_SB_TOGGLE_FLOW_CONTROL_RESTART_XON </entry><entry>3</entry></row>

<row><entry>TELNET_LINEMODE</entry><entry>34</entry><entry>1184</entry></row>
<row><entry>TELNET_SB_LINEMODE_MODE</entry><entry>1</entry></row>
<row><entry>TELNET_SB_LINEMODE_FORWARDMASK</entry><entry>2</entry></row>
<row><entry>TELNET_SB_LINEMODE_SLC</entry><entry>3</entry></row>

<row><entry>TELNET_X_DISPLAY_LOCATION</entry><entry>35</entry><entry>1096</entry></row>
<row><entry>TELNET_SB_X_DISPLAY_LOCATION_IS</entry><entry>0</entry></row>
<row><entry>TELNET_SB_X_DISPLAY_LOCATION_SEND</entry><entry>1</entry></row>

<row><entry>TELNET_OLD_ENVIRONMENT</entry><entry>36</entry><entry>1408</entry></row>
<row><entry>TELNET_SB_OLD_ENVIRONMENT_IS</entry><entry>0</entry></row>
<row><entry>TELNET_SB_OLD_ENVIRONMENT_SEND</entry><entry>1</entry></row>
<row><entry>TELNET_SB_OLD_ENVIRONMENT_INFO</entry><entry>2</entry></row>

<row><entry>TELNET_AUTHENTICATION</entry><entry>37</entry><entry>2941</entry></row>
<row><entry>TELNET_SB_AUTHENTICATION_IS</entry><entry>0</entry></row>
<row><entry>TELNET_SB_AUTHENTICATION_SEND</entry><entry>1</entry></row>
<row><entry>TELNET_SB_AUTHENTICATION_REPLY</entry><entry>2</entry></row>
<row><entry>TELNET_SB_AUTHENTICATION_NAME</entry><entry>3</entry></row>

<row><entry>TELNET_ENCRYPT</entry><entry>38</entry><entry>2946</entry></row>
<row><entry>TELNET_SB_ENCRYPT_IS</entry><entry>0</entry></row>
<row><entry>TELNET_SB_ENCRYPT_SUPPORT</entry><entry>1</entry></row>
<row><entry>TELNET_SB_ENCRYPT_REPLY</entry><entry>2</entry></row>
<row><entry>TELNET_SB_ENCRYPT_START</entry><entry>3</entry></row>
<row><entry>TELNET_SB_ENCRYPT_END</entry><entry>4</entry></row>
<row><entry>TELNET_SB_ENCRYPT_REQUEST_START</entry><entry>5</entry></row>
<row><entry>TELNET_SB_ENCRYPT_REQUEST_END</entry><entry>6</entry></row>
<row><entry>TELNET_SB_ENCRYPT_ENC_KEYID</entry><entry>7</entry></row>
<row><entry>TELNET_SB_ENCRYPT_DEC_KEYID</entry><entry>8</entry></row>

<row><entry>TELNET_ENVIRONMENT</entry><entry>39</entry><entry>1572</entry></row>
<row><entry>TELNET_SB_ENVIRONMENT_IS</entry><entry>0</entry></row>
<row><entry>TELNET_SB_ENVIRONMENT_SEND</entry><entry>1</entry></row>
<row><entry>TELNET_SB_ENVIRONMENT_INFO</entry><entry>2</entry></row>

<row><entry>TELNET_TN3270E</entry><entry>40</entry><entry>1647</entry></row>
<row><entry>TELNET_SB_TN3270E_ASSOCIATE</entry><entry>0</entry></row>
<row><entry>TELNET_SB_TN3270E_CONNECT</entry><entry>1</entry></row>
<row><entry>TELNET_SB_TN3270E_DEVICE_TYPE</entry><entry>2</entry></row>
<row><entry>TELNET_SB_TN3270E_FUNCTIONS</entry><entry>3</entry></row>
<row><entry>TELNET_SB_TN3270E_IS</entry><entry>4</entry></row>
<row><entry>TELNET_SB_TN3270E_REASON</entry><entry>5</entry></row>
<row><entry>TELNET_SB_TN3270E_REJECT</entry><entry>6</entry></row>
<row><entry>TELNET_SB_TN3270E_REQUEST</entry><entry>7</entry></row>
<row><entry>TELNET_SB_TN3270E_SEND</entry><entry>8</entry></row>

<row><entry>TELNET_CHARSET</entry><entry>42</entry><entry>2066</entry></row>
<row><entry>TELNET_SB_CHARSET_REQUEST</entry><entry>1</entry></row>
<row><entry>TELNET_SB_CHARSET_ACCEPTED</entry><entry>2</entry></row>
<row><entry>TELNET_SB_CHARSET_REJECTED</entry><entry>3</entry></row>
<row><entry>TELNET_SB_CHARSET_TTABLE_IS</entry><entry>4</entry></row>
<row><entry>TELNET_SB_CHARSET_TTABLE_REJECTED</entry><entry>5</entry></row>
<row><entry>TELNET_SB_CHARSET_TTABLE_ACK</entry><entry>6</entry></row>
<row><entry>TELNET_SB_CHARSET_TTABLE_NAK</entry><entry>7</entry></row>

<row><entry>TELNET_COM_PORT</entry><entry>44</entry><entry>2217</entry></row>
<row><entry>TELNET_SB_COM_PORT_CLI_SET_BAUDRATE</entry><entry>1</entry></row>
<row><entry>TELNET_SB_COM_PORT_CLI_SET_DATASIZE</entry><entry>2</entry></row>
<row><entry>TELNET_SB_COM_PORT_CLI_SET_PARITY</entry><entry>3</entry></row>
<row><entry>TELNET_SB_COM_PORT_CLI_SET_STOPSIZE</entry><entry>4</entry></row>
<row><entry>TELNET_SB_COM_PORT_CLI_SET_CONTROL</entry><entry>5</entry></row>
<row><entry>TELNET_SB_COM_PORT_CLI_NOTIFY_LINESTATE</entry><entry>6</entry></row>
<row><entry>TELNET_SB_COM_PORT_CLI_NOTIFY_MODEMSTATE </entry><entry>7</entry></row>
<row><entry>TELNET_SB_COM_PORT_CLI_FLOWCONTROL_SUSPEND </entry><entry>8</entry></row>
<row><entry>TELNET_SB_COM_PORT_CLI_FLOWCONTROL_RESUME </entry><entry>9</entry></row>
<row><entry>TELNET_SB_COM_PORT_CLI_SET_LINESTATE_MASK </entry><entry>10</entry></row>
<row><entry>TELNET_SB_COM_PORT_CLI_SET_MODEMSTATE_MASK </entry><entry>11</entry></row>
<row><entry>TELNET_SB_COM_PORT_CLI_PURGE_DATA</entry><entry>12</entry></row>
<row><entry>TELNET_SB_COM_PORT_SVR_SET_BAUDRATE</entry><entry>101</entry></row>
<row><entry>TELNET_SB_COM_PORT_SVR_SET_DATASIZE</entry><entry>102</entry></row>
<row><entry>TELNET_SB_COM_PORT_SVR_SET_PARITY</entry><entry>103</entry></row>
<row><entry>TELNET_SB_COM_PORT_SVR_SET_STOPSIZE</entry><entry>104</entry></row>
<row><entry>TELNET_SB_COM_PORT_SVR_SET_CONTROL</entry><entry>105</entry></row>
<row><entry>TELNET_SB_COM_PORT_SVR_NOTIFY_LINESTATE</entry><entry>106</entry></row>
<row><entry>TELNET_SB_COM_PORT_SVR_NOTIFY_MODEMSTATE </entry><entry>107</entry></row>
<row><entry>TELNET_SB_COM_PORT_SVR_FLOWCONTROL_SUSPEND </entry><entry>108</entry></row>
<row><entry>TELNET_SB_COM_PORT_SVR_FLOWCONTROL_RESUME </entry><entry>109</entry></row>
<row><entry>TELNET_SB_COM_PORT_SVR_SET_LINESTATE_MASK </entry><entry>110</entry></row>
<row><entry>TELNET_SB_COM_PORT_SVR_SET_MODEMSTATE_MASK </entry><entry>111</entry></row>
<row><entry>TELNET_SB_COM_PORT_SVR_PURGE_DATA</entry><entry>112</entry></row>

<row><entry>TELNET_KERMIT</entry><entry>47</entry><entry>2840</entry></row>
<row><entry>TELNET_SB_KERMIT_START_SERVER</entry><entry>0</entry></row>
<row><entry>TELNET_SB_KERMIT_STOP_SERVER</entry><entry>1</entry></row>
<row><entry>TELNET_SB_KERMIT_REQ_START_SERVER</entry><entry>2</entry></row>
<row><entry>TELNET_SB_KERMIT_REQ_STOP_SERVER</entry><entry>3</entry></row>
<row><entry>TELNET_SB_KERMIT_SOP</entry><entry>4</entry></row>
<row><entry>TELNET_SB_KERMIT_RESP_START_SERVER</entry><entry>8</entry></row>
<row><entry>TELNET_SB_KERMIT_RESP_STOP_SERVER</entry><entry>9</entry></row>

<row><entry>TELNET_EXOPL</entry><entry>255</entry><entry>861</entry></row>

<row><entry>TELNET_SUBLIMINAL_MSG</entry><entry>257</entry><entry>1097</entry></row>

</tbody>
</tgroup>
</table>
	

  </appendix>
  <metainfo>
    <enums>
      <enum maturity="stable" id="enum.telnet.opt">
        <description>
          Telnet proxy option hashes.
        </description>
        <item>
          <name>TELNET_OPT_ACCEPT</name>
        </item>
        <item>
          <name>TELNET_OPT_REJECT</name>
        </item>
        <item>
          <name>TELNET_OPT_ABORT</name>
        </item>
        <item>
          <name>TELNET_OPT_DROP</name>
        </item>
        <item>
          <name>TELNET_OPT_POLICY</name>
        </item>
      </enum>
      <enum maturity="stable" id="enum.telnet.prot">
        <description>
          Protocol parameter hashes to control the dataflow.
        </description>
        <item>
          <name>TELNET_TERMINAL_TYPE</name>
        </item>
        <item>
          <name>TELNET_TERMINAL_SPEED</name>
        </item>
        <item>
          <name>TELNET_X_DISPLAY_LOCATION</name>
        </item>
        <item>
          <name>TELNET_ENVIRONMENT</name>
        </item>
        <item>
          <name>TELNET_SUPPRESS_GO_AHEAD</name>
        </item>
        <item>
          <name>TELNET_ECHO</name>
        </item>
        <item>
          <name>TELNET_NAWS</name>
        </item>
      </enum>
      <enum maturity="stable" id="enum.telnet.sb">
        <description>
          SB hashes of Telnet.
        </description>
        <item>
          <name>TELNET_SB_IS</name>
        </item>
        <item>
          <name>TELNET_SB_SEND</name>
        </item>
        <item>
          <name>TELNET_SB_INFO</name>
        </item>
      </enum>
    </enums>
    <constants>
      <constantgroup maturity="stable" id="const.telnet.log">
        <description>
          Parameters of the logging system. These values are printed into the log messages.
        </description>
        <item>
          <name>TELNET_POLICY</name>
          <value>"telnet.policy"</value>
        </item>
      </constantgroup>
    </constants>
    <actiontuples>
      <actiontuple maturity="stable" id="action.telnet.opt" action_enum="enum.telnet.opt">
	<description>
	  Action codes for Telnet options
	</description>
	<tuple action="TELNET_OPT_ACCEPT">
	  <args/>
	  <description>
	    <para>
	      Allow the option.
	    </para>
	  </description>
	</tuple>
	<tuple action="TELNET_OPT_DROP">
	  <args/>
	  <description>
	    <para>
	      Reject the option.
	    </para>
	  </description>
	</tuple>
	<tuple action="TELNET_OPT_ABORT">
	  <args/>
	  <description>
	    <para>
	      Reject the option and terminate the Telnet session.
	    </para>
	  </description>
	</tuple>
	<tuple action="TELNET_OPT_POLICY">
	  <args>METHOD</args>
	  <description>
	    <para>
	      Call the function specified to make a decision about the event. The function receives two parameters: self, and option (an integer). See <xref linkend="proxy_policies"/> for details.
	    </para>
	  </description>
	</tuple>
      </actiontuple>
    </actiontuples>    
  </metainfo>
</module>"""

from Zorp import *
from Proxy import Proxy

TELNET_OPT_ACCEPT	= 1
TELNET_OPT_REJECT	= 3
TELNET_OPT_ABORT	= 4
TELNET_OPT_DROP		= 5
TELNET_OPT_POLICY	= 6

# No negotiation is needed for that command
TELNET_NEG_NONE		= 255

# option name				value	RFC, subopt
# -------------------------             ------	-----------
#TELNET_BINARY				= "0"	# 856

TELNET_ECHO				= "1"	# 857

TELNET_SUPPRESS_GO_AHEAD		= "3"	# 858

#TELNET_STATUS				= "5"	# 859 
#TELNET_SB_STATUS_SB_IS				= "0"
#TELNET_SB_STATUS_SB_SEND			= "1"

#TELNET_TIMING_MARK			= "6"	# 860

#TELNET_RCTE				= "7"	# 726

#TELNET_NAOCRD				= "10"	# 652
#TELNET_SB_NAOCRD_DR				= "0"
#TELNET_SB_NAOCRD_DS				= "1"

#TELNET_NAOHTS				= "11"	# 653
#TELNET_SB_NAOHTS_DR				= "0"
#TELNET_SB_NAOHTS_DS				= "1"

#TELNET_NAOHTD				= "12"	# 654
#TELNET_SB_NAOHTD_DR				= "0"
#TELNET_SB_NAOHTD_DS				= "1"

#TELNET_NAOFFD				= "13"	# 655
#TELNET_SB_NAOFFD_DR				= "0"
#TELNET_SB_NAOFFD_DS				= "1"

#TELNET_NAOVTS				= "14"	# 656
#TELNET_SB_NAOVTS_DR				= "0"
#TELNET_SB_NAOVTS_DS				= "1"

#TELNET_NAOVTD				= "15"	# 657
#TELNET_SB_NAOVTD_DR				= "0"
#TELNET_SB_NAOVTD_DS				= "1"

#TELNET_NAOLFD				= "16"	# 658
#TELNET_SB_NAOLFD_DR				= "0"
#TELNET_SB_NAOLFD_DS				= "1"

#TELNET_EXTEND_ASCII			= "17"	# 698

#TELNET_LOGOUT				= "18"	# 727

#TELNET_BM				= "19"	# 735
#TELNET_SB_BM_DEFINE				= "1"
#TELNET_SB_BM_ACCEPT				= "2"
#TELNET_SB_BM_REFUSE				= "3"
#TELNET_SB_BM_LITERAL				= "4"
#TELNET_SB_BM_CANCEL				= "5"

#TELNET_DET				= "20"	# 1043, 732
#TELNET_SB_DET_DEFINE				= "1"
#TELNET_SB_DET_ERASE				= "2"
#TELNET_SB_DET_TRANSMIT				= "3"
#TELNET_SB_DET_FORMAT				= "4"
#TELNET_SB_DET_MOVE_CURSOR			= "5"
#TELNET_SB_DET_SKIP_TO_LINE			= "6"
#TELNET_SB_DET_SKIP_TO_CHAR			= "7"
#TELNET_SB_DET_UP				= "8"
#TELNET_SB_DET_DOWN				= "9"
#TELNET_SB_DET_LEFT				= "10"
#TELNET_SB_DET_RIGHT				= "11"
#TELNET_SB_DET_HOME				= "12"
#TELNET_SB_DET_LINE_INSERT			= "13"
#TELNET_SB_DET_LINE_DELETE			= "14"
#TELNET_SB_DET_CHAR_INSERT			= "15"
#TELNET_SB_DET_CHAR_DELETE			= "16"
#TELNET_SB_DET_READ_CURSOR			= "17"
#TELNET_SB_DET_CURSOR_POSITION			= "18"
#TELNET_SB_DET_REVERSE_TAB			= "19"
#TELNET_SB_DET_TRANSMIT_SCREEN			= "20"
#TELNET_SB_DET_TRANSMIT_UNPROTECTED		= "21"
#TELNET_SB_DET_TRANSMIT_LINE			= "22"
#TELNET_SB_DET_TRANSMIT_FIELD			= "23"
#TELNET_SB_DET_TRANSMIT_REST_SCREEN		= "24"
#TELNET_SB_DET_TRANSMIT_REST_LINE		= "25"
#TELNET_SB_DET_TRANSMIT_REST_FIELD		= "26"
#TELNET_SB_DET_TRANSMIT_MODIFIED		= "27"
#TELNET_SB_DET_DATA_TRANSMIT			= "28"
#TELNET_SB_DET_ERASE_SCREEN			= "29"
#TELNET_SB_DET_ERASE_LINE			= "30"
#TELNET_SB_DET_ERASE_FIELD			= "31"
#TELNET_SB_DET_ERASE_REST_SCREEN		= "32"
#TELNET_SB_DET_ERASE_REST_LINE			= "33"
#TELNET_SB_DET_ERASE_REST_FIELD			= "34"
#TELNET_SB_DET_ERASE_UNPROTECTED		= "35"
#TELNET_SB_DET_FORMAT_DATA			= "36"
#TELNET_SB_DET_REPEAT				= "37"
#TELNET_SB_DET_SUPPRESS_PROTECTION		= "38"
#TELNET_SB_DET_FIELD_SEPARATOR			= "39"
#TELNET_SB_DET_FN				= "40"
#TELNET_SB_DET_ERROR				= "41"

#TELNET_SUPDUP				= "21"	# 736, 734

#TELNET_SUPDUP_OUTPUT			= "22"	# 749

#TELNET_SEND_LOCATION			= "23"	# 779

TELNET_TERMINAL_TYPE			= "24"	# 1091
TELNET_SB_TERMINAL_TYPE_IS			= "0"
TELNET_SB_TERMINAL_TYPE_SEND			= "1"

TELNET_EOR				= "25"	# 885

#TELNET_TUID				= "26"	# 927

#TELNET_OUTMRK				= "27"	# 933

#TELNET_TTYLOC				= "28	# 946

#TELNET_3270_REGIME			= "29"	# 1041
#TELNET_SB_3270_REGIME_IS			= "0"
#TELNET_SB_3270_REGIME_ARE			= "1"

#TELNET_X3_PAD				= "30"	# 1053
#TELNET_SB_X3_PAD_SET				= "0"
#TELNET_SB_X3_PAD_RESPONSE_SET			= "1"
#TELNET_SB_X3_PAD_IS				= "2"
#TELNET_SB_X3_PAD_RESPONSE_IS			= "3"
#TELNET_SB_X3_PAD_SEND				= "4"

TELNET_NAWS				= "31"	# 1073

TELNET_TERMINAL_SPEED			= "32"	# 1079
TELNET_SB_TERMINAL_SPEED_IS			= "0"
TELNET_SB_TERMINAL_SPEED_SEND			= "1"

#TELNET_TOGGLE_FLOW_CONTROL		= "33"	# 1372
#TELNET_SB_TOGGLE_FLOW_CONTROL_OFF		= "0"
#TELNET_SB_TOGGLE_FLOW_CONTROL_ON		= "1"
#TELNET_SB_TOGGLE_FLOW_CONTROL_RESTART_ANY	= "2"
#TELNET_SB_TOGGLE_FLOW_CONTROL_RESTART_XON	= "3"

#TELNET_LINEMODE			= "34"	# 1184
#TELNET_SB_LINEMODE_MODE			= "1"
#TELNET_SB_LINEMODE_FORWARDMASK			= "2"
#TELNET_SB_LINEMODE_SLC				= "3"

TELNET_X_DISPLAY_LOCATION		= "35"	# 1096
TELNET_SB_X_DISPLAY_LOCATION_IS			= "0"
TELNET_SB_X_DISPLAY_LOCATION_SEND		= "1"

#TELNET_OLD_ENVIRONMENT			= "36"	# 1408
#TELNET_SB_OLD_ENVIRONMENT_IS			= "0"
#TELNET_SB_OLD_ENVIRONMENT_SEND			= "1"
#TELNET_SB_OLD_ENVIRONMENT_INFO			= "2"

#TELNET_AUTHENTICATION			= "37"	# 2941
#TELNET_SB_AUTHENTICATION_IS			= "0"
#TELNET_SB_AUTHENTICATION_SEND			= "1"
#TELNET_SB_AUTHENTICATION_REPLY			= "2"
#TELNET_SB_AUTHENTICATION_NAME			= "3"

#TELNET_ENCRYPT				= "38"	# 2946
#TELNET_SB_ENCRYPT_IS				= "0"
#TELNET_SB_ENCRYPT_SUPPORT			= "1"
#TELNET_SB_ENCRYPT_REPLY			= "2"
#TELNET_SB_ENCRYPT_START			= "3"
#TELNET_SB_ENCRYPT_END				= "4"
#TELNET_SB_ENCRYPT_REQUEST_START		= "5"
#TELNET_SB_ENCRYPT_REQUEST_END			= "6"
#TELNET_SB_ENCRYPT_ENC_KEYID			= "7"
#TELNET_SB_ENCRYPT_DEC_KEYID			= "8"

TELNET_ENVIRONMENT			= "39"	# 1572
TELNET_SB_ENVIRONMENT_IS			= "0"
TELNET_SB_ENVIRONMENT_SEND			= "1"
TELNET_SB_ENVIRONMENT_INFO			= "2"

#TELNET_TN3270E				= "40"	# 1647
#TELNET_SB_TN3270E_ASSOCIATE			= "0"
#TELNET_SB_TN3270E_CONNECT			= "1"
#TELNET_SB_TN3270E_DEVICE_TYPE			= "2"
#TELNET_SB_TN3270E_FUNCTIONS			= "3"
#TELNET_SB_TN3270E_IS				= "4"
#TELNET_SB_TN3270E_REASON			= "5"
#TELNET_SB_TN3270E_REJECT			= "6"
#TELNET_SB_TN3270E_REQUEST			= "7"
#TELNET_SB_TN3270E_SEND				= "8"

#TELNET_CHARSET				= "42"	# 2066
#TELNET_SB_CHARSET_REQUEST			= "1"
#TELNET_SB_CHARSET_ACCEPTED			= "2"
#TELNET_SB_CHARSET_REJECTED			= "3"
#TELNET_SB_CHARSET_TTABLE_IS			= "4"
#TELNET_SB_CHARSET_TTABLE_REJECTED		= "5"
#TELNET_SB_CHARSET_TTABLE_ACK			= "6"
#TELNET_SB_CHARSET_TTABLE_NAK			= "7"

#TELNET_COM_PORT			= "44"	# 2217
#TELNET_SB_COM_PORT_CLI_SET_BAUDRATE		= "1"
#TELNET_SB_COM_PORT_CLI_SET_DATASIZE		= "2"
#TELNET_SB_COM_PORT_CLI_SET_PARITY		= "3"
#TELNET_SB_COM_PORT_CLI_SET_STOPSIZE		= "4"
#TELNET_SB_COM_PORT_CLI_SET_CONTROL		= "5"
#TELNET_SB_COM_PORT_CLI_NOTIFY_LINESTATE	= "6"
#TELNET_SB_COM_PORT_CLI_NOTIFY_MODEMSTATE	= "7"
#TELNET_SB_COM_PORT_CLI_FLOWCONTROL_SUSPEND	= "8"
#TELNET_SB_COM_PORT_CLI_FLOWCONTROL_RESUME	= "9"
#TELNET_SB_COM_PORT_CLI_SET_LINESTATE_MASK	= "10"
#TELNET_SB_COM_PORT_CLI_SET_MODEMSTATE_MASK	= "11"
#TELNET_SB_COM_PORT_CLI_PURGE_DATA		= "12"
#TELNET_SB_COM_PORT_SVR_SET_BAUDRATE		= "101"
#TELNET_SB_COM_PORT_SVR_SET_DATASIZE		= "102"
#TELNET_SB_COM_PORT_SVR_SET_PARITY		= "103"
#TELNET_SB_COM_PORT_SVR_SET_STOPSIZE		= "104"
#TELNET_SB_COM_PORT_SVR_SET_CONTROL		= "105"
#TELNET_SB_COM_PORT_SVR_NOTIFY_LINESTATE	= "106"
#TELNET_SB_COM_PORT_SVR_NOTIFY_MODEMSTATE	= "107"
#TELNET_SB_COM_PORT_SVR_FLOWCONTROL_SUSPEND	= "108"
#TELNET_SB_COM_PORT_SVR_FLOWCONTROL_RESUME	= "109"
#TELNET_SB_COM_PORT_SVR_SET_LINESTATE_MASK	= "110"
#TELNET_SB_COM_PORT_SVR_SET_MODEMSTATE_MASK	= "111"
#TELNET_SB_COM_PORT_SVR_PURGE_DATA		= "112"

#TELNET_KERMIT				= "47"	# 2840
#TELNET_SB_KERMIT_START_SERVER			= "0"
#TELNET_SB_KERMIT_STOP_SERVER			= "1"
#TELNET_SB_KERMIT_REQ_START_SERVER		= "2"
#TELNET_SB_KERMIT_REQ_STOP_SERVER		= "3"
#TELNET_SB_KERMIT_SOP				= "4"
#TELNET_SB_KERMIT_RESP_START_SERVER		= "8"
#TELNET_SB_KERMIT_RESP_STOP_SERVER		= "9"

TELNET_EXOPL				= "255"	# 861

#TELNET_SUBLIMINAL_MSG			= "257"	# 1097


################################################################################
# Non-RFC telnet options
#
# 2 - reconnection			# [nic 50005]
# 4 - approx msg size negotiation	# [ethernet]
# 8 - output line width			# [nic 50005]
# 9 - output page size			# [nic 50005]
# 41 - xauth				# [Earhart]
# 43 - remote serial port		# [Barnes]
# 45 - suppress local echo		# [Atmar]
# 46 - start tls			# [Boe]
# 48 - send url				# [Croft]
# 49 - forward X			# [Altman]
# 50-137 - unassigned			# [IANA]
# 138 - telopt pragma logon		# [McGregory]
# 139 - telopt sspi logon		# [McGregory]
# 140 - telopt pargma heartbeat		# [McGregory]
# 141-254 - unassigned			# [IANA]
# 256 - unassigned			# [IANA]

TELNET_SB_IS	= "0"
TELNET_SB_SEND	= "1"
TELNET_SB_INFO	= "2"

TELNET_POLICY	= "telnet.policy"

class AbstractTelnetProxy(Proxy):
	"""<class maturity="stable" abstract="yes">
          <summary>
            Class encapsulating the abstract Telnet proxy.
          </summary>
          <description>
            <para>
              This class implements the Telnet protocol (as described in RFC 854) and its most common
              extensions. Although not all possible options are checked by the low
              level proxy, it is possible to filter any option
              and suboption negotiation sequences using policy callbacks.
	      AbstractTelnetProxy serves as a starting point for customized proxy classes, but is itself not directly usable. Service definitions should refer to a customized class derived from AbstractTelnetProxy, or one of the predefined TelnetProxy proxy classes. AbstractTelnetProxy denies all options by default.
            </para>
          </description>
          <metainfo>
            <attributes>
              <attribute maturity="stable">
                <name>option</name>
                <type>
                  <hash>
                    <key>
		      <choice>
			<string/>
			<tuple>
			  <string/>
			  <string/>
			</tuple>
		      </choice>
                    </key>
                    <value>
                      <link id="action.telnet.opt"/>
                    </value>
                  </hash>
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
                  Normative policy hash for Telnet options 
                indexed by the option and (optionally) the suboption. See also <xref linkend="telnet_policies"/>. 
                </description>
              </attribute>
              <attribute maturity="stable">
                <name>negotiation</name>
                <type>
                  <hash>
                    <key>
                      <string/>
                    </key>
                    <value>
                      <integer/>
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
                  Normative hash listing which options must be negotiated for a given command. See <xref linkend="telnet_negotiation"/> for details.	  
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
                <name>current_var_name</name>
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
                  Name of the variable being negotiated.
                </description>
              </attribute>
              <attribute maturity="stable">
                <name>current_var_value</name>
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
                  Value of the variable being negotiated (e.g.: value of an environment variable,
                  an X display location value, etc.).
                </description>
              </attribute>
              <attribute maturity="stable">
                <name>enable_audit</name>
                <type>
                  <boolean/>
                </type>
                <default>FALSE</default>
                <conftime>
                  <write/>
                </conftime>
                <runtime>
                  <read/>
                </runtime>
                <description>
                  Enable session auditing.
                </description>
              </attribute>
            </attributes>
          </metainfo>
        </class>
        """
	name = "telnet"
	def __init__(self, session):
		"""<method maturity="stable" internal="yes">
                  <summary>
                    Constructor to initialize a TelnetProxy instance.
                  </summary>
                  <description>
                    <para>
                      This function initializes a TelnetProxy instance by calling
                      the inherited __init__ constructor with appropriate 
                      parameters.
                    </para>
                  </description>
                  <metainfo>
                    <arguments/>
                  </metainfo>
                </method>
                """
		Proxy.__init__(self, session)

	def config(self):
                """<method maturity="stable" internal="yes">
                  <metainfo>
                    <arguments/>
                  </metainfo>
                </method>
                """
		pass

class TelnetProxy(AbstractTelnetProxy):
	"""<class maturity="stable">
          <summary>
            Default Telnet proxy based on AbstractTelnetProxy.
          </summary>
          <description>
	  <para>TelnetProxy is a proxy class based on AbstractTelnetProxy, allowing the use of all Telnet options.</para>
          </description>
          <metainfo>
            <attributes/>
          </metainfo>
        </class>
        """
	def config(self):
		"""<method maturity="stable" internal="yes">
                  <metainfo>
                    <arguments/>
                  </metainfo>
                </method>
                """
		self.option["*"]	= TELNET_OPT_ACCEPT
		self.option["*", "*"]	= TELNET_OPT_ACCEPT
		self.negotiation["239"]	= int(TELNET_EOR)

class TelnetProxyStrict(AbstractTelnetProxy):
	"""<class maturity="stable">
          <summary>
            Telnet proxy based on AbstractTelnetProxy, allowing only the minimal command set.
          </summary>
          <description>
	  <para>TelnetProxyStrict is a proxy class based on AbstractTelnetProxy, allowing the use of the options minimally required for a useful Telnet session.</para>
	  <para>The following options are permitted: ECHO; SUPPRESS_GO_AHEAD; TERMINAL_TYPE; NAWS; EOR; TERMINAL_SPEED; X_DISPLAY_LOCATION; ENVIRONMENT.
		    All other options are rejected.
		    </para>
          </description>
          <metainfo>
            <attributes/>
          </metainfo>
        </class>
        """
	def config(self):
		"""<method maturity="stable" internal="yes">
                  <summary>
                    Configuration for TelnetProxy
                  </summary>
                  <description>
                    <para>
                      It enables all options needed for a useful Telnet session.
                    </para>
		    
                  </description>
                  <metainfo>
                    <arguments/>
                  </metainfo>
                </method>
                """
		self.option[TELNET_ECHO]		= TELNET_OPT_ACCEPT
		self.option[TELNET_SUPPRESS_GO_AHEAD]	= TELNET_OPT_ACCEPT
		self.option[TELNET_TERMINAL_TYPE]	= TELNET_OPT_ACCEPT
		self.option[TELNET_NAWS]		= TELNET_OPT_ACCEPT
		self.option[TELNET_EOR]			= TELNET_OPT_ACCEPT
		self.option[TELNET_TERMINAL_SPEED]	= TELNET_OPT_ACCEPT
		self.option[TELNET_X_DISPLAY_LOCATION]	= TELNET_OPT_ACCEPT
		self.option[TELNET_ENVIRONMENT]		= TELNET_OPT_ACCEPT
		self.option["*"]			= TELNET_OPT_REJECT

		self.option[TELNET_TERMINAL_TYPE,	TELNET_SB_TERMINAL_TYPE_IS] 		= TELNET_OPT_ACCEPT
		self.option[TELNET_TERMINAL_TYPE,	TELNET_SB_TERMINAL_TYPE_SEND] 		= TELNET_OPT_ACCEPT
		self.option[TELNET_TERMINAL_SPEED,	TELNET_SB_TERMINAL_SPEED_IS] 		= TELNET_OPT_ACCEPT
		self.option[TELNET_TERMINAL_SPEED,	TELNET_SB_TERMINAL_SPEED_SEND] 		= TELNET_OPT_ACCEPT
		self.option[TELNET_X_DISPLAY_LOCATION,	TELNET_SB_X_DISPLAY_LOCATION_IS] 	= TELNET_OPT_ACCEPT
		self.option[TELNET_X_DISPLAY_LOCATION,	TELNET_SB_X_DISPLAY_LOCATION_SEND]	= TELNET_OPT_ACCEPT
		self.option[TELNET_ENVIRONMENT,		TELNET_SB_ENVIRONMENT_IS] 		= TELNET_OPT_ACCEPT
		self.option[TELNET_ENVIRONMENT,		TELNET_SB_ENVIRONMENT_SEND] 		= TELNET_OPT_ACCEPT
		self.option[TELNET_ENVIRONMENT,		TELNET_SB_ENVIRONMENT_INFO] 		= TELNET_OPT_ACCEPT
		self.option[TELNET_NAWS,		"*"]					= TELNET_OPT_ACCEPT
		self.option[TELNET_EOR,			"*"]					= TELNET_OPT_ACCEPT
		self.option["*",			"*"]					= TELNET_OPT_REJECT

		self.negotiation["239"] 		= int(TELNET_EOR)

