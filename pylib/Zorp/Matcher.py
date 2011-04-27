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
    Module defining interface to the Matchers.
  </summary>
  <description>
  <para>
    In general, matcher policies can be used to find out if a parameter is
    included in a list (or which elements of a list correspond to a certain
    parameter), and influence the behavior of the proxy class based on the
    results. Matchers can be used for a wide range of tasks, for example, to
    determine if the particular IP address or URL that a client is trying to
    access is on a black or whitelist, or to verify that a particular e-mail
    address is valid.
  </para>
  </description>
</module>
"""

from Zorp import *
from Cache import TimedCache
import os, re, string, DNS, types, time, smtplib, socket, traceback

class MatcherPolicy:
        """<class maturity="stable" type="matcherpolicy">
          <summary>
            Class encapsulating a Matcher which can be used by a name.
          </summary>
          <description>
            <para>
            Matcher policies can be used to find out if a parameter is included
            in a list, or which elements of a list correspond to a certain
            parameter), and influence the behavior of the proxy class based on
            the results. Matchers can be used for a wide range of tasks, for
            example, to determine if the particular IP address or URL that a
            client is trying to access is on a black or whitelist, or to verify
            that a particular e-mail address is valid.
            </para>
            <para>
            MatcherPolicy instances are reusable matchers that contain configured
            instances of the matcher classes (e.g., DNSMatcher, RegexpMatcher)
            available in Zorp. For examples, see the specific matcher classes.
            </para>
          </description>
        </class>
        """
        def __init__(self, name, matcher):
                """<method internal="yes">
                <metainfo>
                  <arguments>
                    <argument maturity="stable">
                      <name>matcher</name>
                      <type>
                        <class filter="matcher" instance="yes"/>
                      </type>
                      <description>The encapsulated Matcher</description>
                    </argument>
                    <argument maturity="stable">
                      <name>name</name>
                      <type>
                        <string/>
                      </type>
                      <description>The name of the Matcher</description>
                    </argument>
                  </arguments>
                </metainfo>
                </method>
                """
                self.name = name
                self.matcher = matcher
                if Globals.matchers.has_key(name):
                        raise ValueError, "Duplicate matcher policy: %s" % name
                Globals.matchers[name] = self

def getMatcher(matcher_or_name_or_whatever):
        """<function internal="yes">
        </function>"""
        if isinstance(matcher_or_name_or_whatever, AbstractMatcher):
                return matcher_or_name_or_whatever
        if isinstance(matcher_or_name_or_whatever, MatcherPolicy):
                return matcher_or_name_or_whatever.matcher
        elif isinstance(matcher_or_name_or_whatever, str):
                if Globals.matchers.has_key(matcher_or_name_or_whatever):
                        return Globals.matchers[matcher_or_name_or_whatever].matcher
                log(None, CORE_POLICY, 3, "No such matcher; matcher='%s'" % (matcher_or_name_or_whatever))
        else:
                raise MatcherException, "Matcher is of invalid type"


class AbstractMatcher:
        """
        <class maturity="stable" abstract="yes">
          <summary>
            Class encapsulating the abstract string matcher.
          </summary>
          <description>
            <para>
              This abstract class encapsulates a string matcher that
              determines whether a given string is found in a backend database.
            </para>
            <para>
              Specialized subclasses of AbstractMatcher exist such as 'RegexpFileMatcher'
              which use regular expressions stored in flat files to find matches.
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
                    Constructor to initialize an AbstractMatcher instance.
                  </summary>
                  <description>
                    This constructor initializes an AbstractMatcher instance. Currently it
                    does nothing.
                  </description>
                  <metainfo>
                    <arguments/>
                  </metainfo>
                </method>
                """
                pass

        def checkMatch(self, str):
                """
                <method internal="yes">
                  <summary>
                    Virtual function to check if a given string actually matches.
                  </summary>
                  <description>
                    <para>
                      This function determines if a given string actually matches with an element of a backend.
                    </para>
                    <para>
                      It can raise a MatcherException to indicate general failure.
                    </para>
                  </description>
                  <metainfo>
                    <arguments>
                      <argument maturity="stable">
                        <name>str</name>
                        <type></type>
                        <description>string to check</description>
                      </argument>
                    </arguments>
                  </metainfo>
                </method>
                """
                raise NotImplementedError


class RegexpMatcher(AbstractMatcher):
        """
        <class maturity="stable">
          <summary>
            Class encapsulating a Matcher which uses regular expressions for string matching.
          </summary>
          <description>
            <para>
              A simple regular expression based matcher with a match and an ignore list. Searches are case-insensitive.
            </para>
            <example>
            <title>RegexpMatcher example</title>
            <para>The following RegexpMatcher matches only the <parameter>smtp.example.com</parameter> string.
            </para>
            <synopsis>
MatcherPolicy(name="Smtpdomains", matcher=RegexpMatcher (match_list=("smtp.example.com",), ignore_list=None))
            </synopsis>
            </example>
          </description>
          <metainfo>
            <attributes>
              <attribute maturity="stable">
                <name>match</name>
                <type></type>
                <description>A list of compiled regular expressions which result in a positive match.
                </description>
              </attribute>
              <attribute maturity="stable">
                <name>ignore</name>
                <type></type>
                <description>A list of compiled regular expressions defining the strings to be ignored even if
                 <parameter>match</parameter> resulted in a positive match.</description>
              </attribute>
            </attributes>
          </metainfo>
        </class>
        """
        def __init__(self, match_list=None, ignore_list=None, ignore_case=TRUE):
                """
                <method maturity="stable">
                  <summary>
                    Constructor to initialize a RegexpMatcher instance.
                  </summary>
                  <description>
                    <para>
                      This constructor initializes a RegexpMatcher instance by setting the
                      <parameter>match</parameter> and <parameter>ignore</parameter> attributes to an
                      empty list.
                    </para>
                  </description>
                  <metainfo>
                    <arguments>
                      <argument maturity="stable">
                        <name>match_list</name>
                        <type>
                          <filename/>
                        </type>
                        <default>None</default>
                        <description>The list of regular expressions to match.</description>
                      </argument>
                      <argument maturity="stable">
                        <name>ignore_list</name>
                        <type>
                          <filename/>
                        </type>
                        <default>None</default>
                        <description>The list of regular expressions to ignore.</description>
                      </argument>
                    </arguments>
                  </metainfo>
                </method>
                """
                AbstractMatcher.__init__(self)
                self.match = []
                self.ignore = []
                self.ignore_case = ignore_case
                if match_list:
                        for x in match_list:
                                re = self.compilePattern(x)
                                if re:
                                        self.match.append(re)
                if ignore_list:
                        for x in ignore_list:
                                re = self.compilePattern(x)
                                if re:
                                        self.ignore.append(re)

        def compilePattern(self, pat):
                """<method internal="yes">
                </method>
                """
                try:
                        if self.ignore_case == TRUE:
                                return (re.compile(pat.rstrip(), re.IGNORECASE), pat)
                        else:
                                return (re.compile(pat.rstrip()), pat)
                except re.error:
                        log(None, CORE_POLICY, 3, "Error compiling regular expression; expr='%s'", (pat))

        def checkMatch(self, str):
                """
                <method internal="yes">
                  <summary>
                    Function to determine if a given string actually matches.
                  </summary>
                  <description>
                    <para>
                      This function uses the attributes 'match' and 'ignore' to check
                      if a string matches.
                    </para>
                  </description>
                  <metainfo>
                    <arguments>
                      <argument maturity="stable">
                        <name>str</name>
                        <type></type>
                        <description>string to check</description>
                      </argument>
                    </arguments>
                  </metainfo>
                </method>
                """
                for pattern in self.match:
                        if pattern[0].search(str):
                                for pattern_ign in self.ignore:
                                        if pattern_ign[0].search(str):
                                                return FALSE
                                ## LOG ##
                                # This message reports that a matching regexp pattern was found
                                # for the given string.
                                ##
                                log(None, CORE_POLICY, 4, "Matching regexp found; str='%s', pattern='%s'", (str, pattern[1]))
                                return TRUE
                return FALSE


class RegexpFileMatcher(RegexpMatcher):
        """
        <class maturity="stable">
          <summary>
            Class encapsulating Matcher which uses regular expressions stored in files for string matching.
          </summary>
          <description>
            <para>
              This class is similar to <link linkend="python.Matcher.RegexpMatcher">RegexpMatcher</link>, but
              stores the regular expressions to match and ignore in files. For example, this class can be used
              for URL filtering. The matcher itself stores only the paths and the filenames to the lists. Zorp
              automatically monitors the file and reloads it when it is modified. Searches are case-insensitive.
            </para>
           <example>
            <title>RegexpFileMatcher example</title>
            <synopsis>
MatcherPolicy(name="demo_regexpfilematcher", matcher=RegexpFileMatcher(match_fname="/tmp/match_list.txt", ignore_fname="/tmp/ignore_list.txt"))
            </synopsis>
            </example>
          </description>
          <metainfo>
            <attributes>
              <attribute maturity="stable">
                <name>match_file</name>
                <type></type>
                <description>Name of the file storing the patterns for positive matches.</description>
              </attribute>
              <attribute maturity="stable">
                <name>match_date</name>
                <type></type>
                <description>Date (in unix timestamp format) when the
                <parameter>match_file</parameter> was loaded.
                </description>
              </attribute>
              <attribute maturity="stable">
                <name>ignore_file</name>
                <type></type>
                <description>Name of the file storing the patterns to ignore.</description>
              </attribute>
              <attribute maturity="stable">
                <name>ignore_date</name>
                <type></type>
                <description>Date (in unix timestamp format) when the
                <parameter>ignore_file</parameter> was loaded.
                </description>
              </attribute>
            </attributes>
          </metainfo>
        </class>
        """
        def __init__(self, match_fname=None, ignore_fname=None):
                """
                <method maturity="stable">
                  <summary>
                    Constructor to initialize a RegexpFileMatcher instance.
                  </summary>
                  <description>
                    <para>
                      This constructor initializes an instance of the RegexpFileMatcher class.
                    </para>
                  </description>
                  <metainfo>
                    <arguments>
                      <argument maturity="stable">
                        <name>match_fname</name>
                        <type>
                          <filename/>
                        </type>
                        <default>None</default>
                        <description>Name of the file storing the patterns for positive matches.</description>
                      </argument>
                      <argument maturity="stable">
                        <name>ignore_fname</name>
                        <type>
                          <filename/>
                        </type>
                        <default>None</default>
                        <description>Name of the file storing the patterns to ignore.</description>
                      </argument>
                    </arguments>
                  </metainfo>
                </method>
                """
                RegexpMatcher.__init__(self)
                self.match_file = match_fname
                self.match_date = 0
                self.ignore_file = ignore_fname
                self.ignore_date = 0

        def readFile(self, filename, array):
                """
                <method internal="yes">
                  <summary>
                    Function to read the contents of a file to an array of regular expressions.
                  </summary>
                  <description>
                    <para>
                      This function is called to load a set of patterns to an
                      array. The file is read line by line, and each line is
                      compiled as a regular expression.
                    </para>
                  </description>
                  <metainfo>
                    <arguments>
                      <argument maturity="stable">
                        <name>filename</name>
                        <type></type>
                        <description>file to read</description>
                      </argument>
                      <argument maturity="stable">
                        <name>array</name>
                        <type></type>
                        <description>array to place compiled regular expressions into</description>
                      </argument>
                    </arguments>
                  </metainfo>
                </method>
                """
                f = open(filename, 'r')
                line = string.rstrip(f.readline())
                while line:
                        re = self.compilePattern(line)
                        if re:
                                array.append(re)
                        line = string.rstrip(f.readline())

        def checkMatch(self, str):
                """
                <method internal="yes">
                  <summary>
                    Function to determine if a string matches.
                  </summary>
                  <description>
                    <para>
                      This function is part of the AbstractMatch interface, and is
                      called when the fate of a given string is to be determined.
                      The implementation here checks if the pattern files have been
                      changed, loads them if necessary and decides if the given string
                      matches.
                    </para>
                  </description>
                  <metainfo>
                    <arguments>
                      <argument maturity="stable">
                        <name>str</name>
                        <type></type>
                        <description>string to check</description>
                      </argument>
                    </arguments>
                  </metainfo>
                </method>
                """
                if self.match_file:
                        try:
                                st = os.stat(self.match_file)
                                if self.match_date < st[8]:
                                        self.match_date = st[8]
                                        self.match = []
                                        self.readFile(self.match_file, self.match)
                        except OSError:
                                ## LOG ##
                                # This message indicates that the Zorp was unable to open the file containing the match regexps.
                                # It is likely that the file does not exists or Zorp is not permitted to read it.
                                # @see: Matcher.RegexpFileMatcher
                                ##
                                log(None, CORE_POLICY, 3, "Error opening match file; filename='%s'", (self.match_file,))

                if self.ignore_file:
                        try:
                                st = os.stat(self.ignore_file)
                                if self.ignore_date < st[8]:
                                        self.ignore_date = st[8]
                                        self.ignore = []
                                        self.readFile(self.ignore_file, self.ignore)
                        except OSError:
                                ## LOG ##
                                # This message indicates that the Zorp was unable to open the file containing the ignore regexps.
                                # It is likely that the file does not exists or Zorp is not permitted to read it.
                                # @see: Matcher.RegexpFileMatcher
                                ##
                                log(None, CORE_POLICY, 3, "Error opening ignore file; filename='%s'", (self.ignore_file,))

                return RegexpMatcher.checkMatch(self, str)

class CombineMatcher(AbstractMatcher):
        """

        <class maturity="stable">
          <summary>
            Matcher for implementing logical expressions based on other matchers.
          </summary>
          <description>
            <para>
              This matcher makes it possible to combine the results of several
              matchers using logical operations. CombineMatcher uses
              prefix-notation in its expressions and uses the following format:
              the operand, a comma, first argument, a comma, second argument.
              For example, an AND expression should be formatted the following
              way: <parameter>(Z_AND, matcher1, matcher2)</parameter>.
              Expressions using more than one operands should be bracketed, e.g.,
              <parameter>(Z_OR (Z_AND, matcher1, matcher2), matcher3)</parameter>.
              The following oprations are available:
            </para>
                <itemizedlist>
                        <listitem>
                        <para>
                        <emphasis>Z_AND
                        </emphasis>:
                        Logical AND operation.
                        </para>
                        </listitem>
                        <listitem>
                        <para>
                        <emphasis>Z_OR
                        </emphasis>:
                        Logical OR operation.
                        </para>
                        </listitem>
                        <listitem>
                        <para>
                        <emphasis>Z_XOR
                        </emphasis>:
                        Logical XOR operation.
                        </para>
                        </listitem>
                        <listitem>
                        <para>
                        <emphasis>Z_NOT
                        </emphasis>:
                        Logical negation.
                        </para>
                        </listitem>
                        <listitem>
                        <para>
                        <emphasis>Z_EQ
                        </emphasis>:
                        Logical equation.
                        </para>
                        </listitem>
                </itemizedlist>
        <example>
          <title>Whitelisting e-mail recipients</title>
          <para>A simple use for CombineMatcher is to filter the recipients of
          e-mail addresses using the following process:</para>
          <orderedlist>
            <listitem>
              <para>An SmtpInvalidMatcher (called <parameter>SmtpCheckrecipient</parameter>)
                verifies that the recipient exists.</para>
            </listitem>
            <listitem>
              <para>A RegexpMatcher (called <parameter>SmtpWhitelist</parameter>)
              or RegexpFileMatcher is used to check if the address is on a
              predefined list (list of permitted addresses).</para>
            </listitem>
            <listitem>
              <para>A CombineMatcher (called <parameter>SmtpCombineMatcher</parameter>)
              sums up the results of the matchers with a logical AND operation.
              </para>
            </listitem>
            <listitem>
              <para>An SmtpProxy (called <parameter>SmtpRecipientMatcherProxy</parameter>)
                references <parameter>SmtpCombineMatcher</parameter> in its
                  <parameter>recipient_matcher</parameter> attribute.</para>
            </listitem>
          </orderedlist>
          <synopsis>
Python:
class SmtpRecipientMatcherProxy(SmtpProxy):
  recipient_matcher="SmtpCombineMatcher"
  def config(self):
    SmtpProxy.config(self)

MatcherPolicy(name="SmtpCombineMatcher", matcher=CombineMatcher (expr=(Z_AND, "SmtpCheckrecipient", "SmtpWhitelist")))
MatcherPolicy(name="SmtpWhitelist", matcher=RegexpMatcher (match_list=("info@example.com",), ignore_list=None))
MatcherPolicy(name="SmtpCheckrecipient", matcher=SmtpInvalidRecipientMatcher (server_port=25, cache_timeout=60, attempt_delivery=FALSE, force_delivery_attempt=FALSE, server_name="recipientcheck.example.com"))
            </synopsis>
        </example>
          </description>
          <metainfo>
            <attributes>
              <attribute internal="yes">
                <name>op</name>
                <type>STRING</type>
                <description>The operator</description>
              </attribute>
              <attribute internal="yes">
                <name>arg</name>
                <type>TUPLE</type>
                <description>Argument tuple, elements are instances of any descendant of AbstractMatcher.
                </description>
              </attribute>
            </attributes>
          </metainfo>
        </class>
        """
        def __init__(self, expr):
                """<method internal="yes">
                <summary>
                  Constructor to initialize a CombineMatcher instance.
                </summary>
                <description>
                  <para>
                    This constructor initializes an instance of the CombineMatcher class.
                  </para>
                </description>
                <metainfo>
                  <arguments>
                    <argument>
                      <name>expr</name>
                      <type>
                        <link id="action.zorp.logical.operator"/>
                      </type>
                      <description>The expression tuple</description>
                    </argument>
                  </arguments>
                </metainfo>
                </method>
                """
                AbstractMatcher.__init__(self)
                self.arg = []

                # check for operator and argument count
                argcount = len(expr) - 1
                if argcount < 0:
                        raise MatcherException, "Missing operator in CombineMatcher expression"
                self.op = expr[0]
                if self.op == Z_NOT:
                        if argcount != 1:
                                raise MatcherException, "Invalid number of arguments (%d) for operator %s in CombineMatcher expression" % (argcount, self.op)
                elif self.op == Z_AND:
                        if argcount < 1:
                                raise MatcherException, "Invalid number of arguments (%d) for operator %s in CombineMatcher expression" % (argcount, self.op)
                elif self.op == Z_OR:
                        if argcount < 1:
                                raise MatcherException, "Invalid number of arguments (%d) for operator %s in CombineMatcher expression" % (argcount, self.op)
                elif self.op == Z_XOR:
                        if argcount < 1:
                                raise MatcherException, "Invalid number of arguments (%d) for operator %s in CombineMatcher expression" % (argcount, self.op)
                elif self.op == Z_EQ:
                        if argcount < 1:
                                raise MatcherException, "Invalid number of arguments (%d) for operator %s in CombineMatcher expression" % (argcount, self.op)
                else:
                        raise MatcherException, "Invalid operator %s in CombineMatcher expression" % (self.op)

                for argidx in range(argcount):
                        next_arg = expr[argidx + 1]
                        if type(next_arg) == types.TupleType or type(next_arg) == types.ListType:
                                self.arg.append(CombineMatcher(next_arg))
                        else:
                                self.arg.append(getMatcher(next_arg))

        def checkMatch(self, str):
                """<method internal="yes">
                <summary>
                  Virtual function to check if a given string actually matches.
                </summary>
                <description>
                  <para>
                    This function evaluates the arguments and makes a decision according to
                    the operator. NOTE: early decision is used, so in cases AND(FALSE, X) and
                    OR(TRUE, X) the matcher X won't be evaluated at all.
                  </para>
                  <para>
                    It can raise a MatcherException to indicate general failure.
                  </para>
                </description>
                <metainfo>
                  <arguments/>
                </metainfo>
                </method>
                """
                # 1st operand must be evaluated anyway
                if self.op == Z_NOT:
                        return not self.arg[0].checkMatch(str)
                elif self.op == Z_AND:
                        for match in self.arg:
                                if not match.checkMatch(str):
                                        return FALSE
                        return TRUE
                elif self.op == Z_OR:
                        for match in self.arg:
                                if match.checkMatch(str):
                                        return TRUE
                        return FALSE
                elif self.op == Z_XOR:
                        res = FALSE
                        for match in self.arg:
                                res = res != match.checkMatch(str)
                        return res
                elif self.op == Z_EQ:
                        res = None
                        for match in self.arg:
                                if not res:
                                        res = match.checkMatch(str)
                                elif res != match.checkMatch(str):
                                        return FALSE
                        return TRUE
                else:
                        raise MatcherException, "Invalid operator %s in evaluating CombineMatcher" % (self.op)
                return res


class DNSMatcher(AbstractMatcher):
        """
        <class maturity="stable">
          <summary>
            DNS matcher
          </summary>
          <description>
            <para>
              DNSMatcher retrieves the IP addresses of domain names. This can be used in domain name based
              policy decisions, for example to allow encrypted connections only to trusted e-banking sites.
            </para>
            <para>
              DNSMatcher operates as follows: it resolves the IP addresses stored in the list of domain names using the specified Domain Name Server,
              and compares the results to the IP address of the connection (i.e., the IP address of the server or the client).
                The matcher returns a true value if the IP addresses resolved from the list of domain names include the
                IP address of the connection.
            </para>
            <example>
            <title>DNSMatcher example</title>
            <para>
            The following DNSMatcher class uses the <parameter>dns.example.com</parameter> name server to
            resolve the <parameter>example2.com</parameter> and <parameter>example3.com</parameter> domain names.
            </para>
            <synopsis>
MatcherPolicy(name="ExampleDomainMatcher", matcher=DNSMatcher(server="dns.example.com", hosts=("example2.com", "example3.com")))
            </synopsis>
            </example>
          </description>
          <metainfo>
            <attributes/>
          </metainfo>
        </class>
        """

        DNS.DiscoverNameServers()

        def __init__(self, hosts, server=None):
                """
                <method maturity="stable">
                  <summary>
                    Constructor to initialize an instance of the DNSMatcher class.
                  </summary>
                  <description>
                    <para>
                      This constructor initializes an instance of the DNSMatcher class.
                    </para>
                  </description>
                  <metainfo>
                    <arguments>
                      <argument maturity="stable">
                        <name>hosts</name>
                        <type>
                          <list>
                            <string/>
                          </list>
                        </type>
                        <description>Hostnames to resolve.</description>
                      </argument>
                      <argument maturity="stable">
                        <name>server</name>
                        <type>
                          <string/>
                        </type>
                        <default>None</default>
                        <description>IP address of the DNS server to query. Defaults to the servers set in
                        the <filename>resolv.conf</filename> file.</description>
                      </argument>
                    </arguments>
                  </metainfo>
                </method>
                """
                self.expires = -1
                self.server = server
                if type(hosts) == type(''):
                        self.hosts = [hosts]
                else:
                        self.hosts = hosts

        def fillCache(self, now=None):
                """<method internal="yes">
                </method>
                """
                self.cache = {}
                for host in self.hosts:

                        params={}
                        params["name"]  = host
                        params["qtype"] = "A"
                        if self.server:
                                params["server"] = self.server
                        r = DNS.DnsRequest(**params)
                        a = r.req()
                        if not now:
                                now = time.time()

                        ttl = -1
                        for answer in a.answers:
                                self.cache[answer["data"]] = 1
                                if ttl > answer["ttl"] or ttl == -1:
                                        ttl = answer["ttl"]

                        if ttl < 0:
                                log(None, CORE_ERROR, 3, "Error resolving host; host='%s'", host)

                        if (now + ttl) < self.expires:
                                self.expires = now + ttl

        def checkMatch(self, str):
                """<method internal="yes"/>
                """
                now = time.time()
                if self.expires < 0 or now > self.expires:
                        self.fillCache(now)
                if self.cache.has_key(str):
                        return TRUE
                else:
                        return FALSE

class WindowsUpdateMatcher(DNSMatcher):
        """
        <class maturity="stable">
          <summary>
            Windows Update matcher
          </summary>
          <description>
            <para>WindowsUpdateMatcher is actually a DNSMatcher used to retrieve the IP addresses currently
            associated with the <filename>v5.windowsupdate.microsoft.nsatc.net</filename>,
            <filename>v4.windowsupdate.microsoft.nsatc.net</filename>, and
            <filename>update.microsoft.nsatc.net</filename> domain names from the specified name server.
            Windows Update is running
            on a distributed server farm, using the DNS round robin method and a short TTL to constantly change
            the set of servers currently visible, consequently the IP addresses of the servers are constantly
            changing.</para>
            <example>
            <title>WindowsUpdateMatcher example</title>
            <synopsis>
MatcherPolicy(name="demo_windowsupdatematcher", matcher=WindowsUpdateMatcher())
            </synopsis>
            <!-- FIXME example -->
            </example>

          </description>
          <metainfo>
            <attributes/>
          </metainfo>
        </class>
        """
        def __init__(self, server=None):
                """
                <method maturity="stable">
                  <summary>
                    Constructor to initialize an instance of the WindowsUpdateMatcher class.
                  </summary>
                  <description>
                    <para>
                      This constructor initializes an instance of the WindowsUpdateMatcher class.
                    </para>
                  </description>
                  <metainfo>
                    <arguments>
                      <argument maturity="stable">
                        <name>server</name>
                        <type>
                          <string/>
                        </type>
                        <default>None</default>
                        <description>The IP address of the name server to query.</description>
                      </argument>
                    </arguments>
                  </metainfo>
                </method>
                """
                DNSMatcher.__init__(self,
                                    ['v5.windowsupdate.microsoft.nsatc.net', 'v4.windowsupdate.microsoft.nsatc.net', 'update.microsoft.com.nsatc.net'],
                                    server)


class SmtpProto(smtplib.SMTP):
        """<class internal="yes">
        </class>
        """
        def __init__(self, host = '', port = 0, local_hostname = None, bind_addr = ''):
                self.bind_addr = bind_addr
                smtplib.SMTP.__init__(self, host, port, local_hostname)

        def connect(self, host='localhost', port = 0):
                """<method internal="yes">
                </method>
                """
                msg = "Error resolving hostname"
                for addr in socket.getaddrinfo(host, port, 0, socket.SOCK_STREAM):
                        af, socktype, proto, canonname, sa = addr
                        try:
                                self.sock = socket.socket(af, socktype, proto)
                                if self.bind_addr:
                                        self.sock.bind((self.bind_addr, 0))
                                self.sock.connect(sa)
                                # success
                                break
                        except socket.error, msg:
                                if self.sock:
                                        self.sock.close()
                                self.sock = None
                if not self.sock:
                        raise socket.error, msg
                (code, msg) = self.getreply()
                return (code, msg)


class SmtpInvalidRecipientMatcher(AbstractMatcher):
        """<class maturity="stable" type="matcher">
          <summary>
            Class verifying the validity of the recipient addresses in E-mails.
          </summary>
          <description>
          <para>
            This class encapsulates a VRFY/RCPT based validity checker to transparently verify the existance of
            E-mail addresses. Instead of immediately sending the e-mail to the recipient SMTP server, Zorp queuries an
                independent SMTP server about the existance of the recipient e-mail address.
          </para>
          <para>
            Instances of this class can be referred to in the <parameter>recipient_matcher</parameter>
            attribute of the <link linkend="python.Smtp.SmtpProxy">SmtpProxy</link> class. The SmtpProxy
            will automatically reject unknown recipients even if the recipient SMTP
            server would accept them.
          </para>
          <example>
          <title>SmtpInvalidMatcher example</title>
          <synopsis>
Python:
class SmtpRecipientMatcherProxy(SmtpProxy):
  recipient_matcher="SmtpCheckrecipient"
  def config(self):
    SmtpProxy.config(self)

MatcherPolicy(name="SmtpCheckrecipient", matcher=SmtpInvalidRecipientMatcher (server_port=25, cache_timeout=60, attempt_delivery=FALSE, force_delivery_attempt=FALSE, server_name="recipientcheck.example.com"))
            </synopsis>
        </example>
          </description>
          <metainfo>
            <attributes/>
          </metainfo>
        </class>
        """
        def __init__(self, server_name, server_port=25, cache_timeout=60, attempt_delivery=FALSE, force_delivery_attempt=FALSE, sender_address='<>', bind_name=''):
                """<method maturity="stable">
                  <summary>
                  </summary>
                  <description>
                  </description>
                  <metainfo>
                  <arguments>
                      <argument maturity="stable">
                        <name>server_name</name>
                        <type>
                          <string/>
                        </type>
                        <description>
                          Domain name of the SMTP server that will verify the addresses.
                        </description>
                      </argument>
                      <argument maturity="stable">
                        <name>server_port</name>
                        <type>
                          <integer/>
                        </type>
                        <default>25</default>
                        <description>
                          Port of the target server.
                        </description>
                      </argument>
                      <argument maturity="stable">
                        <name>cache_timeout</name>
                        <type>
                          <integer/>
                        </type>
                        <default>60</default>
                        <description>
                          How long will the result of an address verification be retained (in seconds).
                        </description>
                      </argument>
                      <argument maturity="obsolete">
                        <name>attempt_delivery</name>
                        <type>
                          <boolean/>
                        </type>
                        <default>FALSE</default>
                        <description>
                          Obsolete, ignored.
                        </description>
                      </argument>
                      <argument maturity="stable">
                        <name>force_delivery_attempt</name>
                        <type>
                          <boolean/>
                        </type>
                        <default>FALSE</default>
                        <description>
                          Force a delivery attempt even if the autodetection code otherwise
                          would use VRFY. Useful if the server always returns success for VRFY.
                        </description>
                      </argument>
                      <argument maturity="stable">
                        <name>sender_address</name>
                        <type>
                          <string/>
                        </type>
                        <default>"&lt;&gt;"</default>
                        <description>
                          This value will be used as the mail sender for the
                          attempted mail delivery. Mail delivery is attempted if
                          the <parameter>force_delivery_attempt</parameter> is TRUE,
                          or the recipient server does not support the VRFY command.
                        </description>
                      </argument>
                      <argument maturity="stable">
                        <name>bind_name</name>
                        <type>
                          <string/>
                        </type>
                        <default>""</default>
                        <description>
                          Specifies the hostname to bind to before initiating the connection to the SMTP server.
                        </description>
                      </argument>
                    </arguments>
                  </metainfo>
                </method>
                """
                AbstractMatcher.__init__(self)
                self.force_delivery_attempt = force_delivery_attempt
                self.server_name = server_name
                self.server_port = server_port
                self.bind_name = bind_name
                self.sender_address = sender_address
                self.cache = TimedCache('smtp_valid_recipients(%s)' % server_name, cache_timeout)

        def checkMatch(self, email):
                """<method internal="yes">
                </method>
                """
                # email is a fully qualified email address like address@domain.com
                try:
                        cached = self.cache.lookup(email)
                        if cached != None:
                                ## LOG ##
                                # This message reports that the recipient address has been already checked and
                                # Zorp uses the cached information.
                                ##
                                log(None, CORE_DEBUG, 6, "Cached recipient match found; email='%s', cached='%d'", (email, cached))
                                if cached:
                                        return TRUE
                                else:
                                        return FALSE
                except KeyError:
                        cached = None

                try:
                        ## LOG ##
                        # This message reports that the recipient address has not been already checked and
                        # Zorp is going to check it now directly.
                        ##
                        log(None, CORE_DEBUG, 6, "Recipient validity not cached, trying the direct way; email='%s'", (email))
                        server = SmtpProto(self.server_name, self.server_port, bind_addr=self.bind_name)
                        try:
                                (smtp_code, smtp_msg) = server.ehlo()
                                if smtp_code > 299:
                                        (smtp_code, smtp_msg) = server.helo()
                                        esmtp = FALSE
                                else:
                                        esmtp = TRUE
                                if smtp_code > 299:
                                        raise MatcherException, "Server refused our EHLO/HELO command."
                                present = FALSE
                                smtp_code = -1

                                if not self.force_delivery_attempt and (not esmtp or server.has_extn("VRFY")):
                                        log(None, CORE_DEBUG, 6, "Trying to use VRFY to check email address validity; email='%s'", (email,))
                                        (smtp_code, smtp_msg) = server.verify(email)
                                        present = (smtp_code < 300)
                                else:
                                        log(None, CORE_DEBUG, 6, "Attempting delivery to check email address validity; email='%s'", (email,))
                                        (smtp_code, smtp_msg) = server.mail(self.sender_address)
                                        if smtp_code == 250:
                                                (smtp_code, smtp_msg) = server.rcpt(email)
                                                present = (smtp_code < 300)
                                        else:
                                                ## LOG ##
                                                # This message indicates that the sender address was rejected during the recipient address
                                                # verify check and Zorp rejects the recipient address.
                                                ##
                                                log(None, CORE_ERROR, 3, "SMTP sender was rejected, unable to verify user existence; email='%s', server_address='%s', server_port='%d'", (email, self.server_name, self.server_port))
                                                raise MatcherException, "Server has not accepted our sender (%s)." % self.sender_address
                                if present:
                                        ## LOG ##
                                        # This message reports that the recipient address verify was successful and Zorp accepts it.
                                        ##
                                        log(None, CORE_INFO, 5, "Server accepted recipient; email='%s'", email)
                                        # we only cache successful lookups
                                        self.cache.store(email, not present)
                                elif smtp_code != -1:
                                        ## LOG ##
                                        # This message reports that the recipient address verify was unsuccessful and Zorp rejects it.
                                        ##
                                        log(None, CORE_INFO, 4, "Server rejected recipient; email='%s'", email)
                        finally:
                                server.quit()
                except (socket.error, smtplib.SMTPException), e:
                        ## LOG ##
                        # This message indicates that an SMTP error occurred during the recipient address verify
                        # and Zorp rejects it.
                        ##
                        log(None, CORE_ERROR, 3, "SMTP error during recipient validity checking; info='%s'", e)
                        raise MatcherException, "SMTP error or socket failure while checking user validity (%s)" % str(e)

                # we return when we want to reject...
                return not present
