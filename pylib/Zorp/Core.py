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
  <summary>Module defining interface to the Core.</summary>
  <description>
    <para>
      This module imports all public Zorp interfaces and makes it easy to use
      those from the user policy file by simply importing all symbols from
      Zorp.Core.
    </para>
  </description>
</module>
"""
  
import new
import socket

from Zorp import *
import Zorp
from Zone import InetZone
from Service import Service, PFService
from SockAddr import SockAddrInet, SockAddrInetHostname, SockAddrInetRange, SockAddrUnix


from Router import TransparentRouter, DirectedRouter, InbandRouter
from Chainer import ConnectChainer, MultiTargetChainer, StateBasedChainer, RoundRobinChainer, FailoverChainer, SideStackChainer
from Domain import InetDomain
from Listener import Listener, ZoneListener, CSZoneListener
from Dispatch import Dispatcher, ZoneDispatcher, CSZoneDispatcher, NDimensionDispatcher
from NAT import NATPolicy, ForgeClientSourceNAT, StaticNAT, OneToOneNAT, OneToOneMultiNAT, RandomNAT, HashNAT, GeneralNAT
from Proxy import proxyLog
from Auth import InbandAuthentication, AuthCache, AuthPolicy, AuthenticationPolicy
from Stack import StackingProvider, RemoteStackingBackend
from Matcher import MatcherPolicy, AbstractMatcher, RegexpMatcher, RegexpFileMatcher, CombineMatcher, DNSMatcher, WindowsUpdateMatcher, SmtpInvalidRecipientMatcher
from Resolver import DNSResolver, HashResolver, ResolverPolicy

# conntrack support
try:
	from Receiver import Receiver, ZoneReceiver, CSZoneReceiver
except:
	pass

# ipv6 support
try:
	from SockAddr import SockAddrInet6
	from Zone import Inet6Zone
except:
	pass

