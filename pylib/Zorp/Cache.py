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
  <summary>Module defining general cache related classes and functions.
  </summary>
  <description>
    <para>
      Caching is used throughout the policy layer to improve performance. This
      module includes a couple of general caching classes used by various parts
      of the policy code.
    </para>
  </description>
  <metainfo/>
</module>
"""

from Zorp import *

import time, threading

class AbstractCache:
        """
        <class internal="yes" abstract="yes">
          <metainfo>
            <attributes/>
          </metainfo>
        </class>
        """
        def __init__(self, name):
                """
                <method internal="yes">
                </method>
                """
                self.name = name

        def store(self, key, value):
                """
                <method internal="yes">
                <description>
                  <para>
                    Stores a value in the cache identified by
                    'key'. Deletes the item if value is None.
                  </para>
                </description>
                </method>
                """
                pass

        def lookup(self, key):
                """
                <method internal="yes">
                <description>
                  <para>
                    Looks up a value identified by 'key', returns None if not found.
                  </para>
                </description>
                </method>
                """
                pass

        def clear(self):
                """
                <method internal="yes">
                </method>
                """
                pass

class ShiftCache(AbstractCache):
        """
        <class internal="yes">
        </class>
        """
        def __init__(self, name, shift_threshold):
                """
                <method internal="yes">
                </method>
                """
                AbstractCache.__init__(self, name)
                self.cache = {}
                self.old_cache = {}
                self.shift_threshold = shift_threshold

        def store(self, key, value):
                """
                <method internal="yes">
                </method>
                """
                if len(self.cache) > self.shift_threshold:
                        ## LOG ##
                        # This message indicates that the cache size(threshold) is reached, and cache is shifted.
                        # @see: Cache.ShiftCache
                        ##
                        log(None, CORE_MESSAGE, 3, "Cache over shift-threshold, shifting; cache='%s', threshold='%d'", (self.name, self.shift_threshold,))
                        self.old_cache = self.cache
                        self.cache = {}
                if value:
                        self.cache[key] = value
                else:
                        try:
                                del self.cache[key]
                        except KeyError:
                                pass

                try:
                        del self.old_cache[key]
                except KeyError:
                        pass

        def lookup(self, key):
                """
                <method internal="yes">
                </method>
                """
                val = None
                try:
                        return self.cache[key]
                except KeyError:
                        pass

                try:
                        val = self.old_cache[key]
                        self.cache[key] = val
                        del self.old_cache[key]
                except KeyError:
                        pass
                return val

        def clear(self):
                """
                <method internal="yes">
                </method>
                """
                self.cache = {}
                self.old_cache = {}


class TimedCache(AbstractCache):
        """
        <class internal="yes">
        </class>

        """
        def __init__(self, name, timeout, update_stamp=TRUE, cleanup_threshold=100):
                """
                <method internal="yes">
                </method>
                """
                AbstractCache.__init__(self, name)
                self.timeout = timeout
                self.update_stamp = update_stamp
                self.cleanup_threshold = cleanup_threshold
                self.cache = {}

        def cleanup(self):
                """
                <method internal="yes">
                </method>
                """
                now = time.time()
                for x in self.cache.keys():
                        if now - self.cache[x][0] > self.timeout:
                                del self.cache[x]

        def lookup(self, key):
                """
                <method internal="yes">
                </method>
                """
                if len(self.cache) > self.cleanup_threshold:
                        self.cleanup()
                if self.cache.has_key(key):
                        entry = self.cache[key]
                        if time.time() - entry[0] > self.timeout:
                                del self.cache[key]
                        else:
                                if self.update_stamp:
                                        entry[0] = time.time()
                                return entry[1]
                return None

        def store(self, key, value):
                """
                <method internal="yes">
                </method>
                """
                if value:
                        if not self.cache.has_key(key) or self.cache[key][1] != value:
                                # only update if value is different
                                self.cache[key] = [time.time(), value]
                else:
                        try:
                                del self.cache[key]
                        except KeyError:
                                pass

        def clear(self):
                """
                <method internal="yes">
                </method>
                """
                self.cache = {}


class LockedCache(AbstractCache):
        """
        <class internal="yes">
        </class>
        """
        def __init__(self, child_cache):
                self.child_cache = child_cache
                self.lock = threading.Lock()

        def store(self, key, value):
                """
                <method internal="yes">
                </method>
                """
                try:
                        self.lock.acquire()
                        return self.child_cache.store(key, value)
                finally:
                        self.lock.release()

        def lookup(self, key):
                """
                <method internal="yes">
                </method>
                """
                try:
                        self.lock.acquire()
                        return self.child_cache.lookup(key)
                finally:
                        self.lock.release()

        def clear(self):
                """
                <method internal="yes">
                </method>
                """
                try:
                        self.lock.acquire()
                        return self.child_cache.clear()
                finally:
                        self.lock.release()
