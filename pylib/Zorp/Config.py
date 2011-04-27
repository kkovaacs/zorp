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
    The Config module defines global options of Zorp.
  </summary>
  <description>
    <para>
      This module defines global options of Zorp.
      For a detailed description of the options, see <xref
      linkend="appendix_globaloptions"/>.
    </para>
  </description>
</module>
"""
import new, sys

TRUE = 1
FALSE = 0

config = sys.modules[__name__]

def addConfigContainer(cont):
	"""
	<function internal="yes">
	  <summary>
	    Create a container for global configuration variables.
	  </summary>
	</function>
	"""
	setattr(config, cont, new.module(cont))

addConfigContainer('blob')
# The directory where blobs are swapped out
config.blob.temp_directory = '/var/lib/zorp/tmp/'

# Maximum disk usage (1G)
config.blob.max_disk_usage = 1024*0x100000

# Maximum memory usage (256M)
config.blob.max_mem_usage = 256*0x100000

# Low water mark for blob swapout, it stops when reaching this amount in memory
config.blob.lowat = 96*0x100000

# High water mark for blob swapout, swapout starts when having this amount of memory used
config.blob.hiwat = 128*0x100000

# The maximum size for blobs that are never swapped.
config.blob.noswap_max = 16384

addConfigContainer('audit')

# Whether each session has a separate audit trail file.
config.audit.per_session = FALSE

## Session level options, controlling what to do when auditing is enabled
## for a session.

# whether to write records to audit trail file (if you disable this and
# config.audit.ids, then initializing the audit trail will fail)
config.audit.audit = TRUE

# Whether audit trail encryption is enabled
config.audit.encrypt = FALSE

# Whether to compress audit trails
config.audit.compress = TRUE

# Sign the digest record
config.audit.sign = FALSE

# Timestamp the digest record
config.audit.timestamp = FALSE

config.audit.ids = FALSE

## Compression options

# The compression level for audit trail files
config.audit.compress_level = 1

## Encryption options

# List of X.509 PEM certificates. to encrypt the audit trail with
config.audit.encrypt_certificate_list = None

# File names which contain an X.509 PEM certificate to encrypt the audit
# trail file, overrides the setting for config.audit.encrypt_certificate_list
#config.audit.encrypt_certificate_list_file = [ ["", "" ], ]
# by default empty:
config.audit.encrypt_certificate_list_file = None

# X.509 PEM certificate to encrypt the audit trail file for. Fallback if config.audit.encrypt_certifiace_list is empty
config.audit.encrypt_certificate = None

# File name which contains an X.509 PEM certificate to encrypt the audit
# trail file, overrides the setting for config.audit.encrypt_certificate
config.audit.encrypt_certificate_file = None

## Sign related options

# Seconds between audit trail digest record is written
# Optionally the digest can be timestamped by a server and sign by an RSA key
# This whole record is the digital sign of the trail
config.audit.sign_interval = 30

# RSA or DSA  private key to sign the digest calculated for the sign record
config.audit.sign_private_key = None

# Certificate to sign the digest calculated for the sign record
config.audit.sign_certificate = None

# File of private key to sign the digest calculated for the sign record
config.audit.sign_private_key_file = None

# File of the certificate to sign the digest calculated for the sign record
config.audit.sign_certificate_file = None

## Timestamping options

# Timestamping URL for the digest record
config.audit.timestamp_url = ""

# Policy of the timestamping server (ASN1)
# in form of "1.2.4.3.124.7"
config.audit.timestamp_policy = ""

# Max length of the timestamp field of the digest record
config.audit.timestamp_length = 3072

## IDS options

# Interface to use towards the IDS sensor
config.audit.ids_interface = ""

# IDS source MAC address
config.audit.ids_src_mac = ""

# IDS destination MAC address
config.audit.ids_dst_mac = ""

## Misc parameters

# Audit trail files are reopened (and a new one started) when they reach this number
config.audit.reopen_size_threshold = 2000000000L

# Audit trail files are reopened after this amount of time has elapsed
config.audit.reopen_time_threshold = 28800

# Rate of filling the bucket in byte/sec
config.audit.rate_limit = 2*1024*1024 

# Interval between two notifications, if bucket is empty, in seconds
config.audit.rate_notification_interval = 300

# Maximum size of audit trail files in bytes
config.audit.write_size_max = 50*1024*1024

# Terminate proxy if cannot write audit trail (max size exceeded)
config.audit.terminate_on_max_size = FALSE

addConfigContainer('options')

# The timeout used when establishing server side connection.
config.options.timeout_server_connect = 30000

# The default language used for user messages in various proxies.
config.options.language = "en"

# Zone and CSZoneDispatcher shift cache parameter
config.options.zone_dispatcher_shift_threshold = 1000

# Zone lookup shift cache parameter
config.options.zone_cache_shift_threshold = 1000

# Inbound DAC shift cache parameter
config.options.inbound_service_cache_threshold = 1000

# Outbound DAC shift cache parameter
config.options.outbound_service_cache_threshold = 1000

# DSCP -> thread priority mapping
config.options.dscp_prio_mapping = {}

# KZorp enabled or not. If KZorp is not present in the kernel and this is
# enabled, Zorp startup/shutdown/reload will be delayed by about 5sec
config.options.kzorp_enabled = TRUE

