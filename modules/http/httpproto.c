/***************************************************************************
 *
 * Copyright (c) 2000, 2001, 2002, 2003, 2004, 2005, 2006, 2007, 2008, 2009,
 * 2010, 2011 BalaBit IT Ltd, Budapest, Hungary
 *
 * This program is free software; you can redistribute it and/or modify it
 * under the terms of the GNU General Public License version 2 as published
 * by the Free Software Foundation.
 *
 * Note that this permission is granted for only version 2 of the GPL.
 *
 * As an additional exemption you are allowed to compile & link against the
 * OpenSSL libraries as published by the OpenSSL project. See the file
 * COPYING for details.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 675 Mass Ave, Cambridge, MA 02139, USA.
 *
 * $Id: httpproto.c,v 1.8 2002/07/22 14:31:15 sasa Exp $
 *
 * Author: Balazs Scheidler <bazsi@balabit.hu>
 * Auditor: 
 * Last audited version: 
 * Notes:
 *   Based on the code by: Viktor Peter Kovacs <vps__@freemail.hu>
 *
 ***************************************************************************/

#include "http.h"

#include <string.h>

static HttpElementInfo request_proto_table[] =
{
  { "HEAD", HTTP_REQ_FLG_HEAD, -1 },
  { "OPTIONS", HTTP_REQ_FLG_ASTERIX, -1 },
  { "CONNECT", HTTP_REQ_FLG_CONNECT, -1 },
  { NULL, 0, 0 },
};

static HttpElementInfo response_proto_table[] =
{
  { "100", HTTP_RESP_FLG_CONTINUE, -1 },			/* unused => hardcoded */
  { "101", HTTP_RESP_FLG_SUPPRESS | HTTP_RESP_FLG_STOP, -1 },	/* update to protocol (similar to connect) */

  { "204", HTTP_RESP_FLG_SUPPRESS, -1 },
  { "205", HTTP_RESP_FLG_DONTEXPECT, -1 },
  { "304", HTTP_RESP_FLG_SUPPRESS, -1 },

  { "402", HTTP_RESP_FLG_STOP, -1 },

  { NULL, 0, 0 },
};

static HttpElementInfo request_hdr_proto_table[] =
{
  {
    "Allow",
    HTTP_HDR_CF_ALPHA |
    HTTP_HDR_CF_COMMA | HTTP_HDR_CF_SPACE,
    64
  },
  {
    "Authorization",
    HTTP_HDR_CF_ALPHA |
    HTTP_HDR_CF_SPACE | HTTP_HDR_CF_NUMERIC |
    HTTP_HDR_CF_EQUAL,
    256
  },
  {
    "Content-Encoding",
    HTTP_HDR_CF_ALPHA |
    HTTP_HDR_CF_DASH | HTTP_HDR_CF_SLASH,
    64
  },
  {
    "Content-Length",
    HTTP_HDR_CF_NUMERIC,
    64
  },
  {
    "Content-Type",
    HTTP_HDR_CF_ALPHA |
    HTTP_HDR_CF_DASH | HTTP_HDR_CF_SLASH |
    HTTP_HDR_CF_NUMERIC | HTTP_HDR_CF_SPACE |
    HTTP_HDR_CF_EQUAL | HTTP_HDR_CF_SEMICOLON |
    HTTP_HDR_CF_QUOTE,
    64
  },
  {
    "Date",
    HTTP_HDR_CF_ALPHA |
    HTTP_HDR_CF_NUMERIC | HTTP_HDR_CF_COMMA |
    HTTP_HDR_CF_SPACE | HTTP_HDR_CF_COLON,
    128
  },
  {
    "Expires",
    HTTP_HDR_CF_ALPHA |
    HTTP_HDR_CF_NUMERIC | HTTP_HDR_CF_COMMA |
    HTTP_HDR_CF_SPACE | HTTP_HDR_CF_COLON |
    HTTP_HDR_CF_DASH,
    128
  },
  {
    "From",
     HTTP_HDR_CF_AT |
    HTTP_HDR_CF_ALPHA | HTTP_HDR_CF_NUMERIC |
    HTTP_HDR_CF_DASH | HTTP_HDR_CF_DOT |
    HTTP_HDR_CF_UNDERLINE,
    256
  },
  {
    "If-Modified-Since",
    HTTP_HDR_CF_ALPHA |
    HTTP_HDR_CF_NUMERIC | HTTP_HDR_CF_COMMA |
    HTTP_HDR_CF_SPACE | HTTP_HDR_CF_COLON |
    HTTP_HDR_CF_EQUAL | HTTP_HDR_CF_SEMICOLON,
    128
  },
  {
    "Last-Modified",
    HTTP_HDR_CF_ALPHA |
    HTTP_HDR_CF_NUMERIC | HTTP_HDR_CF_COMMA |
    HTTP_HDR_CF_SPACE | HTTP_HDR_CF_COLON,
    128
  },
  {
    "Pragma",
    HTTP_HDR_CF_ALPHA |
    HTTP_HDR_CF_DASH,
    64
  },
  {
    "Referer",
    HTTP_HDR_FF_URL,
    -1
  },
  {
    "User-Agent",
    HTTP_HDR_CF_ALPHA |
    HTTP_HDR_CF_NUMERIC | HTTP_HDR_CF_SLASH |
    HTTP_HDR_CF_BACKSLASH | HTTP_HDR_CF_DOT |
    HTTP_HDR_CF_SPACE | HTTP_HDR_CF_DASH |
    HTTP_HDR_CF_BRACKET | HTTP_HDR_CF_SEMICOLON |
    HTTP_HDR_CF_COLON,
    256
  },

  // RFC 2068 (HTTP/1.1)
  {
    "Accept",
    HTTP_HDR_CF_ALPHA |
    HTTP_HDR_CF_DASH | HTTP_HDR_CF_SLASH |
    HTTP_HDR_CF_NUMERIC | HTTP_HDR_CF_SPACE |
    HTTP_HDR_CF_SEMICOLON | HTTP_HDR_CF_COMMA |
    HTTP_HDR_CF_ASTERIX | HTTP_HDR_CF_EQUAL |
    HTTP_HDR_CF_DOT | HTTP_HDR_CF_PLUS,
    512
  },
  {
    "Accept-Charset",
    HTTP_HDR_CF_ALPHA |
    HTTP_HDR_CF_NUMERIC | HTTP_HDR_CF_DASH |
    HTTP_HDR_CF_SPACE | HTTP_HDR_CF_COMMA |
    HTTP_HDR_CF_SEMICOLON | HTTP_HDR_CF_EQUAL |
    HTTP_HDR_CF_DOT | HTTP_HDR_CF_ASTERIX,
    128
  },
  {
    "Accept-Encoding",
    HTTP_HDR_CF_ALPHA |
    HTTP_HDR_CF_NUMERIC | HTTP_HDR_CF_DASH |
    HTTP_HDR_CF_SPACE | HTTP_HDR_CF_COMMA |
    HTTP_HDR_CF_SEMICOLON | HTTP_HDR_CF_EQUAL |
    HTTP_HDR_CF_ASTERIX | HTTP_HDR_CF_DOT,
    128
  },
  {
    "Accept-Language",
    HTTP_HDR_CF_ALPHA |
    HTTP_HDR_CF_NUMERIC | HTTP_HDR_CF_DASH |
    HTTP_HDR_CF_SPACE | HTTP_HDR_CF_COMMA |
    HTTP_HDR_CF_SEMICOLON | HTTP_HDR_CF_EQUAL |
    HTTP_HDR_CF_DOT,
    128
  },
  {
    "Accept-Ranges",
    HTTP_HDR_CF_ALPHA,
    64
  },
  {
    "Cache-Control",
    HTTP_HDR_CF_ALPHA |
    HTTP_HDR_CF_NUMERIC | HTTP_HDR_CF_SPACE |
    HTTP_HDR_CF_EQUAL | HTTP_HDR_CF_DASH |
    HTTP_HDR_CF_COMMA | HTTP_HDR_CF_QUOTE,
    128
  },
  {
    "Content-Base",
    HTTP_HDR_CF_ALPHA |
    HTTP_HDR_CF_DASH | HTTP_HDR_CF_SLASH,
    128
  },
  {
    "Content-Location",
    HTTP_HDR_FF_URL,
    -1
  },
  {
    "Content-MD5",
    HTTP_HDR_FF_ANY,
    64
  },
  {
    "Content-Range",
    HTTP_HDR_CF_ALPHA |
    HTTP_HDR_CF_NUMERIC | HTTP_HDR_CF_SPACE |
    HTTP_HDR_CF_DASH | HTTP_HDR_CF_SLASH,
    64
  },
  {
    "ETag",
    HTTP_HDR_CF_ALPHA |
    HTTP_HDR_CF_NUMERIC | HTTP_HDR_CF_DASH |
    HTTP_HDR_CF_EQUAL | HTTP_HDR_CF_SEMICOLON |
    HTTP_HDR_CF_COLON | HTTP_HDR_CF_SPACE |
    HTTP_HDR_CF_HASHMARK | HTTP_HDR_CF_QUOTE,
    64
  },
  {
    "Host",
    HTTP_HDR_CF_ALPHA |
    HTTP_HDR_CF_NUMERIC | HTTP_HDR_CF_DOT |
    HTTP_HDR_CF_DASH | HTTP_HDR_CF_UNDERLINE |
    HTTP_HDR_CF_SLASH | HTTP_HDR_CF_COLON,
    512
  },
  {
    "If-Match",
    HTTP_HDR_FF_ANY,
    512
  },
  {
    "If-None-Match",
    HTTP_HDR_FF_ANY,
    512
  },
  {
    "If-Range",
    HTTP_HDR_CF_ALPHA |
    HTTP_HDR_CF_NUMERIC | HTTP_HDR_CF_COLON |
    HTTP_HDR_CF_DOT | HTTP_HDR_CF_SEMICOLON |
    HTTP_HDR_CF_SPACE | HTTP_HDR_CF_HASHMARK |
    HTTP_HDR_CF_DASH,
    128
  },
  {
    "If-Unmodified-Since",
    HTTP_HDR_CF_ALPHA |
    HTTP_HDR_CF_NUMERIC | HTTP_HDR_CF_COMMA |
    HTTP_HDR_CF_SPACE | HTTP_HDR_CF_COLON,
    128
  },
  {
    "Max-Forwards",
    HTTP_HDR_CF_NUMERIC,
    128
  },
  {
    "Proxy-Authorization",
    HTTP_HDR_CF_ALPHA |
    HTTP_HDR_CF_SPACE | HTTP_HDR_CF_NUMERIC |
    HTTP_HDR_CF_EQUAL,
    256
  },
  {
    "Range",
    HTTP_HDR_CF_ALPHA |
    HTTP_HDR_CF_NUMERIC | HTTP_HDR_CF_DASH |
    HTTP_HDR_CF_EQUAL | HTTP_HDR_CF_COMMA,
    64
  },
  {
    "Transfer-Encoding",
    HTTP_HDR_CF_ALPHA,
    64
  },
  {
    "Upgrade",
    HTTP_HDR_CF_ALPHA |
    HTTP_HDR_CF_NUMERIC | HTTP_HDR_CF_SPACE |
    HTTP_HDR_CF_COMMA | HTTP_HDR_CF_SLASH |
    HTTP_HDR_CF_DOT,
    128
  },
  {
    "Via",
    HTTP_HDR_CF_ALPHA |
    HTTP_HDR_CF_NUMERIC | HTTP_HDR_CF_SLASH |
    HTTP_HDR_CF_COLON | HTTP_HDR_CF_AND |
    HTTP_HDR_CF_DOT | HTTP_HDR_CF_DASH |
    HTTP_HDR_CF_UNDERLINE,
    512
  },
  /* RFC 2109 */
  {
    "Cookie",
    HTTP_HDR_FF_ANY,
    -1
  },
  // RFC 2227
  {
    "Meter",
    HTTP_HDR_CF_ALPHA |
    HTTP_HDR_CF_NUMERIC | HTTP_HDR_CF_SPACE |
    HTTP_HDR_CF_COMMA | HTTP_HDR_CF_DASH |
    HTTP_HDR_CF_EQUAL,
    128
  },
  /* RFC 2295 */
  {
    "Accept-Features",
    HTTP_HDR_FF_ANY,
    512
  },
  {
    "Negotiate",
    HTTP_HDR_CF_ALPHA |
    HTTP_HDR_CF_ASTERIX | HTTP_HDR_CF_DASH,
    64
  },
  /* RFC 2518 (WebDAV) */
  {
    "DAV",
    HTTP_HDR_CF_ALPHA |
    HTTP_HDR_CF_NUMERIC | HTTP_HDR_CF_COMMA |
    HTTP_HDR_CF_SPACE,
    64
  },
  {
    "Depth",
    HTTP_HDR_CF_NUMERIC |
    HTTP_HDR_CF_ALPHA,
    64
  },
  {
    "Destination",
    HTTP_HDR_CF_ALPHA |
    HTTP_HDR_CF_NUMERIC | HTTP_HDR_CF_SLASH |
    HTTP_HDR_CF_COLON | HTTP_HDR_CF_AND |
    HTTP_HDR_CF_DOT | HTTP_HDR_CF_DASH |
    HTTP_HDR_CF_UNDERLINE,
    512
  },
  {
    "If",
    HTTP_HDR_FF_ANY,
    512
  },
  {
    "Lock-Token",
    HTTP_HDR_CF_ALPHA |
    HTTP_HDR_CF_NUMERIC | HTTP_HDR_CF_SLASH |
    HTTP_HDR_CF_COLON | HTTP_HDR_CF_AND |
    HTTP_HDR_CF_DOT | HTTP_HDR_CF_DASH |
    HTTP_HDR_CF_UNDERLINE,
    512
  },
  {
    "Overwrite",
    HTTP_HDR_CF_ALPHA,
    8
  },
  {
    "Timeout",
     HTTP_HDR_FF_ANY,
    64
  },
  // RFC 2616 (HTTP/1.1)
  {
    "Expect",
    HTTP_HDR_CF_ALPHA |
    HTTP_HDR_CF_NUMERIC | HTTP_HDR_CF_SPACE |
    HTTP_HDR_CF_EQUAL | HTTP_HDR_CF_SEMICOLON |
    HTTP_HDR_CF_COMMA,
    128
  },
  {
    "TE",
    HTTP_HDR_CF_ALPHA |
    HTTP_HDR_CF_NUMERIC | HTTP_HDR_CF_SPACE |
    HTTP_HDR_CF_DASH | HTTP_HDR_CF_COMMA |
    HTTP_HDR_CF_SEMICOLON | HTTP_HDR_CF_EQUAL |
    HTTP_HDR_CF_DOT,
    128
  },
  {
    "Trailer",
    HTTP_HDR_CF_ALPHA |
    HTTP_HDR_CF_DASH | HTTP_HDR_CF_NUMERIC,
    128
  },
  // RFC 2965
  {
    "Cookie2",
    HTTP_HDR_FF_ANY,
    -1
  },
  // Nokia MMS Extension
  {
    "X-NOKIA-MMSC-Message-Id",
    HTTP_HDR_CF_ALPHA |
    HTTP_HDR_CF_NUMERIC | HTTP_HDR_CF_AT,
    128
  },
  {
    "X-NOKIA-MMSC-Status",
    HTTP_HDR_CF_NUMERIC,
    64
  },
  {
    "X-NOKIA-MMSC-Charging",
    HTTP_HDR_CF_NUMERIC,
    8
  },
  {
    "X-NOKIA-MMSC-Charged-Party",
     HTTP_HDR_CF_ALPHA,
    64
  },
  {
    "X-NOKIA-MMSC-To",
    HTTP_HDR_CF_NUMERIC |
    HTTP_HDR_CF_ALPHA | HTTP_HDR_CF_SLASH |
    HTTP_HDR_CF_EQUAL | HTTP_HDR_CF_PLUS |
    HTTP_HDR_CF_AT | HTTP_HDR_CF_DOT |
    HTTP_HDR_CF_DASH | HTTP_HDR_CF_UNDERLINE,
    128
  },
  {
    "X-NOKIA-MMSC-From",
    HTTP_HDR_CF_NUMERIC |
    HTTP_HDR_CF_ALPHA | HTTP_HDR_CF_SLASH |
    HTTP_HDR_CF_EQUAL | HTTP_HDR_CF_PLUS |
    HTTP_HDR_CF_AT | HTTP_HDR_CF_DOT |
    HTTP_HDR_CF_DASH | HTTP_HDR_CF_UNDERLINE,
    128
  },
  {
    "X-NOKIA-MMSC-Message-Type",
    HTTP_HDR_CF_ALPHA,
    64
  },
  {
    "X-NOKIA-MMSC-Version",
    HTTP_HDR_CF_NUMERIC |
    HTTP_HDR_CF_DOT,
    16
  },
  {
    "Proxy-Connection",
    HTTP_HDR_CF_ALPHA |
    HTTP_HDR_CF_DASH,
    64
  },
  {
    "Connection",
    HTTP_HDR_CF_ALPHA |
    HTTP_HDR_CF_DASH | HTTP_HDR_CF_COMMA |
    HTTP_HDR_CF_SPACE,
    64
  },

  // SOAP 1.1
  {
    "SOAPAction",
    HTTP_HDR_FF_ANY,
    -1
  },
  {
    NULL,
    0,
    0
  }
};

static HttpElementInfo response_hdr_proto_table[] =
{
  // RFC 1945 (HTTP/1.0)
  {
    "Allow",
    HTTP_HDR_CF_ALPHA |
    HTTP_HDR_CF_COMMA | HTTP_HDR_CF_SPACE,
    64},
  {
    "Content-Encoding",
    HTTP_HDR_CF_ALPHA |
    HTTP_HDR_CF_DASH | HTTP_HDR_CF_SLASH,
    64},
  {
    "Content-Length",
    HTTP_HDR_CF_NUMERIC,
    64
  },
  {
    "Content-Type",
    HTTP_HDR_CF_ALPHA |
    HTTP_HDR_CF_DASH | HTTP_HDR_CF_SLASH |
    HTTP_HDR_CF_NUMERIC | HTTP_HDR_CF_SPACE |
    HTTP_HDR_CF_EQUAL | HTTP_HDR_CF_SEMICOLON |
    HTTP_HDR_CF_QUOTE,
    64
  },
  {
    "Date",
    HTTP_HDR_CF_ALPHA |
    HTTP_HDR_CF_NUMERIC | HTTP_HDR_CF_COMMA |
    HTTP_HDR_CF_SPACE | HTTP_HDR_CF_COLON,
    128
  },
  {
    "Expires",
    HTTP_HDR_CF_ALPHA |
    HTTP_HDR_CF_NUMERIC | HTTP_HDR_CF_COMMA |
    HTTP_HDR_CF_SPACE | HTTP_HDR_CF_COLON |
    HTTP_HDR_CF_DASH,
    128
  },
  {
    "Last-Modified",
    HTTP_HDR_CF_ALPHA |
    HTTP_HDR_CF_NUMERIC | HTTP_HDR_CF_COMMA |
    HTTP_HDR_CF_SPACE | HTTP_HDR_CF_COLON,
    128
  },
  {
    "Location",
    HTTP_HDR_FF_URL,
    -1
  },
  {
    "Pragma",
    HTTP_HDR_CF_ALPHA |
    HTTP_HDR_CF_DASH,
    64
  },
  {
    "Server",
    HTTP_HDR_CF_ALPHA |
    HTTP_HDR_CF_NUMERIC | HTTP_HDR_CF_SLASH |
    HTTP_HDR_CF_COLON | HTTP_HDR_CF_AND |
    HTTP_HDR_CF_DOT | HTTP_HDR_CF_DASH |
    HTTP_HDR_CF_UNDERLINE | HTTP_HDR_CF_BRACKET |
    HTTP_HDR_CF_SPACE,
    512
  },
  {
    "WWW-Authenticate",
    HTTP_HDR_CF_ALPHA |
    HTTP_HDR_CF_SPACE | HTTP_HDR_CF_NUMERIC |
    HTTP_HDR_CF_EQUAL | HTTP_HDR_CF_DOT |
    HTTP_HDR_CF_QUOTE,
    256
  },

  // RFC 2065 (HTTP/1.1)
  {
    "Age",
    HTTP_HDR_CF_NUMERIC,
    64
  },
  {
    "Authorization",
    HTTP_HDR_CF_ALPHA |
    HTTP_HDR_CF_SPACE | HTTP_HDR_CF_NUMERIC |
    HTTP_HDR_CF_EQUAL,
    256
  },
  {
    "Cache-Control",
    HTTP_HDR_CF_ALPHA |
    HTTP_HDR_CF_NUMERIC | HTTP_HDR_CF_SPACE |
    HTTP_HDR_CF_EQUAL | HTTP_HDR_CF_DASH |
    HTTP_HDR_CF_COMMA | HTTP_HDR_CF_QUOTE,
    128
  },
  {
    "Content-Base",
    HTTP_HDR_CF_ALPHA |
    HTTP_HDR_CF_DASH | HTTP_HDR_CF_SLASH,
    128
  },
  {
    "Content-Location",
    HTTP_HDR_FF_URL,
    -1
  },
  {
    "Content-MD5",
    HTTP_HDR_FF_ANY,
    64
  },
  {
    "Content-Range",
    HTTP_HDR_CF_ALPHA |
    HTTP_HDR_CF_NUMERIC | HTTP_HDR_CF_SPACE |
    HTTP_HDR_CF_DASH | HTTP_HDR_CF_SLASH,
    64
  },
  {
    "ETag",
    HTTP_HDR_CF_ALPHA |
    HTTP_HDR_CF_NUMERIC | HTTP_HDR_CF_DASH |
    HTTP_HDR_CF_EQUAL | HTTP_HDR_CF_SEMICOLON |
    HTTP_HDR_CF_COLON | HTTP_HDR_CF_SPACE |
    HTTP_HDR_CF_HASHMARK | HTTP_HDR_CF_QUOTE,
    64
  },
  {
    "Proxy-Authenticate",
    HTTP_HDR_CF_ALPHA |
    HTTP_HDR_CF_SPACE | HTTP_HDR_CF_NUMERIC |
    HTTP_HDR_CF_EQUAL,
    256
  },
  {
    "Public",
    HTTP_HDR_CF_ALPHA |
    HTTP_HDR_CF_SPACE | HTTP_HDR_CF_COMMA,
    128
  },
  {
    "Range",
    HTTP_HDR_CF_ALPHA |
    HTTP_HDR_CF_NUMERIC | HTTP_HDR_CF_DASH |
    HTTP_HDR_CF_EQUAL | HTTP_HDR_CF_COMMA,
    64
  },
  {
    "Retry-After",
    HTTP_HDR_CF_ALPHA |
    HTTP_HDR_CF_NUMERIC | HTTP_HDR_CF_COMMA |
    HTTP_HDR_CF_SPACE | HTTP_HDR_CF_COLON,
    128
  },
  {
    "Transfer-Encoding",
    HTTP_HDR_CF_ALPHA,
    64
  },
  {
    "Upgrade",
    HTTP_HDR_CF_ALPHA |
    HTTP_HDR_CF_NUMERIC | HTTP_HDR_CF_SPACE |
    HTTP_HDR_CF_COMMA | HTTP_HDR_CF_SLASH |
    HTTP_HDR_CF_DOT,
    128
  },
  {
    "Vary",
    HTTP_HDR_FF_ANY,
    128
  },
  {
    "Via",
    HTTP_HDR_CF_ALPHA |
    HTTP_HDR_CF_NUMERIC | HTTP_HDR_CF_SLASH |
    HTTP_HDR_CF_COLON | HTTP_HDR_CF_AND |
    HTTP_HDR_CF_DOT | HTTP_HDR_CF_DASH |
    HTTP_HDR_CF_UNDERLINE | HTTP_HDR_CF_SPACE |
    HTTP_HDR_CF_BRACKET,
    512
  },
  {
    "Warning",
    HTTP_HDR_FF_ANY,
    512
  },
  // RFC 2069
  {
    "Proxy-Authentication-info",
    HTTP_HDR_FF_ANY,
    512
  },
  // RFC 2109
  {
    "Set-Cookie",
    HTTP_HDR_FF_ANY,
    -1
  },
  // RFC 2227
  {
    "Meter",
    HTTP_HDR_CF_ALPHA |
    HTTP_HDR_CF_NUMERIC | HTTP_HDR_CF_SPACE |
    HTTP_HDR_CF_COMMA | HTTP_HDR_CF_DASH |
    HTTP_HDR_CF_EQUAL,
    128
  },
  // RFC 2295
  {
    "Alternates",
    HTTP_HDR_FF_ANY,
    512
  },
  {
    "TCN",
    HTTP_HDR_FF_ANY,
    128
  },
  {
    "Variant-Vary",
    HTTP_HDR_FF_ANY,
    512
  },
  // RFC 2518 (WebDAV)
  {
    "DAV",
    HTTP_HDR_CF_ALPHA |
    HTTP_HDR_CF_NUMERIC | HTTP_HDR_CF_COMMA |
    HTTP_HDR_CF_SPACE,
    64
  },
  {
    "Depth",
    HTTP_HDR_CF_NUMERIC |
    HTTP_HDR_CF_ALPHA,
    64
  },
  {
    "Destination",
    HTTP_HDR_FF_URL,
    -1
  },
  {
    "If",
    HTTP_HDR_FF_ANY,
    512
  },
  {
    "Lock-Token",
    HTTP_HDR_CF_ALPHA |
    HTTP_HDR_CF_NUMERIC | HTTP_HDR_CF_SLASH |
    HTTP_HDR_CF_COLON | HTTP_HDR_CF_AND |
    HTTP_HDR_CF_DOT | HTTP_HDR_CF_DASH |
    HTTP_HDR_CF_UNDERLINE,
    512
  },
  {
    "Overwrite",
    HTTP_HDR_CF_ALPHA,
    8
  },
  {
    "Status-URI",
    HTTP_HDR_FF_URL,
    -1
  },
  // RFC 2616 (HTTP/1.1)
  {
    "Accept-Ranges",
    HTTP_HDR_CF_ALPHA,
    64
  },
  {
    "Trailer",
    HTTP_HDR_CF_ALPHA |
    HTTP_HDR_CF_DASH | HTTP_HDR_CF_NUMERIC,
    128
  },
  // RFC 2965
  {
    "Set-Cookie2",
    HTTP_HDR_FF_ANY,
    -1
  },
  // Nokia MMS Extension
  {
    "X-NOKIA-MMSC-Message-Id",
    HTTP_HDR_CF_ALPHA |
    HTTP_HDR_CF_NUMERIC | HTTP_HDR_CF_AT,
    128
  },
  {
    "X-NOKIA-MMSC-Status",
    HTTP_HDR_CF_NUMERIC,
    64
  },
  {
    "X-NOKIA-MMSC-Charging",
    HTTP_HDR_CF_NUMERIC,
    8
  },
  {
    "X-NOKIA-MMSC-Charged-Party",
    HTTP_HDR_CF_ALPHA,
    64
  },
  {
    "X-NOKIA-MMSC-To",
    HTTP_HDR_CF_NUMERIC |
    HTTP_HDR_CF_ALPHA | HTTP_HDR_CF_SLASH |
    HTTP_HDR_CF_EQUAL | HTTP_HDR_CF_PLUS |
    HTTP_HDR_CF_AT | HTTP_HDR_CF_DOT |
    HTTP_HDR_CF_DASH | HTTP_HDR_CF_UNDERLINE,
    128
  },
  {
    "X-NOKIA-MMSC-From",
    HTTP_HDR_CF_NUMERIC |
    HTTP_HDR_CF_ALPHA | HTTP_HDR_CF_SLASH |
    HTTP_HDR_CF_EQUAL | HTTP_HDR_CF_PLUS |
    HTTP_HDR_CF_AT | HTTP_HDR_CF_DOT |
    HTTP_HDR_CF_DASH | HTTP_HDR_CF_UNDERLINE,
    128
  },
  {
    "X-NOKIA-MMSC-Message-Type",
    HTTP_HDR_CF_ALPHA,
    64
  },
  {
    "X-NOKIA-MMSC-Version",
    HTTP_HDR_CF_NUMERIC |
    HTTP_HDR_CF_DOT,
    16
  },
  // Non-rfc(? :o)
  {
    "Content-disposition",
    HTTP_HDR_CF_ALPHA |
    HTTP_HDR_CF_DASH,
    64
  },
  {
    "Proxy-Connection",
    HTTP_HDR_CF_ALPHA |
    HTTP_HDR_CF_DASH,
    64
  },
  {
    "Connection",
    HTTP_HDR_CF_ALPHA |
    HTTP_HDR_CF_DASH | HTTP_HDR_CF_COMMA |
    HTTP_HDR_CF_SPACE,
    64
  },
  {
    "X-Cache",
    HTTP_HDR_CF_ALPHA |
    HTTP_HDR_CF_DOT | HTTP_HDR_CF_UNDERLINE |
    HTTP_HDR_CF_DASH | HTTP_HDR_CF_NUMERIC |
    HTTP_HDR_CF_SPACE,
    128
  },
  {
    "X-Cache-Lookup",
    HTTP_HDR_CF_ALPHA |
    HTTP_HDR_CF_DOT | HTTP_HDR_CF_UNDERLINE |
    HTTP_HDR_CF_DASH | HTTP_HDR_CF_NUMERIC |
    HTTP_HDR_CF_SPACE | HTTP_HDR_CF_COLON,
    128
  },
  {
    "SOAPAction",
    HTTP_HDR_FF_ANY,
    512
  },
  {
    NULL,
    0,
    0
  }
};

GHashTable *request_proto_hash;
GHashTable *response_proto_hash;
GHashTable *request_hdr_proto_hash;
GHashTable *response_hdr_proto_hash;
gboolean has_url_filter_license;

static GHashTable *
http_proto_fill_hash(HttpElementInfo *table, gboolean casesens)
{
  GHashTable *hash = NULL;
  gint x;

  if (casesens)
    hash = g_hash_table_new(g_str_hash, g_str_equal);
  else
    hash = g_hash_table_new((GHashFunc) http_filter_hash_bucket,(GCompareFunc) http_filter_hash_compare);

  for (x = 0; table[x].name; x++)
    g_hash_table_insert(hash, table[x].name, &table[x]);

  return hash;
}


void
http_proto_init(void)
{
  request_proto_hash = http_proto_fill_hash(request_proto_table, TRUE);
  response_proto_hash = http_proto_fill_hash(response_proto_table, TRUE);
  request_hdr_proto_hash = http_proto_fill_hash(request_hdr_proto_table, FALSE);
  response_hdr_proto_hash = http_proto_fill_hash(response_hdr_proto_table, FALSE);
}
