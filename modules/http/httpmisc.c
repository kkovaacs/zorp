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
 * $Id: httpmisc.c,v 1.21 2004/02/03 10:57:59 bazsi Exp $
 *
 * Author: Balazs Scheidler <bazsi@balabit.hu>
 * Auditor: 
 * Last audited version: 
 * Notes:
 *   Based on the code by: Viktor Peter Kovacs <vps__@freemail.hu>
 *
 ***************************************************************************/

#include "http.h"

#include <zorp/log.h>

#include <ctype.h>
#include <zorp/log.h>

#define HTTP_URL_HOST_ESCAPE_CHARS      "/$&+,:;=?@ \"'<>#%{}|\\^~[]`"
#define HTTP_URL_USER_ESCAPE_CHARS      "/$&+,:;=?@ \"'<>#%{}|\\^~[]`"
#define HTTP_URL_PASSWD_ESCAPE_CHARS    "/$&+,:;=?@ \"'<>#%{}|\\^~[]`"
#define HTTP_URL_FILE_ESCAPE_CHARS      "?#% \"<>"
#define HTTP_URL_QUERY_ESCAPE_CHARS     "/$&+,:;=?@ \"'<>#%{}|\\^~[]`"
#define HTTP_URL_FRAGMENT_ESCAPE_CHARS  "/$&+,:;=?@ \"'<>#%{}|\\^~[]`"

/**
 * xdigit_value:
 * @c: possible hexadecimal character
 *
 * Return the hexadecimal value of @c or return -1 if not a hexadecimal character.
 **/
static inline gint 
xdigit_value(char c)
{
  c = tolower(c);
  if (c >= '0' && c <= '9')
    return c - '0';
  else if (c >= 'a' && c <= 'f')
    return c - 'a' + 10;
  return -1;
}

/**
 * xdigit_char:
 * @nibble: half byte to return hexadecimal equivalent for
 *
 * Return the hexadecimal character representing @nibble.
 **/
static inline gchar
xdigit_char(gint nibble)
{
  if (nibble >= 0 && nibble <= 9)
    return nibble + '0';
  else if (nibble >= 10 && nibble <= 15)
    return nibble - 10 + 'A';
  return '?';
}


/**
 * http_string_url_decode_hex_byte:
 * @dst: store decoded value here
 * @src: read hexadecimal numbers from here
 * @reason: error reason text if the operation fails
 *
 * Convert a hexadecimal encoded byte to the equivalent value.
 **/
static inline gboolean
http_string_url_decode_hex_byte(guchar *dst, const gchar *src, const gchar **reason)
{
  if (isxdigit(*src) && isxdigit(*(src+1)))
    {
      *dst = (xdigit_value(*src) << 4) + xdigit_value(*(src+1));
    }
  else
    {
      *reason = "Invalid hexadecimal encoding";
      return FALSE;
    }
  return TRUE;
}


/**
 * http_string_assign_url_decode:
 * @part: store the decoded string here
 * @permit_invalid_hex_escape: whether to treat invalid url encoding sequences as errors
 * @src: source string to decode
 * @len: length of string pointed to by @src
 * @reason: terror reason text if the operation fails
 *
 * Decodes an URL part such as username, password or host name. Assumes
 * single byte destination encoding, e.g. US-ASCII with the 128-255 range
 * defined.
 **/
static gboolean
http_string_assign_url_decode(GString *part, gboolean permit_invalid_hex_escape, const gchar *src, gint len, const gchar **reason)
{
  gchar *dst;
  gint left = len;
  
  /* url decoding shrinks the string, using len is a good bet */
  g_string_set_size(part, len);
  dst = part->str;
  while (left)
    {
      guchar c = (guchar) *src;
      
      if (*src == '%')
        {
          *reason = "Hexadecimal encoding too short";
          if (left < 2 || !http_string_url_decode_hex_byte(&c, src+1, reason))
            {
              if (permit_invalid_hex_escape)
                {
                  /* if the escaping is invalid we emit a literal '%' which
                   * will be escaped in http_format_url
                   */
                  c = '%';
                }
              else
                {
                  return FALSE;
                }
            }
          else
            {
              src += 2;
              left -= 2;
            }
        }
      *dst = c;
      dst++; 
      src++;
      left--;
    }
  *dst = 0;
  part->len = dst - part->str;
  /* some space might still be allocated at the end of the string 
   * but we don't care to avoid reallocing and possible data copy */
  return TRUE;
}

/**
 * http_string_assign_url_decode_unicode:
 * @part: store the decoded string here
 * @permit_invalid_hex_escape: whether to treat invalid url encoding sequences as errors
 * @src: source string to decode
 * @len: length of string pointed to by @src
 * @reason: error reason text if the operation fails
 *
 * Decodes an URL part such as username, password or host name. Assumes
 * UTF8 destination encoding, decoding possible %uXXXX sequences as UCS2.
 **/
static gboolean
http_string_assign_url_decode_unicode(GString *part, gboolean permit_invalid_hex_escape, const gchar *str, gint len, const gchar **reason)
{
  const guchar *src = str;
  gchar *dst;
  gint left = len;
  
  /* possible maximum utf8 length is 6 times the amount of UCS2 chars, note
   * that real unicode characters can only be encoded by the %uXXXX encoding
   * which in turn decreases the number of needed bytes */

  g_string_set_size(part, (len + 1) * 6);
  dst = part->str;
  while (left)
    {
      gunichar c = (gunichar) *src;
      
      if (*src == '%')
        {
          if (*(src+1) != 'u')
            {
              guchar cb;
              
              *reason = "Hexadecimal encoding too short";
              if (left < 2 || !http_string_url_decode_hex_byte(&cb, src+1, reason))
                {
                  if (permit_invalid_hex_escape)
                    {
                      c = '%';
                    }
                  else
                    return FALSE;
                }
              else
                {
                  c = (gunichar) cb;
                  src += 2;
                  left -= 2;
                }
            }
          else
            {
              guchar cbhi, cblo;
              
              *reason = "Unicode hexa encoding too short";
              if (left < 4 || 
                  !http_string_url_decode_hex_byte(&cbhi, src + 2, reason) ||
                  !http_string_url_decode_hex_byte(&cblo, src + 4, reason))
                {
                  if (permit_invalid_hex_escape)
                    {
                      c = '%';
                    }
                  else
                    {
                      return FALSE;
                    }
                }
              else
                {
                  c = (cbhi << 8) + cblo;
                  src += 5;
                  left -= 5;
                }
            }
        }
      
      dst += g_unichar_to_utf8(c, dst);
      src++;
      left--;
    }
  *dst = 0;
  
  part->len = dst - part->str;
  /* some space might still be allocated at the end of the string 
   * but we don't care to avoid reallocing and possible data copy */
  return TRUE;
}

/**
 * http_string_append_url_encode:
 * @result: store the decoded string here
 * @unsafe_chars: a string of characters to be URL encoded
 * @str: source string to decode
 * @len: length of string pointed to by @src
 * @reason: error reason text if the operation fails
 *
 * Encodes a plain US-ASCII string to be a part of a URL, e.g. encodes
 * unsafe and non-latin characters using URL hexadecimal encoding.
 **/
gboolean
http_string_append_url_encode(GString *result, const gchar *unsafe_chars, const gchar *str, gint len, const gchar **reason G_GNUC_UNUSED)
{
  const guchar *src;
  gchar *dst;
  gsize orig_len = result->len;
  
  g_string_set_size(result, orig_len + (len+1) * 3);
  src = str;
  dst = result->str + orig_len;
  while (*src)
    {
      if (*src <= 0x1F || *src > 0x7F || strchr(unsafe_chars, *src))
        {
          *dst = '%';
          *(dst+1) = xdigit_char((*src & 0xf0) >> 4);
          *(dst+2) = xdigit_char((*src & 0x0f));
          dst += 2;
        }
      else
        {
          *dst = *src;
        }
      src++;
      dst++;
    }
  *dst = 0;
  result->len = dst - result->str;
  return TRUE;
}

/**
 * http_string_append_url_encode_unicode:
 * @result: store the decoded string here
 * @unsafe_chars: a string of characters to be URL encoded
 * @str: source string to decode
 * @len: length of string pointed to by @src
 * @reason: error reason text if the operation fails
 *
 * Encodes an UTF8 string to be a part of a URL, e.g. encodes unsafe and
 * non-latin characters using URL hexadecimal encoding.
 **/
gboolean
http_string_append_url_encode_unicode(GString *result, const gchar *unsafe_chars, const gchar *str, gint len, const gchar **reason)
{
  const guchar *src;
  gchar *dst;
  gsize orig_len = result->len;
  
  g_string_set_size(result, orig_len + (len+1) * 6);
  src = str;
  dst = result->str + orig_len;
  while (*src)
    {
      gunichar c = g_utf8_get_char(src);
      
      if (c <= 0x1F || (c > 0x7F && c < 0x100) || strchr(unsafe_chars, (gchar) c))
        {
          *dst = '%';
          *(dst+1) = xdigit_char((c & 0xf0) >> 4);
          *(dst+2) = xdigit_char((c & 0x0f));
          dst += 2;
        }
      else if (c > 0xFF && c < 0x10000)
        {
          *dst = '%';
          *(dst+1) = 'u';
          *(dst+2) = xdigit_char((c & 0xf000) >> 12);
          *(dst+3) = xdigit_char((c & 0x0f00) >> 8);
          *(dst+4) = xdigit_char((c & 0x00f0) >> 4);
          *(dst+5) = xdigit_char((c & 0x000f));
          dst += 5;
        }
      else if (c > 0xFFFF)
        {
          *reason = "Error recoding character, value not fitting into UCS2 found";
          return FALSE;
        }
      else
        {
          *dst = (gchar) c;
        }
      src = g_utf8_next_char(src);
      dst++;
    }
  *dst = 0;
  result->len = dst - result->str;
  return TRUE;
}

/**
 * http_string_assign_url_canonicalize:
 * @result: store the canonicalized string here
 * @permit_invalid_hex_escape: whether to treat invalid url encoding sequences as errors
 * @unsafe_chars: a string of characters to be URL encoded
 * @str: source string to decode
 * @len: length of string pointed to by @src
 * @reason: error reason text if the operation fails
 *
 * Decode and encode the parts of an URL making sure that a single possible encoding
 * form is used.
 **/
gboolean
http_string_assign_url_canonicalize(GString *result, gboolean permit_invalid_hex_escape, const gchar *unsafe_chars, const gchar *str, gint len, const gchar **reason)
{
  gchar *dst;
  const gchar *src;
  gint left = len;
  
  /* possible maximum utf8 length is 6 times the amount of utf16 chars, note
   * that real unicode characters can only be encoded by the %uXXXX encoding
   * which in turn decreases the number of needed bytes */

  g_string_set_size(result, (len + 1) * 6);
  dst = result->str;
  src = str;
  while (left)
    {
      guchar c = (guchar) *src;
      gboolean was_encoded = FALSE;
      
      if (*src == '%')
        {
          *reason = "Hexadecimal encoding too short";
          if (left < 2 || !http_string_url_decode_hex_byte(&c, src + 1, reason))
            {
              if (permit_invalid_hex_escape)
                {
                  c = '%';
                }
              else
                {
                  return FALSE;
                }
            }
          else
            {
              src += 2;
              left -= 2;
              was_encoded = TRUE;
            }
        }

      /* ok, character to store is in c, encode it again */
      
      if (c <= 0x1F || (c > 0x7F) || (was_encoded && strchr(unsafe_chars, (gchar) c)))
        {
          /* these characters must be encoded regardless of their original form */
          *dst = '%';
          *(dst+1) = xdigit_char((c & 0xf0) >> 4);
          *(dst+2) = xdigit_char((c & 0x0f));
          dst += 2;
        }
      else
        {
          *dst = (gchar) c;
        }
      
      dst++;
      src++;
      left--;
    }
  *dst = 0;
  
  result->len = dst - result->str;
  /* some space might still be allocated at the end of the string 
   * but we don't care to avoid reallocing and possible data copy */
  return TRUE;
}

/**
 * http_string_assign_url_canonicalize_unicode:
 * @result: store the canonicalized string here
 * @permit_invalid_hex_escape: whether to treat invalid url encoding sequences as errors
 * @unsafe_chars: a string of characters to be URL encoded
 * @str: source string to decode
 * @len: length of string pointed to by @src
 * @reason: error reason text if the operation fails
 *
 * Decode and encode the parts of an URL making sure that a single possible
 * encoding form is used, also permit unicode encoding with %uXXXX
 * sequences.
 **/
gboolean
http_string_assign_url_canonicalize_unicode(GString *result, gboolean permit_invalid_hex_escape, const gchar *unsafe_chars, const gchar *str, gint len, const gchar **reason)
{
  gchar *dst;
  const guchar *src;
  gint left = len;
  
  /* possible maximum utf8 length is 6 times the amount of utf16 chars, note
   * that real unicode characters can only be encoded by the %uXXXX encoding
   * which in turn decreases the number of needed bytes */

  g_string_set_size(result, (len + 1) * 6);
  dst = result->str;
  src = str;
  while (left)
    {
      gunichar c = (gunichar) *src;
      gboolean was_encoded = FALSE;
      
      if (*src == '%')
        {
          if (*(src+1) != 'u')
            {
              guchar cb;
              
              *reason = "Hexadecimal encoding too short";
              if (left < 2 || !http_string_url_decode_hex_byte(&cb, src+1, reason))
                {
                  if (permit_invalid_hex_escape)
                    {
                      c = '%';
                    }
                  else
                    {
                      return FALSE;
                    }
                }
              else
                {
                  c = (gunichar) cb;
                  src += 2;
                  left -= 2;
                }
            }
          else
            {
              guchar cbhi, cblo;
              
              *reason = "Unicode hexa encoding too short";
              if (left < 4 || 
                  !http_string_url_decode_hex_byte(&cbhi, src + 2, reason) ||
                  !http_string_url_decode_hex_byte(&cblo, src + 4, reason))
                {
                  if (permit_invalid_hex_escape)
                    {
                      c = '%';
                    }
                  else
                    {
                      return FALSE;
                    }
                }
              else
                {
                  c = (cbhi << 8) + cblo;
                  src += 5;
                  left -= 5;
                }
            }
            
          was_encoded = TRUE;
        }

      /* ok, character to store is in c, encode it again */
      
      if (c <= 0x1F || (c > 0x7F && c < 0x100))
        {
          /* these characters must be encoded regardless of their original form */
          *dst = '%';
          *(dst+1) = xdigit_char((c & 0xf0) >> 4);
          *(dst+2) = xdigit_char((c & 0x0f));
          dst += 2;
        }
      else if (c < 0x100 && strchr(unsafe_chars, (gchar) c))
        {
          /* unsafe characers are left intact if they were stored unescaped */
          if (was_encoded)
            {
              *dst = '%';
              *(dst+1) = xdigit_char((c & 0xf0) >> 4);
              *(dst+2) = xdigit_char((c & 0x0f));
              dst += 2;
            }
          else
            {
              *dst = c;
            }
        }
      else if (c > 0xFF && c < 0x10000)
        {
          *dst = '%';
          *(dst+1) = 'u';
          *(dst+2) = xdigit_char((c & 0xf000) >> 12);
          *(dst+3) = xdigit_char((c & 0x0f00) >> 8);
          *(dst+4) = xdigit_char((c & 0x00f0) >> 4);
          *(dst+5) = xdigit_char((c & 0x000f));
          dst += 5;
        }
      else if (c > 0xFFFF)
        {
          *reason = "Error recoding character, value not fitting into UCS2 found";
          return FALSE;
        }
      else
        {
          *dst = (gchar) c;
        }
      
      dst++;
      src++;
      left--;
    }
  *dst = 0;
  
  result->len = dst - result->str;
  /* some space might still be allocated at the end of the string 
   * but we don't care to avoid reallocing and possible data copy */
  return TRUE;
}

/**
 * http_parse_url:
 * @url: store URL parts to this structure
 * @permit_unicode_url: permit IIS style unicode character encoding
 * @permit_invalid_hex_escape: permit invalid hexadecimal escaping, treat % in these cases literally
 * @url_str: URL to parse
 * @reason: parse error 
 *
 * Parse the URL specified in @url_str and store the resulting parts in
 * @url. Scheme, username, password, hostname and filename are stored in
 * decoded form (UTF8 in permit_unicode_url case), query and fragment are
 * stored in URL encoded, but canonicalized form.
 *
 * Returns: TRUE for success, FALSE otherwise setting @reason to the explanation
 **/
gboolean
http_parse_url(HttpURL *url, gboolean permit_unicode_url, gboolean permit_invalid_hex_escape,
               gboolean permit_relative_url, gchar *url_str, const gchar **reason)
{
  gchar *p, *end, *part[4], *sep[4], *query_start, *fragment_start, *file_start;
  gsize file_len, query_len = 0, fragment_len = 0;
  int i;

  z_enter();
  g_string_truncate(url->scheme, 0);
  g_string_truncate(url->user, 0);
  g_string_truncate(url->passwd, 0);
  g_string_truncate(url->host, 0);
  g_string_truncate(url->file, 0);
  g_string_truncate(url->query, 0);
  g_string_truncate(url->fragment, 0);
  url->port = 0;

  p = url_str;
  while (*p && *p != ':')
    p++;
  if (!*p)
    {
      if (!permit_relative_url)
        {
          *reason = "URL has no scheme, colon missing";
          z_return(FALSE);
        }
      else
        goto relative_url;
    }
  if (*(p + 1) != '/' || *(p + 2) != '/')
    {
      /* protocol not terminated by '//' */
      *reason = "Scheme not followed by '//'";
      z_return(FALSE);
    }
  g_string_assign_len(url->scheme, url_str, p - url_str);
  p += 3;

  for (i = 0; i < 4; i++)
    {
      part[i] = p;
      while (*p && *p != ':' && *p != '/' && *p != '@' && *p != '?' && *p != '#')
        p++;
      sep[i] = p;
      if (!*p || *p == '/')
        break;
      p++;
    }
  *reason = "Unrecognized URL construct";
  switch (i)
    {
    case 0:
      /* hostname only */
      if (!http_string_assign_url_decode(url->host, permit_invalid_hex_escape, part[0], sep[0] - part[0], reason))
        z_return(FALSE);

      break;

    case 1:
      /* username && host || hostname && port number */
      if (*sep[0] == ':')
        {
          if (!http_string_assign_url_decode(url->host, permit_invalid_hex_escape, part[0], sep[0] - part[0], reason))
            z_return(FALSE);
          /* port number */
          url->port = strtoul(part[1], &end, 10);
          if (end != sep[1])
            {
              *reason = "Error parsing port number";
              z_return(FALSE);
            }
        }
      else if (*sep[0] == '@')
        {
          /* username */
          if (!http_string_assign_url_decode(url->user, permit_invalid_hex_escape, part[0], sep[0] - part[0], reason) ||
              !http_string_assign_url_decode(url->host, permit_invalid_hex_escape, part[1], sep[1] - part[1], reason))
            z_return(FALSE);
        }
      else
        {
          z_return(FALSE);
        }
      break;

    case 2:
      /* username && host && port || username && password && host */
      if (*sep[0] == '@' && *sep[1] == ':')
        {
          /* username, host, port */
          if (!http_string_assign_url_decode(url->user, permit_invalid_hex_escape, part[0], sep[0] - part[0], reason) ||
              !http_string_assign_url_decode(url->host, permit_invalid_hex_escape, part[1], sep[1] - part[1], reason))
            z_return(FALSE);
          url->port = strtoul(part[2], &end, 10);
          if (end != sep[2])
            {
              *reason = "Error parsing port number";
              z_return(FALSE);
            }
        }
      else if (*sep[0] == ':' && *sep[1] == '@')
        {
          /* username, password, host */
          if (!http_string_assign_url_decode(url->user, permit_invalid_hex_escape, part[0], sep[0] - part[0], reason) ||
              !http_string_assign_url_decode(url->passwd, permit_invalid_hex_escape, part[1], sep[1] - part[1], reason) ||
              !http_string_assign_url_decode(url->host, permit_invalid_hex_escape, part[2], sep[2] - part[2], reason))
            z_return(FALSE);
        }
      else
        {
          z_return(FALSE);
        }
      break;

    case 3:
      /* username && password && hostname && port */
      if (*sep[0] == ':' && *sep[1] == '@' && *sep[2] == ':')
        {
          if (!http_string_assign_url_decode(url->user, permit_invalid_hex_escape, part[0], sep[0] - part[0], reason) ||
              !http_string_assign_url_decode(url->passwd, permit_invalid_hex_escape, part[1], sep[1] - part[1], reason) ||
              !http_string_assign_url_decode(url->host, permit_invalid_hex_escape, part[2], sep[2] - part[2], reason))
            z_return(FALSE);
          url->port = strtoul(part[3], &end, 10);
          if (end != sep[3])
            {
              *reason = "Error parsing port number";
              z_return(FALSE);
            }
        }
      else
        {
          z_return(FALSE);
        }
      break;

    default:
      /* not reached */
      z_return(FALSE);
    }

 relative_url:

  file_start = p;
  if (*file_start != '/')
    {
      if (*file_start == '\0')
        {
          g_string_assign(url->file, "/");
          z_return(TRUE);
        }
      *reason = "Invalid path component in URL";
      z_return(FALSE);
    }
  g_string_assign(url->original_local, file_start);

  query_start = strchr(p, '?');
  fragment_start = strchr(p, '#');
  if (query_start && fragment_start)
    {
      if (query_start > fragment_start)
        {
          *reason = "The fragment part starts earlier than the query";
          z_return(FALSE);
        }
      file_len = query_start - file_start;
      query_start++;
      query_len = fragment_start - query_start;
      fragment_start++;
      fragment_len = strlen(fragment_start);
    }
  else if (query_start)
    {
      file_len = query_start - file_start;
      query_start++;
      query_len = strlen(query_start);
    }
  else if (fragment_start)
    {
      file_len = fragment_start - file_start;
      fragment_start++;
      fragment_len = strlen(fragment_start);
    }
  else
    {
      file_len = strlen(file_start);
    }
  
  if (!(permit_unicode_url ? http_string_assign_url_decode_unicode : http_string_assign_url_decode)
             (url->file, permit_invalid_hex_escape, file_start, file_len, reason))
    z_return(FALSE);
    
  /* query and fragment is not url-decoded as it is impossible to get the original back */
  if (query_start && !(permit_unicode_url ? http_string_assign_url_canonicalize_unicode : http_string_assign_url_canonicalize)
               (url->query, permit_invalid_hex_escape, HTTP_URL_QUERY_ESCAPE_CHARS, query_start, query_len, reason))
    z_return(FALSE);

  if (fragment_start && !(permit_unicode_url ? http_string_assign_url_canonicalize_unicode : http_string_assign_url_canonicalize)
                 (url->fragment, permit_invalid_hex_escape, HTTP_URL_FRAGMENT_ESCAPE_CHARS, fragment_start, fragment_len, reason))
    z_return(FALSE);
    
  z_return(TRUE);
}

/**
 * http_format_url:
 * @url: HttpURL structure
 * @encode_buf: restructured URL
 * @format_absolute: whether to forman an absolute or a relative URL
 * @permit_unicode_url: whether to permit UCS2 encoded characters
 * @reason: error reason if any
 *
 * Reformat the already parsed URL from its internal representation.
 **/
gboolean
http_format_url(HttpURL *url, GString *encode_buf, gboolean format_absolute, gboolean permit_unicode_url, gboolean canonicalized, const gchar **reason)
{
  if (format_absolute)
    {
      g_string_assign(encode_buf, url->scheme->str);
      g_string_append(encode_buf, "://");
      if (url->user->len && !http_string_append_url_encode(encode_buf, HTTP_URL_USER_ESCAPE_CHARS, url->user->str, url->user->len, reason))
        return FALSE;
      if (url->passwd->len)
        {
          g_string_append_c(encode_buf, ':');
          if (!http_string_append_url_encode(encode_buf, HTTP_URL_PASSWD_ESCAPE_CHARS, url->passwd->str, url->passwd->len, reason))
            return FALSE;
        }
      if (url->user->len || url->passwd->len)
        g_string_append_c(encode_buf, '@');
      if (!http_string_append_url_encode(encode_buf, HTTP_URL_HOST_ESCAPE_CHARS, url->host->str, url->host->len, reason))
        return FALSE;
      if (url->port)
        g_string_sprintfa(encode_buf, ":%d", url->port);
    }

  if (!canonicalized)
    {
      g_string_append(encode_buf, url->original_local->str);
    }
  else
    {
      if (!(permit_unicode_url ? http_string_append_url_encode_unicode : http_string_append_url_encode)
              (encode_buf, HTTP_URL_FILE_ESCAPE_CHARS, url->file->str, url->file->len, reason))
        {
          return FALSE;
        }
          
      if (url->query->len)
        {
          g_string_append_c(encode_buf, '?');
          g_string_append(encode_buf, url->query->str);
        }
      if (url->fragment->len)
        {
          g_string_append_c(encode_buf, '#');
          g_string_append(encode_buf, url->fragment->str);
        }
    }
  return TRUE;
}

/**
 * http_init_url:
 * @url: HttpURL structure
 *
 * Initializes the fields in @url.
 **/
void
http_init_url(HttpURL *url)
{
  url->original_local = g_string_sized_new(64);
  url->scheme = g_string_sized_new(4);
  url->user = g_string_sized_new(0);
  url->passwd = g_string_sized_new(0);
  url->host = g_string_sized_new(32);
  url->file = g_string_sized_new(64);
  url->query = g_string_sized_new(0);
  url->fragment = g_string_sized_new(0);
}

/**
 * http_destroy_url:
 * @url: HttpURL structure
 *
 * Frees all storage associated with @url.
 **/
void
http_destroy_url(HttpURL *url)
{
  g_string_free(url->original_local, TRUE);
  g_string_free(url->scheme, TRUE);
  g_string_free(url->user, TRUE);
  g_string_free(url->passwd, TRUE);
  g_string_free(url->host, TRUE);
  g_string_free(url->file, TRUE);
  g_string_free(url->query, TRUE);
  g_string_free(url->fragment, TRUE);
}

#define SKIP_SPACES \
  do \
    { \
      while (left > 0 && *src == ' ') \
        { \
          src++; \
          left--; \
        } \
    } \
  while (0)
  
#define COPY_SPACE \
  do \
    { \
      while (left > 0 && avail > 0 && *src != ' ' && *src) \
        { \
          *dst++ = *src++; \
          left--; \
          avail--; \
        } \
      *dst = 0; \
    } \
  while (0)
	

/**
 * http_split_request:
 * @self: HttpProxy instance
 * @line: request line
 * @length: length of @line
 *
 * Split an incoming HTTP request to method, url and HTTP version, and store
 * the resulting items in @self.
 **/
gboolean
http_split_request(HttpProxy *self, gchar *line, gint length)
{
  gchar *src, *dst;
  gint left, avail;

  z_proxy_enter(self);
  g_string_truncate(self->request_method, 0);
  self->request_flags = -1;
  self->request_version[0] = 0;
  g_string_truncate(self->request_url, 0);
  src = line;
  left = length;
  dst = self->request_method->str;
  avail = self->request_method->allocated_len;
  COPY_SPACE;
  self->request_method->len = strlen(self->request_method->str);
  if (!self->request_method->len || (*src != ' ' && avail == 0))
    {
      /*LOG
        This message indicates that the request method sent by the client is
        invalid.
       */
      z_proxy_log(self, HTTP_VIOLATION, 1, "Request method empty, or too long; line='%.*s'", left, src);
      /* request method empty, or request buffer overflow */
      z_proxy_return(self, FALSE);
    }

  SKIP_SPACES;
  avail = self->max_url_length;
  g_string_truncate(self->request_url, 0);
  while (left > 0 && avail > 0 && *src != ' ' && *src) 
    { 
      g_string_append_c(self->request_url, *src++);
      left--; 
      avail--; 
    } 

  if (!self->request_url->str[0] || (*src != ' ' && avail == 0))
    {
      /* url missing, or too long */
      /*LOG
        This message indicates that the URL sent by the client is invalid.
       */
      z_proxy_log(self, HTTP_VIOLATION, 1, "URL missing, or too long; line='%.*s'", left, src);
      z_proxy_return(self, FALSE);
    }

  SKIP_SPACES;
  dst = self->request_version;
  avail = sizeof(self->request_version) - 1;
  COPY_SPACE;
  if (*src != ' ' && avail == 0)
    {
      /* protocol version too long */
      /*LOG
        This message indicates that the protocol version sent by the client
        is invalid.
       */
      z_proxy_log(self, HTTP_VIOLATION, 1, "Protocol version missing, or too long; line='%.*s'", left, src);
      z_proxy_return(self, FALSE);
    }
  
  /*LOG
    This message reports the processed request details.
   */
  z_proxy_log(self, HTTP_REQUEST, 6, "Request details; command='%s', url='%s', version='%s'", self->request_method->str, self->request_url->str, self->request_version);
  z_proxy_return(self, TRUE);
}

/**
 * http_split_request:
 * @self: HttpProxy instance
 * @line: request line
 * @length: length of @line
 *
 * Split an incoming HTTP response to HTTP version, status and message
 * storing the resulting items in @self.
 **/
gboolean
http_split_response(HttpProxy *self, gchar *line, gint line_length)
{
  gchar *src, *dst;
  gint left, avail;

  z_proxy_enter(self);
  self->response_version[0] = 0;
  self->response[0] = 0;
  g_string_truncate(self->response_msg, 0);
  src = line;
  left = line_length;
  dst = self->response_version;
  avail = sizeof(self->response_version) - 1;
  COPY_SPACE;
  if (memcmp(self->response_version, "HTTP", 4) != 0)
    {
      /* no status line */
      /*LOG
        This message indicates that the server sent an invalid response status line.
       */
      z_proxy_log(self, HTTP_RESPONSE, 6, "Invalid HTTP status line; line='%s'", dst);
      z_proxy_return(self, FALSE);
    }

  if (!self->response_version[0] || (*src != ' ' && avail == 0))
    {
      /* response version empty or too long */
      /*LOG
        This message indicates that the protocol version sent by the server
        is invalid.
       */
      z_proxy_log(self, HTTP_VIOLATION, 1, "Response version empty or too long; line='%.*s'", line_length, line);
      z_proxy_return(self, FALSE);
    }
  
  SKIP_SPACES;
  dst = self->response;
  avail = sizeof(self->response) - 1;
  COPY_SPACE;
  if (!self->response[0] || (*src != ' ' && left && avail == 0))
    {
      /* response code empty or too long */
      /*LOG
        This message indicates that the response code sent by the server is
        invalid.
       */
      z_proxy_log(self, HTTP_VIOLATION, 1, "Response code empty or too long; line='%.*s'", line_length, line);
      z_proxy_return(self, FALSE);
    }
  
  self->response_code = atoi(self->response);
  SKIP_SPACES;
  avail = 256;
  while (left > 0 && avail > 0) 
    { 
      g_string_append_c(self->response_msg, *src);
      src++;
      left--; 
      avail--; 
    } 
  *dst = 0; 
 
  /*LOG
    This message reports the processed response details.
   */
  z_proxy_log(self, HTTP_RESPONSE, 7, "Response details; version='%s', response_code='%s', response_msg='%s'", self->response_version, self->response, self->response_msg->str);
  z_proxy_return(self, TRUE);
}

#undef SKIP_SPACES
#undef COPY_SPACE

/**
 * http_parse_version:
 * @self: HttpProxy instance
 * @side: 0 for request, 1 for response
 * @version_str: version specification as returned by the peer
 *
 * Parse and store an HTTP version supplied in @version_str storing it to
 * self->proto_version[side].
 **/
gboolean
http_parse_version(HttpProxy *self, gint side, gchar *version_str)
{
  z_proxy_enter(self);
  if (strcasecmp(version_str, "HTTP/1.1") == 0)
    {
      self->proto_version[side] = 0x0101;
    }
  else if (strcasecmp(version_str, "HTTP/1.0") == 0)
    {
      self->proto_version[side] = 0x0100;
    }
  else if (version_str[0] == 0)
    {
      self->proto_version[side] = 0x0009;
    }
  else
    {
      /* unknown protocol version */
      if (side == EP_CLIENT)
	/*LOG
	  This message indicates that the protocol version sent by the
	  client is unsupported.
	 */
        z_proxy_log(self, HTTP_REQUEST, 3, "Unknown protocol version; version='%s'", version_str);
      else
	/*LOG
	  This message indicates that the protocol version sent by the
	  server is unsupported.
	 */
        z_proxy_log(self, HTTP_RESPONSE, 3, "Unknown protocol version; version='%s'", version_str);
      self->proto_version[side] = 0x0100;
      z_proxy_return(self, FALSE);
    }
  z_proxy_return(self, TRUE);
}
