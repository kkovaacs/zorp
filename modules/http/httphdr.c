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
 * $Id: httphdr.c,v 1.19 2004/07/26 11:45:57 bazsi Exp $
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

/* these headers are not allowed to be duplicated, the first header is
 * used, the rest is dropped. All headers that is likely to be used
 * for an access control decision should be added here
 */
static gchar *smuggle_headers[] =
{
  "Content-Length",      /* makes complete request smuggling possible */
  "Transfer-Encoding",   /* trick the proxy to use a different transfer-encoding than the server */
  "Content-Type",        /* different content-types */
  "Host",                /* different hostname in URL, e.g. http://goodsite.org/index.html instead of http://evilsite.org/index.html */
  "Connection",          /* different connection mode, might cause the connection to stall */
  "Proxy-Connection",    /* -"- */
  "Authorization",       /* different credentials (username/password) */
  "Proxy-Authorization"  /* -"- */
};


gboolean
http_header_equal(gconstpointer k1, gconstpointer k2)
{
  return g_strcasecmp(k1, k2) == 0;
}

guint
http_header_hash(gconstpointer key)
{
  const char *p = key;
  guint h = toupper(*p);
    
  if (h)
    for (p += 1; *p != '\0'; p++)
      h = (h << 5) - h + toupper(*p);
                
  return h;
}

static void
http_header_free(HttpHeader *h)
{
  g_string_free(h->name, TRUE);
  g_string_free(h->value, TRUE);
  g_free(h);
}

void
http_log_headers(HttpProxy *self, gint side, gchar *tag)
{
  HttpHeaders *hdrs = &self->headers[side];
  
  if ((side == EP_CLIENT && z_log_enabled(HTTP_REQUEST, 7)) ||
      (side == EP_SERVER && z_log_enabled(HTTP_RESPONSE, 7)))
    {
      GList *l = g_list_last(hdrs->list);

      while (l)
        {
          HttpHeader *hdr = (HttpHeader *) l->data;
          if (hdr->present)
            {
              if (side == EP_CLIENT)
                /*NOLOG*/
                z_proxy_log(self, HTTP_REQUEST, 7, "Request %s header; hdr='%s', value='%s'", tag, 
                            hdr->name->str, hdr->value->str);
              else
                /*NOLOG*/
                z_proxy_log(self, HTTP_RESPONSE, 7, "Response %s header; hdr='%s', value='%s'", tag, 
                            hdr->name->str, hdr->value->str);
            }            
	  l = g_list_previous(l);
        }
    }
}

/* duplicated headers are simply put on the list and not inserted into
   the hash, thus looking up a header by name always results the first
   added header */

HttpHeader *
http_add_header(HttpHeaders *hdrs, gchar *name, gint name_len, gchar *value, gint value_len)
{
  HttpHeader *h;
  HttpHeader *orig;

  h = g_new0(HttpHeader, 1);
  h->name = g_string_sized_new(name_len + 1);

  g_string_assign_len(h->name, name, name_len);

  h->value = g_string_sized_new(value_len + 1);
  g_string_assign_len(h->value, value, value_len);
  h->present = TRUE;

  if (!http_lookup_header(hdrs, h->name->str, &orig))
    {
      hdrs->list = g_list_prepend(hdrs->list, h);
      g_hash_table_insert(hdrs->hash, h->name->str, hdrs->list);
    }
  else
    {
      guint i;

      for (i = 0; i < sizeof(smuggle_headers) / sizeof(smuggle_headers[0]); i++)
        {
          if (strcmp(smuggle_headers[i], h->name->str) == 0)
            {
              http_header_free(h);
              h = NULL;
              break;
            }
        }
      if (h)
        {
          /* not found in smuggle_headers */
          hdrs->list = g_list_prepend(hdrs->list, h);
        }
      else
        {
          z_log(NULL, HTTP_VIOLATION, 3,
              "Possible smuggle attack, removing header duplication; header='%.*s', value='%.*s', prev_value='%.*s'",
              name_len, name, value_len, value, (gint) orig->value->len, orig->value->str);
        }
    }
  return h;
}

static gboolean
http_clear_header(gpointer key G_GNUC_UNUSED, 
                  gpointer value G_GNUC_UNUSED, 
                  gpointer user_data G_GNUC_UNUSED)
{
  return TRUE;
}

void
http_clear_headers(HttpHeaders *hdrs)
{
  GList *l;

  for (l = hdrs->list; l; l = l->next)
    http_header_free(l->data);
  g_list_free(hdrs->list);
  hdrs->list = NULL;
  g_string_truncate(hdrs->flat, 0);
  g_hash_table_foreach_remove(hdrs->hash, http_clear_header, NULL);
}

gboolean
http_lookup_header(HttpHeaders *headers, gchar *what, HttpHeader **p)
{
  GList *l;

  l = g_hash_table_lookup(headers->hash, what);
  if (l)
    {
      *p = l->data;
      return TRUE;
    }
  *p = NULL;
  return FALSE;
}

static void
http_insert_headers(gchar *key, ZPolicyObj *f, HttpHeaders *hdrs)
{
  guint filter_type;
  gchar *value;

  if (!z_policy_tuple_get_verdict(f, &filter_type))
    {
      /* filter has no type field */
      return;
    }
  switch (filter_type)
    {
    case HTTP_HDR_INSERT:
    case HTTP_HDR_REPLACE:
      if (!z_policy_var_parse(f, "(is)", &filter_type, &value))
	{
	  /* error parsing HTTP_INSERT or HTTP_REPLACE rule */
	  return;
	}

      http_add_header(hdrs, key, strlen(key), value, strlen(value));
      break;
    default:
      break;
    }
}

static gboolean
http_check_header_charset(HttpProxy *self, gchar *header, guint flags, const gchar **reason)
{
  gint i;

  *reason = FALSE;
  if (flags & HTTP_HDR_FF_ANY)
    return TRUE;

  if (flags & HTTP_HDR_FF_URL)
    {
      HttpURL url;
      gboolean success;

      http_init_url(&url);
      success = http_parse_url(&url, self->permit_unicode_url, self->permit_invalid_hex_escape, TRUE, header, reason);
      http_destroy_url(&url);

      return success;
    }
  for (i = 0; header[i]; i++)
    {
      gboolean ok;
      guchar c = header[i];

      ok = FALSE;
      if ((flags & HTTP_HDR_CF_ALPHA) &&
          ((c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z')))
        ok = TRUE;
      else if ((flags & HTTP_HDR_CF_NUMERIC) &&
          (c >= '0' && c <= '9'))
        ok = TRUE;
      else if ((flags & HTTP_HDR_CF_SPACE) &&
          (c == ' '))
        ok = TRUE;
      else if ((flags & HTTP_HDR_CF_COMMA) &&
          (c == ','))
        ok = TRUE;
      else if ((flags & HTTP_HDR_CF_DOT) &&
          (c == '.'))
        ok = TRUE;
      else if ((flags & HTTP_HDR_CF_BRACKET) &&
          (c == '[' || c == ']' || c == '{' || c == '}' || c == '(' || c == ')'))
        ok = TRUE;
      else if ((flags & HTTP_HDR_CF_EQUAL) &&
          (c == '='))
        ok = TRUE;
      else if ((flags & HTTP_HDR_CF_DASH) &&
          (c == '-'))
        ok = TRUE;
      else if ((flags & HTTP_HDR_CF_SLASH) &&
          (c == '/'))
        ok = TRUE;
      else if ((flags & HTTP_HDR_CF_COLON) &&
          (c == ':'))
        ok = TRUE;
      else if ((flags & HTTP_HDR_CF_SEMICOLON) &&
          (c == ';'))
        ok = TRUE;
      else if ((flags & HTTP_HDR_CF_AT) &&
          (c == '@'))
        ok = TRUE;
      else if ((flags & HTTP_HDR_CF_UNDERLINE) &&
          (c == '_'))
        ok = TRUE;
      else if ((flags & HTTP_HDR_CF_AND) &&
          (c == '&'))
        ok = TRUE;
      else if ((flags & HTTP_HDR_CF_BACKSLASH) &&
          (c == '\\'))
        ok = TRUE;
      else if ((flags & HTTP_HDR_CF_ASTERIX) &&
          (c == '*'))
        ok = TRUE;
      else if ((flags & HTTP_HDR_CF_DOLLAR) &&
          (c == '$'))
        ok = TRUE;
      else if ((flags & HTTP_HDR_CF_HASHMARK) &&
          (c == '#'))
        ok = TRUE;
      else if ((flags & HTTP_HDR_CF_PLUS) &&
          (c == '+'))
        ok = TRUE;
      else if ((flags & HTTP_HDR_CF_QUOTE) &&
          (c == '"' || c == '\''))
        ok = TRUE;
      else if ((flags & HTTP_HDR_CF_QUESTIONMARK) &&
          (c == '?'))
        ok = TRUE;
      else if ((flags & HTTP_HDR_CF_PERCENT) &&
          (c == '%'))
        ok = TRUE;
      else if ((flags & HTTP_HDR_CF_TILDE) &&
          (c == '~'))
        ok = TRUE;
      else if ((flags & HTTP_HDR_CF_EXCLAM) &&
          (c == '!'))
        ok = TRUE;
      if (!ok)
        {
          *reason = "Invalid character found";
          return FALSE;
        }
    }
  return TRUE;
}

gboolean
http_filter_headers(HttpProxy *self, guint side, HttpHeaderFilter filter)
{
  HttpHeaders *headers = &self->headers[side];
  GHashTable *hash = (side == EP_CLIENT) ? self->request_header_policy : self->response_header_policy;
  gint action;
  GList *l;

  z_proxy_enter(self);
  l = headers->list;
  while (l)
    {
      HttpHeader *h = (HttpHeader *) l->data;
      ZPolicyObj *f;

      if (filter)
	action = filter(self, h->name, h->value);
      else
	action = HTTP_HDR_ACCEPT;

      g_string_assign_len(self->current_header_name, h->name->str, h->name->len);
      g_string_assign_len(self->current_header_value, h->value->str, h->value->len);

      f = g_hash_table_lookup(hash, self->current_header_name->str);
      if (!f)
	f = g_hash_table_lookup(hash, "*");
      if (f)
	{
	  guint filter_type;
	  ZPolicyObj *handler, *res;
	  gchar *name, *value;
	  
	  z_policy_lock(self->super.thread);
	  if (!z_policy_tuple_get_verdict(f, &filter_type))
	    {
	      /* filter has no type field */
	      z_policy_unlock(self->super.thread);
	      z_proxy_return(self, FALSE);
	    }
	  z_policy_unlock(self->super.thread);
	  switch (filter_type)
	    {
	    case HTTP_HDR_POLICY:
	      z_policy_lock(self->super.thread);
	      if (!z_policy_var_parse(f, "(iO)", &filter_type, &handler))
		{
		  /* error parsing HTTP_POLICY_CALL rule */
                  z_policy_unlock(self->super.thread);
		  z_proxy_return(self, FALSE);
		}
	      res = z_policy_call_object(handler, 
					 z_policy_var_build("(s#s#)", 
							    h->name->str, h->name->len, 
							    h->value->str, h->value->len),
					 self->super.session_id);
	      if (!z_policy_var_parse(res, "i", &action))
		{
		  /*LOG
		    This message indicates that the call-back for the given
		    header was invalid. Check your request_headers and
		    response_headers hashes.
		   */
		  z_proxy_log(self, HTTP_POLICY, 1, "Policy call-back for header returned invalid value; header='%s'", self->current_header_name->str);
		  z_policy_var_unref(res);
		  z_policy_unlock(self->super.thread);
		  z_proxy_return(self, FALSE);
		}
	      z_policy_var_unref(res);
	      z_policy_unlock(self->super.thread);
              g_string_assign_len(h->name, self->current_header_name->str, self->current_header_name->len);
              g_string_assign_len(h->value, self->current_header_value->str, self->current_header_value->len);
	      break;
              
	    case HTTP_HDR_INSERT:
	      /* insert header that already exists */
	      action = HTTP_HDR_ACCEPT;
	      break;
              
	    case HTTP_HDR_ACCEPT:
	      break;
              
	    case HTTP_HDR_REPLACE:
	    case HTTP_HDR_DROP:
	      action = HTTP_HDR_DROP;
	      break;
              
	    case HTTP_HDR_CHANGE_NAME:
	      z_policy_lock(self->super.thread);
	      if (!z_policy_var_parse(f, "(is)", &filter_type, &name))
		{
		  /* invalid CHANGE_NAME rule */
		  /*LOG
		    This message indicates that the HDR_CHANGE_NAME
		    parameter is invalid, for the given header.  Check your
		    request_headers and response_headers hashes.
		   */
		  z_proxy_log(self, HTTP_POLICY, 1, "Invalid HTTP_HDR_CHANGE_NAME rule in header processing; header='%s'", self->current_header_name->str);
		  z_policy_unlock(self->super.thread);
		  z_proxy_return(self, FALSE);
		}
	      g_string_assign(h->name, name);
	      z_policy_unlock(self->super.thread);
	      action = HTTP_HDR_ACCEPT;
	      break;
              
	    case HTTP_HDR_CHANGE_VALUE:
	      z_policy_lock(self->super.thread);
	      if (!z_policy_var_parse(f, "(is)", &filter_type, &value))
		{
		  /* invalid CHANGE_VALUE rule */
		  /*LOG
		    This message indicates that the HDR_CHANGE_VALUE
		    parameter is invalid, for the given header.  Check your
		    request_headers and response_headers hashes.
		   */
		  z_proxy_log(self, HTTP_POLICY, 1, "Invalid HTTP_HDR_CHANGE_VALUE rule in header processing; header='%s'", self->current_header_name->str);
		  z_policy_unlock(self->super.thread);
		  z_proxy_return(self, FALSE);
		}
	      g_string_assign(h->value, value);
	      z_policy_unlock(self->super.thread);
	      action = HTTP_HDR_ACCEPT;
	      break;

	    case HTTP_HDR_CHANGE_BOTH:
	      z_policy_lock(self->super.thread);
	      if (!z_policy_var_parse(f, "(iss)", &filter_type, &name, &value))
		{
		  /* invalid CHANGE_BOTH rule */
		  /*LOG
		    This message indicates that the HDR_CHANGE_BOTH
		    parameter is invalid, for the given header.  Check your
		    request_headers and response_headers hashes.
		   */
		  z_proxy_log(self, HTTP_POLICY, 1, "Invalid HTTP_HDR_CHANGE_BOTH rule in header processing; header='%s'", self->current_header_name->str);
		  z_policy_unlock(self->super.thread);
		  z_proxy_return(self, FALSE);
		}
	      g_string_assign(h->name, name);
	      g_string_assign(h->value, value);
	      z_policy_unlock(self->super.thread);
	      action = HTTP_HDR_ACCEPT;
	      break;

	    case HTTP_HDR_ABORT:
	      action = HTTP_HDR_ABORT;
	      break;
              
	    default:
	      action = HTTP_HDR_ABORT;
	      /*LOG
	        This message indicates that the action is invalid, for the
		given header.  Check your request_headers and
		response_headers hashes.
	       */
	      z_proxy_log(self, HTTP_POLICY, 1, "Invalid value in header action tuple; header='%s', filter_type='%d'",
		  self->current_header_name->str, filter_type);
	      break;
	    }
	}

      if (action == HTTP_HDR_ACCEPT && self->strict_header_checking)
        {
          HttpElementInfo *info;
          const gchar *reason;

          if (side == EP_CLIENT)
            info = http_proto_request_hdr_lookup(h->name->str);
          else
            info = http_proto_response_hdr_lookup(h->name->str);

          if (info)
            {
              if (info->max_len >= 0 && h->value->len > (guint) info->max_len)
                {
                  z_proxy_log(self, HTTP_VIOLATION, 3,
                              "Header failed strict checking, value too long; "
                              "header='%s', value='%s', length='%zd', max_length='%zd'",
                              h->name->str, h->value->str, h->value->len, info->max_len);
                  action = self->strict_header_checking_action;
                  goto exit_check;
                }
              if (!http_check_header_charset(self, h->value->str, info->flags, &reason))
                {
                  z_proxy_log(self, HTTP_VIOLATION, 3,
                              "Header failed strict checking, it contains invalid characters; "
                              "header='%s', value='%s', reason='%s'",
                              h->name->str, h->value->str, reason);
                  action = self->strict_header_checking_action;
                  goto exit_check;
                }
            exit_check:
              ;
            }
          else
            {
              z_proxy_log(self, HTTP_VIOLATION, 3,
                          "Header failed strict checking, it is unknown; header='%s', value='%s'",
                          h->name->str, h->value->str);
              action = self->strict_header_checking_action;
            }
        }

      switch (action)
	{
	case HTTP_HDR_ACCEPT:
	  break;
          
	case HTTP_HDR_DROP:
	  h->present = FALSE;
	  break;

	default:
	  self->error_code = HTTP_MSG_POLICY_VIOLATION;
	  z_proxy_return(self, FALSE);
	}
      l = g_list_next(l);

    }

  z_policy_lock(self->super.thread);
  g_hash_table_foreach(hash, (GHFunc) http_insert_headers, headers);
  z_policy_unlock(self->super.thread);
  z_proxy_return(self, TRUE);
}

gboolean
http_fetch_headers(HttpProxy *self, int side)
{
  HttpHeaders *headers = &self->headers[side];
  gchar *line;
  GIOStatus res;
  gsize line_length;
  guint count = 0;
  HttpHeader *last_hdr = NULL;

  z_proxy_enter(self);
  http_clear_headers(headers);
  /* check if we have to fetch request headers */
  if (self->proto_version[side] < 0x0100)
    z_proxy_return(self, TRUE);
  
  while (1)
    {
      gchar *colon, *value, c;
      guint name_len;
      
      res = z_stream_line_get(self->super.endpoints[side], &line, &line_length, NULL);
      if (res != G_IO_STATUS_NORMAL)
        {
          if (res == G_IO_STATUS_EOF && side == EP_SERVER && self->permit_null_response)
            break;
	  /*LOG
	    This message indicates that Zorp was unable to fetch headers
	    from the server.  Check the permit_null_response attribute.
	   */
          z_proxy_log(self, HTTP_ERROR, 3, "Error reading from peer while fetching headers;");
	  z_proxy_return(self, FALSE);
	}
      if (line_length == 0)
        break;

      if (*line == ' ' || *line == '\t')
        {
          /* continuation line */
          /* skip whitespace */
          while (line_length && (*line == ' ' || *line == '\t'))
            {
              line++;
              line_length--;
            }
          if (last_hdr) 
            {
              g_string_append_len(last_hdr->value, line, line_length);
            }
          else
            {
              /* first line is a continuation line? bad */
	      /*LOG
	       	This message indicates that Zorp fetched an invalid header from the server.
		It is likely caused by a buggy server.
	       */
              z_proxy_log(self, HTTP_VIOLATION, 2, "First header starts with white space; line='%.*s", (gint) line_length, line);
              z_proxy_return(self, FALSE);
            }
          goto next_header;
        }

      name_len = 0;
      c = line[name_len];
      while (name_len < line_length &&
             !(c == '(' || c == ')' || c == '<' || c == '>' || c == '@' ||
               c == ',' || c == ';' || c == ':' || c == '\\' || c == '"' ||
               c == '/' || c == '[' || c == ']' || c == '?' || c == '=' ||
               c == '{' || c == '}' || c == ' ' || c == '\t'))
        {
          name_len++;
          c = line[name_len];
        }

      for (colon = &line[name_len]; (guint) (colon - line) < line_length && *colon == ' ' && *colon != ':'; colon++)
        ;
      if (*colon != ':')
        {
	  /*LOG
	    This message indicates that the server sent an invalid HTTP
	    header.
	   */
          z_proxy_log(self, HTTP_VIOLATION, 2, "Invalid HTTP header; line='%.*s'", (gint) line_length, line);
          if (self->strict_header_checking)
            z_proxy_return(self, FALSE);

          goto next_header;
        }
      /* strip trailing white space */
      while (line_length > 0 && line[line_length - 1] == ' ') 
        line_length--;

      for (value = colon + 1; (guint) (value - line) < line_length && *value == ' '; value++)
        ;

      last_hdr = http_add_header(headers, line, name_len, value, &line[line_length] - value);

    next_header:
      count++;
      if (count > self->max_header_lines)
        {
          /* too many headers */
	  /*LOG
	    This message indicates that the server tried to send more header
	    lines, than the allowed maximum.  Check the max_header_lines
	    attribute.
	   */
          z_proxy_log(self, HTTP_POLICY, 2, "Too many header lines; max_header_lines='%d'", self->max_header_lines);
          z_proxy_return(self, FALSE);
        }
    }
  /*  g_string_append(headers, "\r\n"); */
  http_log_headers(self, side, "prefilter");
  z_proxy_return(self, TRUE);
}

gboolean
http_flat_headers_into(HttpHeaders *hdrs, GString *into)
{
  GList *l = g_list_last(hdrs->list);

  g_string_truncate(into, 0);
  while (l)
    {
      if (((HttpHeader *) l->data)->present)
        {
          g_string_append_len(into, ((HttpHeader *) l->data)->name->str, ((HttpHeader *) l->data)->name->len);
          g_string_append_len(into, ": ", 2);
          g_string_append_len(into, ((HttpHeader *) l->data)->value->str, ((HttpHeader *) l->data)->value->len);
          g_string_append_len(into, "\r\n", 2);
        }
      l = g_list_previous(l);
    }

  return TRUE;
}

gboolean
http_flat_headers(HttpHeaders *hdrs)
{
  return http_flat_headers_into(hdrs, hdrs->flat);
}

void
http_init_headers(HttpHeaders *hdrs)
{
  hdrs->hash = g_hash_table_new(http_header_hash, http_header_equal);
  hdrs->flat = g_string_sized_new(256);
}

void
http_destroy_headers(HttpHeaders *hdrs)
{
  http_clear_headers(hdrs);
  g_hash_table_destroy(hdrs->hash);
  g_string_free(hdrs->flat, TRUE);
}

enum
{
  HTTP_COOKIE_NAME,
  HTTP_COOKIE_VALUE,
  HTTP_COOKIE_DOTCOMA
} HttpCookieState;

GHashTable *
http_parse_header_cookie(HttpHeaders *hdrs)
{
  GHashTable *cookie_hash = g_hash_table_new_full(g_str_hash, g_str_equal, g_free, g_free);
  HttpHeader *hdr;
  if (http_lookup_header(hdrs, "Cookie", &hdr))
    {
      gint state = HTTP_COOKIE_NAME;
      gchar key[256];
      guint key_pos = 0;
      gchar value[4096];
      guint value_pos = 0;
      gint i = 0;
      gchar *hdr_str = hdr->value->str;

      while (hdr_str[i])
        {
          switch(state)
            {
            case HTTP_COOKIE_NAME:
              if (hdr_str[i] == '=')
                {
                  key[key_pos] = 0;
                  state = HTTP_COOKIE_VALUE;
                }
              else
                {
                  key[key_pos++] = hdr_str[i];
                }
              if (key_pos > sizeof(key))
                {
                  goto exit_error;
                }
              break;
            case HTTP_COOKIE_VALUE:
              if (hdr_str[i] == ';')
                {
                  state = HTTP_COOKIE_DOTCOMA;
                }
              else
                {
                  value[value_pos++] = hdr_str[i];
                }
              if (value_pos > sizeof(value))
                {
                  goto exit_error;
                }
              break;
            case HTTP_COOKIE_DOTCOMA:
              if (hdr_str[i] != ' ' &&
                  hdr_str[i] != '\r' &&
                  hdr_str[i] != '\n' &&
                  hdr_str[i] != '\t')
                {
                  if (hdr_str[i] == '$' && FALSE)
                    {
                      value[value_pos++] = hdr_str[i];
                      if (value_pos > sizeof(value))
                        {
                          goto exit_error;
                        }
                      state = HTTP_COOKIE_VALUE;
                    }
                  else
                    {
                      value[value_pos] = 0;
                      g_hash_table_insert(cookie_hash, g_strdup(key), g_strdup(value));
                      key_pos = value_pos = 0;
                      key[key_pos++] = hdr_str[i];
                      state = HTTP_COOKIE_NAME;
                    }
                }
            }
          i++;
        }
      if (key_pos && value_pos)
        {
          value[value_pos] = 0;
          g_hash_table_insert(cookie_hash, g_strdup(key), g_strdup(value));
          key_pos = value_pos = 0;
        }
      goto exit;
    }
exit_error:
  g_hash_table_destroy(cookie_hash);
  cookie_hash = NULL;
exit:

  return cookie_hash;
}
