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
 * $Id: http.c,v 1.175 2004/07/26 11:45:57 bazsi Exp $
 * 
 * Author: Balazs Scheidler <bazsi@balabit.hu>
 * Auditor: 
 * Last audited version: 
 * Notes:
 *   Slightly based on the code by: Viktor Peter Kovacs <vps__@freemail.hu>
 *   
 ***************************************************************************/

#include "http.h"

#include <zorp/thread.h>
#include <zorp/registry.h>
#include <zorp/log.h>
#include <zorp/policy.h>
#include <zorp/authprovider.h>
#include <zorp/misc.h>
#include <zorp/policy.h>
#include <zorp/code_base64.h>
#include <zorp/streamblob.h>
#include <zorp/streamline.h>
#include <zorp/random.h>
#include <zorp/code.h>
#include <zorp/code_base64.h>
#include <zorp/bllookup.h>

#include <zorp/proxy/errorloader.h>

#include <ctype.h>
#include <sys/socket.h>
#include <unistd.h>
#include <fcntl.h>

#include <netdb.h>
static GHashTable *auth_hash = NULL;
static GMutex *auth_mutex = NULL;

typedef struct _ZorpAuthInfo
{
  time_t last_auth_time;
  time_t accept_credit;
  time_t create_time;
} ZorpAuthInfo;

/**
 * http_filter_hash_compare:
 * @a: first item
 * @b: second item
 * 
 * This function is the hash compare function for request header hashes.
 **/
gint
http_filter_hash_compare(gconstpointer a, gconstpointer b)
{
  z_enter();
  if (strcasecmp((char *) a, (char *) b) == 0)
    z_return(1);

  z_return(0);
}

/**
 * http_filter_hash_bucket:
 * @a: item to calculate hash value for
 * 
 * This function is the hash calculation function for request header hashes.
 **/
gint
http_filter_hash_bucket(gconstpointer a)
{
  int sum = 0;
  char *s = (char *) a;

  z_enter();
  while (*s != 0)
    {
      sum += toupper(*s);     
      s++;
    }
  z_return(sum % 16);
}

/**
 * http_config_set_defaults:
 * @self: HttpProxy instance
 *
 * This function initializes various attributes exported to the Python layer
 * for possible modification.
 **/
static void
http_config_set_defaults(HttpProxy *self)
{
  z_proxy_enter(self);
  self->connection_mode = HTTP_CONNECTION_CLOSE;
  self->server_connection_mode = HTTP_CONNECTION_CLOSE;
  self->force_reconnect = FALSE;
  self->transparent_mode = TRUE;
  self->permit_server_requests = TRUE;
  self->permit_proxy_requests = FALSE;
  self->permit_unicode_url = FALSE;
  self->permit_http09_responses = TRUE;

  self->rewrite_host_header = TRUE;
  self->require_host_header = TRUE;
  self->strict_header_checking = FALSE;
  self->strict_header_checking_action = Z_DROP;
  self->permit_null_response = TRUE;
  self->max_line_length = 4096;
  self->max_url_length = 4096;
  self->max_header_lines = 50;
  self->max_hostname_length = 256;
  self->max_chunk_length = 0;
  self->timeout_request = 10000;
  self->timeout_response = 300000;
  self->timeout = 300000;
  self->default_http_port = 80;
  self->default_ftp_port = 21;
  self->use_default_port_in_transparent_mode = TRUE;
  self->use_canonicalized_urls = TRUE;
  self->max_body_length = 0;
  self->buffer_size = 1500;
  self->rerequest_attempts = 0;

  http_init_headers(&self->headers[EP_CLIENT]);
  http_init_headers(&self->headers[EP_SERVER]);

  http_init_url(&self->request_url_parts);
  self->request_url = g_string_sized_new(128);

  self->current_header_name = g_string_sized_new(16);
  self->current_header_value = g_string_sized_new(32);

  self->parent_proxy = g_string_sized_new(0);
  self->parent_proxy_port = 3128;

  self->target_port_range = g_string_new("80,443");
  self->auth_header_value = g_string_sized_new(32);

  self->remote_server = g_string_sized_new(32);
  self->connected_server = g_string_sized_new(32);
  self->request_method = g_string_sized_new(16);
  self->response_msg = g_string_sized_new(32);

  self->request_method_policy =
    g_hash_table_new((GHashFunc) http_filter_hash_bucket,
                     (GCompareFunc) http_filter_hash_compare);
  self->request_header_policy =
    g_hash_table_new((GHashFunc) http_filter_hash_bucket,
                     (GCompareFunc) http_filter_hash_compare);

  self->response_policy = 
    z_dim_hash_table_new(1, 2, DIMHASH_WILDCARD, DIMHASH_CONSUME);
  self->response_header_policy =
    g_hash_table_new((GHashFunc) http_filter_hash_bucket,
                     (GCompareFunc) http_filter_hash_compare);

  self->error_info = g_string_sized_new(0);
  self->error_msg = g_string_sized_new(0);
  self->error_headers = g_string_sized_new(0);
  self->error_code = -1;
  self->error_status = 500;
  self->error_files_directory = g_string_sized_new(0);

  self->error_silent = FALSE;
  
  self->max_auth_time = 0;

  self->auth_realm = g_string_new("Zorp HTTP auth");
  self->old_auth_header = g_string_sized_new(0);
  self->auth_by_cookie = FALSE;


  self->request_categories = NULL;

  z_proxy_return(self);

}

/**
 * http_config_init:
 * @self: HttpProxy instance
 *
 * This function is called right after the config() method to initialize
 * settings the Python layer specified for us. 
 **/
static void
http_config_init(HttpProxy *self)
{
  z_proxy_enter(self);
  if (self->max_line_length > HTTP_MAX_LINE)
    self->max_line_length = HTTP_MAX_LINE;
  self->super.endpoints[EP_CLIENT]->timeout = self->timeout_request;
  self->poll = z_poll_new();
  z_proxy_return(self);
}

/**
 * http_query_request_url:
 * @self: HttpProxy instance
 * @name: name of requested variable
 * @value: unused
 *
 * This function is registered as a Z_VAR_TYPE_CUSTOM get handler, e.g. it
 * is called whenever one of the request_url_* attributes are requested from
 * Python. Instead of presetting those attributes before calling into Python
 * we calculate their value dynamically.
 **/
static ZPolicyObj *
http_query_request_url(HttpProxy *self, gchar *name, gpointer value G_GNUC_UNUSED)
{
  ZPolicyObj *res = NULL;

  z_proxy_enter(self);
  if (strcmp(name, "request_url") == 0)
    res = z_policy_var_build("s#", self->request_url->str, self->request_url->len);
  else if (strcmp(name, "request_url_proto") == 0 || strcmp(name, "request_url_scheme") == 0)
    res = z_policy_var_build("s#", self->request_url_parts.scheme->str, self->request_url_parts.scheme->len);
  else if (strcmp(name, "request_url_username") == 0)
    res = z_policy_var_build("s#", self->request_url_parts.user->str, self->request_url_parts.user->len);
  else if (strcmp(name, "request_url_passwd") == 0)
    res = z_policy_var_build("s#", self->request_url_parts.passwd->str, self->request_url_parts.passwd->len);
  else if (strcmp(name, "request_url_host") == 0)
    res = z_policy_var_build("s#", self->request_url_parts.host->str, self->request_url_parts.host->len);
  else if (strcmp(name, "request_url_port") == 0)
    res = z_policy_var_build("i", self->request_url_parts.port ? self->request_url_parts.port : self->default_http_port);
  else if (strcmp(name, "request_url_file") == 0)
    res = z_policy_var_build("s#", self->request_url_parts.file->str, self->request_url_parts.file->len);
  else if (strcmp(name, "request_url_query") == 0)
    res = z_policy_var_build("s#", self->request_url_parts.query->str, self->request_url_parts.query->len);
  else
    PyErr_SetString(PyExc_AttributeError, "Unknown attribute");
  z_proxy_return(self, res);
}

/**
 * http_set_request_url:
 * @self: HttpProxy instance
 * @name: name of requested variable
 * @value: unused
 * @new: new value for attribute
 *
 * This function is registered as a Z_VAR_TYPE_CUSTOM set handler, e.g. it
 * is called whenever the request_url attribute are changed from Python.
 * We need to reparse the URL in these cases.
 **/
static gint
http_set_request_url(HttpProxy *self, gchar *name G_GNUC_UNUSED, gpointer value G_GNUC_UNUSED, PyObject *new)
{
  z_proxy_enter(self);
  if (strcmp(name, "request_url") == 0)
    {
      gchar *str;
      const gchar *reason;

      if (!PyArg_Parse(new, "s", &str))
        z_proxy_return(self, -1);

      if (!http_parse_url(&self->request_url_parts, self->permit_unicode_url,
                          self->permit_invalid_hex_escape, FALSE, str, &reason))
        {
          z_proxy_log(self, HTTP_ERROR, 2, "Policy tried to force an invalid URL; url='%s', reason='%s'", str, reason);
          z_policy_raise_exception_obj(z_policy_exc_value_error, "Invalid URL.");
          z_proxy_return(self, 0);
        }

      if (!http_format_url(&self->request_url_parts, self->request_url, TRUE, self->permit_unicode_url, TRUE, &reason))
        {
          z_proxy_log(self, HTTP_ERROR, 2, "Error canonicalizing URL; url='%s', reason='%s'", str, reason);
          z_policy_raise_exception_obj(z_policy_exc_value_error, "Invalid URL.");
          z_proxy_return(self, -1);
        }
      z_proxy_return(self, 0);
    }
  z_policy_raise_exception_obj(z_policy_exc_attribute_error, "Can only set request_url");
  z_proxy_return(self, -1);
}

/**
 * http_query_mime_type:
 * @self: HttpProxy instance
 * @name: name of requested variable
 * @value: unused
 *
 * This function is registered as a Z_VAR_TYPE_CUSTOM get handler, e.g. it
 * is called whenever one of the request_mime_type or response_mime_type
 * attributes are requested from Python. Instead of presetting those
 * attributes before calling into Python we calculate their value
 * dynamically.
 **/
static ZPolicyObj *
http_query_mime_type(HttpProxy *self, gchar *name, gpointer value G_GNUC_UNUSED)
{
  ZPolicyObj *res = NULL;
  HttpHeader *hdr;
  gboolean success;

  z_proxy_enter(self);
  if (strcmp(name, "request_mime_type") == 0)
    {
      success = http_lookup_header(&self->headers[EP_CLIENT], "Content-Type", &hdr);
    }
  else if (strcmp(name, "response_mime_type") == 0)
    {
      success = http_lookup_header(&self->headers[EP_SERVER], "Content-Type", &hdr);
    }
  else
    {
      PyErr_SetString(PyExc_AttributeError, "Unknown attribute");
      z_proxy_return(self, NULL);
    }

  if (!success || !hdr)
    {
      res = PyString_FromString("");
    }
  else
    {
      gchar *start, *end;

      start = hdr->value->str;
      while (*start == ' ')
        start++;
      end = strchr(hdr->value->str, ';');
      if (end)
        {
          end--;
          while (end > start && *end == ' ')
            end--;
        }
      if (end)
        res = PyString_FromStringAndSize(hdr->value->str, (end - start + 1));
      else
        res = PyString_FromString(hdr->value->str);
    }
  z_proxy_return(self, res);
}

static ZPolicyObj *
http_policy_header_manip(HttpProxy *self, ZPolicyObj *args)
{
  gint action, side;
  gchar *header, *new_value = NULL;
  HttpHeader *p = NULL;
  ZPolicyObj *res = NULL;

  z_proxy_enter(self);
  if (!z_policy_var_parse_tuple(args, "iis|s", &action, &side, &header, &new_value))
    goto error;

  side &= 1;
  switch (action)
    {
    case 0:
      /* get */
      if (http_lookup_header(&self->headers[side], header, &p))
        {
          res = z_policy_var_build("s", p->value->str);
        }
      else
        {
          z_policy_var_ref(z_policy_none);
          res = z_policy_none;
        }
      break;
      
    case 1:
      /* set */
      if (!new_value)
        goto error_set_exc;

      if (!http_lookup_header(&self->headers[side], header, &p))
        p = http_add_header(&self->headers[side], header, strlen(header), new_value, strlen(new_value));
      g_string_assign(p->value, new_value);
      p->present = TRUE;
      z_policy_var_ref(z_policy_none);
      res = z_policy_none;
      break;

    default:
      goto error_set_exc;
    }
  z_proxy_return(self, res);

 error_set_exc:
  z_policy_raise_exception_obj(z_policy_exc_value_error, "Invalid arguments.");

 error:
  z_proxy_return(self, NULL);

}

/**
 * http_register_vars:
 * @self: HttpProxy instance
 *
 * This function is called upon startup to export Python attributes.
 **/
static void
http_register_vars(HttpProxy *self)
{
  z_proxy_enter(self);
  z_proxy_var_new(&self->super, "transparent_mode",
                  Z_VAR_TYPE_INT | Z_VAR_GET | Z_VAR_SET_CONFIG | Z_VAR_GET_CONFIG,
                  &self->transparent_mode);

  z_proxy_var_new(&self->super, "permit_server_requests",
                  Z_VAR_TYPE_INT | Z_VAR_GET | Z_VAR_SET_CONFIG | Z_VAR_GET_CONFIG,
                  &self->permit_server_requests);

  z_proxy_var_new(&self->super, "permit_null_response",
                  Z_VAR_TYPE_INT | Z_VAR_GET | Z_VAR_SET_CONFIG | Z_VAR_GET_CONFIG,
                  &self->permit_null_response);

  z_proxy_var_new(&self->super, "permit_proxy_requests",
                  Z_VAR_TYPE_INT | Z_VAR_GET | Z_VAR_SET_CONFIG | Z_VAR_GET_CONFIG,
                  &self->permit_proxy_requests);

  z_proxy_var_new(&self->super, "permit_unicode_url",
                  Z_VAR_TYPE_INT | Z_VAR_GET | Z_VAR_SET_CONFIG | Z_VAR_GET_CONFIG,
                  &self->permit_unicode_url);

  z_proxy_var_new(&self->super, "permit_invalid_hex_escape",
                  Z_VAR_TYPE_INT | Z_VAR_GET | Z_VAR_SET_CONFIG | Z_VAR_GET_CONFIG,
                  &self->permit_invalid_hex_escape);

  z_proxy_var_new(&self->super, "permit_http09_responses",
                  Z_VAR_TYPE_INT | Z_VAR_GET | Z_VAR_SET_CONFIG | Z_VAR_GET_CONFIG,
                  &self->permit_http09_responses);

  z_proxy_var_new(&self->super, "permit_both_connection_headers",
                  Z_VAR_TYPE_INT | Z_VAR_GET | Z_VAR_SET_CONFIG | Z_VAR_GET_CONFIG,
                  &self->permit_both_connection_headers);

  z_proxy_var_new(&self->super, "permit_ftp_over_http",
                  Z_VAR_TYPE_INT | Z_VAR_GET | Z_VAR_SET_CONFIG | Z_VAR_GET_CONFIG,
                  &self->permit_ftp_over_http);

  /* close or keep-alive */
  z_proxy_var_new(&self->super, "connection_mode", 
                  Z_VAR_TYPE_INT | Z_VAR_GET | Z_VAR_SET,
                  &self->connection_mode);

  z_proxy_var_new(&self->super, "keep_persistent", 
                  Z_VAR_TYPE_INT | Z_VAR_GET_CONFIG | Z_VAR_SET_CONFIG | Z_VAR_GET,
                  &self->keep_persistent);

  /* string containing parent proxy */
  z_proxy_var_new(&self->super, "parent_proxy",
                  Z_VAR_TYPE_STRING | Z_VAR_GET | Z_VAR_SET | Z_VAR_SET_CONFIG | Z_VAR_GET_CONFIG,
                  self->parent_proxy);

  /* parent proxy port */
  z_proxy_var_new(&self->super, "parent_proxy_port",
                  Z_VAR_TYPE_INT | Z_VAR_GET | Z_VAR_SET | Z_VAR_SET_CONFIG | Z_VAR_GET_CONFIG,
                  &self->parent_proxy_port);

  /* default port if portnumber is not specified in urls */
  z_proxy_var_new(&self->super, "default_port",
                  Z_VAR_TYPE_ALIAS | Z_VAR_GET | Z_VAR_SET | Z_VAR_SET_CONFIG | Z_VAR_GET_CONFIG,
                  "default_http_port");

  z_proxy_var_new(&self->super, "use_default_port_in_transparent_mode",
                  Z_VAR_TYPE_INT | Z_VAR_GET | Z_VAR_SET_CONFIG | Z_VAR_GET_CONFIG,
                  &self->use_default_port_in_transparent_mode);

  z_proxy_var_new(&self->super, "use_canonicalized_urls",
                  Z_VAR_TYPE_INT | Z_VAR_GET | Z_VAR_SET | Z_VAR_SET_CONFIG | Z_VAR_GET_CONFIG,
                  &self->use_canonicalized_urls);

  z_proxy_var_new(&self->super, "default_http_port",
                  Z_VAR_TYPE_INT | Z_VAR_GET | Z_VAR_SET | Z_VAR_SET_CONFIG | Z_VAR_GET_CONFIG,
                  &self->default_http_port);

  z_proxy_var_new(&self->super, "default_ftp_port",
                  Z_VAR_TYPE_INT | Z_VAR_GET | Z_VAR_SET | Z_VAR_SET_CONFIG | Z_VAR_GET_CONFIG,
                  &self->default_ftp_port);

  /* rewrite host header when redirecting */
  z_proxy_var_new(&self->super, "rewrite_host_header",
                  Z_VAR_TYPE_INT | Z_VAR_GET | Z_VAR_SET | Z_VAR_SET_CONFIG | Z_VAR_GET_CONFIG,
                  &self->rewrite_host_header);

  z_proxy_var_new(&self->super, "reset_on_close",
                  Z_VAR_TYPE_INT | Z_VAR_GET | Z_VAR_SET | Z_VAR_SET_CONFIG | Z_VAR_GET_CONFIG,
                  &self->reset_on_close);

  /* require host header */
  z_proxy_var_new(&self->super, "require_host_header",
                  Z_VAR_TYPE_INT | Z_VAR_GET | Z_VAR_SET_CONFIG | Z_VAR_GET_CONFIG,
                  &self->require_host_header);

  /* enable strict header checking */
  z_proxy_var_new(&self->super, "strict_header_checking",
                  Z_VAR_TYPE_INT | Z_VAR_GET | Z_VAR_SET_CONFIG | Z_VAR_GET_CONFIG,
                  &self->strict_header_checking);

  /* enable strict header checking */
  z_proxy_var_new(&self->super, "strict_header_checking_action",
                  Z_VAR_TYPE_INT | Z_VAR_GET | Z_VAR_SET_CONFIG | Z_VAR_GET_CONFIG,
                  &self->strict_header_checking_action);

  /* integer */
  z_proxy_var_new(&self->super, "max_line_length",
                  Z_VAR_TYPE_INT | Z_VAR_GET | Z_VAR_SET_CONFIG | Z_VAR_GET_CONFIG,
                  &self->max_line_length);

  /* integer */
  z_proxy_var_new(&self->super, "max_url_length",
                  Z_VAR_TYPE_INT | Z_VAR_GET | Z_VAR_SET | Z_VAR_SET_CONFIG | Z_VAR_GET_CONFIG,
                  &self->max_url_length);

  /* integer */
  z_proxy_var_new(&self->super, "max_hostname_length",
                  Z_VAR_TYPE_INT | Z_VAR_GET | Z_VAR_SET | Z_VAR_SET_CONFIG | Z_VAR_GET_CONFIG,
                  &self->max_hostname_length);

  /* integer */
  z_proxy_var_new(&self->super, "max_header_lines",
                  Z_VAR_TYPE_INT | Z_VAR_GET | Z_VAR_SET | Z_VAR_SET_CONFIG | Z_VAR_GET_CONFIG,
                  &self->max_header_lines);

  /* integer */
  z_proxy_var_new(&self->super, "max_keepalive_requests",
                  Z_VAR_TYPE_INT | Z_VAR_GET | Z_VAR_SET | Z_VAR_SET_CONFIG | Z_VAR_GET_CONFIG,
                  &self->max_keepalive_requests);

  /* integer */
  z_proxy_var_new(&self->super, "max_body_length",
                  Z_VAR_TYPE_INT | Z_VAR_GET | Z_VAR_SET | Z_VAR_SET_CONFIG | Z_VAR_GET_CONFIG,
                  &self->max_body_length);

  /* integer */
  z_proxy_var_new(&self->super, "max_chunk_length",
                  Z_VAR_TYPE_INT | Z_VAR_GET | Z_VAR_SET | Z_VAR_SET_CONFIG | Z_VAR_GET_CONFIG,
                  &self->max_chunk_length);

  /* integer */
  z_proxy_var_new(&self->super, "request_count",
                  Z_VAR_TYPE_INT | Z_VAR_GET,
                  &self->request_count);

  /* timeout value in milliseconds */
  z_proxy_var_new(&self->super, "timeout", 
                  Z_VAR_TYPE_INT | Z_VAR_GET | Z_VAR_SET | Z_VAR_SET_CONFIG | Z_VAR_GET_CONFIG,
                  &self->timeout);

  /* timeout value in milliseconds */
  z_proxy_var_new(&self->super, "buffer_size", 
                  Z_VAR_TYPE_INT | Z_VAR_GET | Z_VAR_SET_CONFIG | Z_VAR_GET_CONFIG,
                  &self->buffer_size);

  /* timeout value in milliseconds */
  z_proxy_var_new(&self->super, "timeout_request", 
                  Z_VAR_TYPE_INT | Z_VAR_GET | Z_VAR_SET | Z_VAR_GET_CONFIG | Z_VAR_SET_CONFIG,
                  &self->timeout_request);

  /* timeout value in milliseconds */
  z_proxy_var_new(&self->super, "timeout_response", 
		  Z_VAR_TYPE_INT | Z_VAR_GET | Z_VAR_SET | Z_VAR_GET_CONFIG | Z_VAR_SET_CONFIG,
                  &self->timeout_response);

  /* number of rerequest attempts */
  z_proxy_var_new(&self->super, "rerequest_attempts", 
		  Z_VAR_TYPE_INT | Z_VAR_GET | Z_VAR_SET | Z_VAR_GET_CONFIG | Z_VAR_SET_CONFIG,
                  &self->rerequest_attempts);

  /* timeout value in milliseconds */
  z_proxy_var_new(&self->super, "timeout_response", 
		  Z_VAR_TYPE_INT | Z_VAR_GET | Z_VAR_SET | Z_VAR_GET_CONFIG | Z_VAR_SET_CONFIG,
                  &self->timeout_response);

  /* hash indexed by request method */
  z_proxy_var_new(&self->super, "request",
                  Z_VAR_TYPE_HASH | Z_VAR_GET | Z_VAR_GET_CONFIG,
                  self->request_method_policy);

  /* hash indexed by header name */
  z_proxy_var_new(&self->super, "request_header",
                  Z_VAR_TYPE_HASH | Z_VAR_GET | Z_VAR_GET_CONFIG,
                  self->request_header_policy);

  /* hash indexed by response code */
  z_proxy_var_new(&self->super, "response",
                  Z_VAR_TYPE_DIMHASH | Z_VAR_GET | Z_VAR_GET_CONFIG,
                  self->response_policy);

  /* hash indexed by header name */
  z_proxy_var_new(&self->super, "response_header",
                  Z_VAR_TYPE_HASH | Z_VAR_GET | Z_VAR_GET_CONFIG,
                  self->response_header_policy);

  /* header manipulation */
  z_proxy_var_new(&self->super, "_AbstractHttpProxy__headerManip",
                  Z_VAR_TYPE_METHOD | Z_VAR_GET,
                  self, http_policy_header_manip);

  /* string containing current url proto */
  z_proxy_var_new(&self->super, "request_method",
                  Z_VAR_TYPE_STRING | Z_VAR_GET,
                  self->request_method);

  /* string containing current url */
  z_proxy_var_new(&self->super, "request_url",
                  Z_VAR_TYPE_CUSTOM | Z_VAR_GET | Z_VAR_SET,
                  NULL, http_query_request_url, http_set_request_url, NULL);

  /* string containing current url proto */
  z_proxy_var_new(&self->super, "request_url_proto",
                  Z_VAR_TYPE_CUSTOM | Z_VAR_GET,
                  NULL, http_query_request_url, NULL, NULL);

  /* string containing current url proto */
  z_proxy_var_new(&self->super, "request_url_scheme",
                  Z_VAR_TYPE_CUSTOM | Z_VAR_GET,
                  NULL, http_query_request_url, NULL, NULL);

  /* string containing current url username */
  z_proxy_var_new(&self->super, "request_url_username",
                  Z_VAR_TYPE_CUSTOM | Z_VAR_GET,
                  NULL, http_query_request_url, NULL, NULL);

  /* string containing current url passwd */
  z_proxy_var_new(&self->super, "request_url_passwd",
                  Z_VAR_TYPE_CUSTOM | Z_VAR_GET,
                  NULL, http_query_request_url, NULL, NULL);

  /* string containing current url hostname */
  z_proxy_var_new(&self->super, "request_url_host",
                  Z_VAR_TYPE_CUSTOM | Z_VAR_GET,
                  NULL, http_query_request_url, NULL, NULL);

  /* string containing current url port */
  z_proxy_var_new(&self->super, "request_url_port",
                  Z_VAR_TYPE_CUSTOM | Z_VAR_GET,
                  NULL, http_query_request_url, NULL, NULL);

  /* string containing current url file */
  z_proxy_var_new(&self->super, "request_url_file",
                  Z_VAR_TYPE_CUSTOM | Z_VAR_GET,
                  NULL, http_query_request_url, NULL, NULL);

  /* string containing current url query */
  z_proxy_var_new(&self->super, "request_url_query",
                  Z_VAR_TYPE_CUSTOM | Z_VAR_GET,
                  NULL, http_query_request_url, NULL, NULL);

  /* string containing current url fragment */
  z_proxy_var_new(&self->super, "request_url_fragment",
                  Z_VAR_TYPE_CUSTOM | Z_VAR_GET,
                  NULL, http_query_request_url, NULL, NULL);

  /* string containing request mime type */
  z_proxy_var_new(&self->super, "request_mime_type",
                  Z_VAR_TYPE_CUSTOM | Z_VAR_GET,
                  NULL, http_query_mime_type, NULL, NULL);

  /* string containing response mime type */
  z_proxy_var_new(&self->super, "response_mime_type",
                  Z_VAR_TYPE_CUSTOM | Z_VAR_GET,
                  NULL, http_query_mime_type, NULL, NULL);

  /* string containing current header name */
  z_proxy_var_new(&self->super, "current_header_name",
                  Z_VAR_TYPE_STRING | Z_VAR_GET | Z_VAR_SET,
                  self->current_header_name);

  /* string containing current header value */
  z_proxy_var_new(&self->super, "current_header_value",
                  Z_VAR_TYPE_STRING | Z_VAR_GET | Z_VAR_SET,
                  self->current_header_value);

  /* error response */
  z_proxy_var_new(&self->super, "error_status", 
                  Z_VAR_TYPE_INT | Z_VAR_GET | Z_VAR_SET | Z_VAR_SET_CONFIG | Z_VAR_GET_CONFIG,
                  &self->error_status);

  /* error silence */
  z_proxy_var_new(&self->super, "error_silent", 
                  Z_VAR_TYPE_INT | Z_VAR_GET | Z_VAR_SET | Z_VAR_SET_CONFIG | Z_VAR_GET_CONFIG, 
                  &self->error_silent);

  /* string inserted into error messages */
  z_proxy_var_new(&self->super, "error_info",
                  Z_VAR_TYPE_STRING | Z_VAR_GET | Z_VAR_SET,
                  self->error_info);

  z_proxy_var_new(&self->super, "error_msg",
                  Z_VAR_TYPE_STRING | Z_VAR_GET | Z_VAR_SET,
                  self->error_msg);

  z_proxy_var_new(&self->super, "error_headers",
                  Z_VAR_TYPE_STRING | Z_VAR_GET | Z_VAR_SET,
                  self->error_headers);

  z_proxy_var_new(&self->super, "auth_forward",
                  Z_VAR_TYPE_INT | Z_VAR_GET | Z_VAR_SET | Z_VAR_GET_CONFIG | Z_VAR_SET_CONFIG,
                  &self->auth_forward);

  z_proxy_var_new(&self->super, "auth",
                  Z_VAR_TYPE_OBJECT | Z_VAR_GET | Z_VAR_SET_CONFIG,
                  &self->auth);

  z_proxy_var_new(&self->super, "auth_realm",
                  Z_VAR_TYPE_STRING | Z_VAR_GET | Z_VAR_SET_CONFIG,
                  self->auth_realm);
  
  z_proxy_var_new(&self->super, "max_auth_time",
                  Z_VAR_TYPE_INT | Z_VAR_GET | Z_VAR_SET_CONFIG,
                  &self->max_auth_time);

  z_proxy_var_new(&self->super, "target_port_range", 
                  Z_VAR_TYPE_STRING | Z_VAR_GET | Z_VAR_SET | Z_VAR_GET_CONFIG | Z_VAR_SET_CONFIG, 
                  self->target_port_range);

  z_proxy_var_new(&self->super, "error_files_directory",
                  Z_VAR_TYPE_STRING | Z_VAR_GET | Z_VAR_SET | Z_VAR_GET_CONFIG | Z_VAR_SET_CONFIG,
                  self->error_files_directory);

  /* compatibility with Zorp 0.8.x */
  z_proxy_var_new(&self->super, "transparent_server_requests",
                  Z_VAR_TYPE_ALIAS | Z_VAR_GET | Z_VAR_SET | Z_VAR_SET_CONFIG | Z_VAR_GET_CONFIG,
                  "permit_server_requests");  

  z_proxy_var_new(&self->super, "transparent_proxy_requests",
                  Z_VAR_TYPE_ALIAS | Z_VAR_GET | Z_VAR_SET | Z_VAR_SET_CONFIG | Z_VAR_GET_CONFIG,
                  "permit_proxy_requests");  

  z_proxy_var_new(&self->super, "request_timeout",
                  Z_VAR_TYPE_ALIAS | Z_VAR_GET | Z_VAR_SET | Z_VAR_GET_CONFIG | Z_VAR_SET_CONFIG,
                  "timeout_request");

  z_proxy_var_new(&self->super, "request_headers",
                  Z_VAR_TYPE_ALIAS | Z_VAR_GET | Z_VAR_GET_CONFIG,
                  "request_header");

  z_proxy_var_new(&self->super, "response_headers",
                  Z_VAR_TYPE_ALIAS | Z_VAR_GET | Z_VAR_GET_CONFIG,
                  "response_header");

  z_proxy_var_new(&self->super, "url_proto",
                  Z_VAR_TYPE_ALIAS | Z_VAR_GET,
                  "request_url_proto");

  z_proxy_var_new(&self->super, "url_username",
                  Z_VAR_TYPE_ALIAS | Z_VAR_GET,
                  "request_url_username");

  z_proxy_var_new(&self->super, "url_passwd",
                  Z_VAR_TYPE_ALIAS | Z_VAR_GET,
                  "request_url_passwd");

  z_proxy_var_new(&self->super, "url_host",
                  Z_VAR_TYPE_ALIAS | Z_VAR_GET,
                  "request_url_host");

  z_proxy_var_new(&self->super, "url_port",
                  Z_VAR_TYPE_ALIAS | Z_VAR_GET,
                  "request_url_port");

  z_proxy_var_new(&self->super, "url_file",
                  Z_VAR_TYPE_ALIAS | Z_VAR_GET,
                  "request_url_file");

  z_proxy_var_new(&self->super, "error_response",
                  Z_VAR_TYPE_ALIAS | Z_VAR_GET | Z_VAR_SET,
                  "error_status");

  z_proxy_var_new(&self->super, "auth_by_cookie",
                  Z_VAR_TYPE_INT | Z_VAR_GET | Z_VAR_SET_CONFIG | Z_VAR_GET_CONFIG,
                  &self->auth_by_cookie);

  z_proxy_var_new(&self->super, "auth_cache_time",
                  Z_VAR_TYPE_INT | Z_VAR_GET | Z_VAR_SET_CONFIG | Z_VAR_GET_CONFIG,
                  &self->auth_cache_time);

  z_proxy_var_new(&self->super, "auth_cache_update",
                  Z_VAR_TYPE_INT | Z_VAR_GET | Z_VAR_SET_CONFIG | Z_VAR_GET_CONFIG,
                  &self->auth_cache_update);


  z_proxy_var_new(&self->super, "request_categories",
                  Z_VAR_TYPE_OBJECT | Z_VAR_GET,
                  &self->request_categories);

  z_proxy_return(self);
}

/**
 * http_error_message:
 * @self: HttpProxy instance
 * @response_code: HTTP status code to return
 * @message_code: HTTP message code (one of HTTP_MSG_*)
 * @infomsg: additional information added into error messages
 *
 * This function formats and returns an error page to the client when its
 * request cannot be fulfilled. It switches to non-persistent mode and
 * prepares the proxy for shutdown.
 **/
static gboolean
http_error_message(HttpProxy *self, gint response_code, guint message_code, GString *infomsg)
{
  gchar *messages[] = 
    { 
      NULL, 
      "clientsyntax.html", 
      "serversyntax.html", 
      "policysyntax.html", 
      "policyviolation.html", 
      "invalidurl.html", 
      "connecterror.html", 
      "ioerror.html", 
      "auth.html",
      "clienttimeout.html",
      "servertimeout.html",
      "badcontent.html",
      "ftperror.html",
      "redirect.html"
    };
  gchar response[256], filename[256];
  gchar *error_msg;

  z_proxy_enter(self); 
  if (message_code >= (sizeof(messages) / sizeof(char *)))
    {
      /*LOG
        This message indicates that Zorp caught an invalid error code
        internally. Please report this event to the Zorp QA team (at
        devel@balabit.com).
       */
      z_proxy_log(self, HTTP_ERROR, 2, "Internal error, error code out of range; error_code='%d'", message_code);
      z_proxy_return(self, FALSE);
    }

  if (message_code == 0)
    z_proxy_return(self, TRUE);

  if (self->proto_version[EP_CLIENT] >= 0x0100)
    {
      g_snprintf(response, sizeof(response), "HTTP/1.0 %d %s\r\n", response_code, self->error_msg->len > 0 ? self->error_msg->str : "Error encountered");

      if (http_write(self, EP_CLIENT, response, strlen(response)) != G_IO_STATUS_NORMAL)
        z_proxy_return(self, FALSE); /* error writing error message is already sent by http_write */

      /* FIXME: we should not use self->headers[EP_SERVER] for this purpose */
      g_string_truncate(self->headers[EP_SERVER].flat, 0);
      if (!self->transparent_mode)
        g_string_append(self->headers[EP_SERVER].flat, "Proxy-Connection: close\r\n");
      else
        g_string_append(self->headers[EP_SERVER].flat, "Connection: close\r\n");

      g_string_append(self->headers[EP_SERVER].flat, self->error_headers->str);
      g_string_append(self->headers[EP_SERVER].flat, "Content-Type: text/html\r\n\r\n");
      if (http_write(self, EP_CLIENT, self->headers[EP_SERVER].flat->str, self->headers[EP_SERVER].flat->len) != G_IO_STATUS_NORMAL)
        z_proxy_return(self, FALSE);
    }
    
  if ((self->request_flags & HTTP_REQ_FLG_HEAD))
    z_proxy_return(self, TRUE); /* we are responding to a HEAD request, do not return a body */

  if (self->error_files_directory->len)
    g_snprintf(filename, sizeof(filename), "%s/%s", self->error_files_directory->str, messages[message_code]);
  else
    g_snprintf(filename, sizeof(filename), ZORP_DATADIR "/http/" "%s/%s", self->super.language->str, messages[message_code]);

  if (self->error_silent)
    {
      /*LOG
        This message reports that Zorp would send the given error page to
        the browser, if silent mode would not be enabled. It is likely that
        some protocol/configuration/proxy error occurred.
       */
      z_proxy_log(self, HTTP_DEBUG, 6, "An error occurred, would serve error file, but silent mode is enabled; filename='%s'", filename);
      z_proxy_return(self, FALSE);
    }

  /*LOG
    This message reports that Zorp is sending the given error page to the
    clients browser. It is likely that some protocol/configuration/proxy
    error occurred.
   */
  z_proxy_log(self, HTTP_DEBUG, 6, "An error occurred, serving error file; filename='%s'", filename);
  error_msg = z_error_loader_format_file(filename, infomsg->str, Z_EF_ESCAPE_HTML, NULL, NULL);
  if (error_msg)
    {
      http_write(self, EP_CLIENT, error_msg, strlen(error_msg));
      g_free(error_msg);
    }

  z_proxy_return(self, TRUE);
}

/**
 * http_client_stream_init:
 * @self: HttpProxy instance
 * 
 * This function is called upon startup to initialize our client stream.
 **/
static gboolean
http_client_stream_init(HttpProxy *self)
{
  ZStream *tmpstream;
  z_proxy_enter(self);

  z_proxy_enter(self);
  tmpstream = self->super.endpoints[EP_CLIENT];
  self->super.endpoints[EP_CLIENT] = z_stream_line_new(tmpstream, self->max_line_length, ZRL_EOL_CRLF | ZRL_PARTIAL_READ);
  z_stream_unref(tmpstream);
  /* timeout is initialized after the config event */
  z_proxy_return(self, TRUE);
}

/**
 * http_server_stream_init:
 * @self: HttpProxy instance
 * 
 * This function is called upon startup to initialize our server stream.
 **/
static gboolean
http_server_stream_init(HttpProxy *self)
{
  ZStream *tmpstream;
  z_proxy_enter(self);

  z_proxy_enter(self);
  tmpstream = self->super.endpoints[EP_SERVER];
  self->super.endpoints[EP_SERVER] = z_stream_line_new(tmpstream, self->max_line_length, ZRL_EOL_CRLF | ZRL_PARTIAL_READ);
  z_stream_unref(tmpstream);
  self->super.endpoints[EP_SERVER]->timeout = self->timeout;
  z_proxy_return(self, TRUE);
}

/**
 * http_server_stream_is_initialized:
 * @self: HttpProxy instance
 *
 * This function returns whether or not the server stream has already
 * been initialized. Currently, it just checks if a StreamLine has been
 * pushed onto the stack.
 */
static gboolean
http_server_stream_is_initialized(HttpProxy *self)
{
  gboolean res;

  z_proxy_enter(self);

  res = (z_stream_search_stack(self->super.endpoints[EP_SERVER], G_IO_IN, Z_CLASS(ZStreamLine)) != NULL);

  z_proxy_return(self, res);
}

GIOStatus
http_write(HttpProxy *self, guint side, gchar *buf, size_t buflen)
{
  GIOStatus res;
  gsize bytes_written;

  z_proxy_enter(self);
  if (!self->super.endpoints[side])
    {
      /*LOG
        This message reports that Zorp was about to write to an invalid
        stream. Please report this event to the Zorp QA team (at
        devel@balabit.com).
       */
      z_proxy_log(self, HTTP_ERROR, 1, "Error writing stream, stream is NULL; side='%s'", side == EP_CLIENT ? "client" : "server");
      z_proxy_return(self, G_IO_STATUS_ERROR);
    }
  res = z_stream_write(self->super.endpoints[side], buf, buflen, &bytes_written, NULL);
  if (res != G_IO_STATUS_NORMAL || buflen != bytes_written)
    {
      /* FIXME: move this to a separate function */
      /*LOG
        This message reports that Zorp was unable to write to the given
        stream. It is likely that the peer closed the connection
        unexpectedly.
       */
      z_proxy_log(self, HTTP_ERROR, 1, "Error writing stream; side='%s', res='%x', error='%s'", side == EP_CLIENT ? "client" : "server", res, g_strerror(errno));

      self->error_code = HTTP_MSG_IO_ERROR;
      self->error_status = 502;
      g_string_sprintf(self->error_info, "Error writing to %s (%s)", side == EP_CLIENT ? "client" : "server", g_strerror(errno));
      z_proxy_return(self, G_IO_STATUS_ERROR);
    }
  z_proxy_return(self, res);
}   

static int
http_parse_connection_hdr_value(HttpProxy *self G_GNUC_UNUSED, HttpHeader *hdr)
{
  z_proxy_enter(self);
  if (strcasecmp(hdr->value->str, "keep-alive") == 0)
    z_proxy_return(self, HTTP_CONNECTION_KEEPALIVE);
  else if (strcasecmp(hdr->value->str, "close") == 0)
    z_proxy_return(self, HTTP_CONNECTION_CLOSE);

  z_proxy_log(self, HTTP_ERROR, 4, "Unknown connection header value; value='%s'", hdr->value->str);
  z_proxy_return(self, HTTP_CONNECTION_UNKNOWN);
}

static void
http_assign_connection_hdr_value(HttpProxy *self, GString *value)
{
  z_proxy_enter(self);
  if (self->connection_mode == HTTP_CONNECTION_KEEPALIVE)
    g_string_assign(value, "keep-alive");
  else if (self->connection_mode == HTTP_CONNECTION_CLOSE)
    g_string_assign(value, "close");
  z_proxy_return(self);
}

static inline gboolean
http_parent_proxy_enabled(HttpProxy *self)
{
  return !!self->parent_proxy->len;
}

static gboolean
http_process_base64(gchar *dst, guint dstlen, gchar *src, guint srclen)
{
  ZCode *auth_line;

  z_enter();
  auth_line = z_code_base64_decode_new(0, FALSE);
  if (!z_code_transform(auth_line, src, srclen) ||
      !z_code_finish(auth_line))
    {
      z_code_free(auth_line);
      z_return(FALSE);
    }
  dstlen = z_code_get_result(auth_line, dst, dstlen-1); 
  dst[dstlen] = 0;
  z_code_free(auth_line);
  z_return(TRUE);
}

/* FIXME: optimize header processing a bit (no need to copy hdr into a
   buffer) */
static gboolean
http_process_auth_info(HttpProxy *self, HttpHeader *h, ZorpAuthInfo *auth_info)
{
  gchar userpass[128];
  gchar *p;
  gchar **up;

  z_proxy_enter(self);
  if (self->old_auth_header->len &&
      strcmp(h->value->str, self->old_auth_header->str) == 0)
    z_proxy_return(self, TRUE);

  if (strncmp(h->value->str, "Basic", 5) != 0)
    {
      /*LOG
        This message indicates that the client tried to use the given
        unsupported HTTP authentication. Currently only Basic HTTP
        authentication is supported by Zorp.
       */
      z_proxy_log(self, HTTP_ERROR, 3, "Only Basic authentication is supported; authentication='%s'", h->value->str);
      /* not basic auth */
      z_proxy_return(self, FALSE);
    }

  p = h->value->str + 5;
  while (*p == ' ') 
    p++;

  if (!http_process_base64(userpass, sizeof(userpass), p, strlen(p)))
    {
      /*LOG
        This message indicates that the client sent a malformed 
        username:password field, during the authentication phase.
       */
      z_proxy_log(self, HTTP_VIOLATION, 1, "Invalid base64 encoded username:password pair;");
      z_proxy_return(self, FALSE);
    }

  up = g_strsplit(userpass, ":", 2);
  if (up)
    {
      gboolean res;
      gchar **groups = NULL;

      z_policy_lock(self->super.thread);
      res = z_auth_provider_check_passwd(self->auth, self->super.session_id, up[0], up[1], &groups, &self->super);
      z_policy_unlock(self->super.thread);
      if (res)
        {
          res = z_proxy_user_authenticated(&self->super, up[0], (gchar const **) groups);
          g_string_assign(self->old_auth_header, h->value->str);
          g_mutex_lock(auth_mutex);
          if (self->auth_cache_time > 0)
            {
              auth_info->last_auth_time = time(NULL);
            }
          g_mutex_unlock(auth_mutex);
        }
      g_strfreev(up);
      g_strfreev(groups);
      z_proxy_return(self, res);
    }
  /*LOG
    This message indicates that the username:password field received
    during authentication was malformed.
   */
  z_proxy_log(self, HTTP_VIOLATION, 2, "No colon is found in the decoded username:password pair;");
  z_proxy_return(self, FALSE);
}

static gboolean
http_rewrite_host_header(HttpProxy *self, gchar *host, gint host_len, guint port)
{
  HttpHeader *h;

  z_proxy_enter(self);  
  if (self->rewrite_host_header && http_lookup_header(&self->headers[EP_CLIENT], "Host", &h))
    {
      /* NOTE: the constant 80 below is intentional, if
       * default_port is changed we still have to send
       * correct host header (containing port number)
       */
      if (port != 80 && port != 0)
        g_string_sprintf(h->value, "%.*s:%d", host_len, host, port);
      else
        g_string_sprintf(h->value, "%.*s", host_len, host);
    }
  z_proxy_return(self, TRUE);
}

static gboolean
http_format_request(HttpProxy *self, gboolean stacked, GString *request)
{
  gboolean res = TRUE;
  const gchar *reason;
  GString *url = g_string_sized_new(self->request_url->len);

  z_proxy_enter(self);
  if (self->proto_version[EP_CLIENT] >= 0x0100)
    {
      if (self->request_flags & HTTP_REQ_FLG_CONNECT)
        {
          g_assert(http_parent_proxy_enabled(self));

          http_flat_headers(&self->headers[EP_CLIENT]);
          g_string_sprintf(request, "%s %s %s\r\n%s\r\n",  
                           self->request_method->str, self->request_url->str, self->request_version,
                           self->headers[EP_CLIENT].flat->str);
        }
      else
        {
          if (!stacked)
            {
              http_flat_headers(&self->headers[EP_CLIENT]);

              if (!http_format_url(&self->request_url_parts, url, http_parent_proxy_enabled(self), self->permit_unicode_url, self->use_canonicalized_urls, &reason))
                res = FALSE;
                
#define g_string_append_gstring(r, s) g_string_append_len(r, s->str, s->len)
#define g_string_append_const(r, s) g_string_append_len(r, s, __builtin_strlen(s))

              /* slightly less than a page to make sure it fits on a page even with the malloc overhead */
              g_string_set_size(request, 4000); 
              g_string_truncate(request, 0);
              g_string_append_gstring(request, self->request_method);
              g_string_append_c(request, ' ');
              g_string_append_gstring(request, url);
              g_string_append_c(request, ' ');
              g_string_append(request, self->request_version);
              g_string_append_const(request, "\r\n");
              g_string_append_gstring(request, self->headers[EP_CLIENT].flat);
              g_string_append_const(request, "\r\n");
            }
          else
            {
              http_flat_headers_into(&self->headers[EP_CLIENT], request);
            }
        }
    }
  else
    {
      if (!http_format_url(&self->request_url_parts, url, FALSE, self->permit_unicode_url, self->use_canonicalized_urls, &reason))
        res = FALSE;
      else
        g_string_sprintf(request, "%s %s\r\n", self->request_method->str, url->str);
    }

  if (!res)
    z_proxy_log(self, HTTP_ERROR, 3, "Error reformatting requested URL; url='%s', reason='%s'", self->request_url->str, reason);
  g_string_free(url, TRUE);
  z_proxy_return(self, res);
}

static gboolean
http_format_early_request(HttpProxy *self, gboolean stacked, GString *preamble)
{
  if (stacked)
    return http_format_request(self, stacked, preamble);
  else
    g_string_assign(preamble, "");
  return TRUE;
}

static gboolean
http_fetch_request(HttpProxy *self)
{
  gchar *line;
  gsize line_length;
  gint empty_lines = 0;
  guint res;

  z_proxy_enter(self); 
  /* FIXME: this can probably be removed as http_fetch_header does this */
  http_clear_headers(&self->headers[EP_CLIENT]);
  while (empty_lines < HTTP_MAX_EMPTY_REQUESTS) 
    {
      self->super.endpoints[EP_CLIENT]->timeout = self->timeout_request;
      res = z_stream_line_get(self->super.endpoints[EP_CLIENT], &line, &line_length, NULL);
      self->super.endpoints[EP_CLIENT]->timeout = self->timeout;
      if (res == G_IO_STATUS_EOF)
        {
          self->error_code = HTTP_MSG_OK;
          z_proxy_return(self, FALSE);
        }

      if (res != G_IO_STATUS_NORMAL)
        {
          self->error_code = HTTP_MSG_OK; 
          if (errno == ETIMEDOUT)
            {
              if (self->request_count == 0)
                {
                  self->error_code = HTTP_MSG_CLIENT_TIMEOUT;
                  self->error_status = 408;
                }
            }
          z_proxy_return(self, FALSE);
        }
      if (line_length != 0)
        break;
      empty_lines++;
    }

  if (!http_split_request(self, line, line_length))
    {
      g_string_assign(self->error_info, "Invalid request line.");
      /*LOG
        This message indicates that the client sent an invalid HTTP request
        to the proxy.
       */
      z_proxy_log(self, HTTP_VIOLATION, 2, "Invalid HTTP request received; line='%.*s'", (gint)line_length, line);
      z_proxy_return(self, FALSE);
    }
  self->request_flags = http_proto_request_lookup(self->request_method->str);

  if (!http_parse_version(self, EP_CLIENT, self->request_version))
    z_proxy_return(self, FALSE); /* parse version already logged */

  if (!http_fetch_headers(self, EP_CLIENT))
    z_proxy_return(self, FALSE); /* fetch headers already logged */
  
  if (self->rerequest_attempts > 0)
    {
      HttpHeader *transfer_encoding_hdr, *content_length_hdr;
      gboolean has_data = FALSE;
      
      if (http_lookup_header(&self->headers[EP_CLIENT], "Transfer-Encoding", &transfer_encoding_hdr))
        has_data = TRUE;
        
      if (http_lookup_header(&self->headers[EP_CLIENT], "Content-Length", &content_length_hdr))
        has_data = TRUE;
      self->request_data_stored = TRUE;

      if (self->request_data)
        z_blob_truncate(self->request_data, 0, -1);
      
      if (has_data)
        {
          gchar session_id[MAX_SESSION_ID];
          ZStream *blob_stream;
          gboolean success;
          
          if (!self->request_data)
            self->request_data = z_blob_new(NULL, 0);
            
          g_snprintf(session_id, sizeof(session_id), "%s/post", self->super.session_id);
          blob_stream = z_stream_blob_new(self->request_data, session_id);
          blob_stream->timeout = -1;
          /* fetch data associated with request */
          success = http_data_transfer(self, HTTP_TRANSFER_TO_BLOB, EP_CLIENT, self->super.endpoints[EP_CLIENT], EP_SERVER, blob_stream, FALSE, FALSE, http_format_early_request);
          z_stream_unref(blob_stream);
          if (!success)
            z_proxy_return(self, FALSE);
        }
    }
  z_proxy_return(self, TRUE);
}

static gboolean
http_remove_old_auth(gpointer key G_GNUC_UNUSED, gpointer value, gpointer user_data)
{
  ZorpAuthInfo *real_value = (ZorpAuthInfo *)value;
  time_t max_time = MAX(MAX(real_value->last_auth_time, real_value->accept_credit), real_value->create_time);
  time_t cut_time = GPOINTER_TO_UINT(user_data);

  return max_time < cut_time;
}

static inline gchar *
http_process_create_realm(HttpProxy *self, time_t now, gchar *buf, guint buflen)
{
  if (self->max_auth_time > 0)
    g_snprintf(buf, buflen, "Basic realm=\"%s (id:%x)\"", self->auth_realm->str, (int)now);
  else
    g_snprintf(buf, buflen, "Basic realm=\"%s\"", self->auth_realm->str);
  
  return buf;
}

static gboolean
http_get_client_info(HttpProxy *self, gchar *key, guint key_length)
{
  ZCode *coder;
  guchar raw_key[32];
  gsize pos;
  GHashTable *cookie_hash;
  gchar *our_value;

  cookie_hash = http_parse_header_cookie(&self->headers[EP_CLIENT]);
  if (cookie_hash)
    {
      our_value = g_hash_table_lookup(cookie_hash, "ZorpRealm");
      if (our_value)
        {
          g_strlcpy(key, our_value, key_length);
          goto exit;
        }
    }
  if (!z_random_sequence_get(Z_RANDOM_STRONG, raw_key, sizeof(raw_key)))
    {
      return FALSE;
    }

  coder = z_code_base64_encode_new(256, 255);

  if (coder == NULL)
    {
      return FALSE;
    }

  if (!z_code_transform(coder, raw_key, sizeof(raw_key)) ||
      !z_code_finish(coder))
    {
      return FALSE;
    }
  pos = z_code_get_result(coder, key, key_length - 1);
  key[pos-2] = 0;
exit:
  return TRUE;
}

static gboolean
http_check_name(HttpProxy *self)
{
  z_proxy_enter(self);
  ZProxyHostIface *host_iface = Z_CAST(z_proxy_find_iface(&self->super, Z_CLASS(ZProxyHostIface)), ZProxyHostIface);
  if (host_iface == NULL)
    host_iface = Z_CAST(z_proxy_find_iface(self->super.parent_proxy, Z_CLASS(ZProxyHostIface)), ZProxyHostIface);

  if (host_iface)
    {
      gchar error_reason[256];

      if (!z_proxy_host_iface_check_name(host_iface, self->remote_server->str, error_reason, sizeof(error_reason)))
        {
          z_proxy_log(self, HTTP_ERROR, 3, "Error checking hostname; error='%s'", error_reason);
          g_string_assign(self->error_info, error_reason);
          z_proxy_return(self, FALSE);
        }
      z_object_unref(&host_iface->super);
    }
  z_proxy_return(self, TRUE);
}


static gboolean
http_process_request(HttpProxy *self)
{
  HttpHeader *h;
  const gchar *reason;
  static time_t prev_cleanup = 0;
  ZorpAuthInfo *auth_info;

  /* The variable below is to keep the code simple.
     There are some situation when Zorp should put
     a Set-Cookie header into the answer. But the
     condition is not too simple. And the good place
     when all the condititons could evaluate esaily is
     too early to get server domain name which is
     needed for the header. So the header should be set
     in a latter place. This variable is to know that this
     should happen. */
  gboolean need_cookie_header = FALSE;
  gchar client_key[512];

  z_proxy_enter(self);  
  if (self->proto_version[EP_CLIENT] > 0x0100)
    self->connection_mode = HTTP_CONNECTION_KEEPALIVE;
  else    
    self->connection_mode = HTTP_CONNECTION_CLOSE;

  if (self->auth)
    {
      if (self->proto_version[EP_CLIENT] >= 0x0100)
        {
          ZSockAddr *client_addr;
          struct in_addr c_addr;
          time_t now = time(NULL);
          gchar buf[4096];
          
          if (self->auth_by_cookie)
            {
              if (!http_get_client_info(self, client_key, sizeof(client_key)))
                g_assert_not_reached();
            }
          else
            {
              z_proxy_get_addresses(&self->super, NULL, &client_addr, NULL, NULL, NULL, NULL);
              c_addr = z_sockaddr_inet_get_address(client_addr);
              z_sockaddr_unref(client_addr);
              z_inet_ntoa(client_key, sizeof(client_key), c_addr);
            }
          
          g_mutex_lock(auth_mutex);
          
          if (now > prev_cleanup + (2 * MAX(self->max_auth_time, self->auth_cache_time)))
            {
              g_hash_table_foreach_remove(auth_hash, http_remove_old_auth,
                                        GUINT_TO_POINTER(now - (2 * MAX(self->max_auth_time, self->auth_cache_time))));
              prev_cleanup = now;
            }
          
          auth_info = g_hash_table_lookup(auth_hash, client_key);

          if (auth_info == NULL)
            {
              auth_info = g_new0(ZorpAuthInfo, 1);
              auth_info->create_time = now;
              g_hash_table_insert(auth_hash, g_strdup(client_key), auth_info);
            }

          if (self->auth_cache_time > 0 && auth_info->last_auth_time + self->auth_cache_time > now)
            {
              if (self->auth_cache_update)
                {
                  auth_info->last_auth_time = now;
                }

              g_mutex_unlock(auth_mutex);
            }
          else
            {
              /* authentication is required */
              g_string_truncate(self->auth_header_value, 0);
              h = NULL;
              g_mutex_unlock(auth_mutex);

              if (self->transparent_mode)
                {
                  if ((auth_info->accept_credit > 0 && auth_info->accept_credit < now) ||
                      !http_lookup_header(&self->headers[EP_CLIENT], "Authorization", &h) ||
                      !http_process_auth_info(self, h, auth_info))
                    {
                      g_mutex_lock(auth_mutex);
                      if (self->max_auth_time > 0)
                        auth_info->accept_credit = now + self->max_auth_time;
                      g_mutex_unlock(auth_mutex);
                      self->error_code = HTTP_MSG_AUTH_REQUIRED;
                      self->error_status = 401;
                      g_string_sprintf(self->error_msg, "Authentication is required.");
                      g_string_sprintfa(self->error_headers, "WWW-Authenticate: %s\r\n",
                                        http_process_create_realm(self, now, buf, sizeof(buf)));
                      z_proxy_return(self, FALSE);
                    }
                }
              else if ((auth_info->accept_credit > 0 && auth_info->accept_credit < now) ||
                      !http_lookup_header(&self->headers[EP_CLIENT], "Proxy-Authorization", &h) ||
                      !http_process_auth_info(self, h, auth_info))
                {
                  g_mutex_lock(auth_mutex);
                  if (self->max_auth_time > 0)
                    auth_info->accept_credit = now + self->max_auth_time;
                  g_mutex_unlock(auth_mutex);
                  self->error_code = HTTP_MSG_AUTH_REQUIRED;
                  self->error_status = 407;
                  g_string_sprintf(self->error_msg, "Authentication is required.");
                  g_string_sprintfa(self->error_headers, "Proxy-Authenticate: %s\r\n",
                                    http_process_create_realm(self, now, buf, sizeof(buf)));
                  z_proxy_return(self, FALSE);
                }
              g_string_assign(self->auth_header_value, h->value->str);
              if (self->auth_by_cookie)
                need_cookie_header = TRUE;
            }
        }
      else
        {
          z_proxy_log(self, HTTP_POLICY, 2, "Authentication required, but client requested HTTP/0.9 which does not support authentication;");
          z_proxy_return(self, FALSE);
        }
    }

  if (self->request_flags & HTTP_REQ_FLG_CONNECT)
    {
      if (self->proto_version[EP_CLIENT] >= 0x0100)
        {
          self->request_type = HTTP_REQTYPE_PROXY;
          z_proxy_return(self, TRUE);
        }
      self->error_code = HTTP_MSG_CLIENT_SYNTAX;
      g_string_sprintf(self->error_info, "CONNECT method requires HTTP/1.0 or later");
      /*LOG
        This message indicates that the client sent a CONNECT method
        request, but it is only supported for HTTP/1.0 or later.
        */
      z_proxy_log(self, HTTP_VIOLATION, 1, "CONNECT method without version specification;");
      z_proxy_return(self, FALSE);
    }

  /* detect request type and set connection header in self */
  self->connection_hdr = NULL;
  if (self->proto_version[EP_CLIENT] < 0x0100)
    {
      /* no proxy protocol for version 0.9 */
      self->request_type = HTTP_REQTYPE_SERVER;
    }
  else 
    {
      HttpHeader *pconn_hdr = NULL, *conn_hdr = NULL;

      http_lookup_header(&self->headers[EP_CLIENT], "Proxy-Connection", &pconn_hdr);
      http_lookup_header(&self->headers[EP_CLIENT], "Connection", &conn_hdr);
      if (pconn_hdr && conn_hdr)
        {
          if (!self->permit_both_connection_headers)
            {
              /* both Proxy-Connection & Connection headers ... */
              self->error_code = HTTP_MSG_CLIENT_SYNTAX;
              g_string_sprintf(self->error_info, "Both Proxy-Connection and Connection headers exist.");
              /*LOG
                This message indicates that the client sent both Connection and
                Proxy-Connection headers, but these are mutually exclusive. It
                is likely sent by a buggy proxy/browser on the client side.
               */
              z_proxy_log(self, HTTP_VIOLATION, 1, "Both Proxy-Connection and Connection headers exist;");
              z_proxy_return(self, FALSE);
            }
          else
            {
              if (self->request_url->str[0] == '/')
                self->request_type = HTTP_REQTYPE_SERVER;
              else
                self->request_type = HTTP_REQTYPE_PROXY;
            }
        }
      else if (pconn_hdr)
        {
          self->request_type = HTTP_REQTYPE_PROXY;
        }
      else if (conn_hdr)
        {
          self->request_type = HTTP_REQTYPE_SERVER;
        }
      else if (self->request_url->str[0] != '/')
        {
          /* neither Connection nor Proxy-Connection header exists, and URI
             doesn't seem to be a simple filename */
          self->request_type = HTTP_REQTYPE_PROXY;
        }
      else
        {
          /* default */
          self->request_type = HTTP_REQTYPE_SERVER;
        }

      if (self->request_type == HTTP_REQTYPE_SERVER)
        {
          if (pconn_hdr)
            pconn_hdr->present = FALSE;
          self->connection_hdr = conn_hdr;
        }
      if (self->request_type == HTTP_REQTYPE_PROXY)
        {
          if (conn_hdr)
            conn_hdr->present = FALSE;
          self->connection_hdr = pconn_hdr;
        }
    }

  if (self->connection_hdr)
    {
      /* connection_mode overridden by connection header */
      gint connection_mode = http_parse_connection_hdr_value(self, self->connection_hdr);
      
      if (connection_mode != HTTP_CONNECTION_UNKNOWN)
        self->connection_mode = connection_mode;
    }

  if (self->transparent_mode &&
      ((self->request_type == HTTP_REQTYPE_PROXY && !self->permit_proxy_requests) ||
       (self->request_type == HTTP_REQTYPE_SERVER && !self->permit_server_requests)))
    {
      /* */
      self->error_code = HTTP_MSG_POLICY_VIOLATION;
      g_string_sprintf(self->error_info, "%s requests not permitted in transparent mode.", 
                       self->request_type == HTTP_REQTYPE_SERVER ? "server" : "proxy");
      /*LOG
        This message indicates that the client sent the given type request,
        which is not permitted by the policy. Check the
        permit_proxy_requests and the permit_server_requests attributes.
       */
      z_proxy_log(self, HTTP_POLICY, 2, 
                  "This request type is not permitted in transparent mode; request_type='%s'", 
                  self->request_type == HTTP_REQTYPE_SERVER ? "server" : "proxy");
      z_proxy_return(self, FALSE);
    }

  if (http_lookup_header(&self->headers[EP_CLIENT], "Host", &h))
    g_string_assign(self->remote_server, h->value->str);
  else
    g_string_truncate(self->remote_server, 0);

  if (self->transparent_mode)
    {
      if (self->request_url->str[0] == '/')
        {
          gchar buf[self->remote_server->len + 32];

          /* no protocol description */
          if (!self->remote_server->len)
            {
              if (!self->require_host_header)
                {
                  /* no host header */
                  /*LOG
                    This message indicates that no Host header was sent by
                    the client. As the content of the host header is used
                    to reconstruct the requested URL, the request_url
                    attribute will refer to a host named 'unknown'.
                    */
                  z_proxy_log(self, HTTP_VIOLATION, 4, "No host header in transparent request, 'unknown' is used instead;");
                  g_string_assign(self->remote_server, "unknown");
                }
              else
                {
                  self->error_code = HTTP_MSG_CLIENT_SYNTAX;
                  if (self->proto_version[EP_CLIENT] < 0x0100)
                    {
                      g_string_sprintf(self->error_info, "'Host:' header is required, and HTTP/0.9 can't transfer headers.");
                      /*LOG
                        This message indicates that an HTTP/0.9 request was
                        sent by the client, and Host header is required by
                        the policy, but HTTP/0.9 does not support headers.
                        Check the require_host_header attribute.
                       */
                      z_proxy_log(self, HTTP_POLICY, 2, "'Host:' header is required, and HTTP/0.9 can't transfer headers;");
                    }
                  else
                    {
                      g_string_sprintf(self->error_info, "No 'Host:' header in request, and policy requires this.");
                      /*LOG
                        This message indicates that no Host header was sent
                        by the client, but it was required by the policy.
                        Check the require_host_header attribute.
                       */
                      z_proxy_log(self, HTTP_POLICY, 2, "No 'Host:' header in request, and policy requires this;");
                    }

                  z_proxy_return(self, FALSE);
                }
            }
          g_snprintf(buf, sizeof(buf), "http://%s", self->remote_server->str);
          g_string_prepend(self->request_url, buf);
        }
    }

  if (!http_parse_url(&self->request_url_parts, self->permit_unicode_url,
                      self->permit_invalid_hex_escape, FALSE, self->request_url->str, &reason))
    {
      /* invalid URL */
      self->error_code = HTTP_MSG_INVALID_URL;
      g_string_sprintf(self->error_info, "Badly formatted url: %s", self->request_url->str);
      /*LOG
        This message indicates that there was an error parsing an already
        canonicalized URL.  Please report this event to the Zorp QA team (at
        devel@balabit.com)
       */
      z_proxy_log(self, HTTP_ERROR, 1, "Error parsing URL; url='%s', reason='%s'", self->request_url->str, reason);
      z_proxy_return(self, FALSE);
    }
  if (!http_format_url(&self->request_url_parts, self->request_url, TRUE, self->permit_unicode_url, TRUE, &reason))
    {
      self->error_code = HTTP_MSG_INVALID_URL;
      g_string_sprintf(self->error_info, "Error canonicalizing url (%s): %s", reason, self->request_url->str);
      /*LOG
        This message indicates that there was an error parsing an already
        canonicalized URL.  Please report this event to the Zorp QA team (at
        devel@balabit.com)
       */
      z_proxy_log(self, HTTP_ERROR, 1, "Error parsing URL; url='%s', reason='%s'", self->request_url->str, reason);
      z_proxy_return(self, FALSE);
    }

  self->remote_port = self->request_url_parts.port;
  if (need_cookie_header)
  {
    gchar *hostname = self->request_url_parts.host->str;
    gchar *startpos = hostname;
    gchar *dotpos = strchr(startpos, '.');
    gchar *nextdotpos = NULL;

    if (dotpos != NULL)
      nextdotpos = strchr(dotpos + 1, '.');
    while (nextdotpos != NULL)
      {
        startpos = dotpos;
        dotpos = nextdotpos;
        nextdotpos = strchr(dotpos + 1, '.');
      }
    self->append_cookie = g_string_sized_new(32);
    g_string_printf(self->append_cookie, "ZorpRealm=%s; path=/; domain=%s", client_key, startpos);
  }
  z_proxy_return(self, TRUE);
}

static gboolean
http_process_filtered_request(HttpProxy *self)
{
  if ((self->request_flags & HTTP_REQ_FLG_CONNECT))
    {
      self->server_protocol = HTTP_PROTO_HTTP;
    }
  else if (http_parent_proxy_enabled(self) &&
           (strcasecmp(self->request_url_parts.scheme->str, "http") == 0 ||
            strcasecmp(self->request_url_parts.scheme->str, "ftp") == 0 ||
            strcasecmp(self->request_url_parts.scheme->str, "cache_object") == 0))
    {
      self->server_protocol = HTTP_PROTO_HTTP;
    }
  else if (!http_parent_proxy_enabled(self) && strcasecmp(self->request_url_parts.scheme->str, "ftp") == 0)
    {
      if (self->permit_ftp_over_http)
        {
          self->server_protocol = HTTP_PROTO_FTP;
        }
      else
        {
          /*LOG
            This message indicates that a client tried to use FTP over HTTP
            which is not allowed by default. Either set a parent proxy or
            enable the permit_ftp_over_http attribute.
           */
          z_proxy_log(self, HTTP_POLICY, 2, "Client attempted to use FTP over HTTP, which is currently disabled;");
          self->error_code = HTTP_MSG_CLIENT_SYNTAX;
          z_proxy_return(self, FALSE);
        }
    }
  else if (!http_parent_proxy_enabled(self) && strcasecmp(self->request_url_parts.scheme->str, "http") == 0)
    {
      self->server_protocol = HTTP_PROTO_HTTP;
    }
  else
    {
      /* unsupported protocol */
      self->error_code = HTTP_MSG_CLIENT_SYNTAX;
      g_string_sprintf(self->error_info, "Unsupported scheme: %s", self->request_url_parts.scheme->str);
      /*LOG
        This message indicates that the requested URL refers to an
        unsupported protocol scheme. Zorp currently knows about http and
        cache_object protocols, and can support the ftp protocol
        if a parent_proxy supporting ftp over http tunneling is present.
       */
      z_proxy_log(self, HTTP_ERROR, 3, "Unsupported scheme in URL; proto='%s'", self->request_url_parts.scheme->str);
      z_proxy_return(self, FALSE);
    }

  if (self->request_url_parts.host->len > self->max_hostname_length)
    {
      self->error_code = HTTP_MSG_CLIENT_SYNTAX;
      g_string_sprintf(self->error_info, "Too long hostname in URL: %s", self->request_url_parts.host->str);
      /*LOG
        This message indicates that the HTTP request was rejected because
        the hostname part in the URL was too long. You can increase the permitted
        limit by changing the max_hostname_length attribute. 
       */
      z_proxy_log(self, HTTP_POLICY, 2, "Too long hostname in URL; host='%s', length='%" G_GSIZE_FORMAT "', max_hostname_length='%d'",
                  self->request_url_parts.host->str, self->request_url_parts.host->len, self->max_hostname_length);
      z_proxy_return(self, FALSE);
    }

  if (self->remote_port == 0)
    {
      if (self->server_protocol == HTTP_PROTO_HTTP)
        self->remote_port = self->default_http_port;
      else
        self->remote_port = self->default_ftp_port;
    }

  if (!(self->request_flags & HTTP_REQ_FLG_CONNECT))
    http_rewrite_host_header(self, self->request_url_parts.host->str, self->request_url_parts.host->len, self->remote_port);

  if (http_parent_proxy_enabled(self))
    {
      self->remote_port = self->parent_proxy_port;
      g_string_assign(self->remote_server, self->parent_proxy->str);
    }
  else
    {
      g_string_assign(self->remote_server, self->request_url_parts.host->str);
    }

  /*LOG
    This is an accounting message that reports the requested method and URL.
   */
  z_proxy_log(self, HTTP_ACCOUNTING, 4, "Accounting; command='%s', url='%s'", self->request_method->str, self->request_url->str);
  z_proxy_return(self, TRUE);  
} 

/* FIXME: this code should be converted into an explicit referral to the
 * modified headers, e.g. instead of looping over all the headers, lookup
 * the necessary headers using http_lookup_header and modify the returned
 * values */
static guint 
http_request_filter_headers(HttpProxy *self, GString *name, GString *value)
{
  gint res = HTTP_HDR_ACCEPT;

  z_proxy_enter(self);
  switch (self->request_type)
    {
    case HTTP_REQTYPE_SERVER:
      /* if we have a parent proxy, Connection -> Proxy-Connection
       * otherwise leave it as is 
       */
      if (strcasecmp(name->str, "Connection") == 0)
        {
          if (http_parent_proxy_enabled(self))
            g_string_assign(name, "Proxy-Connection");
          http_assign_connection_hdr_value(self, value);
        }
      else if (strcasecmp(name->str, "Authorization") == 0)
        {
          if (self->auth)
            {
              /* if inband authentication was performed, drop the
               * authentication header unless forwarding was explicitly
               * requested */
              if (self->auth_forward)
                {
                  g_string_assign(value, self->auth_header_value->str);

                  /* if the upstream is a proxy, forward it as a
                   * Proxy-Authorization header */

                  if (http_parent_proxy_enabled(self))
                    g_string_assign(name, "Proxy-Authorization");
                }
              else
                {
                  res = HTTP_HDR_DROP;
                }
            }
        }
      break;

    case HTTP_REQTYPE_PROXY:
      /* if we have a parent proxy leave it as is
       * otherwise Proxy-Connection -> Connection 
       */
      if (strcasecmp(name->str, "Proxy-Connection") == 0)
        {
          if (http_parent_proxy_enabled(self) == 0)
            g_string_assign(name, "Connection");
          http_assign_connection_hdr_value(self, value);
        }
      else if (strcasecmp(name->str, "Proxy-Authorization") == 0)
        {
          if (self->auth)
            {
              /* if inband authentication was performed, drop the
               * authentication header unless forwarding was explicitly
               * requested */
              if (self->auth_forward)
                {
                  g_string_assign(value, self->auth_header_value->str);
                  /* if the upstream is not a proxy, forward it as a
                   * Authorization header */
                  if (!http_parent_proxy_enabled(self))
                    g_string_assign(name, "Authorization");
                }
              else
                {
                  res = HTTP_HDR_DROP;
                }
            }
        }
      break;
    }
  z_proxy_return(self, res);
}

static gboolean
http_filter_request(HttpProxy *self)
{
  ZPolicyObj *f;
  gint rc;

  z_proxy_enter(self);
  f = g_hash_table_lookup(self->request_method_policy, self->request_method->str);
  if (!f)
    f = g_hash_table_lookup(self->request_method_policy, "*");
  if (f)
    {
      ZPolicyObj *handler, *res;
      gchar *errmsg;
      guint filter_type;

      z_policy_lock(self->super.thread);  
      if (!z_policy_tuple_get_verdict(f, &filter_type))
        {
          /*LOG
            This message indicates that the request hash contains an invalid
            item for the given request method. Check your Zorp
            configuration.
           */
          z_proxy_log(self, HTTP_POLICY, 1, "Invalid item in request hash; method='%s'", self->request_method->str);
          z_policy_unlock(self->super.thread);
          z_proxy_return(self, FALSE);

        }
      z_policy_unlock(self->super.thread);
      g_string_sprintf(self->error_info, "Method %s denied by policy", self->request_method->str);

      switch (filter_type)
        {
        case HTTP_REQ_POLICY:
          z_policy_lock(self->super.thread);
          if (!z_policy_var_parse(f, "(iO)", &filter_type, &handler))
            {
              /*LOG
                This message indicates that the request hash contains an
                invalid POLICY tuple for the given request method.  It
                should contain a valid call-back function in the tuple.
              */
              z_proxy_log(self, HTTP_POLICY, 1, "Error parsing HTTP_REQ_POLICY tuple in request hash; method='%s'", self->request_method->str);
              z_policy_unlock(self->super.thread);
              z_proxy_return(self, FALSE);
            }
          res = z_policy_call_object(handler, 
                                     z_policy_var_build("(sss)", 
                                                        self->request_method->str, self->request_url->str, self->request_version), 
                                     self->super.session_id);
          if (!res || !z_policy_var_parse(res, "i", &rc))
            {
              rc = HTTP_REQ_REJECT;
              g_string_assign(self->error_info, "Error in policy handler, or returned value not integer;");
            }
          z_policy_var_unref(res);
          z_policy_unlock(self->super.thread);
          break;

	case HTTP_REQ_REJECT:
          errmsg = NULL;
          z_policy_lock(self->super.thread);
          if (!z_policy_var_parse_tuple(f, "i|s", &filter_type, &errmsg))
            {
              /*LOG
                This message indicates that the request hash contains an
                invalid REJECT tuple for the given request method.  It
                should contain an error message, which is sent back to the
                client.
              */
              z_proxy_log(self, HTTP_POLICY, 1, "Error parsing HTTP_REQ_REJECT in request hash; req='%s'", self->request_method->str);
              z_policy_unlock(self->super.thread);
              z_proxy_return(self, FALSE);
            }
          z_policy_unlock(self->super.thread);
          if (errmsg)
            g_string_assign(self->error_info, errmsg);
          /* fallthrough */

  case HTTP_REQ_ACCEPT:
  case HTTP_REQ_DENY:
  case HTTP_REQ_ABORT:
          /* dropped command */
          rc = filter_type;
          break;

  default:
          /*LOG
            This message indicates that the request hash contains an invalid
            action for the given request method.  Check your Zorp
            configuration.
          */
          z_proxy_log(self, HTTP_POLICY, 1, "Unknown request hash item; req='%s'", self->request_method->str);
          z_proxy_return(self, FALSE);
        }

      switch (rc)
        {
        case HTTP_REQ_ACCEPT:
          g_string_truncate(self->error_info, 0);
          break;

        default:
          /*LOG
            This log message indicates that the specified HTTP request was not permitted by your policy.
           */
          z_proxy_log(self, HTTP_POLICY, 2, "Request not permitted by policy; req='%s'", self->request_method->str);          
          self->error_code = HTTP_MSG_POLICY_VIOLATION;
          z_proxy_return(self, FALSE);
        }

      if (self->proto_version[EP_CLIENT] >= 0x0100)
        {
          if (!http_filter_headers(self, EP_CLIENT, http_request_filter_headers))
            z_proxy_return(self, FALSE);
        }
      z_proxy_return(self, TRUE);
    }
  self->error_code = HTTP_MSG_POLICY_VIOLATION;
  g_string_sprintf(self->error_info, "Method %s denied by policy", self->request_method->str);
  /*LOG
    This log message indicates that the specified HTTP request was not permitted by your policy.
   */
  z_proxy_log(self, HTTP_POLICY, 2, "Request not permitted by policy; req='%s'", self->request_method->str);
  z_proxy_return(self, FALSE);
}

static gboolean
http_server_stream_ready(HttpProxy *self)
{
  gboolean res = FALSE;

  z_proxy_enter(self);

  if (self->super.endpoints[EP_SERVER])
    {
      GIOStatus rc;
      gchar buf[1];
      gsize bytes_read;
      ZStream *stream = self->super.endpoints[EP_SERVER];

      z_stream_set_nonblock(stream, TRUE);
      rc = z_stream_read(stream, &buf, sizeof(buf), &bytes_read, NULL);
      z_stream_set_nonblock(stream, FALSE);

      if (rc == G_IO_STATUS_NORMAL || rc == G_IO_STATUS_AGAIN)
        {
          res = TRUE;

          if (bytes_read > 0 && !z_stream_unget(stream, buf, bytes_read, NULL))
            {
              z_proxy_log(self, HTTP_ERROR, 2, "Error while checking if server stream is ready, buffer full");
              res = FALSE;
            }
        }
    }

  z_proxy_return(self, res);
}

gboolean
http_connect_server(HttpProxy *self)
{
  z_proxy_enter(self);
  if (!self->super.endpoints[EP_SERVER] ||
      !http_server_stream_ready(self) ||
      (!self->transparent_mode && 
        (strcasecmp(self->remote_server->str, self->connected_server->str) != 0 ||
         self->remote_port != self->connected_port)) ||
      self->force_reconnect)
    {
      gboolean success = FALSE;

      self->force_reconnect = FALSE;
      if (self->super.endpoints[EP_SERVER])
        {
          z_stream_shutdown(self->super.endpoints[EP_SERVER], SHUT_RDWR, NULL);
          z_stream_close(self->super.endpoints[EP_SERVER], NULL);
          z_stream_unref(self->super.endpoints[EP_SERVER]);
          self->super.endpoints[EP_SERVER] = NULL;

          z_proxy_ssl_clear_session(&self->super, EP_SERVER);
        }

      g_string_sprintf(self->error_info, "Error establishing connection to %s", self->remote_server->str);
      if (http_parent_proxy_enabled(self))
        {
          success = z_proxy_connect_server(&self->super, self->parent_proxy->str, self->parent_proxy_port);
        }
      else if (self->transparent_mode && self->use_default_port_in_transparent_mode)
        {
          success = z_proxy_connect_server(&self->super, self->remote_server->str, 
                                           self->server_protocol == HTTP_PROTO_HTTP ? self->default_http_port : self->default_ftp_port);
        }
      else if (z_port_enabled(self->target_port_range->str, self->remote_port))
        {
          success = z_proxy_connect_server(&self->super, self->remote_server->str, self->remote_port);
        }
      else
        {
          /*LOG
            This message indicates that the proxy did not allow
            addressing the specified port as the target_port_range
            attribute does not allow it.
            */
          z_proxy_log(self, HTTP_VIOLATION, 2, "Connecting to this port is prohibited by policy; host='%s', port='%d'", self->remote_server->str, self->remote_port);
          g_string_sprintf(self->error_info, "Connecting to port %d is prohibited by policy.", self->remote_port);
          success = FALSE;
        }

      if (!success)
        {
          /* error connecting to server */
          self->error_code = HTTP_MSG_CONNECT_ERROR;
          self->error_status = 502;
          /* connect_server already logged */
          z_proxy_return(self, FALSE);
        }

      g_string_assign(self->connected_server, self->remote_server->str);
      self->connected_port = self->remote_port;
    }

  if (!http_server_stream_is_initialized(self)
      && !http_server_stream_init(self))
    {
      /* should never happen */
      /*LOG
        This message indicates that initializing the server stream
        failed. Please report this event to the Zorp QA team (at
        devel@balabit.com).
       */
      z_proxy_log(self, HTTP_ERROR, 1, "Internal error initializing server stream;");
      z_proxy_return(self, FALSE);
    }

  z_proxy_return(self, TRUE);
}

static gboolean
http_copy_request(HttpProxy *self)
{
  ZStream *blob_stream = NULL;
  
  z_proxy_enter(self);
  if (!http_connect_server(self))
    z_proxy_return(self, FALSE); /* connect_server already logs */

  if (!http_check_name(self))
    {
      z_proxy_return(self, FALSE);
    }

  if (self->request_data_stored && self->request_data && self->request_data->size > 0)
    {
      gchar session_id[MAX_SESSION_ID];
        
      g_snprintf(session_id, sizeof(session_id), "%s/post", self->super.session_id);
      blob_stream = z_stream_blob_new(self->request_data, session_id);
      blob_stream->timeout = -1;
    }
        
  if (!http_data_transfer(self, blob_stream ? HTTP_TRANSFER_FROM_BLOB : HTTP_TRANSFER_NORMAL, EP_CLIENT, blob_stream ? blob_stream : self->super.endpoints[EP_CLIENT], EP_SERVER, self->super.endpoints[EP_SERVER], FALSE, FALSE, http_format_request))
    {
      /* http_data_transfer already logs */
      z_stream_unref(blob_stream);
      z_proxy_return(self, FALSE);
    }
  z_stream_unref(blob_stream);
  z_proxy_return(self, TRUE);
}

static gboolean 
http_fetch_response(HttpProxy *self)
{
  gchar *line;
  gsize line_length, br;
  GIOStatus res;
  gchar status[4];

  z_proxy_enter(self);
  /* FIXME: this can probably be removed as http_fetch_header does this */
  http_clear_headers(&self->headers[EP_SERVER]);
  self->response[0] = 0;
  self->response_code = -1;
  if (self->proto_version[EP_CLIENT] < 0x0100)
    {
      self->proto_version[EP_SERVER] = 0x0009;
      z_proxy_return(self, TRUE);
    }

  while (self->response_code == -1 || self->response_code == 100 || self->response_code == 102)
    {
      self->super.endpoints[EP_SERVER]->timeout = self->timeout_response;
      res = z_stream_read_chunk(self->super.endpoints[EP_SERVER], status, sizeof(status), &br, NULL);
      self->super.endpoints[EP_SERVER]->timeout = self->timeout;
      if (res != G_IO_STATUS_NORMAL)
        {
          /* the server closed our connection */
          self->error_code = HTTP_MSG_OK;
          z_proxy_return(self, FALSE);
        }
      
      if (!z_stream_unget(self->super.endpoints[EP_SERVER], status, br, NULL))
        {
          /* error falling back to 0.9 */
          /*LOG
            This message indicates that Zorp was unable to enable HTTP/0.9
            compatibility mode, due to the full buffer.  If you experience
            this problem many times, please contact your Zorp support.
           */
          z_proxy_log(self, HTTP_ERROR, 2, "Error in HTTP/0.9 compatibility code, line buffer full;");
          z_proxy_return(self, FALSE);
        }

      if (br == 4 && memcmp(status, "HTTP", 4) == 0)
        {
          res = z_stream_line_get(self->super.endpoints[EP_SERVER], &line, &line_length, NULL);
          if (res != G_IO_STATUS_NORMAL)
            {
              self->error_code = HTTP_MSG_OK;
              z_proxy_return(self, FALSE);
            }
        }
      else if (self->permit_http09_responses)
        {
          self->proto_version[EP_SERVER] = 0x0009;
          z_proxy_return(self, TRUE);
        }
      else
        {
          /* HTTP/0.9 is not permitted by policy */
          g_string_assign(self->error_info, "Server falled back to HTTP/0.9 which is prohibited by policy.");
          /*LOG
            This message indicates that the server sent back HTTP/0.9
            response, which is prohibited by the policy.  It is likely a
            buggy or old server. Check the permit_http09_responses
            attribute.
           */ 
          z_proxy_log(self, HTTP_POLICY, 2, "Server falled back to HTTP/0.9 which is prohibited by policy;");
          z_proxy_return(self, FALSE);
        }

      if (!http_split_response(self, line, line_length))
        {
          /*LOG
            This message indicates the the HTTP status line returned by the
            server was invalid.
           */
          z_proxy_log(self, HTTP_VIOLATION, 1, "Invalid HTTP response heading; line='%.*s'", (gint)line_length, line);
          g_string_assign(self->error_info, "Invalid HTTP response heading");
          z_proxy_return(self, FALSE);
        }

      self->response_flags = http_proto_response_lookup(self->response);
      if (!http_parse_version(self, EP_SERVER, self->response_version))
        {
          g_string_sprintf(self->error_info, "Invalid HTTP version in response (%.*s)", (gint) line_length, line);
          /*LOG
            This message indicates that the server sent the response with an
            invalid HTTP version.  It is likely that the server is buggy.
          */
          z_proxy_log(self, HTTP_VIOLATION, 1, "Error parsing response version; line='%.*s'", (gint) line_length, line);
          z_proxy_return(self, FALSE);
        }

      if (!http_fetch_headers(self, EP_SERVER))
        {
          g_string_assign(self->error_info, "Invalid headers received in response");
          z_proxy_return(self, FALSE);
        }
      if (self->append_cookie)
        {
          http_add_header(&self->headers[EP_SERVER], "Set-Cookie", strlen("Set-Cookie"),
                          self->append_cookie->str, self->append_cookie->len);
          g_string_free(self->append_cookie, TRUE);
          self->append_cookie = NULL;
        }
    }
  z_proxy_return(self, TRUE);
}

static gboolean
http_process_response(HttpProxy *self)
{
  HttpHeader *pconn_hdr = NULL, *conn_hdr = NULL;

  z_proxy_enter(self);
  /* previously set by http_parse_version */
  switch (self->proto_version[EP_SERVER])
    {
    case 0x0009:
      g_strlcpy(self->response, "200", sizeof(self->response_code));
      self->response_code = 200;
      self->response_flags = 0;
      self->connection_mode = HTTP_CONNECTION_CLOSE;
      self->server_connection_mode = HTTP_CONNECTION_CLOSE;
      z_proxy_return(self, TRUE);

    case 0x0100:
      self->server_connection_mode = HTTP_CONNECTION_CLOSE;
      break;
      
    case 0x0101:
      self->server_connection_mode = HTTP_CONNECTION_KEEPALIVE;
      break;
      
    default:
      /*LOG
        This message indicates that the server sent an unsupported protocol
        version. It is likely that the server is buggy.
       */
      z_proxy_log(self, HTTP_VIOLATION, 1, "Unsupported protocol version; version='0x%04x'", self->proto_version[EP_SERVER]);
      z_proxy_return(self, FALSE);
    }

  /* process connection header */
  self->connection_hdr = NULL;
  http_lookup_header(&self->headers[EP_SERVER], "Proxy-Connection", &pconn_hdr);
  http_lookup_header(&self->headers[EP_SERVER], "Connection", &conn_hdr);
  if ((http_parent_proxy_enabled(self) && pconn_hdr) || conn_hdr)
    {
      /* override default */
      if (http_parent_proxy_enabled(self) && pconn_hdr)
        {
          self->connection_hdr = pconn_hdr;
          if (conn_hdr)
            conn_hdr->present = FALSE;
        }
      else
        {
          self->connection_hdr = conn_hdr;
          if (pconn_hdr)
            pconn_hdr->present = FALSE;
        }

      if (self->connection_mode == HTTP_CONNECTION_KEEPALIVE && 
          http_parse_connection_hdr_value(self, self->connection_hdr) != HTTP_CONNECTION_CLOSE)
        self->server_connection_mode = HTTP_CONNECTION_KEEPALIVE;
      else
        self->server_connection_mode = HTTP_CONNECTION_CLOSE;
    }
  else
    {
      /* NOTE: there was no appropriate Connection header in the response, if it
       * is an 1.0 client the connection mode should be changed to
       * connection close regardless what the client specified in its
       * connection header.
       */
      gchar *conn_hdr_str = http_parent_proxy_enabled(self) ? "Proxy-Connection" : "Connection";

      /* we add an appriopriate connection header just as if we received one
       * (e.g. it might be rewritten later by
       * http_response_filter_connection_header), we default to not sending
       * this new header, it will be made visible when we want to ensure
       * that our connection mode must be enforced. */
      self->connection_hdr = http_add_header(&self->headers[EP_SERVER], conn_hdr_str, strlen(conn_hdr_str), "close", 5);
      self->connection_hdr->present = FALSE;
      if (self->proto_version[EP_CLIENT] == 0x0100)
        {
          if (self->connection_mode == HTTP_CONNECTION_KEEPALIVE)
            {
              /* it is somewhat uncertain what happens when an 1.0 client
               * requests keepalive and an 1.1 server responds without a
               * connection header, resolve this uncertainity by adding a 
               * connection header */
              self->connection_hdr->present = TRUE;
            }
          self->server_connection_mode = HTTP_CONNECTION_CLOSE;
        }
    }
  if (self->request_flags & HTTP_REQ_FLG_CONNECT && self->response_code == 200)
    self->server_connection_mode = HTTP_CONNECTION_CLOSE;

  if (!self->keep_persistent && self->server_connection_mode == HTTP_CONNECTION_CLOSE)
    self->connection_mode = HTTP_CONNECTION_CLOSE;

  if (self->response_flags & HTTP_RESP_FLG_STOP)
    z_proxy_return(self, FALSE); /* FIXME: not implemented */

  z_proxy_return(self, TRUE);
}

/**
 * http_fetch_buffered_data:
 * @self: HttpProxy instance
 *
 * Read all buffered data from the client up to maximum ten 4096 chunks.
 * This is needed to avoid sending RSTs to connections where the client sent
 * some unprocessed bytes (like IE 5.0 in the case of POST requests).
 **/
static void
http_fetch_buffered_data(HttpProxy *self)
{
  gchar buf[4096];
  gsize br;
  gint count = 0;

  z_stream_set_nonblock(self->super.endpoints[EP_CLIENT], TRUE);
  while (count < 10 && z_stream_read(self->super.endpoints[EP_CLIENT], buf, sizeof(buf), &br, NULL) == G_IO_STATUS_NORMAL)
    {
      count++;
    }
  z_stream_set_nonblock(self->super.endpoints[EP_CLIENT], FALSE);
}

static ZPolicyObj *
http_response_policy_get(HttpProxy *self)
{
  gchar *response_keys[2];

  response_keys[0] = self->request_method->str;
  response_keys[1] = self->response;

  return z_dim_hash_table_search(self->response_policy, 2, response_keys);
}

static gboolean
http_filter_response(HttpProxy *self)
{
  z_proxy_enter(self);
  if (self->proto_version[EP_SERVER] >= 0x0100)
    {
      ZPolicyObj *f, *res;
      gint rc;

      f = http_response_policy_get(self);
      if (f)
        {
          ZPolicyObj *handler;
          guint filter_type;
          gchar *errmsg;

          z_policy_lock(self->super.thread);  
          if (!z_policy_tuple_get_verdict(f, &filter_type))
            {
              /*LOG
                This message indicates that the response hash contains an
                invalid item for the given response. Check your Zorp
                configuration.
               */
              z_proxy_log(self, HTTP_POLICY, 1, "Invalid response hash item; request='%s', response='%d'", self->request_method->str, self->response_code);
              z_policy_unlock(self->super.thread);
              z_proxy_return(self, FALSE);
            }
          z_policy_unlock(self->super.thread);

          g_string_sprintf(self->error_info, "Response %d for %s denied by policy.", self->response_code, self->request_method->str);
          switch (filter_type)
            {
            case HTTP_RSP_POLICY:
              z_policy_lock(self->super.thread);
              if (!z_policy_var_parse(f, "(iO)", &filter_type, &handler))
                {
                  /*LOG
                    This message indicates that the response hash contains
                    an invalid POLICY tuple for the given response.  It
                    should contain a valid call-back function in the tuple.
                   */
                  z_proxy_log(self, HTTP_POLICY, 1, 
                              "Error parsing HTTP_RSP_POLICY in response hash; request='%s', response='%d'", 
                              self->request_method->str, self->response_code);
                  z_policy_unlock(self->super.thread);
                  z_proxy_return(self, FALSE);
                }
              res = z_policy_call_object(handler, z_policy_var_build("(sssi)", self->request_method->str, self->request_url->str, self->request_version, self->response_code), self->super.session_id);
              if (!z_policy_var_parse(res, "i", &rc))
                {
                  g_string_assign(self->error_info, "Error in policy handler.");
                  rc = HTTP_RSP_REJECT;
                }
              z_policy_var_unref(res);
              z_policy_unlock(self->super.thread);
              break;

	    case HTTP_RSP_REJECT:
              errmsg = NULL;
              z_policy_lock(self->super.thread);
              if (!z_policy_var_parse_tuple(f, "i|s", &filter_type, &errmsg))
                {
                  /*LOG
                    This message indicates that the response hash contains
                    an invalid REJECT tuple for the given response.
                    It should contain an error message, which is sent back to
                    the client.
                   */
                  z_proxy_log(self, HTTP_POLICY, 1, 
                              "Error parsing HTTP_RSP_REJECT in response hash; request='%s', response='%d'", 
                              self->request_method->str, self->response_code);
                  z_policy_unlock(self->super.thread);
                  z_proxy_return(self, FALSE);
                }
              z_policy_unlock(self->super.thread);
              if (errmsg)
                g_string_assign(self->error_info, errmsg);
              /* fallthrough */

	    case HTTP_RSP_ACCEPT:
      case HTTP_RSP_DENY:
      case HTTP_RSP_ABORT:
              /* dropped command */
              rc = filter_type;
              break;

	    default:
              /*LOG
                This message indicates that the response hash contains
                an invalid action for the given response.
                Check your Zorp configuration.
               */
              z_proxy_log(self, HTTP_POLICY, 1, 
                          "Invalid response hash item; request='%s', response='%d'", 
                          self->request_method->str, self->response_code);
              z_proxy_return(self, FALSE);
            }

          switch (rc)
            {
            case HTTP_RSP_ACCEPT:
              break;

            default:
	    case HTTP_RSP_REJECT:
              /*LOG
                This message indicates that the status code returned by the server is
                not a permitted response code for this request.
               */
              z_proxy_log(self, HTTP_POLICY, 2, "Response not permitted by policy; req='%s', rsp='%d'", self->request_method->str, self->response_code);
              self->error_code = HTTP_MSG_POLICY_VIOLATION;
              z_proxy_return(self, FALSE);
            }

        }

      if (!http_filter_headers(self, EP_SERVER, NULL))
        z_proxy_return(self, FALSE);
    }
  z_proxy_return(self, TRUE);
}

static gboolean
http_format_response(HttpProxy *self, gboolean stacked, GString *response)
{
  if (self->proto_version[EP_SERVER] >= 0x0100)
    {
      if (!stacked)
        {
          http_flat_headers(&self->headers[EP_SERVER]);
          g_string_set_size(response, 4000);
          g_string_truncate(response, 0);

          g_string_append_const(response, "HTTP");
          g_string_append_c(response, '/');
          g_string_append_c(response, '0' + ((self->proto_version[EP_SERVER] & 0xFF00) >> 8));
          g_string_append_c(response, '.');
          g_string_append_c(response, '0' + (self->proto_version[EP_SERVER] & 0x00FF));
          g_string_append_c(response, ' ');
          g_string_append(response, self->response);
          g_string_append_c(response, ' ');
          g_string_append_gstring(response, self->response_msg);
          g_string_append_const(response, "\r\n");
          g_string_append_gstring(response, self->headers[EP_SERVER].flat);
          g_string_append_const(response, "\r\n");
        }
      else
        {
          http_flat_headers_into(&self->headers[EP_SERVER], response);
        }
    }
  else
    g_string_truncate(response, 0);
  return TRUE;
}

static gboolean
http_copy_response(HttpProxy *self)
{
  gboolean suppress_data, expect_data;

  z_proxy_enter(self);
  /* self->connection_hdr must never be NULL for server->client direction when at least HTTP/1.0 is used */
  if (self->proto_version[EP_SERVER] >= 0x0100)
    {  
      g_assert(self->connection_hdr);

      if (self->connection_mode != self->server_connection_mode)
        self->connection_hdr->present = TRUE;

      if (self->connection_hdr->present)
        {
          g_string_assign(self->connection_hdr->name, self->request_type == HTTP_REQTYPE_SERVER ? "Connection" : "Proxy-Connection");
          http_assign_connection_hdr_value(self, self->connection_hdr->value);
        }
    }    
  expect_data = (self->response_flags & HTTP_RESP_FLG_DONTEXPECT) == 0;
  suppress_data = (self->response_flags & HTTP_RESP_FLG_SUPPRESS) != 0 ||
                  (self->request_flags & HTTP_REQ_FLG_HEAD) != 0 ||
                  ((self->request_flags & HTTP_REQ_FLG_CONNECT) != 0 && self->response_code == 200);
  if (!http_data_transfer(self, HTTP_TRANSFER_NORMAL, EP_SERVER, self->super.endpoints[EP_SERVER], EP_CLIENT, self->super.endpoints[EP_CLIENT], expect_data, suppress_data, http_format_response))
    z_proxy_return(self, FALSE); /* http_data_transfer already logs */

  z_proxy_return(self, TRUE);
}

static gboolean
http_handle_connect(HttpProxy *self)
{
  /* connect is enabled here */
  guint i; 
  ZPolicyObj *res;
  gboolean called;
  gchar *success, *remote_host;
  gchar *colon, *end;
  gint remote_host_len, remote_port;

  z_proxy_enter(self);
  self->connection_mode = HTTP_CONNECTION_CLOSE;
  colon = strchr(self->request_url->str, ':');
  if (colon)
    {
      remote_host = self->request_url->str;
      remote_host_len = colon - remote_host;
      remote_port = strtoul(colon + 1, &end, 10);
    }
  else
    {
      self->error_code = HTTP_MSG_CLIENT_SYNTAX;
      g_string_sprintf(self->error_info, "Invalid CONNECT request.");
      /*LOG
        This message indicates that the received CONNECT request did not
        include a port number to connect to.
       */
      z_proxy_log(self, HTTP_VIOLATION, 1, "Missing port number in CONNECT request; url='%s'", self->request_url->str);
      z_proxy_return(self, FALSE);
    }

  if (http_parent_proxy_enabled(self))
    {
      g_string_assign(self->remote_server, self->parent_proxy->str);
      self->remote_port = self->parent_proxy_port;
    }
  else
    {
      /* From buffer is longer than we want to copy. */
      g_string_assign_len(self->remote_server, remote_host, remote_host_len);
      self->remote_port = remote_port;
    }

  if (!http_connect_server(self))
    z_proxy_return(self, FALSE);

  if (http_parent_proxy_enabled(self))
    {
      GString *request = g_string_sized_new(64);

      http_format_request(self, FALSE, request);
      if (http_write(self, EP_SERVER, request->str, request->len) != G_IO_STATUS_NORMAL)
        {
          g_string_free(request, TRUE);
          z_proxy_return(self, FALSE);
        }
      g_string_free(request, TRUE);

      if (!http_fetch_response(self))
        z_proxy_return(self, FALSE);
      if (self->response_code != 200)
        {
          /*LOG
            This message indicates that the our parent proxy
            refused our CONNECT request. It is likely that the
            parent proxy does not permit CONNECT method.
           */
          z_proxy_log(self, HTTP_ERROR, 1, "Parent proxy refused our CONNECT request; host='%.*s', port='%d'", remote_host_len, remote_host, remote_port);
          z_proxy_log(self, HTTP_DEBUG, 6, "Processing response and headers (CONNECT);");
          if (!http_process_response(self) || 
              !http_filter_response(self) || 
              !http_copy_response(self))
            {
              z_proxy_log(self, HTTP_ERROR, 2, "Error copying CONNECT response, or CONNECT response rejected by policy; request='%s', response='%d'", self->request_method->str, self->response_code);
            }
          z_proxy_return(self, FALSE);
        }
    }

  /*LOG
    This message reports that CONNECT method is in use, and
    CONNECT method was accepted by out parent proxy.
   */
  z_proxy_log(self, HTTP_DEBUG, 6, "Starting connect method;");
  if (!http_parent_proxy_enabled(self))
    {
      success = "HTTP/1.0 200 Connection established\r\n\r\n";
      if (http_write(self, EP_CLIENT, success, strlen(success)) != G_IO_STATUS_NORMAL)
        z_proxy_return(self, FALSE); /* hmm... I/O error */
    }
  else
    {
      if (!http_process_response(self) ||
          !http_filter_response(self) ||
          !http_copy_response(self))
        {
          z_proxy_log(self, HTTP_ERROR, 2, "Error copying CONNECT response, or CONNECT response rejected by policy; request='%s', response='%d'", self->request_method->str, self->response_code);
          z_proxy_return(self, FALSE);
        }
    }

  /* FIXME: flush already buffered data, before starting plug */

  /* NOTE: the child proxy uses the Python variables session.client_stream
   * and session.server_stream as its streams (see bug: #10347)
   */
  for (i = EP_CLIENT; i < EP_MAX; i++)
    {
      while (self->super.endpoints[i]->child)
        self->super.endpoints[i] = z_stream_pop(self->super.endpoints[i]);
    }
  z_policy_lock(self->super.thread);
  res = z_policy_call(self->super.handler, "connectMethod", z_policy_var_build("()"), &called, self->super.session_id);

  if (!res || res == z_policy_none)
    {
      /*LOG
        This message indicates that an internal error occurred, the
        connectMethod function did not return an integer. Please report this
        event to the Zorp QA team (at devel@balabit.com).
       */
      z_proxy_log(self, HTTP_ERROR, 1, "Internal error, connectMethod is expected to return a proxy instance;");
      self->error_code = HTTP_MSG_POLICY_SYNTAX;
      z_policy_var_unref(res);
      z_policy_unlock(self->super.thread);
      z_proxy_leave(self);
      return FALSE;
    }
  z_policy_var_unref(res);
  z_policy_unlock(self->super.thread);

  /* release, but don't close fds */
  for (i = EP_CLIENT; i < EP_MAX; i++)
    {
      z_stream_unref(self->super.endpoints[i]);
      self->super.endpoints[i] = NULL;
    }
  z_proxy_return(self, TRUE);
}

static void
http_main(ZProxy *s)
{
  HttpProxy *self = Z_CAST(s, HttpProxy);
  gint rerequest_attempts;

  z_proxy_enter(self);
  self->request_count = 0;
  http_client_stream_init(self);
  /* loop for keep-alive */
  while (1)
    {
      self->error_code = -1;
      /*LOG
        This message reports that Zorp is fetching the request and the
        headers from the client.
       */
      z_proxy_log(self, HTTP_DEBUG, 6, "Fetching request and headers;");
      /* fetch request */
      if (!http_fetch_request(self))
        {
          if (self->error_code == -1)
            self->error_code = HTTP_MSG_CLIENT_SYNTAX;
          goto exit_request_loop;
        }
      if (!z_proxy_loop_iteration(s))
        break;
      
      /*LOG
        This message reports that Zorp is processing the fetched request and
        the headers.
       */
      z_proxy_log(self, HTTP_DEBUG, 6, "processing request and headers;");
      if (!http_process_request(self))
        {
          if (self->error_code == -1)
            self->error_code = HTTP_MSG_CLIENT_SYNTAX;
          goto exit_request_loop;
        }

      if (self->max_keepalive_requests != 0 && 
          self->request_count >= self->max_keepalive_requests - 1)
        {
          /*LOG
            This message reports that the maximum number of requests in a keep-alive loop is
            reached, and Zorp is closing after this request. Check the max_keepalive_request
            attribute.
           */
          z_proxy_log(self, HTTP_POLICY, 3, 
                      "Maximum keep-alive request reached, setting connection mode to close; count='%d', max='%d'", 
                      self->request_count, self->max_keepalive_requests);
          self->connection_mode = HTTP_CONNECTION_CLOSE;
        }

      /*LOG
        This message reports that Zorp is filtering the processed
        request and the headers.
       */
      z_proxy_log(self, HTTP_DEBUG, 6, "Filtering request and headers;");
      if (!http_filter_request(self))
        {
          if (self->error_code == -1)
            self->error_code = HTTP_MSG_POLICY_SYNTAX;
	  goto exit_request_loop;
        }

      /*LOG 
        This message indicates that Zorp is recechecking the HTTP request
        after possible changes performed by the policy layer.
       */
      z_proxy_log(self, HTTP_DEBUG, 6, "Reprocessing filtered request;");
      if (!http_process_filtered_request(self))
        {
          if (self->error_code == -1)
            self->error_code = HTTP_MSG_CLIENT_SYNTAX;
          goto exit_request_loop;
        }

      if (self->server_protocol == HTTP_PROTO_HTTP)
        {
          gboolean retry;
          
          if ((self->request_flags & HTTP_REQ_FLG_CONNECT))
            {
              if (http_handle_connect(self))
                z_proxy_return(self); /* connect method was successful, we can now safely quit */

              goto exit_request_loop;
            }
          
          rerequest_attempts = self->rerequest_attempts;
          while (1)
            {
              retry = FALSE;
              /*LOG
                This message reports that Zorp is sending the filtered request and
                headers, and copies the requests data to the server.
               */
              z_proxy_log(self, HTTP_DEBUG, 6, "Sending request and headers, copying request data;");
              if (!retry && !http_copy_request(self))
                {
                  if (self->error_code == -1)
                    self->error_code = HTTP_MSG_CLIENT_SYNTAX;
                  retry = TRUE;
                }

              /*LOG
                This message reports that Zorp is fetching the response and headers
                from the server.
               */
              z_proxy_log(self, HTTP_DEBUG, 6, "Fetching response and headers;");
              if (!retry && !http_fetch_response(self))
                {
                  if (self->error_code == -1)
                    self->error_code = HTTP_MSG_SERVER_SYNTAX;
                  retry = TRUE;
                }
                
              if (retry && rerequest_attempts > 1)
                {
                  z_proxy_log(self, HTTP_ERROR, 3, "Server request failed, retrying; attempts='%d'", rerequest_attempts);
                  self->force_reconnect = TRUE;
                  self->error_code = -1;
                  rerequest_attempts--;
                  continue;
                }
              else if (retry)
                {
                  goto exit_request_loop;
                }
              else
                {
                  break;
                }
            }
            
          if (!z_proxy_loop_iteration(s))
            goto exit_request_loop;

          /*LOG
            This message reports that Zorp is processing the fetched response
            and the headers.
           */
          z_proxy_log(self, HTTP_DEBUG, 6, "Processing response and headers;");
          if (!http_process_response(self))
            {
              if (self->error_code == -1)
                self->error_code = HTTP_MSG_SERVER_SYNTAX;
              goto exit_request_loop;
            }
          /*LOG
            This message reports that Zorp is filtering the processed
            response and the headers.
           */
          z_proxy_log(self, HTTP_DEBUG, 6, "Filtering response and headers;");
          if (!http_filter_response(self))
            {
              if (self->error_code == -1)
                self->error_code = HTTP_MSG_POLICY_SYNTAX;
              goto exit_request_loop;
            }
          /*LOG
            This message reports that Zorp is sending the filtered
            response and headers, and copies the response data to the client.
           */
          z_proxy_log(self, HTTP_DEBUG, 6, "Copying response and headers, copying response data;");
          if (!http_copy_response(self))
            {
              if (self->error_code == -1)
                self->error_code = HTTP_MSG_SERVER_SYNTAX;
              goto exit_request_loop;
            }
        }
      else if (self->server_protocol == HTTP_PROTO_FTP)
        {
          if (!http_handle_ftp_request(self))
            {
              if (self->error_code == -1)
                self->error_code = HTTP_MSG_FTP_ERROR;
            }
          self->connection_mode = HTTP_CONNECTION_CLOSE;
        }
      else
        {
          /*LOG
            This message indicates an internal error in HTTP proxy. Please
            report this event to the Zorp QA team (at devel@balabit.com).
           */
          z_proxy_log(self, CORE_ERROR, 1, "Internal error, invalid server_protocol; server_protocol='%d'", self->server_protocol);
        }

      if (self->connection_mode == HTTP_CONNECTION_CLOSE)
        goto exit_request_loop;

      if (self->server_connection_mode == HTTP_CONNECTION_CLOSE)
        {
          /* close the server connection, but keep the client connection in-tact */
          self->force_reconnect = TRUE;
        }

      self->request_count++;
      /* NOTE:
       * In keepalive mode we have to disable authentication after the first round.
       */
      if (self->auth)
        {
          z_policy_lock(self->super.thread);

          z_policy_var_unref(self->auth);
          self->auth = NULL;

          z_policy_unlock(self->super.thread);
        }
    }

 exit_request_loop:
  /*LOG
    This message reports that Zorp is exiting the keep-alive loop and
    closing the connection.
   */
  z_proxy_log(self, HTTP_DEBUG, 6, "exiting keep-alive loop;");
  if (self->error_code > 0)
    http_error_message(self, self->error_status, self->error_code, self->error_info);

  /* in some cases the client might still have some data already queued to us, 
   * fetch and ignore that data to avoid the RST sent in these cases 
   */
  http_fetch_buffered_data(self);
  
  if (self->error_code <= 0 && self->reset_on_close)
    {
      int fd;
      
      fd = z_stream_get_fd(self->super.endpoints[EP_CLIENT]);
      if (fd >= 0)
        {
          struct linger l;
          
          l.l_onoff = 1;
          l.l_linger = 0;
          setsockopt(fd, SOL_SOCKET, SO_LINGER, &l, sizeof(l));
        }
      /* avoid z_stream_shutdown in the destroy path */
      z_stream_close(self->super.endpoints[EP_CLIENT], NULL);
      z_stream_unref(self->super.endpoints[EP_CLIENT]);
      self->super.endpoints[EP_CLIENT] = NULL;
    }
  z_proxy_return(self);
}

static gboolean
http_config(ZProxy *s)
{
  HttpProxy *self = Z_CAST(s, HttpProxy);

  http_config_set_defaults(self);

  http_register_vars(self);
  if (Z_SUPER(s, ZProxy)->config(s))
    {
      http_config_init(self);

      z_proxy_ssl_set_force_connect_at_handshake(s, TRUE);

      return TRUE;
    }
  return FALSE;
}

static void
http_proxy_free(ZObject *s)
{
  HttpProxy *self = Z_CAST(s, HttpProxy);
  guint i;

  z_enter();
  for (i = EP_CLIENT; i < EP_MAX; i++)
    http_destroy_headers(&self->headers[i]);
  if (self->request_data)
    z_blob_unref(self->request_data);
  g_string_free(self->old_auth_header, TRUE);
  g_string_free(self->auth_header_value, TRUE);
  g_string_free(self->response_msg, TRUE);
  g_string_free(self->connected_server, TRUE);
  g_string_free(self->remote_server, TRUE);
  g_string_free(self->request_url, TRUE);
  http_destroy_url(&self->request_url_parts);
  /* NOTE: hashes are freed up by pyvars */
  z_poll_unref(self->poll);
  z_proxy_free_method(s);
  z_return();
}

static ZProxy *
http_proxy_new(ZProxyParams *params)
{
  HttpProxy *self;

  z_enter();
  self = Z_CAST(z_proxy_new(Z_CLASS(HttpProxy), params), HttpProxy);
  z_return((&self->super));
}

static void http_proxy_free(ZObject *s);

ZProxyFuncs http_proxy_funcs =
{
  { 
    Z_FUNCS_COUNT(ZProxy),
    http_proxy_free,
  },
  .config = http_config,
  .main = http_main,
  NULL
};

ZClass HttpProxy__class = 
{
  Z_CLASS_HEADER,
  &ZProxy__class,
  "HttpProxy",
  sizeof(HttpProxy),
  &http_proxy_funcs.super
};

gint
zorp_module_init(void)
{
  http_proto_init();
  auth_hash = g_hash_table_new_full(g_str_hash, g_str_equal, g_free, g_free);
  auth_mutex = g_mutex_new();
  z_registry_add("http", ZR_PROXY, http_proxy_new);
  return TRUE;
}

