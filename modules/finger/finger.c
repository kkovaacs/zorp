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
 * $Id: finger.c,v 1.42 2004/07/22 09:02:51 bazsi Exp $
 *
 * Author: Bazsi
 * Auditor:
 * Last audited version:
 * Notes:
 *
 ***************************************************************************/
 
#include <zorp/zorp.h>
#include <zorp/streamline.h>
#include <zorp/proxy.h>
#include <zorp/thread.h>
#include <zorp/registry.h>
#include <zorp/log.h>
#include <zorp/policy.h>

#include <ctype.h>

/* log classes used by this module */

#define FINGER_DEBUG     "finger.debug"
#define FINGER_ERROR     "finger.error"
#define FINGER_POLICY    "finger.policy"
#define FINGER_REQUEST   "finger.request"
#define FINGER_VIOLATION "finger.violation"


#define FINGER_REQ_UNSPEC Z_UNSPEC
#define FINGER_REQ_ACCEPT Z_ACCEPT
#define FINGER_REQ_DROP   Z_DROP
#define FINGER_REQ_REJECT Z_REJECT
#define FINGER_REQ_ABORT  Z_ABORT

/*
 * Finger proxy class.
 */
typedef struct _FingerProxy
{
  ZProxy super;
  gint timeout;
  gboolean long_req;
  gint max_hop_count;
  guint max_line_length;
  guint max_username_length;
  guint max_hostname_length;
  gboolean strict_username_check;
  GString *username;
  GString *hostnames;
  GString *response_header;
  GString *response_footer;
} FingerProxy;

extern ZClass FingerProxy__class;          

/**
 * finger_config_set_defaults:
 * @self: FingerProxy instance
 * 
 * Fills in our state with default values.
 **/
static void
finger_config_set_defaults(FingerProxy *self)
{
  z_proxy_enter(self);
  self->max_line_length = 132;
  self->max_username_length = 8;
  self->max_hostname_length = 30;
  self->max_hop_count = 0;
  self->strict_username_check = TRUE;
  self->username = g_string_sized_new(32);
  self->hostnames = g_string_sized_new(0);
  self->response_header = g_string_sized_new(0);
  self->response_footer = g_string_sized_new(0);
  self->timeout = 30000;
  z_proxy_return(self);
}

/**
 * finger_register_vars:
 * @self: FingerProxy instance
 *
 * Registers variables exported to the policy layer.
 **/
static void
finger_register_vars(FingerProxy *self)
{
  z_proxy_enter(self);
#if 0
  z_polict_dict_register(self->super.dict, 
                         Z_VT_INT, "timeout", Z_VF_READ | Z_VF_CFG_RW, &self->timeout, NULL,
                         Z_VT_INT, "max_line_length", Z_VF_READ | Z_VF_CFG_RW, &self->max_line_length, NULL,
                         Z_VT_INT, "max_username_length", Z_VF_READ | Z_VF_CFG_RW, &self->max_username_length, NULL,
                         Z_VT_INT, "max_hostname_length", Z_VF_READ | Z_VF_CFG_RW, &self->max_hostname_length, NULL,
                         Z_VT_INT, "max_hop_count", Z_VF_READ | Z_VF_CFG_RW, &self->max_hop_count, NULL,
#endif

  z_proxy_var_new(&self->super, "timeout",
                  Z_VAR_GET | Z_VAR_SET_CONFIG | Z_VAR_TYPE_INT,
                  &self->timeout);
                  
  z_proxy_var_new(&self->super, "max_line_length",
                  Z_VAR_GET | Z_VAR_SET_CONFIG | Z_VAR_TYPE_INT,
                  &self->max_line_length);
                  
  z_proxy_var_new(&self->super, "max_username_length",
                  Z_VAR_GET | Z_VAR_SET_CONFIG | Z_VAR_TYPE_INT,
                  &self->max_username_length);
                  
  z_proxy_var_new(&self->super, "max_hostname_length",
                  Z_VAR_GET | Z_VAR_SET_CONFIG | Z_VAR_TYPE_INT,
                  &self->max_hostname_length);
                  
  z_proxy_var_new(&self->super, "max_hop_count",
                  Z_VAR_GET | Z_VAR_SET_CONFIG | Z_VAR_TYPE_INT,
                  &self->max_hop_count);
                  
  z_proxy_var_new(&self->super, "request_detailed",
                  Z_VAR_GET | Z_VAR_SET | Z_VAR_TYPE_INT,
                  &self->long_req);                  
  z_proxy_var_new(&self->super, "long_request",
                  Z_VAR_GET | Z_VAR_SET | Z_VAR_TYPE_ALIAS,
                  "request_detailed");
                  
  z_proxy_var_new(&self->super, "request_username",
                  Z_VAR_GET | Z_VAR_SET | Z_VAR_TYPE_STRING,
                  self->username);
  z_proxy_var_new(&self->super, "username",
                  Z_VAR_GET | Z_VAR_SET | Z_VAR_TYPE_ALIAS,
                  "request_username");
                  
  z_proxy_var_new(&self->super, "request_hostnames",
                  Z_VAR_GET | Z_VAR_SET | Z_VAR_TYPE_STRING,
                  self->hostnames);
  z_proxy_var_new(&self->super, "hostnames",
                  Z_VAR_GET | Z_VAR_SET | Z_VAR_TYPE_ALIAS,
                  "request_hostnames");
                  
  z_proxy_var_new(&self->super, "response_header",
                  Z_VAR_GET | Z_VAR_SET | Z_VAR_SET_CONFIG | Z_VAR_TYPE_STRING,
                  self->response_header);
                  
  z_proxy_var_new(&self->super, "response_footer",
                  Z_VAR_GET | Z_VAR_SET | Z_VAR_SET_CONFIG | Z_VAR_TYPE_STRING,
                  self->response_footer);

  z_proxy_var_new(&self->super, "strict_username_check",
                  Z_VAR_GET | Z_VAR_SET_CONFIG | Z_VAR_TYPE_INT,
                  &self->strict_username_check);
  z_proxy_return(self);
}

/**
 * finger_init_client_stream:
 * @self: FingerProxy instance
 *
 * Initialize our client stream. We allocate a readline instance so 
 * that we can fetch input line by line.
 **/
static gboolean
finger_init_client_stream(FingerProxy *self)
{
  ZStream *tmpstream;
  
  z_proxy_enter(self);
  self->super.endpoints[EP_CLIENT]->timeout = self->timeout;
  tmpstream = self->super.endpoints[EP_CLIENT];
  self->super.endpoints[EP_CLIENT] = z_stream_line_new(tmpstream, self->max_line_length, ZRL_EOL_CRLF);
  z_stream_unref(tmpstream);
  z_proxy_return(self, TRUE);
}

/**
 * finger_init_server_stream:
 * @self: FingerProxy instance
 *
 * Initialize our server stream. Exit with an error if our server side
 * is not connected. (ie NULL)
 **/
static gboolean
finger_init_server_stream(FingerProxy *self)
{
  ZStream *tmpstream;
  
  z_proxy_enter(self);
  if (!self->super.endpoints[EP_SERVER])
    z_proxy_return(self, FALSE);
  self->super.endpoints[EP_SERVER]->timeout = self->timeout;
  tmpstream = self->super.endpoints[EP_SERVER];
  self->super.endpoints[EP_SERVER] = z_stream_line_new(tmpstream, self->max_line_length, ZRL_EOL_CRLF);
  z_stream_unref(tmpstream);
  z_proxy_return(self, TRUE);
}

/**
 * finger_fetch_request:
 * @self: FingerProxy instance
 *
 * Read and process a request.
 **/
static gboolean
finger_fetch_request(FingerProxy *self)
{
  gchar *p, *line, *user;
  gint left, hop_count, userlen;
  gsize line_length;
  gint res;
  gboolean fetch_user = TRUE;
  guint hostlen = 0;
  
  z_proxy_enter(self);
  res = z_stream_line_get(self->super.endpoints[EP_CLIENT], &line, &line_length, NULL);
  if (res != G_IO_STATUS_NORMAL)
    {
      /*LOG
        This message is appears when zorp cannot read finger request
       */
      z_proxy_log(self, FINGER_ERROR, 1, "Error reading request;");
      z_proxy_return(self, FALSE);
    }
  
  /*LOG
    This message is say about read finger request
   */
  z_proxy_log(self, FINGER_REQUEST, 6, "Request details; req='%.*s'", (gint) line_length, line);
  p = line;
  left = line_length;
  self->long_req = FALSE;
  while (*p == ' ' && left)
    {
      p++;
      left--;
    }
  if (*p == '/')
    {
      p++;
      left--;
      if (*p == 'W')
        {
          self->long_req = TRUE;
          p++;
          left--;
        }
      else
        {
          /*LOG
            This message appear when zorp cannot parse request
           */
          z_proxy_log(self, FINGER_VIOLATION, 1, "Parse error, dropping request; req='%.*s'", (gint) line_length, line);
          z_proxy_return(self, FALSE);
        }
    }
  while (*p == ' ' && left)
    {
      p++;
      left--;
    }
  hop_count = 0;
  user = p;
  userlen = left;
  g_string_truncate(self->username, 0);
  g_string_truncate(self->hostnames, 0);
  while (*p && left)
    {
      if (*p == '@')
        {
          if (self->max_hop_count != -1)
            {
              hop_count++;
              if (hop_count > self->max_hop_count)
                break;
            }
          fetch_user = FALSE;
          hostlen = 0;
        }
      if (self->strict_username_check &&
          !(isalnum(*p) || *p == '_' || *p == '@' || *p == '.' || *p == '-'))
        {
          /*LOG
            This message say that zorp found an invalid character
            in finger request.
           */
          z_proxy_log(self, FINGER_VIOLATION, 1, "Invalid character, dropping request; line='%.*s'", (gint) line_length, line);
          z_proxy_return(self, FALSE);
        }
      if (fetch_user)
        {
          g_string_append_c(self->username, *p);
          if (self->username->len > self->max_username_length)
            {
              /*LOG
                This message is about too long username found
                in the request.
               */
              z_proxy_log(self, FINGER_VIOLATION, 1, "Username too long, dropping request; line='%.*s'", (gint) line_length, line);
              z_proxy_return(self, FALSE);
            }
        }
      else
        {
          g_string_append_c(self->hostnames, *p);
          if (hostlen > self->max_hostname_length)
            {
              /*LOG
                This message is appear when a too long hostname found
                in the request horname chain.
               */
              z_proxy_log(self, FINGER_VIOLATION, 1, "One hostname is too long in hostname chain, dropping request; req='%.*s'", (gint) line_length, line);
              z_proxy_return(self, FALSE);
            }
          hostlen++;
        }
      p++;
      left--;
    }
  z_proxy_return(self, TRUE);
}

/**
 * finger_send_request:
 * @self: FingerProxy instance
 *
 * Construct and send a request to the server based on the state
 * stored by finger_fetch_request().
 **/
static gboolean
finger_send_request(FingerProxy *self)
{
  gchar request[self->username->len + self->hostnames->len + 6];
  gsize bytes_written;
  
  z_proxy_enter(self);
  if (self->long_req)
    {
      if (self->username->len > 0)
        {
          if (self->hostnames->len > 0)
            g_snprintf(request, sizeof(request), "/W %s%s\r\n",
                       self->username->str,
                       self->hostnames->str);
          else
            g_snprintf(request, sizeof(request), "/W %s\r\n",
                       self->username->str);
        }
      else
        {
          if (self->hostnames->len > 0)
            g_snprintf(request, sizeof(request), "/W %s\r\n",
                       self->hostnames->str);
          else
            g_snprintf(request, sizeof(request), "/W\r\n");
        }
    }
  else
    {
      if (self->username->len > 0)
        {
          if (self->hostnames->len > 0)
            g_snprintf(request, sizeof(request), "%s%s\r\n",
                       self->username->str,
                       self->hostnames->str);
          else
            g_snprintf(request, sizeof(request), "%s\r\n",
                       self->username->str);
        }
      else
        {
          if (self->hostnames->len > 0)
            g_snprintf(request, sizeof(request), "%s\r\n",
                       self->hostnames->str);
          else
            g_snprintf(request, sizeof(request), "\r\n");
        }
    }
  
  if (z_stream_write(self->super.endpoints[EP_SERVER],
                     request,
                     strlen(request),
                     &bytes_written,
                     NULL) != G_IO_STATUS_NORMAL)
    {
      /*LOG
        This message appear when some error
        found in server side.
       */
      z_proxy_log(self, FINGER_ERROR, 1, "Error write request;");
      z_proxy_return(self, FALSE);
    }
  z_proxy_return(self, TRUE);
}

/**
 * finger_copy_response:
 * @self: FingerProxy instance
 *
 * Copy server's response to the client.
 *
 **/
static gboolean
finger_copy_response(FingerProxy *self)
{
  gsize bytes_written;
  gint res = G_IO_STATUS_ERROR;
  
  z_proxy_enter(self);
  if (self->response_header->len &&
      z_stream_write(self->super.endpoints[EP_CLIENT],
                     self->response_header->str,
                     self->response_header->len,
                     &bytes_written,
                     NULL) != G_IO_STATUS_NORMAL)
    {
      /*LOG
        This message appear when some error
        found in client side when writting the header.
       */
      z_proxy_log(self, FINGER_ERROR, 1, "Error write request;");
      z_proxy_return(self, FALSE);
    }

  while (1)
    {
      gchar *line;
      gsize line_len;
      gchar *response;
      
      if (!z_proxy_loop_iteration(&self->super))
        break;
      
      res = z_stream_line_get(self->super.endpoints[EP_SERVER], &line, &line_len, NULL);
      if (res != G_IO_STATUS_NORMAL)
        /* EOF or read error */
        break;

      response = alloca(line_len + 3);
      memcpy(response, line, line_len);
      strcpy(response + line_len, "\r\n");
      if (z_stream_write(self->super.endpoints[EP_CLIENT],
                         response,
                         line_len + 2,
                         &bytes_written,
                         NULL) != G_IO_STATUS_NORMAL)
        {
          /*LOG
            This message appear when some error
            found in client side when writting the response.
           */
          z_proxy_log(self, FINGER_ERROR, 1, "Error write request;");
          z_proxy_return(self, FALSE);
        }

    }
  if (res != G_IO_STATUS_ERROR &&
      self->response_footer->len &&
      z_stream_write(self->super.endpoints[EP_CLIENT],
                     self->response_footer->str,
                     self->response_footer->len,
                     &bytes_written,
                     NULL) != G_IO_STATUS_NORMAL)
    {
      /*LOG
        This message appear when some error
        found in client side when writting the footer.
       */
      z_proxy_log(self, FINGER_ERROR, 1, "Error write request;");
      z_proxy_return(self, FALSE);
    }
  z_proxy_return(self, TRUE);
}

/**
 * finger_query_policy:
 * @self: FingerProxy instance
 *
 * Check the policy about the current request.
 **/
static gboolean
finger_query_policy(FingerProxy *self)
{
  char *errmsg = "Policy violation, request denied.\r\n";
  gsize bytes_written;
  gint res;
  
  z_proxy_enter(self);
  z_policy_lock(self->super.thread);
  res = z_policy_event(self->super.handler, "fingerRequest", z_policy_var_build("(ss)", self->username->str, self->hostnames->str), self->super.session_id);
  switch (res)
    {
    case FINGER_REQ_UNSPEC:
    case FINGER_REQ_REJECT:
    case FINGER_REQ_ABORT:
      /*LOG
        This message is about administrator decision to reject the
        finger session.
       */
      z_proxy_log(self, FINGER_POLICY, 2, "Policy violation, abort session;");
      z_stream_write(self->super.endpoints[EP_CLIENT],
                     errmsg,
                     strlen(errmsg),
                     &bytes_written,
                     NULL);
      /* fallthrough */
      
    case FINGER_REQ_DROP:
      if (res == Z_DROP)
        {
          /*LOG
            This message is about administrator decision to drop
            finger session.
           */
          z_proxy_log(self, FINGER_POLICY, 2, "Policy violation, drop session;");
        }
      z_policy_unlock(self->super.thread);
      z_proxy_return(self, FALSE);

    case FINGER_REQ_ACCEPT:
    default:
      break;
    }
  z_policy_unlock(self->super.thread);
  z_proxy_return(self, TRUE);
}

/**
 * finger_config:
 **/
static gboolean
finger_config(ZProxy *s)
{
  FingerProxy *self = Z_CAST(s, FingerProxy);
  finger_config_set_defaults(self);  
  finger_register_vars(self);
  return Z_SUPER(s, ZProxy)->config(s);
}


/**
 * finger_main:
 * @s: FingerProxy instance
 *
 * main proxy routine.
 **/
static void
finger_main(ZProxy *s)
{
  FingerProxy *self = Z_CAST(s, FingerProxy);
 
  z_proxy_enter(self);
  if (!finger_init_client_stream(self))
    z_proxy_return(self);

  /*LOG
    This debug message is about proxy state when start to
    fetching request
   */
  z_proxy_log(self, FINGER_DEBUG, 6, "fetching request;");
  if (!finger_fetch_request(self))
    {
      char *errmsg = "Finger protocol or disallowed protocol element, request denied.\r\n";
      gsize bytes_written;
      
      z_stream_write(self->super.endpoints[EP_CLIENT],
                     errmsg,
                     strlen(errmsg),
                     &bytes_written,
                     NULL);
      z_proxy_return(self);
    }
  
  /*LOG
    This debug message is about proxy state when finger
    fetched request and asking policy about it
   */
  z_proxy_log(self, FINGER_DEBUG, 6, "asking policy;");
  if (!finger_query_policy(self))
    z_proxy_return(self);
  
  /*LOG
    This debug message is about proxy state when finger
    start connect to server.
   */
  z_proxy_log(self, FINGER_DEBUG, 6, "connecting server;");
  /* this sets the server side endpoint if successful */
  if (!z_proxy_connect_server(&self->super, NULL, 0))
    z_proxy_return(self);

  if (!finger_init_server_stream(self))
    z_proxy_return(self);
  
  /*LOG
    This debug message is about proxy state when finger
    start send the request to server.
   */
  z_proxy_log(self, FINGER_DEBUG, 6, "sending request;");
  if (!finger_send_request(self))
    z_proxy_return(self);
  
  /*LOG
    This debug message is about proxy state when finger
    start to copy server answer to client.
   */
  z_proxy_log(self, FINGER_DEBUG, 6, "copying response;");
  if (!finger_copy_response(self))
    z_proxy_return(self);

  /*LOG
    This debug message is about proxy state when finger
    stop it's work.
   */
  z_proxy_log(self, FINGER_DEBUG, 6, "everything is done;");
  z_proxy_return(self);

}

/**
 * finger_proxy_new:
 * @params: ZProxyParams structure
 *
 * Finger proxy constructor. Allocates and initializes a proxy instance,
 * starts proxy thread.
 **/
static ZProxy *
finger_proxy_new(ZProxyParams *params)
{
  FingerProxy  *self;
  
  z_enter();
  self = Z_CAST(z_proxy_new(Z_CLASS(FingerProxy), params), FingerProxy);
  z_return((ZProxy *) self);
}

ZProxyFuncs finger_proxy_funcs =
{
  { 
    Z_FUNCS_COUNT(ZProxy),
    NULL
  },
  .config = finger_config,
  .main = finger_main,
  NULL
};


ZClass FingerProxy__class = 
{
  Z_CLASS_HEADER,
  &ZProxy__class,
  "FingerProxy",
  sizeof(FingerProxy),
  &finger_proxy_funcs.super
};


/*+

  Module initialization function. Registers a new proxy type.
  
  +*/
gint
zorp_module_init(void)
{
  z_registry_add("finger", ZR_PROXY, finger_proxy_new);
  return TRUE;
}
