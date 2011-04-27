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
 * $Id: whois.c,v 1.30 2004/07/22 10:24:02 bazsi Exp $
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
#include <zorp/proxy.h>

#include <ctype.h>

/* log classes used by this module */

#define WHOIS_DEBUG "whois.debug"
#define WHOIS_ERROR "whois.error"
#define WHOIS_POLICY "whois.policy"
#define WHOIS_REQUEST "whois.request"

/*+

  State information of the Whois proxy.

  +*/
typedef struct _WhoisProxy
{
  ZProxy super;
  gint timeout;
  gint max_request_length;
  gint max_line_length;
  GString *request;
  GString *response_header;
  GString *response_footer;
} WhoisProxy;

extern ZClass WhoisProxy__class;



/*+

  Fill in our state with default values.

  +*/
static void
whois_config_set_defaults(WhoisProxy *self)
{
  z_proxy_enter(self);
  self->max_request_length = 128;
  self->max_line_length = 132;
  self->request = g_string_sized_new(0);
  self->response_header = g_string_sized_new(0);
  self->response_footer = g_string_sized_new(0);
  self->timeout = 30000;
  z_proxy_return(self);
}

/*+

  Register variables exported to the policy layer.

  +*/
static void
whois_register_vars(WhoisProxy *self)
{
  z_proxy_enter(self);
  z_proxy_var_new(&self->super, "timeout", Z_VAR_GET | Z_VAR_SET_CONFIG | Z_VAR_TYPE_INT, &self->timeout);
  z_proxy_var_new(&self->super, "max_line_length", Z_VAR_GET | Z_VAR_SET_CONFIG | Z_VAR_TYPE_INT, &self->max_line_length);
  z_proxy_var_new(&self->super, "max_request_length", Z_VAR_GET | Z_VAR_SET_CONFIG | Z_VAR_TYPE_INT, &self->max_request_length);
  z_proxy_var_new(&self->super, "request", Z_VAR_GET | Z_VAR_SET | Z_VAR_TYPE_STRING, self->request);
  z_proxy_var_new(&self->super, "response_header", Z_VAR_GET | Z_VAR_SET | Z_VAR_SET_CONFIG | Z_VAR_TYPE_STRING, self->response_header);
  z_proxy_var_new(&self->super, "response_footer", Z_VAR_GET | Z_VAR_SET | Z_VAR_SET_CONFIG | Z_VAR_TYPE_STRING, self->response_footer);
  z_proxy_return(self);
}

/*+

  Initialize config that python gave us. For now it's empty.

  +*/
static void
whois_config_init(WhoisProxy *self G_GNUC_UNUSED)
{
  /* should initialize self based on settings previously set by the config event handler */
}

/*+

  Initialize our client stream. We allocate a readline instance so 
  that we can fetch input line by line.

  +*/
static gboolean
whois_init_client_stream(WhoisProxy *self)
{
  ZStream *tmpstream;
  
  z_proxy_enter(self);
  self->super.endpoints[EP_CLIENT]->timeout = self->timeout;
  tmpstream = self->super.endpoints[EP_CLIENT];
  self->super.endpoints[EP_CLIENT] = z_stream_line_new(tmpstream, self->max_line_length, ZRL_EOL_CRLF);
  z_stream_unref(tmpstream);
  z_proxy_return(self, TRUE);
}

/*+

  Initialize our server stream. Exit with an error if our server side
  is not connected. (ie NULL)

  +*/
static gboolean
whois_init_server_stream(WhoisProxy *self)
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

/*+ 

  Read and process a request.
  
  +*/
static gboolean
whois_fetch_request(WhoisProxy *self)
{
  gchar *line;
  gsize line_length;
  gint res;

  z_proxy_enter(self);  
  res = z_stream_line_get(self->super.endpoints[EP_CLIENT],
                          &line,
                          &line_length,
                          NULL);
  if (res != G_IO_STATUS_NORMAL)
    {
      z_proxy_log(self, WHOIS_ERROR, 1, "Empty request received or I/O error;");
      z_proxy_return(self, FALSE);
    }
    
  z_proxy_log(self, WHOIS_REQUEST, 7, "Incoming request; line='%.*s'", (gint) line_length, line);
  if (line_length > (guint) self->max_request_length)
    {
      z_proxy_log(self, WHOIS_REQUEST, 6, "Request too long; length='%zd', max_request_length='%d'", line_length, self->max_request_length);
      z_proxy_return(self, FALSE);
    }
  
  g_string_truncate(self->request, 0);
  g_string_append_len(self->request, line, line_length);
  z_proxy_return(self, TRUE);
}

/*+

  Construct and send a request to the server based on the state
  stored by whois_fetch_request().

  +*/
static gboolean
whois_send_request(WhoisProxy *self)
{
  gchar request[self->request->len + 6];
  gsize bytes_written;
  
  z_proxy_enter(self);
  g_snprintf(request, sizeof(request), "%s\r\n", self->request->str);
  if (z_stream_write(self->super.endpoints[EP_SERVER],
                     request,
                     strlen(request),
                     &bytes_written,
                     NULL) != G_IO_STATUS_NORMAL)
    z_proxy_return(self, FALSE);

  z_proxy_return(self, TRUE);
}

/*+
 
  Copy server's response to the client.

  +*/
static gboolean
whois_copy_response(WhoisProxy *self)
{
  gsize bytes_written;
  
  z_proxy_enter(self);
  if (self->response_header->len &&
      z_stream_write(self->super.endpoints[EP_CLIENT],
                     self->response_header->str,
                     self->response_header->len,
                     &bytes_written,
                     NULL) != G_IO_STATUS_NORMAL)
    z_proxy_return(self, FALSE);

  while (1)
    {
      gchar *line;
      gsize line_len;
      gint res;
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
        z_proxy_return(self, FALSE);
    }
  if (self->response_footer->len &&
      z_stream_write(self->super.endpoints[EP_CLIENT],
                     self->response_footer->str,
                     self->response_footer->len,
                     &bytes_written,
                     NULL) != G_IO_STATUS_NORMAL)
    z_proxy_return(self, FALSE);

  z_proxy_return(self, TRUE);
}

static gboolean
whois_query_policy(WhoisProxy *self)
{
  char *errmsg = "Policy violation, request denied.\r\n";
  gsize bytes_written;
  gint res;

  z_proxy_enter(self);  
  z_policy_lock(self->super.thread);
  res = z_policy_event(self->super.handler, "whoisRequest", z_policy_var_build("(s)", self->request->str), self->super.session_id);
  switch (res)
    {
    case Z_REJECT:
    case Z_ABORT:
      z_stream_write(self->super.endpoints[EP_CLIENT],
                     errmsg,
                     strlen(errmsg),
                     &bytes_written,
                     NULL);
      /* fallthrough */
      
    case Z_DROP:
      z_policy_unlock(self->super.thread);
      z_proxy_return(self, FALSE);

    case Z_UNSPEC:
    case Z_ACCEPT:
    default:
      break;
    }
  z_policy_unlock(self->super.thread);
  z_proxy_return(self, TRUE);
}

static gboolean
whois_config(ZProxy *s)
{
  WhoisProxy *self = Z_CAST(s, WhoisProxy);
  gboolean success = FALSE;

  z_proxy_enter(self);
  whois_config_set_defaults(self);  
  whois_register_vars(self);
  if (Z_SUPER(s, ZProxy)->config(s))
    {
      whois_config_init(self);
      success = TRUE;
    }
  z_proxy_return(self, success);
}

static void
whois_main(ZProxy *s)
{
  WhoisProxy *self = Z_CAST(s, WhoisProxy);

  z_proxy_enter(self);  
  if (!whois_init_client_stream(self))
    z_proxy_return(self);

  z_proxy_log(self, WHOIS_DEBUG, 6, "fetching request;");
  if (!whois_fetch_request(self))
    {
      char *errmsg = "Whois protocol error or disallowed protocol element, request denied.\r\n";
      gsize bytes_written;
      
      z_stream_write(self->super.endpoints[EP_CLIENT],
                     errmsg,
                     strlen(errmsg),
                     &bytes_written,
                     NULL);
      z_proxy_return(self);
    }
  
  z_proxy_log(self, WHOIS_DEBUG, 6, "checking policy;");
  if (!whois_query_policy(self))
    z_proxy_return(self);
  
  z_proxy_log(self, WHOIS_DEBUG, 6, "connecting to server;");
  /* this sets the server side endpoint if successful */
  if (!z_proxy_connect_server(&self->super, NULL, 0))
    z_proxy_return(self);

  if (!whois_init_server_stream(self))
    z_proxy_return(self);
    
  z_proxy_log(self, WHOIS_DEBUG, 6, "sending request;");
  if (!whois_send_request(self))
    z_proxy_return(self);
    
  z_proxy_log(self, WHOIS_DEBUG, 6, "copying response;");
  if (!whois_copy_response(self))
    z_proxy_return(self);

  z_proxy_log(self, WHOIS_DEBUG, 6, "processing done;");
  z_proxy_return(self);
}


/*+

  Whois proxy constructor. Allocates and initializes a proxy instance,
  starts proxy thread.

  +*/
static ZProxy *
whois_proxy_new(ZProxyParams *params)
{
  WhoisProxy  *self;
  
  z_enter();
  self = Z_CAST(z_proxy_new(Z_CLASS(WhoisProxy), params), WhoisProxy);
  z_return((ZProxy *) self);
}

static void
whois_proxy_free(ZObject *s)
{
  WhoisProxy *self G_GNUC_UNUSED = Z_CAST(s, WhoisProxy);
  
  z_enter();
  z_proxy_free_method(s);
  z_return();
}

ZProxyFuncs whois_proxy_funcs =
{
  { 
    Z_FUNCS_COUNT(ZProxy),
    whois_proxy_free,
  },
  .config = whois_config,
  .main = whois_main,
  NULL
};

ZClass WhoisProxy__class = 
{
  Z_CLASS_HEADER,
  &ZProxy__class,
  "WhoisProxy",
  sizeof(WhoisProxy),
  &whois_proxy_funcs.super
};


/*+

  Module initialization function. Registers a new proxy type.
  
  +*/
gint
zorp_module_init(void)
{
  z_registry_add("whois", ZR_PROXY, whois_proxy_new);
  return TRUE;
}
