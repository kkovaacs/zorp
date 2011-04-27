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
 * $Id: plug.c,v 1.89 2004/07/22 09:47:36 bazsi Exp $
 *
 * Author: Balazs Scheidler <bazsi@balabit.hu>
 * Auditor:
 * Last audited version:
 * Notes:
 *
 ***************************************************************************/

#include <zorp/plugsession.h>
#include <zorp/thread.h>
#include <zorp/streamfd.h>
#include <zorp/proxy.h>
#include <zorp/poll.h>
#include <zorp/policy.h>
#include <zorp/thread.h>
#include <zorp/log.h>
#include <zorp/registry.h>
#include <zorp/sockaddr.h>
#include <zorp/io.h>

#include <sys/types.h>
#include <sys/time.h>
#include <unistd.h>
#include <errno.h>
#include <arpa/inet.h>

#define PLUG_DEFAULT_BUFSIZE    1500

#define PLUG_DEBUG "plug.debug"
#define PLUG_ERROR "plug.error"
#define PLUG_POLICY "plug.policy"
#define PLUG_SESSION "plug.session"

typedef struct _PlugProxy
{
  ZProxy super;
  ZPoll *poll;
  ZPlugSessionData session_data;
  ZPlugSession *session;
} PlugProxy;

extern ZClass PlugProxy__class;
            
static gboolean
plug_packet_stat_event(ZPlugSession *session,
                       guint64 client_bytes, guint64 client_pkts, 
                       guint64 server_bytes, guint64 server_pkts,
                       gpointer user_data);
static void
plug_finish(ZPlugSession *session, gpointer user_data);
                       
void
plug_config_set_defaults(PlugProxy *self)
{
  z_proxy_enter(self);

  self->session_data.copy_to_server = TRUE;
  self->session_data.copy_to_client = TRUE;
  self->session_data.timeout = 600000;
  self->session_data.buffer_size = PLUG_DEFAULT_BUFSIZE;
  self->session_data.packet_stats = plug_packet_stat_event;
  self->session_data.finish = plug_finish;
  
  if (self->super.parent_proxy)
    self->session_data.shutdown_soft = TRUE;

  z_proxy_leave(self);
}

void
plug_register_vars(PlugProxy *self)
{
  z_proxy_enter(self);

  z_proxy_var_new(&self->super,
                  "timeout",
                  Z_VAR_GET | Z_VAR_SET_CONFIG | Z_VAR_TYPE_INT,
                  &self->session_data.timeout);

  z_proxy_var_new(&self->super,
                  "copy_to_client",
                  Z_VAR_GET | Z_VAR_SET_CONFIG | Z_VAR_TYPE_INT,
                  &self->session_data.copy_to_client);

  z_proxy_var_new(&self->super,
                  "copy_to_server",
                  Z_VAR_GET | Z_VAR_SET_CONFIG | Z_VAR_TYPE_INT,
                  &self->session_data.copy_to_server);

  z_proxy_var_new(&self->super,
                  "shutdown_soft",
                  Z_VAR_GET | Z_VAR_SET_CONFIG | Z_VAR_TYPE_INT,
                  &self->session_data.shutdown_soft);

  z_proxy_var_new(&self->super,
                  "packet_stats_interval_packet",
                  Z_VAR_GET | Z_VAR_SET_CONFIG | Z_VAR_TYPE_INT,
                  &self->session_data.packet_stats_interval_packet);

  z_proxy_var_new(&self->super,
                  "packet_stats_interval_time",
                  Z_VAR_GET | Z_VAR_SET_CONFIG | Z_VAR_TYPE_INT,
                  &self->session_data.packet_stats_interval_time);

  z_proxy_var_new(&self->super,
                  "buffer_size",
                  Z_VAR_GET | Z_VAR_SET_CONFIG | Z_VAR_TYPE_INT,
                  &self->session_data.buffer_size);

  /* Zorp 1.4 compatibility */
  z_proxy_var_new(&self->super,
                  "packet_stats_interval",
                  Z_VAR_TYPE_ALIAS | Z_VAR_GET | Z_VAR_SET | Z_VAR_GET_CONFIG | Z_VAR_SET_CONFIG,
                  "packet_stats_interval_packet");
  z_proxy_return(self);
}

static gboolean
plug_packet_stat_event(ZPlugSession *session G_GNUC_UNUSED,
                       guint64 client_bytes, guint64 client_pkts, 
                       guint64 server_bytes, guint64 server_pkts,
                       gpointer user_data)
{
  PlugProxy *self = (PlugProxy *) user_data;
  ZPolicyObj *res;
  gboolean called;
  guint resc;

  z_policy_lock(self->super.thread);
  res = z_policy_call(self->super.handler, "packetStats",
                      z_policy_var_build("iiii",
                                         (guint32) client_bytes,
                                         (guint32) client_pkts,
                                         (guint32) server_bytes,
                                         (guint32) server_pkts),
                      &called,
                      self->super.session_id);

  if (called)
    {
      resc = Z_REJECT;
      if (res)
        {
          if (!z_policy_var_parse(res, "i", &resc))
            {
              /*LOG
                This message is logged when the policy layer returned a
                non-integer value in its packetStats() function. packetStats()
                is expected to return Z_REJECT or Z_ACCEPT.
               */
              z_proxy_log(self, PLUG_POLICY, 1, "Invalid return value of packetStats(), integer required;");
            }
          else if (resc != Z_ACCEPT)
            {
              /*LOG
                This message indicates that the verdict returned by the
                packetStats() function requests to terminate the session.
               */
              z_proxy_log(self, PLUG_POLICY, 1, "packetStats() requested to abort session; verdict='%d'", resc);
            }
        }
    }
  else
    {
      resc = Z_ACCEPT;
    }
  z_policy_var_unref(res);
  z_policy_unlock(self->super.thread);
  return resc == Z_ACCEPT;
}

static void
plug_finish(ZPlugSession *session G_GNUC_UNUSED, gpointer user_data)
{
  PlugProxy *self = (PlugProxy *) user_data;
  
  z_proxy_nonblocking_stop(&self->super);
}

static gboolean
plug_request_stack_event(PlugProxy *self, ZStackedProxy **stacked)
{
  ZPolicyObj *res;
  gboolean called;
  gboolean rc = TRUE;

  z_proxy_enter(self);
  z_policy_lock(self->super.thread);
  *stacked = NULL;
  res = z_policy_call(self->super.handler,
                      "requestStack",
                      NULL,
                      &called,
                      self->super.session_id);
  if (res)
    {
      if (res != z_policy_none)
        rc = z_proxy_stack_object(&self->super, res, stacked, NULL);
    }
  else if (called)
    {
      rc = FALSE;
    }
  z_policy_var_unref(res);
  z_policy_unlock(self->super.thread);
  z_proxy_return(self, rc);
}

static gboolean
plug_nonblocking_init(ZProxy *s, ZPoll *poll)
{
  PlugProxy *self = Z_CAST(s, PlugProxy);
  ZStackedProxy *stacked;
  
  z_proxy_enter(self);
  
  if (!z_proxy_connect_server(&self->super, NULL, 0))
    {
      z_proxy_leave(self);
      return FALSE;
    }
    
  if (!plug_request_stack_event(self, &stacked))
    {
      z_proxy_leave(self);
      return FALSE;
    }
  
  self->session = z_plug_session_new(&self->session_data, self->super.endpoints[EP_CLIENT], self->super.endpoints[EP_SERVER], stacked, &self->super);
  if (!self->session)
    {
      z_proxy_leave(self);
      return FALSE;
    }
  z_plug_session_register_vars(self->session, self->super.dict);
  
  if (!z_plug_session_start(self->session, poll))
    {
      z_proxy_leave(self);
      return FALSE;
    }
    
  z_proxy_leave(self);
  return TRUE;
}

static void
plug_nonblocking_deinit(ZProxy *s)
{
  PlugProxy *self = Z_CAST(s, PlugProxy);
  
  if (self->session)
    z_plug_session_cancel(self->session);
}

static gboolean
plug_config(ZProxy *s)
{
  PlugProxy *self = (PlugProxy *) s;

  z_proxy_enter(self);

  plug_config_set_defaults(self);
  plug_register_vars(self);
  if (Z_SUPER(s, ZProxy)->config(s))
    z_proxy_return(self, TRUE);

  z_proxy_return(self, FALSE);
}

ZProxy *
plug_proxy_new(ZProxyParams *params)
{
  PlugProxy *self;
  
  z_enter();
  self = Z_CAST(z_proxy_new(Z_CLASS(PlugProxy), params), PlugProxy);
  self->super.flags |= ZPF_NONBLOCKING;
  
  z_leave();
  return &self->super;
}
    
static void
plug_proxy_free(ZObject *s)
{
  PlugProxy *self = Z_CAST(s, PlugProxy);
  
  z_proxy_enter(self);
  
  z_plug_session_destroy(self->session);
  if (self->poll)
    {
      z_poll_unref(self->poll);
      self->poll = NULL;
    }
    
  z_proxy_free_method(s);
  z_return();
}

ZProxyFuncs plug_proxy_funcs =
{
  { 
    Z_FUNCS_COUNT(ZProxy),
    plug_proxy_free,
  },
  .config = plug_config,
  .startup = NULL,
  .nonblocking_init = plug_nonblocking_init,
  .nonblocking_deinit = plug_nonblocking_deinit,
  .shutdown = NULL,
  .destroy = NULL,
};

ZClass PlugProxy__class = 
{
  Z_CLASS_HEADER,
  &ZProxy__class,
  "PlugProxy",
  sizeof(PlugProxy),
  &plug_proxy_funcs.super
};

gint
zorp_module_init(void)
{
  z_registry_add("plug", ZR_PROXY, plug_proxy_new);
  return TRUE;
}
