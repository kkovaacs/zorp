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
 * $Id: anypy.c,v 1.28 2003/10/13 09:40:54 bazsi Exp $
 *
 * Author: Bazsi
 * Auditor: Bazsi
 * Last audited version: 1.14
 * Notes:
 *
 ***************************************************************************/
 
#include <zorp/zorp.h>
#include <zorp/proxy.h>
#include <zorp/thread.h>
#include <zorp/policy.h>
#include <zorp/zpython.h>
#include <zorp/pystream.h>
#include <zorp/registry.h>
#include <zorp/log.h>
#include <zorp/streamline.h>

#define ANYPY_ERROR "anypy.error"

typedef struct _AnyPyProxy
{
  ZProxy super;
  guint max_line_length[EP_MAX];
} AnyPyProxy;

extern ZClass AnyPyProxy__class;


/**
 * anypy_stream_init:
 * @self: AnyPyProxy instance
 * 
 * This function is called upon startup to initialize our streams.
 **/

static gboolean
anypy_stream_init(AnyPyProxy *self)
{
  z_proxy_enter(self);
  if (!self->super.endpoints[EP_CLIENT] || !self->super.endpoints[EP_SERVER])
    {
      z_proxy_log(self, ANYPY_ERROR, 2, "Server side not yet connected, unable to init streams;");
      z_proxy_leave(self);
      return FALSE;
    }
  self->super.endpoints[EP_CLIENT] = z_stream_push(self->super.endpoints[EP_CLIENT], z_stream_line_new(NULL, self->max_line_length[EP_CLIENT], ZRL_EOL_CRLF));
  self->super.endpoints[EP_SERVER] = z_stream_push(self->super.endpoints[EP_SERVER], z_stream_line_new(NULL, self->max_line_length[EP_SERVER], ZRL_EOL_CRLF));

  z_proxy_leave(self);
  return TRUE;
}


/**
 * anypy_set_verdict:
 * @self: AnyPyProxy instance
 * @args: Python args argument
 * 
 * sets verdict for the parent proxy
 * args is (verdict,description)
 **/
static ZPolicyObj *
anypy_set_verdict(AnyPyProxy * self, ZPolicyObj *args) 
{
  gint verdict;
  gchar *description;
  ZPolicyObj *res = NULL;

  z_proxy_enter(self);

  if (!z_policy_var_parse_tuple(args, "is", &verdict, &description))
    {
      z_policy_raise_exception_obj(z_policy_exc_value_error, "Invalid arguments.");
      z_proxy_leave(self);
      return NULL;
    }
  if (self->super.parent_proxy)
    {
      ZProxyStackIface *iface;
      iface = z_proxy_find_iface(self->super.parent_proxy, Z_CLASS(ZProxyStackIface));
      if (iface)
        {
          z_proxy_stack_iface_set_verdict(iface, verdict, description);
          z_object_unref(&iface->super);
        }
    }
  z_policy_var_ref(z_policy_none);
  res = z_policy_none;
  z_proxy_leave(self);
  return res;
}

/**
 * anypy_config_set_defaults:
 * @self: AnyPyProxy instance
 *
 * This function initializes various attributes exported to the Python layer
 * for possible modification.
 **/
static void
anypy_config_set_defaults(AnyPyProxy *self)
{
  z_proxy_enter(self);

  self->max_line_length[EP_CLIENT] = 4096;
  self->max_line_length[EP_SERVER] = 4096;

  z_proxy_leave(self);
}

/**
 * anypy_register_vars:
 * @self: AyPyProxy instance
 *
 * This function is called upon startup to export Python attributes.
 **/

static void
anypy_register_vars(AnyPyProxy *self)
{
  z_proxy_enter(self);
  /* method for setting the proxy verdict. It should be used before the first write */
  z_proxy_var_new(&self->super, "set_verdict",
	Z_VAR_TYPE_METHOD | Z_VAR_GET,
	self,anypy_set_verdict);
  /* size of line buffer of the client stream */
  z_proxy_var_new(&self->super, "client_max_line_length",
	Z_VAR_TYPE_INT | Z_VAR_GET | Z_VAR_SET_CONFIG | Z_VAR_GET_CONFIG,
	&self->max_line_length[EP_CLIENT]);
  /* size of line buffer of the server stream */
  z_proxy_var_new(&self->super, "server_max_line_length",
	Z_VAR_TYPE_INT | Z_VAR_GET | Z_VAR_SET_CONFIG | Z_VAR_GET_CONFIG,
	&self->max_line_length[EP_SERVER]);
  z_proxy_leave(self);
}

/**
 * anypy_config:
 * @s: AnyPyProxy instance casted to ZProxy
 *
 * This function is called upon startup to configure the proxy.
 * This calls the the __pre_config__, config and __post_config__ events.
 **/
static gboolean
anypy_config(ZProxy *s)
{
  AnyPyProxy *self = Z_CAST(s, AnyPyProxy);
  
  anypy_config_set_defaults(self);
  anypy_register_vars(self);
  if (Z_SUPER(s, ZProxy)->config(s))
    {
      return TRUE;
    }
  return FALSE;
}

static void
anypy_main(ZProxy * s)
{
  AnyPyProxy *self = Z_CAST(s, AnyPyProxy);
  ZPolicyObj *res;
  gboolean called;

  z_proxy_enter(self);
  if (!z_proxy_connect_server(&self->super, NULL, 0) || !anypy_stream_init(self))
    {
      z_proxy_leave(self);
      return;
    }
  z_policy_lock(self->super.thread);  
  res = z_policy_call(self->super.handler, "proxyThread", NULL, &called, self->super.session_id);
  z_policy_var_unref(res);
  z_policy_unlock(self->super.thread);
  z_proxy_return(self);
}

/**
 * anypy_proxy_new:
 * @params: parameters for the AnyPyProxy class constructor
 *
 * This function is called upon startup to create a new AnyPy proxy.
 **/
ZProxy *
anypy_proxy_new(ZProxyParams *params)
{
  AnyPyProxy *self;
  
  z_enter();
  self = Z_CAST(z_proxy_new(Z_CLASS(AnyPyProxy), params), AnyPyProxy);
  z_return(&self->super);
}

ZProxyFuncs anypy_proxy_funcs =
{
  {
    Z_FUNCS_COUNT(ZProxy),
    NULL
  },
  .config = anypy_config,
  .main = anypy_main,
  NULL
};

ZClass AnyPyProxy__class =
{
  Z_CLASS_HEADER,
  &ZProxy__class,
  "AnyPyProxy",
  sizeof(AnyPyProxy),
  &anypy_proxy_funcs.super,
};

gint
zorp_module_init(void)
{
  z_registry_add("anypy", ZR_PYPROXY, anypy_proxy_new);
  return TRUE;
}
