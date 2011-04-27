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
 * $Id: pysockaddr.c,v 1.41 2004/09/13 12:26:53 bazsi Exp $
 *
 * Author  : bazsi
 * Auditor : kisza
 * Last audited version: 1.4
 * Notes:
 *
 ***************************************************************************/

#include <zorp/pyproxygroup.h>
#include <zorp/pyproxy.h>

/**
 * z_policy_proxy_group_start:
 * @self this
 * @args Python params (proxy_class, session)
 *
 * Returns:
 */
static ZPolicyObj *
z_policy_proxy_group_start(gpointer user_data, ZPolicyObj *args, ZPolicyObj *kw G_GNUC_UNUSED)
{
  ZProxyGroup *proxy_group = (ZProxyGroup *) user_data;
  ZPolicyObj *proxy_instance;

  if (!z_policy_var_parse(args, "(O)", &proxy_instance))
    return NULL;

  if (!z_policy_proxy_check(proxy_instance))
    {
      PyErr_SetString(PyExc_ValueError, "Expecting Proxy instance as argument");
      return NULL;
    }
  
  if (!z_policy_proxy_bind_implementation(proxy_instance))
    {
      PyErr_SetString(PyExc_RuntimeError, "Error binding proxy implementation");
      return NULL;
    }
  
  if (z_proxy_group_start_session(proxy_group, z_policy_proxy_get_proxy(proxy_instance)))
    {
      return PyInt_FromLong(1);
    }

  z_policy_var_ref(z_policy_none);
  return z_policy_none;
}


/**
 * z_policy_proxy_group_new_instance:
 * @o unused
 * @args Python arguments: 
 *
 * Returns:
 * The new instance
 */
static ZPolicyObj *
z_policy_proxy_group_new_instance(PyObject *o G_GNUC_UNUSED, PyObject *args)
{
  gint max_sessions;
  ZProxyGroup *proxy_group;
  ZPolicyDict *dict;
  ZPolicyObj *res;
  
  if (!PyArg_Parse(args, "(i)", &max_sessions))
    return NULL;

  proxy_group = z_proxy_group_new(max_sessions);

  dict = z_policy_dict_new();
  
  
  /* NOTE: we need to add a reference to proxy_group here as our instance
   * might be freed earlier than the method reference, in a construct like
   * ProxyGroup(1).start(proxy).
   */
  
  z_policy_dict_register(dict, Z_VT_METHOD, "start", Z_VF_READ, z_policy_proxy_group_start, proxy_group, NULL);
  
  z_policy_dict_set_app_data(dict, proxy_group, (GDestroyNotify) z_proxy_group_orphan);
  res = z_policy_struct_new(dict, Z_PST_PROXY_GROUP);
  return res;
}

PyMethodDef z_policy_proxy_group_funcs[] =
{
  { "ProxyGroup", (PyCFunction) z_policy_proxy_group_new_instance, METH_VARARGS, NULL },
  { NULL,      NULL, 0, NULL }   /* sentinel*/
};


/**
 * z_policy_proxy_group_init:
 *
 * Module initialisation
 */
void
z_policy_proxy_group_module_init(void)
{
  Py_InitModule("Zorp.Zorp", z_policy_proxy_group_funcs);
}
