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
 * $Id: pyproxy.c,v 1.60 2004/07/26 12:31:58 sasa Exp $
 *
 * Author  : Bazsi
 * Auditor : kisza
 * Last audited version: 1.15
 * Notes:
 *
 ***************************************************************************/

#include <zorp/pyproxy.h>
#include <zorp/proxy.h>
#include <zorp/policy.h>
#include <zorp/registry.h>
#include <zorp/modules.h>
#include <zorp/pystream.h>
#include <zorp/log.h>
#include <zorp/szig.h>
#include <zorp/notification.h>

/*
  ZorpProxy is the Python interface to ZProxy.
  */
struct _ZPolicyProxy
{
  PyObject_HEAD
  ZProxy *proxy;
  ZProxy *parent_proxy;
  ZPolicyObj *client_stream;
  ZPolicyObj *session_id;
  ZPolicyObj *module_name;
  ZPolicyObj *proxy_name;
};

/**
 * z_policy_proxy_get_proxy:
 * @obj this
 *
 * Get the embedded proxy.
 *
 * Returns:
 * The embedded proxy
 */
ZProxy *
z_policy_proxy_get_proxy(PyObject *obj)
{
  return ((ZPolicyProxy *) obj)->proxy;
}

/**
 * z_policy_proxy_bind:
 * @self this
 * @args Python args: module_name, session_id, client, parent
 *
 * Constructor of ZPolicyProxy. Class is an abstract one, so the instance
 * already exists, only initialisation has to be done.
 *
 * Searches the registry for module_name, and creates its (C-side) self->proxy
 * using the returned constructor. For details see documentation about the
 * instantiation and invocation of custom proxies.
 *
 * Returns:
 * NULL on error, PyNone on success.
 */ 
gboolean
z_policy_proxy_bind_implementation(PyObject *s)
{
  ZPolicyProxy *self = (ZPolicyProxy *) s;
  ZProxyParams params;
  gpointer proxy_create;
  int proxy_type = ZR_NONE;
  gchar *module_name;
  gchar *proxy_name;

  z_enter();

  if (self->proxy)
    z_return(TRUE);

  module_name = PyString_AsString(self->module_name);
  proxy_name = PyString_AsString(self->proxy_name);

  proxy_create = z_registry_get(proxy_name, &proxy_type);
  if (!proxy_create)
    {
      if (!z_load_module(module_name))
        {
          /*LOG
          This message indicates that Zorp was unable to find the required proxy module.
          Check your installation, or contact your Zorp support for assistance.
          */
          z_log(NULL, CORE_ERROR, 1, "Cannot find proxy module; module='%s', proxy='%s, type='%d'",
                module_name, proxy_name, proxy_type);
          z_leave();
          return FALSE;
        }
      proxy_create = z_registry_get(proxy_name, &proxy_type);
    }
  if (!proxy_create || (proxy_type != ZR_PROXY && proxy_type != ZR_PYPROXY))
    {
      /*LOG
        This message indicates that Zorp was unable to find the required proxy module.
        Check your installation, or contact your Zorp support for assistance.
       */
      z_log(NULL, CORE_ERROR, 1, "Cannot find proxy module; module='%s', proxy='%s, type='%d'", module_name, proxy_name, proxy_type);
      z_leave();
      return FALSE;
    }
  
  params.session_id = PyString_AsString(self->session_id);
  params.pyclient = self->client_stream;
  params.client = z_policy_stream_get_stream(self->client_stream);
  params.handler = (ZPolicyObj *) self;
  params.parent = self->parent_proxy;
  
  /* params.client is referenced through self->client_stream, we need to
   * unref it here as the proxy constructor will take its own reference
   */
  z_stream_unref(params.client);

  Py_BEGIN_ALLOW_THREADS;
  self->proxy = (*(ZProxyCreateFunc) proxy_create)(&params);
  Py_END_ALLOW_THREADS;
  

  z_leave();
  return TRUE;
}

/**
 * z_policy_proxy_getattr:
 * @self this
 * @name Attribute name
 *
 * Get an attribute of the proxy. Actually there is nothing to get from the
 * abstract ZPolicyProxy, rather from its descendants, so if the embedded proxy
 * is initialised, its vars (or session_vars->vars) is searched for the name.
 *
 * Returns:
 * The attribute value
 */
static PyObject *
z_policy_proxy_getattr(ZPolicyProxy *self, PyObject *name_obj)
{
  PyObject *v = NULL;

  g_assert(PyString_Check(name_obj));

  /* NOTE: we don't support fetching proxy attributes as long as the proxy
   * is not initialized */
  if (self->proxy && self->proxy->dict && z_proxy_get_state(self->proxy) >= ZPS_CONFIG)
    {
      const gchar *name = PyString_AS_STRING(name_obj);
      
      if (strcmp(name, "proxy_started") == 0)
        {
          return PyInt_FromLong(1);
        }

      v = z_policy_dict_get_value(self->proxy->dict, z_proxy_get_state(self->proxy) == ZPS_CONFIG, name);
      if (v)
        {
          if (z_log_enabled(CORE_DEBUG, 6))
            {
              PyObject *repr = PyObject_Repr(v);
              /*LOG
                This message reports that the given proxy-exported 
                attribute was fetched, and it contained the also given value.
               */
              z_log(self->proxy->session_id, CORE_DEBUG, 6, "Attribute fetched; attribute='%s', value='%s'", name, PyString_AsString(repr));
              Py_XDECREF(repr);
            }
          return v;
        }
    }
  
  return PyObject_GenericGetAttr((PyObject *) self, name_obj);
}

/**
 * z_policy_proxy_setattr:
 * @self this
 * @name Attribute name
 * @value New attribute value
 *
 * Set an attribute of the proxy. The recognised attribute names are the same
 * as for _getattr, the type of @value is the same as _getattr would return
 * for @name.
 *
 * Returns:
 * The attribute value
 */
static gint
z_policy_proxy_setattr(ZPolicyProxy *self, PyObject *name_obj, PyObject *value)
{
  g_assert(PyString_Check(name_obj));

  if (self->proxy && self->proxy->dict && z_proxy_get_state(self->proxy) >= ZPS_CONFIG)
    { 
      const gchar *name = PyString_AS_STRING(name_obj);

      if (z_policy_dict_set_value(self->proxy->dict, z_proxy_get_state(self->proxy) == ZPS_CONFIG, name, value) == 0)
        {
          if (z_log_enabled(CORE_DEBUG, 6))
            {
              PyObject *repr = PyObject_Repr(value);
              /*LOG
                This message reports that the given proxy-exported attribute
                was changed to the given value.
               */
              z_log(self->proxy->session_id, CORE_DEBUG, 6, "Attribute changed; attribute='%s', newvalue='%s'", name, PyString_AsString(repr));
              Py_XDECREF(repr);
            }
          return 0;
        }
      else
        {
          if (PyErr_Occurred())
            {
              PyErr_Print();
              return 1;
            }
        }
    }
  if (PyErr_Occurred())
    PyErr_Print();
  return PyObject_GenericSetAttr((PyObject *) self, name_obj, value);
}

/**
 * z_policy_proxy_init_instance:
 * @self this
 * @args Python args: module_name, session_id, client, parent
 *
 * Constructor of ZPolicyProxy. Class is an abstract one, so the instance
 * already exists, only initialisation has to be done.
 *
 * Searches the registry for module_name, and creates its (C-side) self->proxy
 * using the returned constructor. For details see documentation about the
 * instantiation and invocation of custom proxies.
 *
 * Returns:
 * NULL on error, PyNone on success.
 */ 
static int
z_policy_proxy_init_instance(ZPolicyProxy *self, PyObject *args)
{
  PyObject *proxy_name, *module_name, *client, *parent, *session_id;
  ZProxy *parent_proxy = NULL;

  z_enter();
  if (!PyArg_ParseTuple(args, "SSSOO", &proxy_name, &module_name, &session_id, &client, &parent))
    {
      z_log(NULL, CORE_ERROR, 2, "Invalid parameters;");
      z_leave();
      return -1;
    }

  if (!z_policy_stream_check(client))
    {
      PyErr_SetString(PyExc_TypeError, "client must be a ZPolicyStream");
      z_leave();
      return -1;
    }
    

  if (parent != z_policy_none)
    {
      parent_proxy = ((ZPolicyProxy *) parent)->proxy;
    }

  z_policy_var_ref(session_id);
  z_policy_var_ref(client);
  z_policy_var_ref(module_name);
  self->proxy_name = proxy_name;
  self->module_name = module_name;
  self->session_id = session_id;
  self->client_stream = client; 
  self->parent_proxy = z_proxy_ref(parent_proxy);
  z_leave();
  return 0;
}


/**
 * z_policy_proxy_free:
 * @self this
 *
 * Destructor of ZPolicyProxy
 */
static void
z_policy_proxy_free(ZPolicyProxy *self)
{
  z_proxy_unref(self->proxy);
  z_proxy_unref(self->parent_proxy);
  z_policy_var_unref(self->client_stream);
  z_policy_var_unref(self->session_id);
  z_policy_var_unref(self->module_name);
  self->ob_type->tp_free((PyObject *) self);
}

static PyMethodDef z_policy_proxy_methods[] =
{
  { NULL, NULL, 0, NULL }
};


PyTypeObject z_policy_proxy_type = 
{
  PyObject_HEAD_INIT(&PyType_Type)
  .ob_size = 0,
  .tp_name = "ZPolicyProxy",
  .tp_basicsize = sizeof(ZPolicyProxy),
  .tp_itemsize = 0,
  .tp_dealloc = (destructor)z_policy_proxy_free,
  .tp_print = NULL,
  .tp_getattr = NULL,
  .tp_setattr = NULL,
  .tp_compare = NULL,
  .tp_repr = NULL,
  .tp_as_number = NULL,
  .tp_as_sequence = NULL,
  .tp_as_mapping = NULL,
  .tp_hash = NULL,
  .tp_call = NULL,
  .tp_str = NULL,
  .tp_getattro = (getattrofunc) z_policy_proxy_getattr,
  .tp_setattro = (setattrofunc) z_policy_proxy_setattr,
  .tp_as_buffer = NULL,
  .tp_flags = Py_TPFLAGS_DEFAULT | Py_TPFLAGS_BASETYPE,
  .tp_doc = "ZPolicyProxy class",
  .tp_traverse = NULL,
  .tp_clear = NULL,
  .tp_richcompare = NULL,
  .tp_weaklistoffset = 0,
  .tp_iter = NULL,
  .tp_iternext = NULL,
  .tp_methods = z_policy_proxy_methods,
  .tp_members = NULL,
  .tp_getset = NULL,
  .tp_base = NULL,
  .tp_dict = NULL,
  .tp_descr_get = NULL,
  .tp_descr_set = NULL,
  .tp_dictoffset = 0,
  .tp_init = (initproc) z_policy_proxy_init_instance,
  .tp_alloc = NULL,
  .tp_new = PyType_GenericNew,
  .tp_free = NULL,
  .tp_is_gc = NULL,
  .tp_bases = NULL,
  .tp_mro = NULL,
  .tp_cache = NULL,
  .tp_subclasses = NULL,
  .tp_weaklist = NULL,
  .tp_del = NULL,
};

/**
 * z_policy_proxy_module_init:
 *
 * Module initialisation.
 * FIXME: some words about GetDict...
 */
void
z_policy_proxy_module_init(void)
{
  PyObject *m;
  void *o;

  if (PyType_Ready(&z_policy_proxy_type) < 0)
    g_assert_not_reached();

  m = PyImport_AddModule("Zorp.Zorp");
  Py_INCREF(&z_policy_proxy_type);
  o = &z_policy_proxy_type;
  PyModule_AddObject(m, "BuiltinProxy", (PyObject *) o);
}
