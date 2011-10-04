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
 * $Id: pydispatch.c,v 1.29 2004/07/02 10:03:33 bazsi Exp $
 *
 * Author  : Bazsi
 * Auditor : 
 * Last audited version: 
 * Notes:
 *
 ***************************************************************************/

#include <zorp/pydispatch.h>
#include <zorp/dispatch.h>
#include <zorp/policy.h>
#include <zorp/log.h>
#include <zorp/pysockaddr.h>
#include <zorp/pystream.h>
#include <zorp/kzorp.h>

/* ZPolicyDispatchBind */

ZDispatchBind *
z_policy_dispatch_bind_get_db(ZPolicyObj *self)
{
  ZDispatchBind *db;

  if (!z_policy_dispatch_bind_check(self))
    return NULL;
  
  db = (ZDispatchBind *) z_policy_dict_get_app_data(z_policy_struct_get_dict(self));
  return z_dispatch_bind_ref(db);
}

ZPolicyObj *
z_policy_dispatch_format(ZPolicyObj *s)
{
  ZPolicyObj *res = Py_None;
  ZDispatchBind *bind = z_policy_dispatch_bind_get_db(s);
  assert(bind != NULL);
  char buf[MAX_SOCKADDR_STRING];

  switch(bind->type)
    {
    case ZD_BIND_SOCKADDR:
      res = PyString_FromFormat("SockAddrInet(%s)", z_sockaddr_format(bind->sa.addr, buf, sizeof(buf)));
      break;

    case ZD_BIND_IFACE:
      res = PyString_FromFormat("DBIface(iface=%s, port=%d)", bind->iface.iface, bind->iface.port);
      break;

    case ZD_BIND_IFACE_GROUP:
      res = PyString_FromFormat("DBIfaceGroup(group=%d, port=%d)", bind->iface_group.group, bind->iface_group.port);
      break;

    default:
      g_assert_not_reached();
      break;
    }
  z_dispatch_bind_unref(bind);
  return res;
}

static ZPolicyObj *
z_policy_dispatch_bind_format(gpointer user_data, ZPolicyObj *args, ZPolicyObj *kw G_GNUC_UNUSED)
{
  ZDispatchBind *bind = (ZDispatchBind *) user_data;
  char buf[MAX_SOCKADDR_STRING];

  if (!z_policy_var_parse(args, "()"))
    return NULL;

  return PyString_FromString(z_dispatch_bind_format(bind, buf, sizeof(buf)));
}
            

static ZPolicyObj *
z_policy_dispatch_bind_new(ZDispatchBind *bind)
{
  ZPolicyDict *dict;
  gint struct_type;
  ZPolicyObj *res;

  dict = z_policy_dict_new();
  z_policy_dict_register(dict, Z_VT_INT16, "protocol", Z_VF_RW, &bind->protocol);
  z_policy_dict_register(dict, Z_VT_INT, "type", Z_VF_READ, &bind->type);
  z_policy_dict_register(dict, Z_VT_METHOD, "format", Z_VF_READ, z_policy_dispatch_bind_format, bind, NULL);

  switch (bind->type)
    {
    case ZD_BIND_SOCKADDR:
      z_policy_dict_register(dict, Z_VT_OBJECT, "sa", Z_VF_RW + Z_VF_LITERAL + Z_VF_CONSUME, z_policy_sockaddr_new(bind->sa.addr));
      struct_type = Z_PST_DB_SOCKADDR;
      break;
    case ZD_BIND_IFACE:
      z_policy_dict_register(dict, Z_VT_CSTRING, "iface", Z_VF_RW, &bind->iface.iface, sizeof(bind->iface.iface));
      z_policy_dict_register(dict, Z_VT_INT16, "port", Z_VF_RW, &bind->iface.port);
      z_policy_dict_register(dict, Z_VT_IP, "ip",   Z_VF_RW, &bind->iface.ip4);
      z_policy_dict_register(dict, Z_VT_IP, "ip_s", Z_VF_RW | Z_VF_IP_STR, &bind->iface.ip4);
      struct_type = Z_PST_DB_IFACE;
      break;
    case ZD_BIND_IFACE_GROUP:
      z_policy_dict_register(dict, Z_VT_INT32, "group", Z_VF_RW, &bind->iface_group.group);
      z_policy_dict_register(dict, Z_VT_INT16, "port", Z_VF_RW, &bind->iface_group.port);
      struct_type = Z_PST_DB_IFACE_GROUP;
      break;
    default:
      g_assert_not_reached();
      break;
    }

  z_dispatch_bind_ref(bind);
  z_policy_dict_set_app_data(dict, bind, (GDestroyNotify) z_dispatch_bind_unref);
  res = z_policy_struct_new(dict, struct_type);
  z_policy_struct_set_format(res, z_policy_dispatch_format);

  return res;
}

static ZPolicyObj *
z_policy_dispatch_bind_new_instance_sa(ZPolicyObj *self G_GNUC_UNUSED, ZPolicyObj *args, ZPolicyObj *kw_args)
{
  gchar *keywords[] = { "sa", "protocol", NULL };
  ZDispatchBind *bind;
  ZPolicyObj *policy_sa, *res;
  ZSockAddr *sa;
  guint protocol = ZD_PROTO_AUTO;

  if (!PyArg_ParseTupleAndKeywords(args, kw_args, "O|i", keywords, &policy_sa, &protocol))
    {
      return NULL;
    }
  if (!z_policy_sockaddr_check(policy_sa))
    {
      PyErr_SetString(PyExc_ValueError, "Expected SockAddr");
      return NULL;
    }

  sa = z_policy_sockaddr_get_sa(policy_sa);
  bind = z_dispatch_bind_new_sa(protocol, sa);
  z_sockaddr_unref(sa);
  res = z_policy_dispatch_bind_new(bind);
  z_dispatch_bind_unref(bind);
  return res;
}

static ZPolicyObj *
z_policy_dispatch_bind_new_instance_iface(ZPolicyObj *self G_GNUC_UNUSED, ZPolicyObj *args, ZPolicyObj *kw_args)
{
  gchar *keywords[] = { "iface", "port", "family", "protocol", "ip", NULL };
  ZDispatchBind *bind;
  ZPolicyObj *res;
  const gchar *iface = NULL, *ip = "0.0.0.0";
  guint protocol = ZD_PROTO_AUTO, port = 0, family = AF_INET;

  if (!PyArg_ParseTupleAndKeywords(args, kw_args, "si|iis", keywords, &iface, &port, &family, &protocol, &ip))
    {
      return NULL;
    }
  if (port == 0)
    {
      PyErr_SetString(PyExc_ValueError, "Interface bound dispatches require a non-zero port");
      return NULL;
    }
  bind = z_dispatch_bind_new_iface(protocol, iface, family, ip, port);
  res = z_policy_dispatch_bind_new(bind);
  z_dispatch_bind_unref(bind);
  return res;
}

static ZPolicyObj *
z_policy_dispatch_bind_new_instance_iface_group(ZPolicyObj *self G_GNUC_UNUSED, ZPolicyObj *args, ZPolicyObj *kw_args)
{
  gchar *keywords[] = { "group", "port", "family", "protocol", NULL };
  ZDispatchBind *bind;
  ZPolicyObj *res, *group_obj;
  guint group = 0;
  guint protocol = ZD_PROTO_AUTO, port = 0, family = AF_INET;

  if (!PyArg_ParseTupleAndKeywords(args, kw_args, "Oi|ii", keywords, &group_obj, &port, &family, &protocol))
    {
      return NULL;
    }
    
  if (z_policy_str_check(group_obj))
    {
      FILE *ifgroups;
      gchar *group_name, *end;
      
      group_name = z_policy_str_as_string(group_obj);
      
      group = strtoul(group_name, &end, 0);
      if (*end != 0)
        {
          group = 0;
          ifgroups = fopen("/etc/iproute2/rt_ifgroup", "r");
          if (ifgroups)
            {
              guint value;
              gchar name[32];
              gchar buf[256];
              
              while (fgets(buf, sizeof(buf), ifgroups))
                { 
                  if (buf[0] == '#' || buf[0] == '\n' || buf[0] == 0)
                    continue;
                  if (sscanf(buf, "%x %32s\n", &value, name) == 2)
                    {
                      if (strcmp(name, group_name) == 0)
                        {
                          group = value;
                          break;
                        }
                    }
                }
              fclose(ifgroups);
            }
        }
      
      if (!group)
        {
          PyErr_SetString(PyExc_RuntimeError, "Error resolving interface group name");
          return NULL;
        }
    }
  else if (PyInt_Check(group_obj))
    {
      group = PyInt_AsLong(group_obj);
    }
    
  if (port == 0)
    {
      PyErr_SetString(PyExc_ValueError, "Interface Group bound dispatches require a non-zero port");
      return NULL;
    }
  bind = z_dispatch_bind_new_iface_group(protocol, group, family, port);
  res = z_policy_dispatch_bind_new(bind);
  z_dispatch_bind_unref(bind);
  return res;
}

/* ZPolicyDispatch class */

typedef struct _ZPolicyDispatch
{
  PyObject_HEAD
  ZPolicy *policy;
  ZPolicyThread *policy_thread;
  ZDispatchEntry *dispatch;
  gboolean threaded;
  PyObject *handler;
} ZPolicyDispatch;

static PyTypeObject z_policy_dispatch_type;
static PyMethodDef z_policy_dispatch_methods[];


/**
 * z_policy_dispatch_accept:
 * @conn The new incoming connection
 * @user_data this
 *
 * Internal callback, will be registered as the callback of ZDispatchEntry
 * instances in the constructor of ZPolicyDispatch. This function will be called
 * on new incoming connections, passes the connection to self->handler, which
 * will end up in the 'accepted' method of AbstractDispatch.
 * 
 * Called by the main thread, so it locks using the global python state
 *
 * Returns: TRUE
 */
static gboolean
z_policy_dispatch_accept(ZConnection *conn, gpointer user_data)
{
  ZPolicyDispatch *self = (ZPolicyDispatch *) user_data;
  PyObject *res, *addr, *local, *pystream, *bound;

  z_enter();
  z_policy_thread_acquire(self->policy_thread);
  if (conn)
    {
      ZSockAddr *tmpsa;
     
      /* NOTE: we cloning sockaddrs here as ref/unref on sockaddrs is not
       * reentrant, thus it is wise to use separate copies in each thread */
      tmpsa = z_sockaddr_clone(conn->dest, FALSE);
      local = z_policy_sockaddr_new(tmpsa);
      z_sockaddr_unref(tmpsa);
      
      tmpsa = z_sockaddr_clone(conn->remote, FALSE);
      addr = z_policy_sockaddr_new(tmpsa);
      z_sockaddr_unref(tmpsa);

      bound = z_policy_dispatch_bind_new(conn->dispatch_bind);
      pystream = z_policy_stream_new(conn->stream);
    }
  else
    {
      local = Py_None;
      addr = Py_None;
      bound = Py_None;
      pystream = Py_None;
      
      Py_XINCREF(local);
      Py_XINCREF(addr);
      Py_XINCREF(bound);
      Py_XINCREF(pystream);
      
    }
  res = PyEval_CallFunction(self->handler, "(OOOO)",
			    pystream, addr, local, bound);
  Py_XDECREF(bound);
  Py_XDECREF(addr);
  Py_XDECREF(local);
  Py_XDECREF(pystream);
  
  /* once python was called we assume that it takes care about the fd
   * we just passed. As an exception if an exception occurs we close it ourselves
   */
  if (!res)
    {
      PyErr_Print();
      if (conn)
        z_stream_close(conn->stream, NULL);
    }
  else if (res == Py_None)
    {
      gchar buf[256];
      /*LOG
	This message indicates that the decision layer denied the
	given connection.
      */
      z_log(NULL, CORE_POLICY, 1, "Connection denied by policy; %s", z_connection_format(conn, buf, sizeof(buf)));
      /* close(fd); */
    }
  Py_XDECREF(res);

  z_policy_thread_release(self->policy_thread);
  if (conn)
    z_connection_destroy(conn, FALSE);
  z_return(TRUE);
}

/**
 * z_policy_dispatch_destroy_notify:
 * @p this
 *
 * This function is used as the DestroyNotify callback for the
 * registered ZDispatchEntry. Deregisters a ZPolicyDispatch/Dispatch
 * instance from its policy.
 */
static void
z_policy_dispatch_destroy_notify(gpointer p)
{
  ZPolicyDispatch *self = (ZPolicyDispatch *) p;
  ZPolicy *policy;
  
  policy = z_policy_ref(self->policy);
  
  z_policy_acquire_main(policy);
  Py_XDECREF(self);
  z_policy_release_main(policy);
  
  z_policy_unref(policy);
}


/**
 * z_policy_dispatch_destroy_method:
 * @self this
 * @args unused
 *
 * Detaches a ZPolicyDispatch instance from its dispatch entry ?and from
 * Python?
 * 
 * Returns: Py_None
 */
static PyObject *
z_policy_dispatch_destroy_method(ZPolicyDispatch *self, PyObject *args G_GNUC_UNUSED)
{
  if (self->dispatch)
    {
      /* our destroy_notify callback locks the interpreter explicitly, thus
       * we need to release it here */

      Py_BEGIN_ALLOW_THREADS;
      z_dispatch_unregister(self->dispatch);
      Py_END_ALLOW_THREADS;
      self->dispatch = NULL;
    }
  Py_XDECREF(self->handler);
  self->handler = NULL;

  Py_XINCREF(Py_None);
  return Py_None;
}

/**
 * z_policy_dispatch_getattr:
 * @o ?Python object?
 * @name ?Method name?
 *
 * ?Finds a method registered to Python by its name?
 *
 * Returns:
 * ?The method?
 */
static PyObject *
z_policy_dispatch_getattr(PyObject *o, char *name)
{
  PyObject *back;
  
  z_enter();
  back = Py_FindMethod(z_policy_dispatch_methods, o, name);
  z_leave();
  return back;
}

/**
 * z_policy_dispatch_new_instance:
 * @o unused
 * @args Python arguments: session_id, protocol, addr, prio, handler, keywords
 *
 * Constructor of ZPolicyDispatch/Dispatch. Creates a new instance, and registers
 * a new dispatcher (self->dispatch), setting its callback to
 * z_policy_dispatch_accept.
 *
 * Returns:
 * The new instance
 */
static PyObject *
z_policy_dispatch_new_instance(PyObject *o G_GNUC_UNUSED, PyObject *args)
{
  ZPolicyDispatch *self = NULL;
  PyObject *addr;
  PyObject *handler, *keywords, *fake_args = NULL;
  ZDispatchBind *db;
  gint prio;
  gchar buf[MAX_SOCKADDR_STRING], *session_id;
  ZDispatchParams params;
  gint session_limit_dummy; /* session_limit is a noop */
  gchar *tcp_keywords[] = { "accept_one", "backlog", "threaded", "mark_tproxy", "transparent", NULL };
  gchar *udp_keywords[] = { "session_limit", "rcvbuf", "threaded", "mark_tproxy", "transparent", NULL };

  /* called by python, so interpreter is locked */
  
  if (current_policy == NULL)
    {
      PyErr_SetString(PyExc_RuntimeError, "Parsing phase has not completed yet, Listener & Receiver must be defined in the instance init() function.");
      return NULL;
    }
  
  /* res is a borrowed reference, no need to unref it */
  if (!PyArg_ParseTuple(args, "sOiOO", &session_id, &addr, &prio, &handler, &keywords))
    return NULL;

  if (!PyCallable_Check(handler))
    {
      PyErr_SetString(PyExc_TypeError, "Handler parameter must be callable");
      return NULL;
    }
    
  if (!z_policy_dispatch_bind_check(addr))
    {
      PyErr_SetString(PyExc_TypeError, "addr parameter must be a DispatchBind object (DBIface or DBSockAddr)");
      return NULL;
    }

  /* from this point, we must exit by goto error_exit */
  
  db = z_policy_dispatch_bind_get_db(addr);
  fake_args = PyTuple_New(0);
  params.common.threaded = FALSE;
  params.common.mark_tproxy = FALSE;
  params.common.transparent = FALSE;
  switch (db->protocol)
    {
    case ZD_PROTO_TCP:
      params.tcp.accept_one = FALSE;
      params.tcp.backlog = 255;
      if (!PyArg_ParseTupleAndKeywords(fake_args, keywords, "|iiiii", tcp_keywords, 
                                       &params.tcp.accept_one, 
                                       &params.tcp.backlog, 
                                       &params.common.threaded,
                                       &params.common.mark_tproxy,
                                       &params.common.transparent))
        {
          goto error_exit;
        }
      break;
    case ZD_PROTO_UDP:

      /* NOTE: params.udp.tracker is a (gchar *) valid only as long as the
       * z_dispatch_register calls returns, it is discarded by Python
       * afterwards.  This is not a problem as this name is used in
       * z_conntrack_new, and never referenced again */
       
      params.udp.rcvbuf = 65536;
      if (!PyArg_ParseTupleAndKeywords(fake_args, keywords, "|iiiii", udp_keywords, 
                                       &session_limit_dummy,
                                       &params.udp.rcvbuf,
                                       &params.common.threaded,
                                       &params.common.mark_tproxy,
                                       &params.common.transparent))
        {
          goto error_exit;
        }
      break;
      
    }

  self = PyObject_New(ZPolicyDispatch, &z_policy_dispatch_type);
  if (!self)
    goto error_exit;

  /*LOG
    This message indicates that a Listener on the given local address is
    started.
   */
  z_log(session_id, CORE_DEBUG, 7, "Dispatcher on address; local='%s', prio='%d'", 
        z_dispatch_bind_format(db, buf, sizeof(buf)), prio);
    
  Py_XINCREF(self);
  self->handler = handler;
  Py_XINCREF(handler);
  self->policy = z_policy_ref(current_policy);
  self->threaded = ((ZDispatchCommonParams *) &params)->threaded;

  self->policy_thread = z_policy_thread_new(self->policy);
  z_policy_thread_ready(self->policy_thread);
  
  /* z_dispatch_register uses a lock also locked by the callback mechanism which keeps it locked
     while our callback is running, this makes a possible cross-lock deadlock:
     1) This function (Python lock) -> z_dispatch_register (chain lock)
     2) z_dispatch_callback (chain lock) -> our callback (Python lock)
     
     That's the reason for BEGIN_ALLOW_THREADS here.
   */
  Py_BEGIN_ALLOW_THREADS;
  self->dispatch = z_dispatch_register(session_id, db, NULL, prio, &params, z_policy_dispatch_accept, self, z_policy_dispatch_destroy_notify);
  Py_END_ALLOW_THREADS;

  if (!self->dispatch)
    {
      Py_XDECREF(self);
      Py_XDECREF(self);
      PyErr_SetString(PyExc_IOError, "Error binding to interface");
      self = NULL;
    }
 error_exit:
  Py_XDECREF(fake_args);
  z_dispatch_bind_unref(db);
  return (PyObject *) self;
}

/**
 * z_policy_dispatch_free:
 * @self this
 *
 * Destructor of ZPolicyDispatch/Dispatch.
 */
static void
z_policy_dispatch_free(ZPolicyDispatch *self)
{
  if (self->handler)
    {
      Py_XDECREF(self->handler);
      self->handler = NULL;
    }
  g_assert(self->dispatch == NULL);

  if (self->policy_thread)
    {
      Py_BEGIN_ALLOW_THREADS;
      /* python must be unlocked */
      z_policy_thread_destroy(self->policy_thread);
      Py_END_ALLOW_THREADS;
      self->policy_thread = NULL;
    }
  if (self->policy)
    {
      z_policy_unref(self->policy);
      self->policy = NULL;
    }
  PyObject_Del(self);
}


static PyMethodDef z_policy_dispatch_methods[] =
{
  { "destroy",     (PyCFunction) z_policy_dispatch_destroy_method, 0, NULL },
  { NULL,          NULL, 0, NULL }   /* sentinel*/
};

static PyTypeObject z_policy_dispatch_type = 
{
  PyObject_HEAD_INIT(&PyType_Type)
  0,
  "ZPolicyDispatch",
  sizeof(ZPolicyDispatch),
  0,
  (destructor) z_policy_dispatch_free,
  0,
  (getattrfunc) z_policy_dispatch_getattr,
  0,
  0,
  0,
  0,
  0,
  0,
  0,
  0,
  0,
  0,
  0,
  0,
  0,
  "ZPolicyDispatch class for Zorp",
  0, 0, 0, 0,
  Z_PYTYPE_TRAILER
};

/**
 * z_policy_dispatch_get_kzorp_result
 * @o unused
 * @args Python arguments: fd
 *
 * Queries the KZorp results for the fd passed in through the
 * getsockopt() interface of KZorp.
 *
 * Returns: A tuple consisting of the results: (client_zone_name,
 * server_zone_name, dispatcher_name, service_name) or None if the
 * lookup was not successful.
 */
static PyObject *
z_policy_dispatch_get_kzorp_result(PyObject *o G_GNUC_UNUSED, PyObject *args)
{
  gint fd;
  struct z_kzorp_lookup_result buf;
  PyObject *ret;

  if (!PyArg_ParseTuple(args, "i", &fd))
    return NULL;

  memset(&buf, 0, sizeof(buf));

  if (!z_kzorp_get_lookup_result(fd, &buf)) {
    Py_XINCREF(Py_None);
    return Py_None;
  }

  ret = Py_BuildValue("(ssss)", &buf.czone_name, &buf.szone_name,
                      &buf.dispatcher_name, &buf.service_name);

  return ret;
}

PyMethodDef z_policy_dispatch_funcs[] =
{
  { "Dispatch", (PyCFunction) z_policy_dispatch_new_instance, METH_VARARGS, NULL },
  { "DBSockAddr",  (PyCFunction) z_policy_dispatch_bind_new_instance_sa, METH_VARARGS | METH_KEYWORDS, NULL },
  { "DBIface",  (PyCFunction) z_policy_dispatch_bind_new_instance_iface, METH_VARARGS | METH_KEYWORDS, NULL },
  { "DBIfaceGroup",  (PyCFunction) z_policy_dispatch_bind_new_instance_iface_group, METH_VARARGS | METH_KEYWORDS, NULL },
  { "getKZorpResult", (PyCFunction) z_policy_dispatch_get_kzorp_result, METH_VARARGS, NULL },
  { NULL,      NULL, 0, NULL }   /* sentinel*/
};

/**
 * z_policy_dispatch_init:
 *
 * Module initialisation
 */
void
z_policy_dispatch_module_init(void)
{
  Py_InitModule("Zorp.Zorp", z_policy_dispatch_funcs);
}

