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
 * $Id: pyattach.c,v 1.14 2004/07/02 10:03:33 bazsi Exp $
 *
 * Author  : Bazsi
 * Auditor :
 * Last audited version:
 * Notes:
 *
 ***************************************************************************/

#include <zorp/pyattach.h>
#include <zorp/attach.h>
#include <zorp/log.h>
#include <zorp/policy.h>
#include <zorp/pysockaddr.h>
#include <zorp/socket.h>
#include <zorp/stream.h>
#include <zorp/streamfd.h>
#include <zorp/pyproxy.h>
#include <zorp/pystream.h>

/*
 * struct ZPolicyAttach
 *
 * Author:  Bazsi, 2000/03/27
 * Purpose: this class encapsulates a connector
 *
 */

typedef struct _ZPolicyAttach
{
  PyObject_HEAD
  ZPolicy *policy;
  ZAttach *attach;
  ZSockAddr *local;
} ZPolicyAttach;

static PyTypeObject z_policy_attach_type;

/**
 * z_policy_attach_block_method:
 * @self this
 * @args not used
 *
 * Zorp.Attach.block, block execution until the connection gets established.
 * (Wrapper around z_attach_block.) Note that if there is a callback installed
 * (@handler of the constructor), then this method will fail.
 *
 * Returns:
 * NULL when there was a callback installed
 * PyNone if an error happened during connecting
 * The new data stream (Zorp.Stream) otherwise
 */
static PyObject *
z_policy_attach_start_method(ZPolicyAttach *self, PyObject *args G_GNUC_UNUSED)
{
  PyObject *res;
  ZConnection *conn;
  gboolean success;
  z_enter();
      
  Py_BEGIN_ALLOW_THREADS
  success = z_attach_start_block(self->attach, &conn);
  Py_END_ALLOW_THREADS
  
  if (success && conn)
    {
      /* NOTE: we don't assign a name to this stream now, it will be assigned later */
      res = z_policy_stream_new(conn->stream);
      self->local = z_sockaddr_ref(conn->local);
      z_connection_destroy(conn, FALSE);
    }
  else
    {
      Py_XINCREF(Py_None);
      res = Py_None;
    }
  z_leave();
  return res;
}

static PyMethodDef z_policy_attach_methods[] =
{
  { "start",       (PyCFunction) z_policy_attach_start_method, 0, NULL },
  { NULL,          NULL, 0, NULL }   /* sentinel*/
};


/**
 * z_policy_attach_getattr:
 * @o: this 
 * @name: Attribute name
 *
 * Get the value of an attribute
 * Currently only the methods and one attribute is supported: 'local', the
 * address of the local endpoint.
 *
 * Returns:
 * The attribute value as a Python object
 */
static PyObject *
z_policy_attach_getattr(PyObject *o, char *name)
{
  ZPolicyAttach *self = (ZPolicyAttach *) o;
  PyObject *back;
  
  z_enter();
  if (strcmp(name, "local") == 0)
    {
      if (self->local)
        {
          back = z_policy_sockaddr_new(self->local);
          z_leave();
          return back;
        }
      else
        {
          Py_XINCREF(Py_None);
          z_leave();
          return Py_None;
        }
    }
  else
    {
      back = Py_FindMethod(z_policy_attach_methods, o, name);
      z_leave();
      return back;
    }
}

/** 
 * z_policy_attach_new_instance:
 * @s not used
 * @args Python args: proxy, protocol, local, remote, handler
 *
 * Constructor of Zorp.Attach. After creating and setting up a new instance,
 * creates self->attach (ZAttach), passing the arguments to its constructor
 * z_attach_new. The argument @handler will be called when the connection
 * got established.
 *
 * Returns:
 * The new instance
 */
static PyObject *
z_policy_attach_new_instance(PyObject *s G_GNUC_UNUSED, PyObject *args, PyObject *keywords)
{
  ZPolicyAttach *self;
  PyObject *local, *remote;
  PyObject *fake_args, *proxy_instance;
  ZAttachParams params;
  static gchar *tcp_keywords[] = { "timeout", "local_loose", "tos", "local_random", NULL };
  static gchar *udp_keywords[] = { "timeout", "local_loose", "tos", "local_random", NULL };
  gchar buf1[MAX_SOCKADDR_STRING], buf2[MAX_SOCKADDR_STRING];
  ZSockAddr *local_sa, *remote_sa;
  guint protocol;

  z_enter();
  /* called by python, no need to lock the interpreter */
   
  if (!PyArg_ParseTuple(args, "OiOO", &proxy_instance, &protocol, &local, &remote))
    return NULL;

  if (!z_policy_proxy_check(proxy_instance))
    {
      PyErr_SetString(PyExc_TypeError, "First argument must be a Proxy instance");
      z_leave();
      return NULL;
    }

  if (((local != Py_None) && !z_policy_sockaddr_check(local)) ||
      (!z_policy_sockaddr_check(remote)))
    {
      PyErr_SetString(PyExc_TypeError, "Local and remote arguments must be SockAddr or None");
      z_leave();
      return NULL;
    }

  memset(&params, 0, sizeof(params));
  params.tos = -1;
  params.timeout = 30000;
  fake_args = PyTuple_New(0);

  switch (protocol)
    {
    case ZD_PROTO_TCP:
      if (!PyArg_ParseTupleAndKeywords(fake_args, keywords, "|iiii", tcp_keywords, &params.timeout, &params.loose, &params.tos, &params.random))
        {
          Py_XDECREF(fake_args);
          return NULL;
        }
      break;
    case ZD_PROTO_UDP:
      if (!PyArg_ParseTupleAndKeywords(fake_args, keywords, "|iiii", udp_keywords, &params.timeout, &params.loose, &params.tos, &params.random))
        {
          Py_XDECREF(fake_args);
          return NULL;
        }
      break;
      
    }
  Py_XDECREF(fake_args);

  self = PyObject_New(ZPolicyAttach, &z_policy_attach_type);
  if (!self)
    {
      z_leave();
      return NULL;
    }
  
  local_sa = local == Py_None ? NULL : z_policy_sockaddr_get_sa(local);
  remote_sa = z_policy_sockaddr_get_sa(remote);

  /*LOG
    This message indicates that Zorp began establishing connection
    with the indicated remote host.
   */
  z_log(z_policy_proxy_get_proxy(proxy_instance)->session_id, CORE_DEBUG, 7, "Connecting to remote host; protocol='%d', local='%s', remote='%s'", 
        protocol,
	local_sa ? z_sockaddr_format(local_sa, buf1, sizeof(buf1)) : "NULL",
	z_sockaddr_format(remote_sa, buf2, sizeof(buf2)));

  self->local = NULL;
  self->policy = NULL;
        
  self->attach = z_attach_new(z_policy_proxy_get_proxy(proxy_instance), protocol, local_sa, remote_sa, &params, NULL, NULL, NULL);

  z_sockaddr_unref(remote_sa);
  z_sockaddr_unref(local_sa);
  if (!self->attach)
    {
      PyErr_SetString(PyExc_IOError, "Error during connect");
      
      Py_XDECREF(self);
      z_leave();
      return NULL;
    }
  self->policy = z_policy_ref(current_policy);

  z_leave();
  return (PyObject *) self;
}

/**
 * z_policy_attach_free:
 * @self: this
 *
 * Destructor for Zorp.Attach, called automatically to free up this instance
 */
static void
z_policy_attach_free(ZPolicyAttach *self)
{
  z_enter();
  if (self->attach)
    {
      z_attach_free(self->attach);
    }
  if (self->policy)
    {
      z_policy_unref(self->policy);
    }
  z_sockaddr_unref(self->local);

  PyObject_Del(self);
  z_leave();
}


PyMethodDef z_policy_attach_funcs[] =
{
  { "Attach",  (PyCFunction) z_policy_attach_new_instance, METH_VARARGS | METH_KEYWORDS, NULL },
  { NULL,      NULL, 0, NULL }   /* sentinel*/
};


static PyTypeObject z_policy_attach_type = 
{
  PyObject_HEAD_INIT(&PyType_Type)
  0,
  "ZPolicyAttach",
  sizeof(ZPolicyAttach),
  0,
  (destructor) z_policy_attach_free,
  0,
  (getattrfunc) z_policy_attach_getattr,
  0,
  0,
  0, /*(reprfunc) z_policy_attach_repr,*/
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
  "ZPolicyAttach class for Zorp",
  0, 0, 0, 0,
  Z_PYTYPE_TRAILER
};


/**
 * z_policy_attach_init:
 *
 * Module initialisation
 */
void
z_policy_attach_module_init(void)
{
  Py_InitModule("Zorp.Zorp", z_policy_attach_funcs);
}
