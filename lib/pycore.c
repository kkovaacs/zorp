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
 * $Id: pycore.c,v 1.10 2004/07/22 07:51:10 bazsi Exp $
 *
 * Author  : Bazsi
 * Auditor : kisza
 * Last audited version: 1.22
 * Notes:
 *
 ***************************************************************************/

/* 
 * this module implements the interface with python 
 */
#include <zorp/pycore.h>
#include <zorp/log.h>
#include <zorp/io.h>
#include <zorp/policy.h>
#include <zorp/sysdep.h>
#include <zorp/streamfd.h>
#include <zorp/cap.h>
#include <zorp/szig.h>
#include <zorp/io.h>
#include <zorp/proxystack.h>

#include <zorp/pystream.h>
#include <zorp/pysockaddr.h>


#include <netdb.h>

PyObject *PyExc_LicenseException;

/* exported python methods */

/**
 * z_py_log:
 * @self: Python self argument
 * @args: Python args tuple
 *
 * Called by Python to send a message to the event log. There are several
 * alternative invocations of this function:
 *
 *   def log(class, verbosity, msg)
 *   def log(session_id, class, verbosity, logformat, args)
 *
 * Returns: Py_None
 **/
static PyObject *
z_py_log(PyObject *self G_GNUC_UNUSED, PyObject *args)
{
  unsigned long verbosity;
  char *class, *msg;
  PyObject *py_session_id, *log_fmt, *log_args, *log_msg = NULL;
  gchar *session_id;

  if (!PyTuple_Check(args))
    {
      PyErr_SetString(PyExc_TypeError, "args must be a tuple");
      return NULL;
    }
  if (PyTuple_Size(args) == 3)
    {
      if (!PyArg_ParseTuple(args, "sis", &class, &verbosity, &msg))
        return NULL;
      session_id = NULL;
    }
  else
    {  
      log_args = Py_None;
      if (!PyArg_ParseTuple(args, "OsiO|O", &py_session_id, &class, &verbosity, &log_fmt, &log_args))
        return NULL;
        
      if (py_session_id == Py_None)
        {
          session_id = NULL;
        }
      else if (PyString_Check(py_session_id))
        {
          session_id = PyString_AsString(py_session_id);
        }
      else
        {
          PyErr_SetString(PyExc_TypeError, "Session ID must be string or None");          
          return NULL;
        }
      
      if (!PyString_Check(log_fmt))
        {
          PyErr_SetString(PyExc_TypeError, "Format must be string");
          return NULL;
        }
      if (!z_log_enabled(class, verbosity))
        {
          Py_XINCREF(Py_None);
          return Py_None;
        }
      if (log_args != Py_None)
        {
          log_msg = PyString_Format(log_fmt, log_args);
          if (!log_msg)
            {
              return NULL;
            }
          msg = PyString_AsString(log_msg);
        }
      else
        {
          msg = PyString_AsString(log_fmt);
        }
        
    }
    
  /*NOLOG*/
  z_log(session_id, class, verbosity, "%s", msg);
  Py_XDECREF(log_msg);
  Py_XINCREF(Py_None);
  return Py_None;
}
 
/*+
  +*/
static PyObject *
z_py_quit(PyObject *self G_GNUC_UNUSED, PyObject *args)
{
  int exit_code;
  
  z_enter();
  if (!PyArg_ParseTuple(args, "i", &exit_code))
    z_return(NULL);
  z_main_loop_quit(exit_code);
  Py_XINCREF(Py_None);
  z_return(Py_None);
}


static PyObject *
z_py_stream_pair(PyObject *self G_GNUC_UNUSED, PyObject *args)
{
  int domain, type, proto = 0;
  int result[2];
  ZStream *streams[2];
  PyObject *pystreams[2], *res;
  
  z_enter();
  if (!PyArg_ParseTuple(args, "ii|i", &domain, &type, &proto))
    z_return(NULL);
  if (socketpair(domain, type, proto, result) == -1)
    {
      PyErr_SetString(PyExc_IOError, "I/O error during socketpair.");
      z_return(NULL);
    }

  streams[0] = z_stream_fd_new(result[0], "streamPair/A");
  streams[1] = z_stream_fd_new(result[1], "streamPair/B");

  pystreams[0] = z_policy_stream_new(streams[0]);
  pystreams[1] = z_policy_stream_new(streams[1]);

  z_stream_unref(streams[0]);
  z_stream_unref(streams[1]);
  
  res = z_policy_var_build("(OO)", pystreams[0], pystreams[1]);
  z_policy_var_unref(pystreams[0]);
  z_policy_var_unref(pystreams[1]);
  z_return(res);
}

static PyObject *
z_py_get_instance_id(PyObject *self G_GNUC_UNUSED, PyObject *args)
{
  static GHashTable *instance_ids = NULL;
  gint *value;
  gchar *service_name;
  
  if (!PyArg_Parse(args, "(s)", &service_name))
    return NULL;
  if (instance_ids == NULL)
    instance_ids = g_hash_table_new(g_str_hash, g_str_equal);
  
  value = g_hash_table_lookup(instance_ids, service_name);
  
  if (!value)
    {
      value = g_new(gint, 1);
      *value = 0;
      g_hash_table_insert(instance_ids, g_strdup(service_name), value);
    }
  else
    {
      (*value)++;
    }
  return PyInt_FromLong(*value);
}


static PyObject *
z_py_szig_event(PyObject *self G_GNUC_UNUSED, PyObject *args)
{
  gint event;
  guint type;
  PyObject *value, *value_repr;
  ZSzigValue *sv;
  GTimeVal tv;
  
  z_enter();
  if (!PyArg_Parse(args, "(iO)", &event, &value) ||
      !PyArg_Parse(value, "(iO)", &type, &value_repr))
    z_return(NULL);
    
  switch (type)
    {
    case Z_SZIG_TYPE_LONG:
      if (!PyInt_Check(value_repr))
        {
          PyErr_SetString(PyExc_ValueError, "Z_SZIG_TYPE_LONG requires an integer argument");
          z_return(NULL);
        }
      sv = z_szig_value_new_long(PyInt_AsLong(value_repr));
      break;
      
    case Z_SZIG_TYPE_TIME:
      if (!PyArg_Parse(value_repr, "(ii)", &tv.tv_sec, &tv.tv_usec))
        z_return(NULL);
      sv = z_szig_value_new_time(&tv);
      break;
      
    case Z_SZIG_TYPE_STRING:
      if (!PyString_Check(value_repr))
        {
          PyErr_SetString(PyExc_ValueError, "Z_SZIG_TYPE_STRING requires a string argument");
          z_return(NULL);
        }
      sv = z_szig_value_new_string(PyString_AsString(value_repr));
      break;
      
    case Z_SZIG_TYPE_PROPS:
      {
        gchar *name;
        PyObject *dict;
        PyObject *key, *value;
        Z_PYTHON_SIZE_TYPE i;
        
        if (!PyArg_Parse(value_repr, "(sO)", &name, &dict))
          z_return(NULL);
        if (!PyDict_Check(dict))
          {
            PyErr_SetString(PyExc_ValueError, "Z_SZIG_TYPE_PROPS requires a mapping as 2nd argument");
            z_return(NULL);
          }
        
        sv = z_szig_value_new_props(name, NULL);
        i = 0;
        while (PyDict_Next(dict, &i, &key, &value)) 
          {
            if (PyString_Check(key))
              {
                if (PyString_Check(value))
                  {
                    z_szig_value_add_prop(sv, PyString_AsString(key), z_szig_value_new_string(PyString_AsString(value)));
                  }
                else if (PyInt_Check(value))
                  {
                    z_szig_value_add_prop(sv, PyString_AsString(key), z_szig_value_new_long(PyInt_AsLong(value)));
                  }
                else
                  {
                    z_szig_value_free(sv, TRUE);
                    PyErr_SetString(PyExc_ValueError, "Z_SZIG_TYPE_PROPS requires a string->string or string->int mapping");
                    z_return(NULL);
                  }
              }
            else
              {
                z_szig_value_free(sv, TRUE);
                PyErr_SetString(PyExc_ValueError, "Z_SZIG_TYPE_PROPS cannot handle not string keys");
                z_return(NULL);
              }
          }
      }
    break;
    
    case Z_SZIG_TYPE_CONNECTION_PROPS:
      {
        gchar *service;
        gint instance_id, sec_conn_id, related_id;
        PyObject *dict;
        PyObject *key, *value;
        Z_PYTHON_SIZE_TYPE i;
        
        if (!PyArg_Parse(value_repr, "(siiiO)", &service, &instance_id, &sec_conn_id, &related_id, &dict))
          z_return(NULL);
        if (!PyDict_Check(dict))
          {
            PyErr_SetString(PyExc_ValueError, "Z_SZIG_TYPE_CONNECTION_PROPS requires a mapping as 5th argument");
            z_return(NULL);
          }
        
        sv = z_szig_value_new_connection_props(service, instance_id, sec_conn_id, related_id, NULL);
        i = 0;
        while (PyDict_Next(dict, &i, &key, &value)) 
          {
            if (!PyString_Check(key) || !PyString_Check(value))
              {
                z_szig_value_free(sv, TRUE);
                PyErr_SetString(PyExc_ValueError, "Z_SZIG_TYPE_CONNECTION_PROPS requires a string->string mapping");
                z_return(NULL);
              }
            z_szig_value_add_connection_prop(sv, PyString_AsString(key), PyString_AsString(value));
          }
      }
    break;

    default:
      PyErr_SetString(PyExc_ValueError, "Unknown SZIG type;");
      z_return(NULL);
    }
  z_szig_event(event, sv);
  Py_XINCREF(Py_None);
  z_return(Py_None);
}


/**
 *  **/
static PyObject *
z_policy_notify_event(PyObject *self G_GNUC_UNUSED, PyObject *args)
{
  Py_XINCREF(Py_None);
  return Py_None;
}

static PyMethodDef zorp_funcs[] = 
{
  { "log", z_py_log, METH_VARARGS, NULL },
  { "quit", z_py_quit, METH_VARARGS, NULL },
  { "streamPair", z_py_stream_pair, METH_VARARGS, NULL },
  { "getInstanceId", z_py_get_instance_id, METH_VARARGS, NULL },
  { "szigEvent", z_py_szig_event, METH_VARARGS, NULL },
  { "notifyEvent", z_policy_notify_event, METH_VARARGS, NULL },
  { NULL, NULL, 0, NULL }
};

void
z_py_zorp_core_init(void)
{
  Py_InitModule("Zorp.Zorp", zorp_funcs);
}

