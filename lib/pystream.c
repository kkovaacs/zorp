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
 * $Id: pystream.c,v 1.31 2004/07/02 10:03:33 bazsi Exp $
 *
 * Author  : Bazsi
 * Auditor : kisza
 * Last audited version: 1.8
 * Notes:
 *
 ***************************************************************************/

#include <zorp/pystream.h>

#include <zorp/zorp.h>
#include <zorp/log.h>
#include <zorp/stream.h>
#include <zorp/streamfd.h>
#include <zorp/streamline.h>
#include <zorp/policy.h>

PyObject *z_policy_stream_new(ZStream *Stream);
static PyObject *z_policy_stream_new_instance(PyObject *self, PyObject *args);
static void z_policy_stream_destroy(PyObject *o);
static PyObject *z_policy_stream_getattr(PyObject *o, char *name);
static gint z_policy_stream_setattr(PyObject *o, char *name,
				     PyObject *value);
static PyObject *z_policy_stream_repr(PyObject *o);
static PyObject *z_policy_stream_read(PyObject *o, PyObject *args);
static PyObject *z_policy_stream_write(PyObject *o, PyObject *args);
static PyObject *z_policy_stream_close(PyObject *o, PyObject *args);
static PyObject *z_policy_stream_readline(PyObject *o, PyObject *args);

static PyObject *z_policy_stream_exception = NULL; 

PyMethodDef z_policy_stream_funcs[] =
{
  { "Stream",  z_policy_stream_new_instance, METH_VARARGS, NULL },
  { NULL,          NULL, 0, NULL }   /* sentinel*/
};

static PyMethodDef py_zorp_stream_methods[] =
{
  { "read",        z_policy_stream_read, METH_VARARGS, NULL },
  { "write",       z_policy_stream_write, METH_VARARGS, NULL },
  { "close",       (PyCFunction) z_policy_stream_close, 0, NULL },
  { "readline",        z_policy_stream_readline, METH_VARARGS, NULL },
  { NULL,          NULL, 0, NULL }   /* sentinel*/
};

PyTypeObject z_policy_stream_type = 
{
  PyObject_HEAD_INIT(&PyType_Type)
  0,
  "ZPolicyStream",
  sizeof(ZPolicyStream),
  0,
  (destructor) z_policy_stream_destroy,
  0,
  (getattrfunc) z_policy_stream_getattr,
  (setattrfunc) z_policy_stream_setattr,
  0,
  (reprfunc) z_policy_stream_repr,
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
  "ZPolicyStream class for Zorp",
  0, 0, 0, 0,
  Z_PYTYPE_TRAILER
};

/**
 * z_policy_stream_new:
 * @str: ZStream instance
 *
 * This function allocates a Python object representing the Zorp stream
 * @str. It is to be called from C code, the Python version of this
 * constructor is below.
 * 
 * Returns: the newly allocated Python object
 **/
PyObject *
z_policy_stream_new(ZStream *str)
{
  ZPolicyStream *self;

  if (str == NULL)
    {
      /*LOG
        This message indicates an internal error, please contact your Zorp support for assistance.
       */
      z_log(NULL, CORE_ERROR, 3, "Internal error in z_policy_stream_new: input ZStream is NULL;");
      return NULL;
    }

  self = PyObject_New(ZPolicyStream, &z_policy_stream_type);
  z_stream_ref(str);
  self->stream = str;
  return (PyObject *) self;
}

/**
 * z_policy_stream_new:
 * @o: Python self argument
 * @args: Python args argument
 *
 * This function can be called from Python to create and initialize a new
 * stream with an underlying ZStreamFD. The function expects two arguments
 * from Python: (fd, name), where fd is the file descriptor to attach the
 * new stream to and name will be the name of this stream.
 *
 * Returns: the newly allocated Python object
 **/
static PyObject *
z_policy_stream_new_instance(PyObject *o G_GNUC_UNUSED, PyObject *args)
{
  ZPolicyStream *self;
  char *name;
  int fd;

  if (!PyArg_ParseTuple(args, "is", &fd, &name))
    return NULL;
  self = PyObject_New(ZPolicyStream, &z_policy_stream_type);
  if (!self)
    return NULL;

  self->stream = z_stream_fd_new(fd, name);
  return (PyObject *) self;
}

/**
 * z_policy_stream_destroy:
 * @o: Python self argument
 *
 * This function is registered as the free function for ZPolicyStream, thus it is
 * called when a ZPolicyStream is to be freed.
 **/
static void
z_policy_stream_destroy(PyObject *o)
{
  ZPolicyStream *self = (ZPolicyStream *) o;

  z_stream_unref(self->stream);
  PyObject_Del(self);
}

/**
 * z_policy_stream_getattr:
 * @o: Python self argument
 * @name: attribute to return
 *
 * This function is called when an attribute from the ZPolicyStream object is
 * read, the support for various builtin attributes (fd, name etc.) is
 * implemented here.
 *
 * Returns: the Python object referring to the attribute
 **/
static PyObject *
z_policy_stream_getattr(PyObject *o, char *name)
{
  ZPolicyStream *self = (ZPolicyStream *) o;
  if (strcmp(name, "fd") == 0)
    {
      return z_policy_var_build("i", z_stream_get_fd(self->stream));
    }
  else if (strcmp(name, "name") == 0)
    {
      return PyString_FromString(self->stream->name);
    }
  else if (strcmp(name, "bytes_recvd") == 0)
    {
      return PyLong_FromUnsignedLong(self->stream->bytes_recvd);
    }
  else if (strcmp(name, "bytes_sent") == 0)
    {
      return PyLong_FromUnsignedLong(self->stream->bytes_sent);
    }
  else if (strcmp(name, "nul_nonfatal") == 0)
    {
      gboolean value;
      z_stream_ctrl(self->stream, ZST_LINE_GET_NUL_NONFATAL,  &value, sizeof(gboolean));
      return Py_BuildValue("i", !!value);
    }
  else if (strcmp(name, "split") == 0)
    {
      gboolean value;
      z_stream_ctrl(self->stream, ZST_LINE_GET_SPLIT,  &value, sizeof(gboolean));
      return Py_BuildValue("i", value);
    }
  else if (strcmp(name, "keepalive") == 0)
    {
      return PyLong_FromLong(z_stream_get_keepalive(self->stream));
    }

  return Py_FindMethod(py_zorp_stream_methods, o, name);
}

/**
 * z_policy_stream_setattr:
 * @o: Python self argument
 * @name: attribute to set
 * @value: new value for attribute
 *
 * This function is called when an attribute from the ZPolicyStream object is
 * written to, the support for various builtin attributes (fd, name etc.) is
 * implemented here.
 *
 * Returns: 1 to indicate failure, 0 for success
 **/
static gint 
z_policy_stream_setattr(PyObject *o, char *name,
			 PyObject *value)
{
  ZPolicyStream *self = (ZPolicyStream *) o;
  gchar *str;
  if (strcmp(name, "name") == 0)
    {
      if (!PyArg_Parse(value, "s", &str))
	{
	  PyErr_SetString(PyExc_TypeError, "Stream name is not a string");
	  return 1;
	}
      else
	{
	  z_stream_set_name(self->stream, str);
	  return 0;
	}
    }
  else if (strcmp(name, "nul_nonfatal") == 0)
    {
      int cval;
      if (!PyArg_Parse(value, "i", &cval))
	{
	  PyErr_SetString(PyExc_TypeError, "nul_nonfatal is boolean");
	  return 1;
	}
      z_stream_ctrl(self->stream, ZST_LINE_SET_NUL_NONFATAL,  &cval, sizeof(int));
      return 0;
    }
  else if (strcmp(name, "split") == 0)
    {
      int cval;
      if (!PyArg_Parse(value, "i", &cval))
	{
	  PyErr_SetString(PyExc_TypeError, "split is boolean");
	  return 1;
	}
      z_stream_ctrl(self->stream, ZST_LINE_SET_SPLIT,  &cval, sizeof(int));
      return 0;
    }
  else if (strcmp(name, "keepalive") == 0)
    {
      gint keepalive; 
      if (!PyArg_Parse(value, "i", &keepalive))
        {
          PyErr_SetString(PyExc_TypeError, "Stream keepalive value is not an integer");
          return 1;
        }
      else
        {
          z_stream_set_keepalive(self->stream, keepalive);
          return 0;
        }
    }

  PyErr_SetString(PyExc_AttributeError, "No such attribute");
  return 1;
}

/**
 * z_policy_stream_repr:
 * @o: ZPolicyStream object
 *
 * __repr__ function for ZPolicyStream objects
 **/
static PyObject *
z_policy_stream_repr(PyObject *o)
{
  ZPolicyStream *self = (ZPolicyStream *) o;

  return PyString_FromString(self->stream->name);
}


/**
 * z_policy_stream_readline
 * @o: Python self, ZPolicyStream object
 * @args: Python args argument
 *
 * readline method exported to Python with this declaration:
 *   def readline(self)
 *
 * gets a line from the stream
 */
 
static PyObject *
z_policy_stream_readline(PyObject *o, PyObject *args G_GNUC_UNUSED)
{
  ZPolicyStream *self = (ZPolicyStream *) o;
  gchar *buf;
  PyObject *pybuf;
  gsize bytes_read;
  gint res;
  
  Py_BEGIN_ALLOW_THREADS
  res = z_stream_line_get(self->stream, &buf, &bytes_read, NULL);
  Py_END_ALLOW_THREADS
  if (res == G_IO_STATUS_NORMAL)
    {
      pybuf = Py_BuildValue("s#", buf, bytes_read);
      return pybuf;
    }
  PyErr_SetObject(z_policy_stream_exception, Py_BuildValue("(i,O)", res, Py_None));
  return NULL;
}


/**
 * z_policy_stream_read:
 * @o: Python self, ZPolicyStream object
 * @args: Python args argument
 *
 * read method exported to Python with this declaration: 
 *   def read(length):
 *
 * the length argument specifies how many bytes need to be read.
 **/
static PyObject *
z_policy_stream_read(PyObject *o, PyObject *args)
{
  ZPolicyStream *self = (ZPolicyStream *) o;
  PyObject *pybuf;
  gchar *buf;
  guint length;
  gsize bytes_read;
  gint res;
  
  if (!PyArg_ParseTuple(args, "i", &length))
    return NULL;

  buf = g_new0(char, length);
  Py_BEGIN_ALLOW_THREADS
  res = z_stream_read(self->stream, buf, length, &bytes_read, NULL);
  Py_END_ALLOW_THREADS
  if (res == G_IO_STATUS_NORMAL)
    {
      pybuf = Py_BuildValue("s#", buf, bytes_read);
      g_free(buf);
      return pybuf;
    }
  g_free(buf);
  PyErr_SetObject(z_policy_stream_exception, Py_BuildValue("(i,O)", res, Py_None));
  return NULL;
}

/**
 * z_policy_stream_write:
 * @o: Python self, ZPolicyStream object
 * @args: Python args argument
 *
 * read method exported to Python with this declaration: 
 *   def read(buf):
 *
 * the buf argument is a Python string which contains the byte sequence to
 * be written.
 **/
static PyObject *
z_policy_stream_write(PyObject *o, PyObject *args)
{
  ZPolicyStream *self = (ZPolicyStream *) o;
  gchar *buf; 
  guint length;
  gsize bytes_written;
  gint res;
  
  if (!PyArg_ParseTuple(args, "s#", &buf, &length))
    return NULL;
    
  Py_BEGIN_ALLOW_THREADS
  res = z_stream_write(self->stream, buf, length, &bytes_written, NULL);
  Py_END_ALLOW_THREADS
  
  if (res != G_IO_STATUS_NORMAL)
    {
      PyErr_SetString(PyExc_IOError, "I/O error writing stream.");
      return NULL;
    }
  
  Py_XINCREF(Py_None);
  return Py_None;
}


/**
 * z_policy_stream_close:
 * @o: Python self argument, ZPolicyStream object
 * @args: Python args argument
 *
 * Close method exported to Python. 
 **/
static PyObject *
z_policy_stream_close(PyObject *o, PyObject *args G_GNUC_UNUSED)
{
  ZPolicyStream *self = (ZPolicyStream *) o;

  z_stream_close(self->stream, NULL);
  Py_XINCREF(Py_None);
  return Py_None;
}

/**
 * z_policy_stream_init:
 * 
 * This function is called at Python initialization to export ZPolicyStream
 * related functions.
 **/
void
z_policy_stream_module_init(void)
{
  PyObject* module;

  PyImport_AddModule("Zorp.Stream");
  module = Py_InitModule("Zorp.Stream", z_policy_stream_funcs);
  
  z_policy_stream_exception = PyErr_NewException("Zorp.Stream.StreamException", NULL, NULL);
  Py_INCREF(z_policy_stream_exception);
  PyModule_AddObject(module, "StreamException", z_policy_stream_exception);
}
