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
 * $Id: pypolicy.c,v 1.68 2004/08/16 10:32:58 bazsi Exp $
 *
 * Author  : Bazsi
 * Auditor : kisza
 * Last audited version: 1.20
 * Notes:
 *   - comments
 *
 ***************************************************************************/

/* 
 * This is an implementation of the policy interface with the python
 * interpreter 
 */

#include <zorp/policy.h>
#include <zorp/log.h>
#include <zorp/zpython.h>

/* for python initialization functions */
#include <zorp/pycore.h>
#include <zorp/pydispatch.h>
#include <zorp/pyattach.h>
#include <zorp/pystream.h>
#include <zorp/pyproxy.h>
#include <zorp/pysockaddr.h>
#include <zorp/pyproxygroup.h>
#include <zorp/pybalance.h>
#include <zorp/notification.h>

/* for capability management */
#include <zorp/cap.h>

ZPolicy *current_policy;

/* Notification thread function and indicating policy termination */
extern gpointer z_notification_thread_main_func(gpointer data);
extern void _notify_event_queue_terminate_request(ZPolicy *policy);


extern void z_py_zorp_balance_init(void);

const gchar *
z_verdict_str(ZVerdict verdict)
{
  static const gchar *verdict_str[] =
  {
    [ZV_UNSPEC] = "Unspecified",
    [ZV_ACCEPT] = "Accept data",
    [ZV_DENY]   = "Deny data",
    [ZV_REJECT] = "Reject data",
    [ZV_ABORT]  = "Abort connection",
    [ZV_DROP]   = "Drop data",
    [ZV_POLICY] = "Call policy",
    [ZV_ERROR]  = "Error while processing",
  };
  if ((guint) verdict <= 7)
    return verdict_str[(guint) verdict];
  return "Unknown";
}

/* helper functions used by proxies */

gboolean 
z_policy_tuple_get_verdict(ZPolicyObj *tuple, guint *verdict)
{
  ZPolicyObj *tmp;
                                                                                
  z_enter();
  if (!z_policy_seq_check(tuple))
    {
      if (z_policy_var_parse(tuple, "i", verdict))
        z_return(TRUE);
      /* not a sequence nor an int */
      z_return(FALSE);
    }
                                                                                
  tmp = z_policy_seq_getitem(tuple, 0);
  if (!tmp || !z_policy_var_parse(tmp, "i", verdict))
    {
      /* policy syntax error */
      z_policy_var_unref(tmp);
      z_return(FALSE);
    }
  z_policy_var_unref(tmp);
  z_return(TRUE);
}


/**
 * z_policy_convert_strv_to_list:
 * @strv: String array to 'listify'
 *
 * Converts an array of C strings to Python list of strings.
 *
 * Returns:
 * The resulting list
 */
PyObject *
z_policy_convert_strv_to_list(gchar const **strv)
{
  PyObject *list;
  gint i;
  
  list = PyList_New(0);
  for (i = 0; strv[i]; i++)
    {
      PyList_Append(list, PyString_FromString(strv[i]));
    }
  return list;
}


/**
 * z_policy_getattr_expr:
 * @container: Base Python object whose attribute is to be set
 * @name: Name of the attribute (see notes below!)
 *
 * Gets an attribute of a Python object, or one of its embedded objects, and
 * so on.
 * If @name is in the form of 'Emb1.Emb2. ... .EmbN.Attribute', then
 * container.Emb1.Emb2. ... .EmbN.Attribute will be asked for.
 * Certainly, if @name is only 'Attribute', then container.Attribute will be
 * returned.
 *
 * Returns:
 * The attribute value on success, otherwise NULL
 */
PyObject *
z_policy_getattr_expr(PyObject *container, const char *name)
{
  PyObject *p, *new_p;
  gchar **attr;
  gint i;
  
  attr = g_strsplit(name, ".", 0);
  
  p = container;

  Py_XINCREF(p);
  for (i = 0; attr[i] && p; i++)
    {
      new_p = PyObject_GetAttrString(p, attr[i]);
      
      Py_XDECREF(p);
      p = new_p;
    }
  g_strfreev(attr);
  return p;
}    


/**
 * z_policy_setattr_expr:
 * @container: Base Python object whose attribute is to be set
 * @name: Name of the attribute (see notes below!)
 * @new_value: New attribute value
 *
 * Sets an attribute of a Python object, or one of its embedded objects, and
 * so on.
 * If @name is in the form of 'Emb1.Emb2. ... .EmbN.Attribute', then
 * container.Emb1.Emb2. ... .EmbN.Attribute will be set to @new_value
 * Certainly, if @name is only 'Attribute', then container.Attribute will be set.
 *
 * Returns:
 * 1 on success, 0 otherwise
 */
gint
z_policy_setattr_expr(PyObject *container, const char *name, PyObject *new_value)
{
  PyObject *p, *new_p;
  gchar **attr;
  gint i;
  gint res = 0;
  
  attr = g_strsplit(name, ".", 0);
  
  p = container;

  Py_XINCREF(p);
  for (i = 0; attr[i] && attr[i+1] && p; i++)
    {
      new_p = PyObject_GetAttrString(p, attr[i]);
      
      Py_XDECREF(p);
      p = new_p;
    }
  if (p && attr[i])
    {
      PyObject_SetAttrString(p, attr[i], new_value);
      res = 1;
    }
  Py_XDECREF(p);
    
  g_strfreev(attr);
  return res;
}    


/**
 * z_policy_setattr:
 * @handler: Python object whose attribute is to be set
 * @name: Attribute name
 * @value: New attribute value
 *
 * Same as z_policy_setattr_expr, but in case of failure, it clears the
 * error by PyErr_Clear()
 *
 * Returns:
 * 1 on success, 0 otherwise
 */
gint 
z_policy_setattr(PyObject *handler, char *name, PyObject *value)
{
  if (z_policy_setattr_expr(handler, name, value) == 0)
    {
      z_policy_error_clear();
      return 0;
    }
  return 1;
}


/**
 * z_policy_getattr:
 * @handler: Python object whose attribute is requested
 * @name: Attribute name
 *
 * Same as z_policy_getattr_expr, but in case of failure, it clears the
 * error by PyErr_Clear()
 *
 * Returns:
 * The attribute value on success, otherwise NULL
 */
PyObject *
z_policy_getattr(PyObject *handler, char *name)
{
  PyObject *res;
  
  res = z_policy_getattr_expr(handler, name);
  if (!res)
    z_policy_error_clear();
  return res;
}


/**
 * z_session_getattr:
 * @handler: Python object whose session attribute is requested
 * @name: Attribute name
 *
 * Gets @handler.session.@name
 * FIXME: some words about its meaning
 *
 * Returns:
 * The attribute value on success, otherwise NULL
 */
PyObject *
z_session_getattr(PyObject *handler, gchar *name)
{
  gchar buf[64];
  PyObject *res;
  
  g_snprintf(buf, sizeof(buf), "session.%s", name);
  res = z_policy_getattr_expr(handler, buf);
  if (!res)
    z_policy_error_clear();
  return res;
}


/**
 * z_global_getattr:
 * @name: Global attribute name
 *
 * Gets a global attribute
 * FIXME: are these the ones in 'policy.py'?
 *
 * Returns:
 * The attribute value on success, otherwise NULL
 */
PyObject *
z_global_getattr(const gchar *name)
{
  PyObject *main_module, *res;
  
  main_module = PyImport_AddModule("__main__");
  res = z_policy_getattr_expr(main_module, name);
  if (!res)
    z_policy_error_clear();
  return res;
}


/**
 * z_policy_var_parse_str:
 * @val: PyObject to parse
 * @result: result is strdup-ed here
 *
 * This function tries to parse @val as a string and strdups the value of
 * the string into @result.  It always consumes @val, thus the caller loses
 * its reference.  This function can be used to quickly parse Python values
 * this way:
 * 
 * z_policy_var_parse_str(z_global_getattr("config.module.string_variable"), &c_variable_string);
 **/
gboolean
z_policy_var_parse_str(PyObject *val, gchar **result)
{
  gchar *strvalue = NULL;
  gboolean res = FALSE;
  
  if (val)
    {
      if (z_policy_var_parse(val, "s", &strvalue))
        {
          *result = g_strdup(strvalue);
          res = TRUE;
        }
      Py_XDECREF(val);
    }
  return res;
}


/**
 * z_policy_var_parse_boolean:
 * @val: PyObject to parse
 * @result: result
 *
 * This function tries to parse @val as a boolean and puts the parsed value
 * into @result.  It always consumes @val, thus the caller loses
 * its reference.  This function can be used to quickly parse Python values
 * this way:
 * 
 * z_policy_var_parse_int(z_global_getattr("config.module.boolean_variable"), &c_variable_boolean);
 **/
gboolean
z_policy_var_parse_boolean(PyObject *val, gboolean *result)
{
  gboolean success;
  gint intval = 0;
  
  success = z_policy_var_parse_int(val, &intval);
  *result = intval;
  return success;
}

/**
 * z_policy_var_parse_int:
 * @val: PyObject to parse
 * @result: result
 *
 * This function tries to parse @val as an integer and puts the parsed value
 * into @result.  It always consumes @val, thus the caller loses
 * its reference.  This function can be used to quickly parse Python values
 * this way:
 * 
 * z_policy_var_parse_int(z_global_getattr("config.module.integer_variable"), &vc_variable_integer);
 **/
gboolean
z_policy_var_parse_int(PyObject *val, gint *result)
{
  gboolean res = TRUE;
  
  if (val)
    {
      if (!z_policy_var_parse(val, "i", result))
        {
          res = FALSE;
        }
      Py_XDECREF(val);
    }
  return res;
}

/**
 * z_policy_var_parse_size:
 * @val: PyObject to parse
 * @result: result
 *
 * This function tries to parse @val as a gsize and puts the parsed value
 * into @result.  It always consumes @val, thus the caller loses
 * its reference.  This function can be used to quickly parse Python values
 * this way:
 * 
 * z_policy_var_parse_int(z_global_getattr("config.module.gsize_variable"), &c_variable_gsize);
 **/
gboolean
z_policy_var_parse_size(PyObject *val, gsize *result)
{
  gboolean res = TRUE;
  
  if (val)
    {
      switch (sizeof(gsize))
        {
        case sizeof(gchar):
          res = z_policy_var_parse(val, "b", result);
          break;

        case sizeof(gshort):
          res = z_policy_var_parse(val, "h", result);
          break;

        case sizeof(gint):
          res = z_policy_var_parse(val, "i", result);
          break;

        case sizeof(gint64):
          res = z_policy_var_parse(val, "L", result);
          break;

        default:
          g_assert(0); /* NOTE: crash out instead of letting the error escalate */
          break;
        }
      Py_XDECREF(val);
    }
  return res;
}

/**
 * z_policy_var_parse_int64:
 * @val: PyObject to parse
 * @result: result
 *
 * This function tries to parse @val as an integer and puts the parsed value
 * into @result.  It always consumes @val, thus the caller loses
 * its reference.  This function can be used to quickly parse Python values
 * this way:
 * 
 * z_policy_var_parse_int(z_global_getattr("config.module.int64_variable"), &c_variable_gint64);
 **/
gboolean
z_policy_var_parse_int64(PyObject *val, gint64 *result)
{
  gboolean res = TRUE;
  
  if (val)
    {
      if (!z_policy_var_parse(val, "L", result))
        {
          res = FALSE;
        }
      Py_XDECREF(val);
    }
  return res;
}


/**
 * z_policy_call_object:
 * @func: Python method to call
 * @args: Arguments to pass to @func
 * @session_id: Session ID for logging
 *
 * Calls @func with @args, and if an error happened, sends log messages
 * (containing @session_id) to the log.
 *
 * Returns:
 * The return value of @func
 */
PyObject *
z_policy_call_object(PyObject *func, PyObject *args, gchar *session_id)
{
  PyObject *res;
  
  PyErr_Clear();
  res = PyObject_CallObject(func, args);
  
  Py_XDECREF(args);
  
  if (!res)
    {
      PyObject *m = PyImport_AddModule("sys");
      
      if (!PyString_Check(PyErr_Occurred()))
        {
          PyErr_Print();
        }
      else
        {
          PyObject *exc, *value, *tb, *str;
          
          PyErr_Fetch(&exc, &value, &tb);
          PyErr_NormalizeException(&exc, &value, &tb);
          
          str = PyObject_Str(value);
          if (!str)
            {
              /*NOLOG*/
              z_log(session_id, CORE_ERROR, 3, "%s;", PyString_AsString(exc));
            }
          else
            {
              /*NOLOG*/
              z_log(session_id, CORE_ERROR, 3, "%s; reason='%s'", PyString_AsString(exc), PyString_AsString(str));
            }
          
          Py_XDECREF(exc);
          Py_XDECREF(value);
          Py_XDECREF(tb);
          Py_XDECREF(str);
        }
      PyObject_SetAttrString(m, "last_traceback", Py_None); 
    }

  return res;
}


/**
 * z_policy_call:
 * @handler: Python object whose method shall be called
 * @name: Method name
 * @args: Arguments to pass to the method
 * @called: Flag to store into whether the call succeeded or not (may be NULL)
 * @session_id: Session ID for logging
 *
 * If the requested method exists and is callable, calls it.
 * If @called is not NULL, it will be set if the call succeeded, cleared if not.
 *
 * Returns:
 * The return value of the call
 */
PyObject *
z_policy_call(PyObject *handler, char *name, PyObject *args, gboolean *called, gchar *session_id)
{
  PyObject *attr;
  PyObject *res;

  z_enter();
  g_assert(PyThreadState_GET());
  attr = PyObject_GetAttrString(handler, name);
  if (!attr || !PyCallable_Check(attr))
    {
      if (attr)
        {
          Py_XDECREF(attr);
          PyErr_Format(PyExc_TypeError, "Event must be callable: %s", name);
          PyErr_Print(); /* produce a backtrace, and handle it immediately */
        }
      PyErr_Clear();
      Py_XDECREF(args);
      res = NULL;
      z_trace(NULL, "Cannot find function; name='%s'", name);
      if (called)
        *called = FALSE;
    }
  else
    {
      if (called)
        *called = TRUE;
      res = z_policy_call_object(attr, args, session_id);
      z_trace(NULL, "Function called; name='%s'", name);
      Py_XDECREF(attr);
    }
  z_return(res);
}


/**
 * z_policy_event:
 * @handler: Python object whom to send the event
 * @name: Method to be called
 * @args: Args to pass to @name
 * @session_id: Session ID
 *
 * Sends an event to an object by calling one of its methods. The methods
 * 'preProcessEvent' and 'postProcessEvent' are called before and after the
 * event handler method.
 * 
 * FIXME: I found no occurences of 'ProcessEvent' but in this function, so I
 * can't track the purpose of this functionality.
 *
 * Returns:
 * Z_UNSPEC, Z_ABORT, ???
 */
gint 
z_policy_event(PyObject *handler, char *name, PyObject *args, gchar *session_id)
{
  PyObject *res;
  unsigned long c_res;
  gboolean called;

  Py_XINCREF(args);
  res = z_policy_call(handler, "preProcessEvent", args, &called, session_id);
  if (res)
    {
      if (PyInt_Check(res))
	{
	  c_res = PyInt_AsLong(res);
	  Py_XDECREF(res);
	  if (c_res != Z_UNSPEC)
	    {
	      Py_XDECREF(args);
	      return c_res;
	    }
	}
      else
	{
	  PyErr_Format(PyExc_TypeError, "preProcessEvent() handlers should return an int.");
	  PyErr_Print(); /* produce a backtrace, and handle it immediately */
	  Py_XDECREF(res);
	}
    }
  else
    if (called)
      return Z_ABORT;
  Py_XINCREF(args);
  res = z_policy_call(handler, name, args, &called, session_id);
  if (res)
    {
      if (PyInt_Check(res))
	{
	  c_res = PyInt_AsLong(res);
	  Py_XDECREF(res);
	  if (c_res != Z_UNSPEC)
	    {
	      Py_XDECREF(args);
	      return c_res;
	    }
	}
      else
	{
	  PyErr_Format(PyExc_TypeError, "Event handlers should return an int: %s", name);
	  PyErr_Print(); /* produce a backtrace, and handle it immediately */
	  Py_XDECREF(res);
	}
    }
  else
    if (called)
      return Z_ABORT;
  res = z_policy_call(handler, "postProcessEvent", args, &called, session_id);
  if (res)
    {
      if (PyInt_Check(res))
	{
	  c_res = PyInt_AsLong(res);
	  Py_XDECREF(res);
	  return c_res;
	}
      else
	{
	  PyErr_Format(PyExc_TypeError, "postProcessEvent() handlers should return an int.");
	  PyErr_Print(); /* produce a backtrace, and handle it immediately */
	  Py_XDECREF(res);
	}
    }
  else
    if (called)
      return Z_ABORT;
  return Z_UNSPEC;
}


/* loadable policies */

GStaticMutex policy_ref_lock = G_STATIC_MUTEX_INIT;

struct _ZPolicyThread
{
  ZPolicy *policy;
  PyThreadState *thread;
  /* thread startup synchronization */
  gboolean startable:1, used:1;
  GMutex   *startable_lock;
  GCond    *startable_signal;
};

GStaticPrivate policy_thread = G_STATIC_PRIVATE_INIT;

static gboolean z_policy_purge(ZPolicy *self);
#include <zorp/coredump.h>



/**
 * z_policy_thread_ready:
 * @self: this
 *
 * Marks the thread ready for starting by setting its 'startable' flag.
 */
void
z_policy_thread_ready(ZPolicyThread *self)
{
  g_mutex_lock(self->startable_lock);
  self->startable = TRUE;
  g_cond_signal(self->startable_signal);
  g_mutex_unlock(self->startable_lock);
}


/**
 * z_policy_thread_wait:
 * @self: this
 *
 * Waits until the thread gets ready for starting
 */
static void
z_policy_thread_wait(ZPolicyThread *self)
{
  g_mutex_lock(self->startable_lock);
  while (!self->startable)
    {
      g_cond_wait(self->startable_signal, self->startable_lock);
    }
  g_mutex_unlock(self->startable_lock);
}


/**
 * z_policy_thread_acquire:
 * @self: this
 *
 * Acquires and stores reference information about the current thread.
 * self->thread is the PyThreadState (context on the Python-side),
 * policy_thread is the thread-private ZPolicyThread* (context on the C-side).
 */
void
z_policy_thread_acquire(ZPolicyThread *self)
{
  z_policy_thread_wait(self);
  
  g_static_private_set(&policy_thread, self, NULL);
  PyEval_AcquireThread(self->thread);

  /* NOTE: this is currently a warning, but it'd probably make sense to
   * actually exclude parallel execution in the same thread by using a mutex
   * in ZPolicyThread. However as this is a risky change at 3.1.x, x >= 14 I
   * only added a warning here.
   */
  if (self->used)
    {
#if 0
      z_log(NULL, CORE_ERROR, 0, "Internal error, ZPolicyThread reused, dumping core & continuing;");
      z_coredump_create();
#endif
    }
  self->used = TRUE;
}


/**
 * z_policy_thread_release:
 * @self:  this
 *
 * Releases reference information acquired by z_policy_thread_acquire.
 */
void
z_policy_thread_release(ZPolicyThread *self)
{
  self->used = FALSE;
  PyEval_ReleaseThread(self->thread);
  g_static_private_set(&policy_thread, NULL, NULL);
}


/**
 * z_policy_thread_self:
 *
 * Get the ZPolicyThread context of the current thread.
 * Uses the thread-private variable 'policy_thread', set by
 * 'z_policy_thread_acquire'.
 *
 * Returns:
 * The current context.
 */
ZPolicyThread *
z_policy_thread_self(void)
{
  return g_static_private_get(&policy_thread);
}


/**
 * z_policy_thread_get_policy:
 * @self: this
 *
 * Get method for the 'policy' attribute
 *
 * Returns:
 * The policy
 */
ZPolicy *
z_policy_thread_get_policy(ZPolicyThread *self)
{
  return self->policy;
}


/**
 * z_policy_thread_new:
 * @policy: The policy to create a thread for
 *
 * Constructor of ZPolicyThread. If the policy already has a main thread,
 * only acquire a new ThreadState instance (start a new thread in that
 * interpreter), else start a new interpreter.
 *
 * Returns:
 * The new instance
 */
ZPolicyThread *
z_policy_thread_new(ZPolicy *policy)
{
  ZPolicyThread *self = g_new0(ZPolicyThread, 1);
  
  /* NOTE: requires the interpreter lock to be held */
  self->startable = FALSE;
  self->startable_lock = g_mutex_new();
  self->startable_signal = g_cond_new();
  
  self->policy = z_policy_ref(policy);
  if (policy->main_thread)
    {
      self->thread = PyThreadState_New(self->policy->main_thread->thread->interp);
    }
  else
    {
      /* initialize a new interpreter instance */
      self->thread = Py_NewInterpreter();
      PyThreadState_Swap(NULL);
    }
  return self;
}

/**
 * z_policy_thread_destroy:
 * @self: this
 *
 * Destructor of ZPolicyThread.
 * The embedded Python thread context (self->thread) will be cleared and 
 * deleted also, and if this thread was the last one running in the
 * interpreter instance, that will be stopped, too.
 */
void
z_policy_thread_destroy(ZPolicyThread *self)
{
  /* acquires the interpreter lock */

  if (self->policy->main_thread != self)
    {
      /* we are one of the secondary threads */
      z_python_lock();
      PyThreadState_Swap(self->thread);
      PyThreadState_Clear(self->thread);
      PyThreadState_Swap(NULL);
      PyThreadState_Delete(self->thread);
      z_python_unlock();
      z_policy_unref(self->policy);
    }
  else
    {
      /* we must be freed at last, when the policy is being destroyed */
      g_assert(self->policy->ref_cnt == 1);
      /* we are the main thread, destroy the interpreter */
      z_policy_purge(self->policy);
      PyEval_AcquireThread(self->thread);
      Py_EndInterpreter(self->thread);
      z_python_unlock();
    }
  g_mutex_free(self->startable_lock);
  g_cond_free(self->startable_signal);
  g_free(self);
}


/**
 * z_policy_free:
 * @self: this
 *
 * Destroys a ZPolicy by freeing its filename and destroying its threads.
 */
static void
z_policy_free(ZPolicy *self)
{
  /* FIXME: we should acquire a thread state to be able to free ourselves */
 
  g_free(self->policy_filename);
  /* NOTE: This must be the last because that destroyer assume that he is the last men standing. */
  z_policy_thread_destroy(self->main_thread);
  g_free(self);
}



/**
 * z_policy_ref:
 * @self: this
 *
 * Increments the reference counter of a ZPolicy.
 * Each policy reference counter is protected by the interpreter lock
 *
 * Returns:
 * this
 */
ZPolicy * 
z_policy_ref(ZPolicy *self)
{
  g_static_mutex_lock(&policy_ref_lock);
  g_assert(self->ref_cnt > 0);
  
  self->ref_cnt++;
  g_static_mutex_unlock(&policy_ref_lock);
  return self;
}

/**
 * z_policy_unref:
 * @self: this
 *
 * Decrements the reference counter of a ZProxy, freeing the instance if
 * the counter drops to zero.
 */
void
z_policy_unref(ZPolicy *self)
{
  g_static_mutex_lock(&policy_ref_lock);
  g_assert(self->ref_cnt > 0);
  
  --self->ref_cnt;

  /* NOTE: This reference counter counts two different reference types:
   *   * the number of references to this ZPolicy instance by the rest of Zorp
   *   * the number of internal references between ZPolicy and the
   *     ZPolicyThread instances started in z_policy_new(): main thread 
   *     and notification thread
   *
   * The main and notification threads form circular references, their
   * destruction must be triggered somehow. Whenever the number of
   * references go low enough we trigger destruction, which will eventually
   * cause the refcounter to go to 0.
   *
   * The trigger to terminate the notification thread is also sent from
   * here, when the refcount goes to 3.
   *
   */   


/* main thread */
#define ZPOLICY_BASE_REFCOUNT 1

  if (self->ref_cnt == ZPOLICY_BASE_REFCOUNT)
    {
      /* ok, only the notification thread & main thread remains, start destructing them now */
      g_static_mutex_unlock(&policy_ref_lock);
      z_policy_free(self);
    }
  else
    {
      g_static_mutex_unlock(&policy_ref_lock);
    }
}


/**
 * z_policy_boot:
 * @self: this
 *
 * 'Boots' a policy:
 * - loads policy.boot (importing necessary modules)
 * - initialises the modules
 *
 * FIXME?: the only check is for the read access on policy.boot
 *          there is no check whether it could be interpreted correctly,
 *          neither for the modules' initialisations
 * 
 * Returns:
 * TRUE if policy.boot exists
 */
gboolean
z_policy_boot(ZPolicy *self)
{
  FILE *bootstrap;
  
  if ((bootstrap = fopen(ZORP_POLICY_BOOT_FILE, "r")) == NULL)
    {
      /*LOG
        This message indicates that the policy.boot file couldn't be opened for
        reading.
       */
      z_log(NULL, CORE_ERROR, 0, "Error opening policy.boot file; file='%s'", ZORP_POLICY_BOOT_FILE);
      return FALSE;
    }

  z_policy_thread_acquire(self->main_thread);

  PyRun_SimpleFile(bootstrap, ZORP_POLICY_BOOT_FILE);
  fclose(bootstrap);

  /* PyImport_AddModule("Zorp.Zorp"); */
  
  z_py_zorp_core_init();
  z_policy_struct_module_init();
  z_policy_dispatch_module_init();
  z_policy_attach_module_init();
  z_policy_stream_module_init();
  z_policy_proxy_module_init();
  z_policy_sockaddr_module_init();
  z_policy_proxy_group_module_init();


  z_policy_thread_release(self->main_thread);
  
  return TRUE;
}

/**
 * z_policy_load:
 * @self: this
 *
 * Load and run a policy file. If the file doesn't exist or a parse error
 * happens, produces an error message in the log.
 *
 * Returns:
 * TRUE on success
 */
gboolean
z_policy_load(ZPolicy *self)
{
  FILE *script;
  int res = -1;
  
  script = fopen(self->policy_filename, "r");
  if (script)
    {
      z_policy_thread_acquire(self->main_thread);
      res = PyRun_SimpleFile(script, self->policy_filename);
      fclose(script);
      z_policy_thread_release(self->main_thread);
    }
  else
    {
      /*LOG
	This message indicates that Zorp was unable to open the policy file.
	Check the permissions of your policy file.
       */
      z_log(NULL, CORE_ERROR, 0, "Error opening policy file; filename='%s'", self->policy_filename);
    }
  
  if (res == -1)
    {
      /*LOG
	This message indicates that Zorp was unable to parse the policy file.
	Check the logs for further information on where the error occurred in the policy.
       */
      z_log(NULL, CORE_ERROR, 0, "Error parsing policy file; filename='%s'", self->policy_filename);
      /* let the error message out */
    }

  return res != -1;
}


/**
 * z_policy_init:
 * @self: this
 * @instance_name: array of instance name and aliases
 *
 * Initialises the current policy by calling ?Zorp.init?.
 * The function interface (not the implementation) here should be
 * independent of python.
 *
 * Returns:
 * TRUE on success
 */
gboolean
z_policy_init(ZPolicy *self, gchar const **instance_name)
{
  PyObject *main_module, *init_func, *res;
  gboolean success = FALSE;
  cap_t saved_caps;
  
  z_policy_thread_acquire(self->main_thread);
  
  main_module = PyImport_AddModule("__main__");
  init_func = PyObject_GetAttrString(main_module, "init");

  saved_caps = cap_save();
  cap_enable(CAP_NET_ADMIN);

  res = PyObject_CallFunction(init_func, "(O)", z_policy_convert_strv_to_list(instance_name));

  cap_restore(saved_caps);

  Py_XDECREF(init_func);
  if (res && z_policy_var_parse(res, "i", &success))
    {
      /* init successful */
    }
  else if (!res)
    {
      PyErr_Print();
    }
  Py_XDECREF(res);
  z_policy_thread_release(self->main_thread);

  return success;
}

/**
 * z_policy_deinit:
 * @self: this
 * @instance_name: array of instance name and aliases
 *
 * Deinitialises the current policy by calling ?Zorp.deinit?.
 *
 * Returns:
 * TRUE on success
 */
gboolean
z_policy_deinit(ZPolicy *self, gchar const **instance_name)
{
  PyObject *main_module, *deinit_func, *res;
  
  z_policy_thread_acquire(self->main_thread);
  
  main_module = PyImport_AddModule("__main__");
  deinit_func = PyObject_GetAttrString(main_module, "deinit");

  res = PyObject_CallFunction(deinit_func, "(O)", z_policy_convert_strv_to_list(instance_name));
  Py_XDECREF(deinit_func);
  if (!res)
    {
      PyErr_Print();
    }
  Py_XDECREF(res);
  z_policy_thread_release(self->main_thread);

  return res != NULL;
}


/**
 * z_policy_purge:
 * @self: this
 *
 * Purge the current thread context by calling ?Zorp.purge?
 * FIXME: z_policy_thread_acquire(self->main_thread) -?-> z_policy_acquire_main(self)
 *
 * Returns:
 * TRUE on success
 */
static gboolean
z_policy_purge(ZPolicy *self)
{
  PyObject *main_module, *purge_func, *res;
  
  z_policy_thread_acquire(self->main_thread);
  
  main_module = PyImport_AddModule("__main__");
  purge_func = PyObject_GetAttrString(main_module, "purge");

  res = PyObject_CallFunction(purge_func, "()");
  Py_XDECREF(purge_func);
  if (!res)
    {
      PyErr_Print();
    }
  Py_XDECREF(res);
  z_policy_thread_release(self->main_thread);

  return res != NULL;
}

/**
 * z_policy_cleanup:
 * @self: this
 * @instance_name: array of instance name and aliases
 *
 * Cleans up the current policy by calling ?Zorp.cleanup?.
 * Currently used by KZorp to flush kernel data structures
 * when Zorp is exiting.
 *
 * Returns:
 * TRUE on success
 */
gboolean
z_policy_cleanup(ZPolicy *self, gchar const **instance_name)
{
  PyObject *main_module, *cleanup_func, *res;
  cap_t saved_caps;
  
  z_policy_thread_acquire(self->main_thread);
  
  main_module = PyImport_AddModule("__main__");
  cleanup_func = PyObject_GetAttrString(main_module, "cleanup");

  saved_caps = cap_save();
  cap_enable(CAP_NET_ADMIN);

  res = PyObject_CallFunction(cleanup_func, "(O)", z_policy_convert_strv_to_list(instance_name));

  cap_restore(saved_caps);

  Py_XDECREF(cleanup_func);
  if (!res)
    {
      PyErr_Print();
    }
  Py_XDECREF(res);
  z_policy_thread_release(self->main_thread);

  return res != NULL;
}

/**
 * z_policy_acquire_main:
 * @self: this
 *
 * Switch to the context of the main thread
 */
void
z_policy_acquire_main(ZPolicy *self)
{
  z_policy_thread_acquire(self->main_thread);
}

/**
 * z_policy_release_main:
 * @self: this
 *
 * Leave the context of the main thread.
 * Note that this doesn't imply 'returning to the previous context', for that
 * you must call z_policy_acquire() explicitely.
 */
void
z_policy_release_main(ZPolicy *self)
{
  z_policy_thread_release(self->main_thread);
}

/**
 * z_policy_new:
 * @filename: Name of the policy file
 *
 * Constructor of ZPolicy, creates a new instance and starts its main thread
 * and notification thread. The policy's refcount is 3: one per thread
 * plus one for the caller.
 *
 * Returns:
 * The new instance
 */
ZPolicy *
z_policy_new(const gchar *filename)
{
  ZPolicy *self = g_new0(ZPolicy, 1);
  
  self->ref_cnt = 1;
  self->policy_filename = g_strdup(filename);
  z_python_lock();
  self->main_thread = z_policy_thread_new(self);
  z_python_unlock();
  z_policy_thread_ready(self->main_thread);
  
  /* the main thread and the notification thread always references us,
   * and we should be deleted when that reference is dropped */
  
  return self;
}

void 
z_policy_raise_exception_obj(PyObject *exc, gchar *desc)
{
  PyErr_SetString(exc, desc);
}


/**
 * z_policy_raise_exception:
 * @exception_name: Name of the exception
 * @desc: Description
 *
 * Generate a Python exception with the given name and descriptions
 */
void 
z_policy_raise_exception(gchar *exception_name, gchar *desc)
{
  PyObject *main_module, *license_exc;
  
  main_module = PyImport_AddModule("__main__");
  license_exc = PyObject_GetAttrString(main_module, exception_name);
  PyErr_SetString(license_exc, desc);
  Py_XDECREF(license_exc);
}

