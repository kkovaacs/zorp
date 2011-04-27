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
 * $Id: policy.h,v 1.35 2004/08/05 14:14:24 sasa Exp $
 *
 ***************************************************************************/

#ifndef ZORP_POLICY_H_INCLUDED
#define ZORP_POLICY_H_INCLUDED

#include <zorp/zorp.h>
#include <zorp/zpython.h>

/*+

  ZPolicyObj is a reference counted data structure, capable of holding
  a value in the policy layer. Currently it's just a simple PyObject.

  +*/
typedef PyObject ZPolicyObj;

typedef struct _ZPolicy ZPolicy;
typedef struct _ZPolicyThread ZPolicyThread;

struct _ZPolicy
{
  gint ref_cnt;
  gchar *policy_filename;
  ZPolicyThread *main_thread;
};

void z_policy_thread_ready(ZPolicyThread *self);
void z_policy_thread_acquire(ZPolicyThread *self);
void z_policy_thread_release(ZPolicyThread *self);
ZPolicyThread *z_policy_thread_new(ZPolicy *policy);
void z_policy_thread_destroy(ZPolicyThread *self);
ZPolicyThread *z_policy_thread_self(void);
ZPolicy *z_policy_thread_get_policy(ZPolicyThread *self);

ZPolicy *z_policy_ref(ZPolicy *self);

void z_policy_unref(ZPolicy *self);

gboolean z_policy_boot(ZPolicy *self);
gboolean z_policy_load(ZPolicy *self);

gboolean z_policy_init(ZPolicy *self, gchar const **instance_name);

ZPolicy *z_policy_new(const gchar *filename);
void z_policy_acquire_main(ZPolicy *self);
void z_policy_release_main(ZPolicy *self);

gboolean z_policy_deinit(ZPolicy *self, gchar const **instance_name);

gboolean z_policy_cleanup(ZPolicy *self, gchar const **instance_name);

#define z_policy_exc_value_error PyExc_ValueError
#define z_policy_exc_attribute_error PyExc_AttributeError
#define z_policy_exc_runtime_error PyExc_RuntimeError

void z_policy_raise_exception(gchar *exception_name, gchar *desc);
void z_policy_raise_exception_obj(ZPolicyObj *exc, gchar *desc);

#define z_policy_lock z_policy_thread_acquire
#define z_policy_unlock z_policy_thread_release

extern ZPolicy *current_policy;

/* Zorp policy verdicts, determines what the proxy does with a specific event
 * Can be extended with proxy specific values above 100 */
typedef enum 
{
  ZV_UNSPEC     = 0, /* policy doesn't specify it, do something sensible */
  ZV_ACCEPT     = 1,
  ZV_DENY       = 2,
  ZV_REJECT     = 3, /* continue and tell the client that we didn't do it */
  ZV_ABORT      = 4, /* abort the connection */
  ZV_DROP       = 5, /* continue and don't do it */
  ZV_POLICY     = 6, /* Policy level will decide what to do */
  ZV_ERROR      = 7, /* Error occured try to nice fail */
  ZV_PROXY_SPECIFIC = 100,
} ZVerdict;

const gchar *z_verdict_str(ZVerdict verdict);

/* deprecated aliases for ZV_* above */
#define Z_UNSPEC   ZV_UNSPEC
#define Z_ACCEPT   ZV_ACCEPT
#define Z_DENY     ZV_DENY  
#define Z_REJECT   ZV_REJECT
#define Z_ABORT    ZV_ABORT 
#define Z_DROP     ZV_DROP  
#define Z_POLICY   ZV_POLICY
#define Z_ERROR    ZV_ERROR

#define z_policy_none Py_None

#define z_policy_var_build(format, args...) Py_BuildValue(format, ##args)
#define z_policy_var_str(v) PyObject_Str(v)
#define z_policy_var_ref(v)   do { Py_XINCREF(v); } while (0)
#define z_policy_var_unref(v) do { Py_XDECREF(v); } while (0)
#define z_policy_var_repr(v)  PyObject_Repr(v)

gboolean z_policy_var_parse_str(PyObject *val, gchar **result);
gboolean z_policy_var_parse_boolean(PyObject *val, gboolean *result);
gboolean z_policy_var_parse_int(PyObject *val, gint *result);
gboolean z_policy_var_parse_int64(PyObject *val, gint64 *result);
gboolean z_policy_var_parse_size(PyObject *val, gsize *result);

static inline gboolean
z_policy_var_parse_uint(PyObject *val, guint *result)
{
  return z_policy_var_parse_int(val, (gint *) result);
}

static inline gboolean
z_policy_var_parse_uint64(PyObject *val, guint64 *result)
{
  return z_policy_var_parse_int64(val, (gint64 *) result);
}

static inline gboolean 
z_policy_var_parse_ssize(PyObject *val, gssize *result)
{
  return z_policy_var_parse_size(val, (gsize *) result);

}


#define z_policy_var_parse(v, format, args...) \
  ({gboolean __res = PyArg_Parse(v, format, ##args); if (!__res) PyErr_Clear(); __res;})
#define z_policy_var_parse_tuple(v, format, args...) \
  ({gboolean __res = PyArg_ParseTuple(v, format, ##args); if (!__res) PyErr_Clear(); __res;})

#define z_policy_tuple_new(s) PyTuple_New(s)
#define z_policy_tuple_resize(s, n) PyTuple_Resize(s, n)
#define z_policy_tuple_getitem(l, i) PyTuple_GetItem(l, i)
#define z_policy_tuple_setitem(v, i, x) PyTuple_SetItem(v, i, x)
#define z_policy_tuple_check(v) PyTuple_Check(v)

#define z_policy_seq_check(v) PySequence_Check(v)
#define z_policy_seq_getitem(v, i) PySequence_GetItem(v, i)
#define z_policy_seq_length(v) PyObject_Length(v)
#define z_policy_seq_get_slice(v, l, h) PySequence_GetSlice(v, l, h)

#define z_policy_list_new(n) PyList_New(n)
#define z_policy_list_getitem(l, i) PyList_GetItem(l, i)
#define z_policy_list_setitem(l, i, x) PyList_SetItem(l, i, x)
#define z_policy_list_append(l, x) PyList_Append(l, x)
#define z_policy_list_size(l) PyList_Size(l)
#define z_policy_list_set_slice(list, l, h, i) PyList_SetSlice(list, l, h, i)

#define z_policy_pdict_check(v) PyDict_Check(v)
#define z_policy_pdict_next(v, pos, k, vl) PyDict_Next(v, pos, k, vl)
#define z_policy_pdict_new() PyDict_New()
#define z_policy_pdict_getitem(v, i) PyDict_GetItem(v, i)
#define z_policy_pdict_getitem_string(v, i) PyDict_GetItemString(v, i)
#define z_policy_pdict_setitem(d, k, v) PyDict_SetItem(d, k, v)
#define z_policy_pdict_setitem_string(d, k, v) PyDict_SetItemString(d, k, v)

#define z_policy_int_new(n) PyInt_FromLong(n)

#define z_policy_str_new(s)  PyString_FromString(s)
#define z_policy_str_check(v) PyString_Check(v)
#define z_policy_str_as_string(v) PyString_AsString(v)


#define z_policy_error_clear() PyErr_Clear()

gboolean z_policy_tuple_get_verdict(ZPolicyObj *tuple, guint *verdict);
ZPolicyObj *z_policy_convert_strv_to_list(gchar const **strv);

ZPolicyObj *z_policy_call(ZPolicyObj *handler, char *name, ZPolicyObj *args, gboolean *called, gchar *session_id);
int z_policy_event(ZPolicyObj *handler, char *name, ZPolicyObj *args, gchar *session_id);
PyObject *z_policy_call_object(PyObject *func, PyObject *args, gchar *session_id);
gint z_policy_setattr(ZPolicyObj *handler, char *name, ZPolicyObj *value);
ZPolicyObj *z_policy_getattr(ZPolicyObj *handler, char *name);
PyObject *z_session_getattr(PyObject *handler, char *name);
PyObject *z_global_getattr(const gchar *name);

#endif
