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
 * $Id$
 *
 * Author  : Bazsi
 * Auditor : 
 * Last audited version:
 * Notes:
 *
 ***************************************************************************/
 
#include <zorp/pydict.h>
#include <zorp/log.h>
#include <zorp/dimhash.h>

#include <sys/types.h>
#include <netinet/in.h>
#include <arpa/inet.h>

/**
 * Description
 *
 *   The ZPolicyDict object is a glue between C variables and types and
 *   their corresponding Python counterparts. It is basically equivalent to
 *   a Python dictionary.
 *
 *   A dictionary is a mapping of (variable name -> C storage description),
 *   where storage description is usually a type (one of Z_VT_*) and a
 *   pointer. The primary user of this interface is pystruct which is a
 *   generic Python type that uses ZPolicyDict as its instance dictionary. 
 *   Simple types like integers and strings are constructed when the
 *   variable of the given type is requested, more complex types (methods,
 *   hashes etc) are constructed on demand, and a reference is cached for
 *   future queries.
 *
 *   As this code is quite closely related to Python, some of its functions
 *   require the Python lock to be held.
 *
 * Destruction
 *
 *   As there are circular references involved ZPolicyDict is destructed in
 *   a two-phase destruction mechanism. ZPolicyDict instances are reference
 *   counted, so in order to destroy an instance the reference count needs
 *   to go to zero, application code usually has a single reference,
 *   z_policy_dict_ref() is rarely needed in application code. This
 *   "application" reference should be freed with a call to
 *   z_policy_dict_destroy(). That function breaks circular references and
 *   prepares the dictionary to be freed. If z_policy_dict_destroy() is not
 *   called that dictionary _will_ be leaked. If z_policy_dict_destroy() is
 *   called multiple times, an assertion will occur.
 *
 * Threading and locking
 *
 *   It is assumed that a ZPolicyDict is constructed from a single thread,
 *   thus variable registration is not protected by mutexes. The reference
 *   counter is an atomic variable, so _ref and _unref can be called from
 *   different threads.
 * 
 **/

typedef struct _ZPolicyDictType ZPolicyDictType;
typedef struct _ZPolicyDictEntry ZPolicyDictEntry;

struct _ZPolicyDictType
{
  void (*parse_args)(ZPolicyDict *self, ZPolicyDictEntry *entry, va_list args);
  ZPolicyObj *(*get_value)(ZPolicyDict *self, ZPolicyDictEntry *entry);
  gint (*set_value)(ZPolicyDict *self, ZPolicyDictEntry *entry, ZPolicyObj *new_value);
  void (*free_fn)(ZPolicyDictEntry *entry);
};

/**
 * ZPolicyDictEntry:
 * 
 * This structure represents an entry in the dictionary.
 **/
struct _ZPolicyDictEntry
{
  ZPolicyDictType *type_funcs;
  ZVarType type;
  const gchar *name;
  guint flags;
  gpointer value;
  /* type specific internal storage, to avoid allocation when literals are used */
  union 
  {
    guint int_value;
    guint8 int8_value;
    guint16 int16_value;
    guint32 int32_value;
    gsize cstring_buflen;
    ZPolicyObj *object_ref;
    struct
    {
      gpointer ptr;
      gchar *desc;
    } ptr;
    struct
    {
      ZPolicyObj *(*get_value)(gpointer user_data, const gchar *name, gpointer value);
      gint (*set_value)(gpointer user_data, const gchar *name, gpointer value, ZPolicyObj *new_value);
      void (*free_value)(gpointer value, gpointer user_data);
      gpointer user_data;
      GDestroyNotify user_data_free;
    } custom;
    struct
    {
      ZPolicyDictMethodFunc method;
      gpointer user_data;
      GDestroyNotify user_data_free;
    } method;
    struct
    {
      GHashTable *table;
      gboolean consume;
    } hash;
    struct
    {
      ZDimHashTable *table;
      gboolean consume;
    } dimhash;
  } ts;
};

/**
 * z_policy_dict_entry_free:
 * @e: ZPolicyDictEntry instance
 *
 * Frees @e by calling the destructor function and freeing the structure itself.
 **/
static void
z_policy_dict_entry_free(ZPolicyDictEntry *e)
{
  if (e->flags & Z_VF_CONSUME)
    e->type_funcs->free_fn(e);

  g_free((gchar *) e->name);
  g_free(e);
}


/**
 * ZPolicyDict:
 *
 * An interface between C and Python, contains a mapping of attributes
 * stored in C variables, can be used as a getattr/setattr backend for
 * Python exported objects, but is not ZPolicyObj compatible on its
 * own 
 */
struct _ZPolicyDict
{
  /* ZPolicyObj that uses this dictionary as backend, used to
     implement alias lookup, borrowed reference to avoid circular
     references */

  ZRefCount ref_cnt;
  ZPolicyObj *wrapper; 
  /* hashtable that contains the registered variables */
  GHashTable *vars;
  gpointer app_data;
  GDestroyNotify app_data_free;
};


/* support functions for types above */

/******************************************************************************
 * int attributes support 
 * value points to a gint
 */

/**
 * z_policy_dict_int_parse_args:
 * @self: ZPolicyDict instance
 * @e: ZPolicyDictEntry being parsed
 * @args: argument list to parse
 **/
static void
z_policy_dict_int_parse_args(ZPolicyDict *self G_GNUC_UNUSED, ZPolicyDictEntry *e, va_list args)
{

  g_assert((e->flags & (Z_VF_DUP+Z_VF_CONSUME)) == 0);

  if (e->flags & Z_VF_LITERAL)
    {
      switch (e->type)
        {
        case Z_VT_INT:
          e->value = &e->ts.int_value;
          e->ts.int_value = va_arg(args, gint);
          break;
        case Z_VT_INT8:
          e->value = &e->ts.int8_value;
          e->ts.int8_value = va_arg(args, gint);
          break;
        case Z_VT_INT16:
          e->value = &e->ts.int16_value;
          e->ts.int16_value = (guint16) va_arg(args, gint);
          break;
        case Z_VT_INT32:
          e->value = &e->ts.int32_value;
          e->ts.int32_value = va_arg(args, guint32);
          break;
        default:
          g_assert_not_reached();
          break;
        }
    }
  else
    {
      e->value = va_arg(args, gpointer);
    }
}

/**
 * z_policy_dict_int_get_value:
 * @self: not used
 * @name: not used
 * @value: (gint*) pointer to the value
 *
 * Gets the value of an integer variable
 *
 * Returns:
 * PyInt value
 */
static ZPolicyObj *
z_policy_dict_int_get_value(ZPolicyDict *self G_GNUC_UNUSED, ZPolicyDictEntry  *e)
{
  ZPolicyObj *res;
  glong value;

  z_enter();
  switch (e->type)
    {
    case Z_VT_INT:
      value = *(gint *) e->value;
      if (e->flags & Z_VF_INT_NET)
        value = ntohl(value);
      break;
    case Z_VT_INT8:
      value = *(guint8 *) e->value;
      break;
    case Z_VT_INT16:
      value = *(guint16 *) e->value;
      if (e->flags & Z_VF_INT_NET)
        value = ntohs(value);
      break;
    case Z_VT_INT32:
      value = *(guint32 *) e->value;
      if (e->flags & Z_VF_INT_NET)
        value = ntohl(value);
      break;
    default:
      g_assert_not_reached();
      break;
    }
  res = PyInt_FromLong(value);
  z_leave();

  return res;
}

/**
 * z_policy_dict_int_set_value:
 * @self: not used
 * @name: not used
 * @value: (gint*) pointer to the value
 * @new: New value
 *
 * Sets the value of an integer variable
 *
 * Returns:
 * 0 on success, nonzero otherwise
 */
static gint
z_policy_dict_int_set_value(ZPolicyDict *self G_GNUC_UNUSED, ZPolicyDictEntry *e, ZPolicyObj *new)
{
  gint value;

  z_enter();
  if (!z_policy_var_parse(new, "i", &value))
    z_return(1);
  switch (e->type)
    {
    case Z_VT_INT:
      if (e->flags & Z_VF_INT_NET)
        value = htonl(value);
      *((gint *) e->value) = value;
      break;
    case Z_VT_INT8:
      *((guint8 *) e->value) = value;
      break;
    case Z_VT_INT16:
      if (e->flags & Z_VF_INT_NET)
        value = htons(value);
      *((guint16 *) e->value) = value;
      break;
    case Z_VT_INT32:
      if (e->flags & Z_VF_INT_NET)
        value = htonl(value);
      *((guint32 *) e->value) = value;
      break;
    default:
      g_assert_not_reached();
      break;
    }
  z_leave();
  return 0;
}

/******************************************************************************
 * string attributes support (Z_VT_STRING and Z_VT_CSTRING
 *  Z_VT_STRING 
 *    literal arguments:
 *      const gchar *
 *    non-literal arguments:
 *      GString *
 *  Z_VT_CSTRING:
 *    literal arguments:
 *      const gchar *, gsize (ignored unless ZF_VF_DUP is specified)
 *    non-literal arguments
 *      const gchar *, gsize
 */

/**
 * z_policy_dict_string_parse_args:
 * @self: ZPolicyDict instance
 * @e: ZPolicyDictEntry being parsed
 * @args: argument list to parse
 **/
static void
z_policy_dict_string_parse_args(ZPolicyDict *self G_GNUC_UNUSED, ZPolicyDictEntry *e, va_list args)
{
  switch (e->type)
    {
    case Z_VT_STRING:
      if (e->flags & Z_VF_LITERAL)
        {
          e->value = g_string_new(va_arg(args, gchar *));
          e->flags |= Z_VF_CONSUME;
        }
      else
        {
          e->value = va_arg(args, gpointer);
        }
      break;
    case Z_VT_CSTRING:
      if (e->flags & Z_VF_LITERAL)
        {
          if (e->flags & Z_VF_DUP)
            {
              gchar *s;

              s = va_arg(args, gchar *);
              e->ts.cstring_buflen = va_arg(args, gsize);
              e->value = g_malloc(e->ts.cstring_buflen);
              g_strlcpy(e->value, s, e->ts.cstring_buflen);
              e->flags |= Z_VF_CONSUME;
            }
          else
            {
              gsize tmp;
              g_assert((e->flags & (Z_VF_WRITE+Z_VF_CFG_WRITE)) == 0);

              e->value = va_arg(args, gchar *);
              tmp = va_arg(args, gsize); // pop size argument
              e->ts.cstring_buflen = strlen((gchar *) e->value);
          
            }
        }
      else
        {
          e->value = va_arg(args, gchar *);
          e->ts.cstring_buflen = va_arg(args, gsize);
        }
      break;
    default:
      g_assert_not_reached();
      break;
    }
}

/**
 * z_policy_dict_string_get_value:
 * @self: not used
 * @name: not used
 * @value: (GString*) pointer to the value
 *
 * Gets the value of a GString variable
 *
 * Returns:
 * PyString value
 */
static ZPolicyObj *
z_policy_dict_string_get_value(ZPolicyDict *self G_GNUC_UNUSED, ZPolicyDictEntry *e)
{
  ZPolicyObj *res;

  z_enter();
  switch (e->type)
    {
    case Z_VT_STRING:
      res = PyString_FromStringAndSize(((GString *) e->value)->str, ((GString *) e->value)->len);
      break;
    case Z_VT_CSTRING:
      res = PyString_FromString((gchar *) e->value);
      break;
    default:
      g_assert_not_reached();
      break;
    }
  z_leave();

  return res;
}

/**
 * z_policy_dict_string_set_value:
 * @self: not used
 * @name: not used
 * @value: (GString*) pointer to the value
 * @new: New value
 *
 * Sets the value of an integer variable
 *
 * Returns:
 * 0 on success, nonzero otherwise
 */
static gint 
z_policy_dict_string_set_value(ZPolicyDict *self G_GNUC_UNUSED, ZPolicyDictEntry *e, ZPolicyObj *new)
{
  gchar *str;
  guint len;
  
  z_enter();
  if (!PyArg_Parse(new, "s#", &str, &len))
    {
      z_leave();
      return 1;
    }
  switch (e->type)
    {
    case Z_VT_STRING:
      g_string_assign((GString *) e->value, str);
      break;
    case Z_VT_CSTRING:
      g_strlcpy((gchar *) e->value, str, MIN(len + 1, e->ts.cstring_buflen));
      break;
    default:
      g_assert_not_reached();
      break;
    }
  z_leave();
  return 0;
}

/**
 * z_policy_dict_string_free:
 * @value: (GString*) pointer to the value
 *
 * Deallocates a string variable
 */
static void
z_policy_dict_string_free(ZPolicyDictEntry *e)
{
  z_enter();
  switch (e->type)
    {
    case Z_VT_STRING:
      g_string_free((GString *) e->value, TRUE);
      break;
    case Z_VT_CSTRING:
      g_free(e->value);
      break;
    default:
      g_assert_not_reached();
      break;
    }
  z_leave();
}

/******************************************************************************
 * method attributes support
 *
 * Expected arguments:
 *   func: C function pointer to call
 *   user_data: argument passed to func
 *   user_data_free (GDestroyNotify): function to free user_data with
 *
 * Represented as:
 *   The value field contains a reference to the newly created 
 */

typedef struct _ZPolicyMethod
{
  PyObject_HEAD
  ZPolicyDict *dict;
  gpointer user_data;
  GDestroyNotify user_data_free;
  ZPolicyDictMethodFunc method;
} ZPolicyMethod;


static PyTypeObject z_policy_method_type;

/**
 * z_policy_method_call:
 * @self: this
 * @args: Arguments to call the method with
 * @kw: not used
 *
 * Call the ZProxy method referred to by @self
 *
 * Returns:
 * The value returned by the method
 */
static ZPolicyObj *
z_policy_method_call(ZPolicyMethod *self, ZPolicyObj *args, ZPolicyObj *kw)
{
  return self->method(self->user_data, args, kw);
}

/**
 * z_policy_method_free:
 * @proxy: ZProxy instance
 * @method: Method function
 *
 * Constructor of ZorpMethod - a Python type that encapsulates a method of a class
 * derived from ZProxy
 *
 * Returns:
 * The new instance
 */
static ZPolicyObj *
z_policy_method_new(ZPolicyDict *dict, ZPolicyDictMethodFunc method, gpointer user_data, GDestroyNotify user_data_free)
{
  ZPolicyMethod *self;
  
  self = PyObject_New(ZPolicyMethod, &z_policy_method_type);
  if (!self)
    return NULL;
  self->user_data = user_data;
  self->user_data_free = user_data_free;
  self->method = method;
  self->dict = z_policy_dict_ref(dict);
  return (ZPolicyObj *) self;
}


/**
 * z_py_zorp_method_free:
 * @self: this
 *
 * Destructor of ZorpMethod
 */
static void
z_policy_method_free(ZPolicyMethod *self)
{
  if (self->user_data && self->user_data_free)
    self->user_data_free(self->user_data);
  z_policy_dict_unref(self->dict);
  PyObject_Del(self);
}

static PyTypeObject z_policy_method_type = 
{
  PyObject_HEAD_INIT(&PyType_Type)
  0,
  "ZPolicyMethod",
  sizeof(ZPolicyMethod),
  0,
  (destructor) z_policy_method_free, 
  0,                                  /* tp_print */
  0,                                  /* tp_getattr */
  0,                                  /* tp_setattr */
  0,                                  /* tp_compare */
  0,                                  /* tp_repr */
  0,                                  /* tp_as_number */
  0,                                  /* tp_as_sequence */
  0,                                  /* tp_as_mapping */
  0,                                  /* tp_hash */
  (ternaryfunc) z_policy_method_call,/* tp_call */
  0,                                  /* tp_str */
  0,                                  /* tp_getattro */
  0,                                  /* tp_setattro */
  0,                                  /* tp_as_buffer */
  0,                                  /* flags */
  "ZPolicyMethod class for Zorp",        /* docstring */
  0, 0, 0, 0,
  Z_PYTYPE_TRAILER
};

/**
 * z_policy_dict_method_parse_args:
 * @self: ZPolicyDict instance
 * @e: ZPolicyDictEntry being parsed
 * @args: argument list to parse
 **/
static void
z_policy_dict_method_parse_args(ZPolicyDict *self G_GNUC_UNUSED, ZPolicyDictEntry *e, va_list args)
{
  g_assert((e->flags & (Z_VF_DUP+Z_VF_CONSUME+Z_VF_LITERAL)) == 0);

  e->flags |= Z_VF_CONSUME;
  
  e->ts.method.method = va_arg(args, ZPolicyDictMethodFunc);
  e->ts.method.user_data = va_arg(args, gpointer);
  e->ts.method.user_data_free = va_arg(args, gpointer);
  e->value = NULL;
}


/**
 * z_policy_dict_method_get_value:
 * @self: not used
 * @name: not used
 * @value: (PyObject*) pointer to the value
 *
 * Get the value of a ZorpMethod variable.
 * Note that this is not the same as _object_get(), since there the argument is
 * a pointer to a pointer to an object, while here only a casting to PyObject* is done.
 *
 * Returns:
 * The PyObject value
 */
static ZPolicyObj *
z_policy_dict_method_get_value(ZPolicyDict *self, ZPolicyDictEntry *e)
{
  ZPolicyObj *res;

  if (!e->value)
    {
      e->value = z_policy_method_new(self, e->ts.method.method, e->ts.method.user_data, e->ts.method.user_data_free);
      e->ts.method.user_data_free = NULL;
    }
  
  res = (ZPolicyObj *) e->value;
  z_policy_var_ref(res);
  return res;
}

/**
 * z_policy_dict_method_free:
 * @value: this
 *
 * Decrements the reference counter of the stored ZPolicyMethod instance.
 */
static void
z_policy_dict_method_free(ZPolicyDictEntry *e)
{
  if (e->value)
    {
      z_policy_var_unref((ZPolicyObj *) e->value);
    }
  else if (e->ts.method.user_data && e->ts.method.user_data_free)
    {
      e->ts.method.user_data_free(e->ts.method.user_data);
      e->ts.method.user_data = NULL;
    }
}

/******************************************************************************
 * object attributes support
 */

/**
 * z_policy_dict_object_parse_args:
 * @self: ZPolicyDict instance
 * @e: ZPolicyDictEntry being parsed
 * @args: argument list to parse
 **/
static void
z_policy_dict_object_parse_args(ZPolicyDict *self G_GNUC_UNUSED, ZPolicyDictEntry *e, va_list args)
{
  g_assert((e->flags & Z_VF_DUP) == 0);

  if (e->flags & Z_VF_LITERAL)
    {
      e->value = &e->ts.object_ref;
      e->ts.object_ref = va_arg(args, ZPolicyObj *);
    }
  else
    {
      e->value = va_arg(args, ZPolicyObj **);
    }

}

/**
 * z_policy_dict_object_get_value:
 * @self: not used
 * @name: not used
 * @value: (ZPolicyObj**) pointer to the value
 *
 * Gets the value of a ZPolicyObj variable
 *
 * Returns:
 * The ZPolicyObj value
 */
static ZPolicyObj *
z_policy_dict_object_get_value(ZPolicyDict *self G_GNUC_UNUSED, ZPolicyDictEntry *e)
{
  ZPolicyObj *r;
  
  z_enter();
  r = *((ZPolicyObj **) e->value);
  z_policy_var_ref(r);
  z_return(r);
}

/**
 * z_policy_dict_object_set_value:
 * @self: not used
 * @name: not used
 * @value: (ZPolicyObj**) pointer to the value
 * @new: New value
 *
 * Sets the value of a ZPolicyObj variable
 *
 * Returns:
 * 1 (always succeeds)
 */
static gint 
z_policy_dict_object_set_value(ZPolicyDict *self G_GNUC_UNUSED, ZPolicyDictEntry *e, ZPolicyObj *new_value)
{
  z_enter();
  z_policy_var_unref(*(ZPolicyObj **) e->value);
  *((ZPolicyObj **) e->value) = new_value;
  z_policy_var_ref(new_value);
  z_return(0);
}

/**
 * z_policy_dict_object_free:
 * @value: (ZPolicyObj**) pointer to the value
 *
 * Decrements the reference counter of a ZPolicyObj variable
 */
static void
z_policy_dict_object_free(ZPolicyDictEntry *e)
{
  z_enter();
  z_policy_var_unref(*((ZPolicyObj **) e->value));
  z_return();
}

/******************************************************************************
 * ip/ipv6 address attributes support
 */

/**
 * z_policy_dict_object_parse_args:
 * @self: ZPolicyDict instance
 * @e: ZPolicyDictEntry being parsed
 * @args: argument list to parse
 **/
static void
z_policy_dict_ip_parse_args(ZPolicyDict *self G_GNUC_UNUSED, ZPolicyDictEntry *e, va_list args)
{
  g_assert((e->flags & (Z_VF_DUP+Z_VF_LITERAL)) == 0);

  e->value = va_arg(args, gpointer);
}

/**
 * z_policy_dict_object_get_value:
 * @self: not used
 * @name: not used
 * @value: (ZPolicyObj**) pointer to the value
 *
 * Gets the value of a ZPolicyObj variable
 *
 * Returns:
 * The ZPolicyObj value
 */
static ZPolicyObj *
z_policy_dict_ip_get_value(ZPolicyDict *self G_GNUC_UNUSED, ZPolicyDictEntry *e)
{
  ZPolicyObj *res;

  z_enter();
  if (e->flags & Z_VF_IP_STR)
    {
      gchar buf[64];

      inet_ntop(e->type == Z_VT_IP ? AF_INET : AF_INET6, e->value, buf, sizeof(buf));
      res = PyString_FromString(buf);
    }
  else if (e->type == Z_VT_IP)
    {
      res = PyInt_FromLong(((struct in_addr *) e->value)->s_addr);
    }
  else
    {
      struct in6_addr *in6 = (struct in6_addr *) e->value;

      res = Py_BuildValue("(iiiiiiii)", 
                          in6->s6_addr16[0],
                          in6->s6_addr16[1],
                          in6->s6_addr16[2],
                          in6->s6_addr16[3],
                          in6->s6_addr16[4],
                          in6->s6_addr16[5],
                          in6->s6_addr16[6],
                          in6->s6_addr16[7]);
    }
  z_return(res);
}

/**
 * z_policy_dict_object_set_value:
 * @self: not used
 * @name: not used
 * @value: (ZPolicyObj**) pointer to the value
 * @new: New value
 *
 * Sets the value of a ZPolicyObj variable
 *
 * Returns:
 * 0 on success, nonzero otherwise
 */
static gint 
z_policy_dict_ip_set_value(ZPolicyDict *self G_GNUC_UNUSED, ZPolicyDictEntry *e, ZPolicyObj *new_value)
{
  z_enter();
  if (e->flags & Z_VF_IP_STR)
    {
      gchar *ip;
      
      if (!PyArg_Parse(new_value, "s", &ip))
        z_return(1);
      inet_pton(e->type == Z_VT_IP ? AF_INET : AF_INET6, ip, e->value);
    }
  else
    {
      switch (e->type)
        {
        case Z_VT_IP6:
          {
            struct in6_addr *in6 = (struct in6_addr *) e->value;

            if (!PyArg_Parse(new_value, "(iiiiiiii)", 
                             &in6->s6_addr16[0],
                             &in6->s6_addr16[1],
                             &in6->s6_addr16[2],
                             &in6->s6_addr16[3],
                             &in6->s6_addr16[4],
                             &in6->s6_addr16[5],
                             &in6->s6_addr16[6],
                             &in6->s6_addr16[7]))
              return 1;
            break;
          }
        case Z_VT_IP:
          {
            struct in_addr *in = (struct in_addr *) e->value;
            
            if (!PyArg_Parse(new_value, "I", &in->s_addr))
              return 1;
            break;
          }
        default:
          g_assert_not_reached();
          break;
        }
    }
      
  z_leave();
  return 0;
}

/**
 * z_policy_dict_object_free:
 * @value: (ZPolicyObj**) pointer to the value
 *
 * Decrements the reference counter of a ZPolicyObj variable
 */
static void
z_policy_dict_ip_free(ZPolicyDictEntry *e)
{
  z_enter();
  g_free(e->value);
  z_return();
}

/******************************************************************************
 * alias support
 */

static void
z_policy_dict_alias_parse_args(ZPolicyDict *self G_GNUC_UNUSED, ZPolicyDictEntry *e, va_list args)
{
  g_assert((e->flags & (Z_VF_DUP+Z_VF_CONSUME+Z_VF_LITERAL)) == 0);
  e->value = va_arg(args, gchar *);
}

/**
 * z_policy_dict_alias_get_value:
 * @self: this
 * @name: not used
 * @value: Name of the alias
 *
 * Gets the real name of an alias-variable
 *
 * Returns:
 * The real name of the variable 
 */
static ZPolicyObj *
z_policy_dict_alias_get_value(ZPolicyDict *self, ZPolicyDictEntry *e)
{
  g_assert(self->wrapper);

  return PyObject_GetAttrString(self->wrapper, (gchar *) e->value);
}

/**
 * z_policy_dict_alias_set_value:
 * @self: this
 * @name: not used
 * @value: Name of the alias
 * @new: Name of the real variable
 *
 * Sets the alias @value to refer to @new
 *
 * Returns:
 * ???
 */
static gint
z_policy_dict_alias_set_value(ZPolicyDict *self, ZPolicyDictEntry *e, ZPolicyObj *new_value)
{
  g_assert(self->wrapper);
  return PyObject_SetAttrString(self->wrapper, (gchar *) e->value, new_value);
}

/******************************************************************************
 * hash-table attributes support
 */

/*
 * Python compatible object, representing a hash of ZPolicyObj instances.
 */
typedef struct _ZPolicyHash
{
  PyObject_HEAD
  ZPolicyDict *dict;
  gboolean consume;
  GHashTable *hash;
} ZPolicyHash;

extern PyTypeObject z_policy_hash_type;


/**
 * z_policy_hash_subscript:
 * @self: this
 * @k: PyString key
 *
 * Performs a lookup for @k in the hash table.
 *
 * Returns:
 * The value if found, otherwise NULL
 */
static ZPolicyObj *
z_policy_hash_subscript(ZPolicyHash *self, ZPolicyObj *k)
{
  gchar *key;
  ZPolicyObj *res;

  if (!PyArg_Parse(k, "s", &key))
    return NULL;
  res = g_hash_table_lookup(self->hash, key);
  if (res)
    {
      z_policy_var_ref(res);
      return res;
    }
  else
    {
      PyErr_SetObject(PyExc_KeyError, k);
      return NULL;
    }
}

/**
 * z_policy_hash_ass_subscript:
 * @self: this
 * @u: PyString key
 * @v: ZPolicyObj value
 *
 * Insert-or-update the value @v for the key @u in the hash table.
 * If there was a previous value for the key, its reference counter
 * is decremented.
 *
 * Returns:
 * 0 on success, -1 otherwise
 */
static gint
z_policy_hash_ass_subscript(ZPolicyHash *self, ZPolicyObj *u, ZPolicyObj *v)
{
  gchar *key;
  ZPolicyObj *res;

  if (!PyArg_Parse(u, "s", &key))
    return -1;

  res = g_hash_table_lookup(self->hash, key);
  if (v == NULL)
    {
      /* delete item */
      if (!res)
        {
          PyErr_SetObject(PyExc_KeyError, u);
          return -1;
        }
      g_hash_table_remove(self->hash, key);
      z_policy_var_unref(res);
      return 0;
    }
  else
    {
      z_policy_var_ref(v);
      g_hash_table_insert(self->hash, key, v);
      z_policy_var_unref(res);
      return 0;
    }
}

/**
 * z_policy_hash_new:
 * @hash: GHashTable containing the items to represent
 *
 * Constructor of ZPolicyHash - the Python type that encapsulates a
 * glib hash table containing ZPolicyObj items.
 *
 * Returns:
 *
 */
static ZPolicyHash *
z_policy_hash_new(ZPolicyDict *dict, GHashTable *hash, gboolean consume)
{
  ZPolicyHash *self = PyObject_New(ZPolicyHash, &z_policy_hash_type);

  self->hash = hash;
  self->consume = consume;
  self->dict = z_policy_dict_ref(dict);
  return self;
}


/**
 * z_policy_hash_unref_items:
 * @key: not used
 * @value: this
 * @user_data: not used
 *
 * Helper function for _free, decrements the reference counter of the objects
 * in the hashtable.
 *
 * Returns:
 *
 */
static gboolean
z_policy_hash_unref_items(gpointer key G_GNUC_UNUSED, gpointer value, gpointer user_data G_GNUC_UNUSED)
{
  z_policy_var_unref((ZPolicyObj *) value);
  return TRUE;
}

static void
z_policy_hash_destroy_table(GHashTable *hash)
{
  g_hash_table_foreach_remove(hash, z_policy_hash_unref_items, NULL);
  g_hash_table_destroy(hash);
}

/**
 * z_policy_hash_free:
 * @self: this
 *
 * Destructor of ZPolicyHash. Removes all items in the hash, and the hash itself, too.
 */
static void
z_policy_hash_free(ZPolicyHash *self)
{
  if (self->consume)
    z_policy_hash_destroy_table(self->hash);
  z_policy_dict_unref(self->dict);
  PyObject_Del(self);
}

PyMappingMethods z_policy_hash_mapping =
{
  NULL,
  (binaryfunc) z_policy_hash_subscript,
  (objobjargproc) z_policy_hash_ass_subscript
};

PyTypeObject z_policy_hash_type =
{
  PyObject_HEAD_INIT(&PyType_Type)
  0,
  "Zorp hash",
  sizeof(ZPolicyHash),
  0,
  (destructor) z_policy_hash_free,
  0,                                  /* tp_print */
  0,                                  /* tp_getattr */
  0,                                  /* tp_setattr */
  0,                                  /* tp_compare */
  0,                                  /* tp_repr */
  0,                                  /* tp_as_number */
  0,                                  /* tp_as_sequence */
  &z_policy_hash_mapping,             /* tp_as_mapping */
  0,                                  /* tp_hash */
  0,                                  /* tp_call */
  0,                                  /* tp_str */
  0,                                  /* tp_getattro */
  0,                                  /* tp_setattro */
  0,                                  /* tp_as_buffer */
  0,                                  /* flags */
  "ZPolicyHash class for Zorp",          /* docstring */
  0, 0, 0, 0,
  Z_PYTYPE_TRAILER
};

void
z_policy_dict_hash_parse_args(ZPolicyDict *self G_GNUC_UNUSED, ZPolicyDictEntry *e, va_list args)
{
  g_assert((e->flags & (Z_VF_DUP+Z_VF_LITERAL)) == 0);

  e->ts.hash.consume = !!(e->flags & Z_VF_CONSUME);
  e->flags |= Z_VF_CONSUME;  
  e->ts.hash.table = va_arg(args, GHashTable *);

  e->value = NULL;

}

/**
 * z_policy_dict_hash_get:
 * @self: not used
 * @name: not used
 * @value: (ZPolicyHash*) pointer to the value
 *
 * Get the value to a ZPolicyHash variable - cast to ZPolicyObj, just like at
 * z_policy_dict_method_get.
 *
 * Returns:
 * The ZPolicyHash value
 */
static ZPolicyObj *
z_policy_dict_hash_get_value(ZPolicyDict *self, ZPolicyDictEntry *e)
{
  ZPolicyObj *res;

  if (!e->value)
    e->value = z_policy_hash_new(self, e->ts.hash.table, e->ts.hash.consume);

  res = (ZPolicyObj *) e->value;
  z_policy_var_ref(res);
  return res;
}

/**
 * z_policy_dict_hash_free:
 * @value: this
 *
 * Destructor of ZPolicyHash
 */
static void
z_policy_dict_hash_free(ZPolicyDictEntry *e)
{
  if (e->value)
    {
      z_policy_var_unref((ZPolicyObj *) e->value);
    }
  else if (e->ts.hash.consume)
    {
      z_policy_hash_destroy_table(e->ts.hash.table);
    }
}

/******************************************************************************
 * Multidimensional hash table attributes support
 */

typedef struct _ZPolicyDimHash
{
  PyObject_HEAD
  ZPolicyDict *dict;
  gboolean consume;
  ZDimHashTable *hash;
} ZPolicyDimHash;

extern PyTypeObject z_policy_dim_hash_type;

/**
 * z_policy_dim_hash_unref_items:
 * @value: this
 *
 * Decrements the reference counter
 *
 * Returns:
 * TRUE
 */
static gboolean
z_policy_dim_hash_unref_items(gpointer value)
{
  z_policy_var_unref((ZPolicyObj *) value);
  return TRUE;
}

/**
 * z_policy_dim_hash_subscript:
 * @self: this
 * @k: key sequence
 *
 * Assembles a composite key ("key0::key1::...:keyN") from the sequence @k and
 * looks up its value from the hash.
 *
 * Returns:
 * The value if found, otherwise NULL
 */
static ZPolicyObj *
z_policy_dim_hash_subscript(ZPolicyDimHash *self, ZPolicyObj *k)
{
  gchar **keys;
  gchar *key;
  guint keynum;
  ZPolicyObj *item;
  ZPolicyObj *stritem;
  ZPolicyObj *res;
  guint i;
  
  
  if (PyArg_Parse(k, "s", &key))
    {
      keynum = 1;
      keys = g_new0(gchar *, keynum);
      keys[0] = g_strdup(key);
    }
  else
    {
      PyErr_Clear();
      if (z_policy_seq_check(k))
        {
          keynum = z_policy_seq_length(k);
      
          keys = g_new0(gchar *, keynum);
      
          for (i = 0; i < keynum; i++)
            {
              item = z_policy_seq_getitem(k, i);
              stritem = z_policy_var_str(item);
              z_policy_var_unref(item);
          
              key = z_policy_str_as_string(stritem);
              keys[i] = g_new0(gchar, strlen(key)+1);
              strcpy(keys[i], key);
              z_policy_var_unref(stritem);
            }
        }
      else
        return NULL;
    }
  res = z_dim_hash_table_lookup(self->hash, keynum, keys);
  z_dim_hash_key_free(keynum, keys);

  if (res)
    {
      z_policy_var_ref(res);
      return res;
    }
  else
    {
      PyErr_SetObject(PyExc_KeyError, k);
      return NULL;
    }
}

/**
 * z_policy_dim_hash_ass_subscript:
 * @self: this
 * @u: key sequence
 * @v: new value
 *
 * Assemble a composite key from the sequence @u, and assign @v to it
 * in the hash, creating a new entry if the key was a new one, or replacing
 * the previous value if it wasn't.
 * 
 * Returns:
 * 0 on success, -1 on error
 */
static gint 
z_policy_dim_hash_ass_subscript(ZPolicyDimHash *self, ZPolicyObj *u, ZPolicyObj *v)
{
  gchar **keys;
  gchar *key;
  guint keynum;
  ZPolicyObj *res;
  ZPolicyObj *item;
  ZPolicyObj *stritem;
  guint i;
  
  if (PyArg_Parse(u, "s", &key))
    {
      keynum = 1;
      keys = g_new0(gchar *, keynum);
      keys[0] = g_new0(gchar, strlen(key)+1);
      strcpy(keys[0], key);
    }
  else
    {
      PyErr_Clear();
      if (z_policy_seq_check(u))
        {
          keynum = z_policy_seq_length(u);
      
          keys = g_new0(gchar *, keynum);
      
          for (i = 0; i < keynum; i++)
            {
              item = z_policy_seq_getitem(u, i);
              stritem = z_policy_var_str(item);
              z_policy_var_unref(item);
          
              key = z_policy_str_as_string(stritem);
              keys[i] = g_new0(gchar, strlen(key)+1);
              strcpy(keys[i], key);
              z_policy_var_unref(stritem);
            }
        }
      else
        return -1;
    }
  res = z_dim_hash_table_lookup(self->hash, keynum, keys);

  if (v == NULL)
    {
      /* delete item */
      if (!res)
        {
          PyErr_SetObject(PyExc_KeyError, u);
          z_dim_hash_key_free(keynum, keys);
          return -1;
        }
      z_dim_hash_table_delete(self->hash, keynum, keys, z_policy_dim_hash_unref_items);
      z_dim_hash_key_free(keynum, keys);
      return 0;
    }
  else
    {
      if (res)
        z_dim_hash_table_delete(self->hash, keynum, keys, z_policy_dim_hash_unref_items);

      z_policy_var_ref(v);
      z_dim_hash_table_insert(self->hash, v, keynum, keys);
      z_dim_hash_key_free(keynum, keys);
      return 0;
    }
}

/**
 * z_policy_dim_hash_new:
 * @hash: ZDimHashTable to create a ZPolicyDimHash around
 *
 * Constructor of ZPolicyDimHash - a Python class that encapsulates a
 * ZDimHashTable.
 *
 * Returns:
 * The new instance
 */
static ZPolicyDimHash *
z_policy_dim_hash_new(ZPolicyDict *dict, ZDimHashTable *hash, gboolean consume)
{
  ZPolicyDimHash *self = PyObject_New(ZPolicyDimHash, &z_policy_dim_hash_type);
  
  self->dict = z_policy_dict_ref(dict);
  self->hash = hash;
  self->consume = consume;
  return self;
}


/**
 * z_policy_dim_hash_free:
 * @self: this
 *
 * Destructor of ZPolicyDimHash
 */
static void
z_policy_dim_hash_free(ZPolicyDimHash *self)
{
  if (self->consume)
    z_dim_hash_table_free(self->hash, z_policy_dim_hash_unref_items);
  z_policy_dict_unref(self->dict);
  PyObject_Del(self);
}

PyMappingMethods z_policy_dim_hash_mapping = 
{
  NULL,
  (binaryfunc) z_policy_dim_hash_subscript,
  (objobjargproc) z_policy_dim_hash_ass_subscript
};

PyTypeObject z_policy_dim_hash_type = 
{
  PyObject_HEAD_INIT(&PyType_Type)
  0,
  "Zorp Multidimensional hash",
  sizeof(ZPolicyDimHash),
  0,
  (destructor) z_policy_dim_hash_free, 
  0,                                  /* tp_print */
  0,                                  /* tp_getattr */
  0,                                  /* tp_setattr */
  0,                                  /* tp_compare */
  0,                                  /* tp_repr */
  0,                                  /* tp_as_number */
  0,                                  /* tp_as_sequence */
  &z_policy_dim_hash_mapping,        /* tp_as_mapping */
  0,                                  /* tp_hash */
  0,  				      /* tp_call */
  0,                                  /* tp_str */
  0,                                  /* tp_getattro */
  0,                                  /* tp_setattro */
  0,                                  /* tp_as_buffer */
  0,                                  /* flags */
  "ZPolicyDimHash class for Zorp",       /* docstring */
  0, 0, 0, 0,
  Z_PYTYPE_TRAILER
};

static void
z_policy_dict_dimhash_parse_args(ZPolicyDict *self G_GNUC_UNUSED, ZPolicyDictEntry *e, va_list args)
{
  g_assert((e->flags & (Z_VF_DUP+Z_VF_LITERAL)) == 0);

  e->ts.dimhash.consume = !!(e->flags & Z_VF_CONSUME);
  e->flags |= Z_VF_CONSUME;
  e->ts.dimhash.table = va_arg(args, ZDimHashTable *);
  e->value = NULL;
}

/**
 * z_policy_dict_dimhash_get_value:
 * @self: not used
 * @name: not used
 * @value: (ZPolicyDimHash*) pointer to the value
 *
 * Get the value to a ZPolicyDimHash variable - cast to ZPolicyObj.
 *
 * Returns:
 * The value
 */
static ZPolicyObj *
z_policy_dict_dimhash_get_value(ZPolicyDict *self, ZPolicyDictEntry *e)
{
  ZPolicyObj *res;

  if (!e->value)
    e->value = z_policy_dim_hash_new(self, e->ts.dimhash.table, e->ts.dimhash.consume);

  res = (ZPolicyObj *) e->value;
  z_policy_var_ref(res);
  return res;
}

/**
 * z_policy_dict_dimhash_free:
 * @value: this
 *
 * Free a dimhash value in a a ZPolicyDict
 */
static void
z_policy_dict_dimhash_free(ZPolicyDictEntry *e)
{
  if (e->value)
    z_policy_var_unref((ZPolicyObj *) e->value);
  else if (e->ts.dimhash.consume)
    z_dim_hash_table_free(e->ts.dimhash.table, z_policy_dim_hash_unref_items);
}

/******************************************************************************
 * custom attributes
 */


static void
z_policy_dict_custom_parse_args(ZPolicyDict *self G_GNUC_UNUSED, ZPolicyDictEntry *e, va_list args)
{
  e->flags |= Z_VF_CONSUME;

  e->value = va_arg(args, gpointer);
  e->ts.custom.get_value = va_arg(args, gpointer);
  e->ts.custom.set_value = va_arg(args, gpointer);
  e->ts.custom.free_value = va_arg(args, gpointer);
  e->ts.custom.user_data = va_arg(args, gpointer);
  e->ts.custom.user_data_free = va_arg(args, GDestroyNotify);
}

/**
 * z_policy_dict_custom_get_value:
 * @self: not used
 * @name: not used
 * @value: 
 *
 * Returns:
 * The value
 */
static ZPolicyObj *
z_policy_dict_custom_get_value(ZPolicyDict *self G_GNUC_UNUSED, ZPolicyDictEntry *e)
{
  return e->ts.custom.get_value(e->ts.custom.user_data, e->name, e->value);
}

/**
 * z_policy_dict_custom_set_value:
 * @self: not used
 * @name: not used
 * @value: 
 *
 * Returns:
 */
static gint
z_policy_dict_custom_set_value(ZPolicyDict *self G_GNUC_UNUSED, ZPolicyDictEntry *e, ZPolicyObj *new_value)
{
  return e->ts.custom.set_value(e->ts.custom.user_data, e->name, e->value, new_value);
}

static void
z_policy_dict_custom_free(ZPolicyDictEntry *e)
{
  if (e->ts.custom.free_value)
    e->ts.custom.free_value(e->value, e->ts.custom.user_data);
      
  if (e->ts.custom.user_data && e->ts.custom.user_data_free)
    e->ts.custom.user_data_free(e->ts.custom.user_data);
}

/******************************************************************************
 * pointer attributes support 
 * value is a gpointer
 */

/**
 * z_policy_dict_ptr_parse_args:
 * @self: ZPolicyDict instance
 * @e: ZPolicyDictEntry being parsed
 * @args: argument list to parse
 **/
static void
z_policy_dict_ptr_parse_args(ZPolicyDict *self G_GNUC_UNUSED, ZPolicyDictEntry *e, va_list args)
{
  g_assert((e->flags & (Z_VF_DUP+Z_VF_CONSUME)) == 0);

  if (e->flags & Z_VF_LITERAL)
    {
      e->value = &e->ts.ptr.ptr;
      e->ts.ptr.ptr = va_arg(args, gpointer);
    }
  else
    {
      e->value = va_arg(args, gpointer *);
    }
  e->ts.ptr.desc = va_arg(args, gchar *);
}

/**
 * z_policy_dict_ptr_get_value:
 * @self: not used
 * @name: not used
 * @value: (gint*) pointer to the value
 *
 * Gets the value of an integer variable
 *
 * Returns:
 * PyInt value
 */
static ZPolicyObj *
z_policy_dict_ptr_get_value(ZPolicyDict *self G_GNUC_UNUSED, ZPolicyDictEntry  *e)
{
  ZPolicyObj *res;

  z_enter();
  /* FIXME: we could support properly reference counted values here, though
   * nothing would use them for now */
  res = PyCObject_FromVoidPtrAndDesc(*(gpointer *) e->value, e->ts.ptr.desc, NULL);
  z_return(res);
}

/**
 * z_policy_dict_ptr_set_value:
 * @self: not used
 * @name: not used
 * @value: (gint*) pointer to the value
 * @new: New value
 *
 * Sets the value of an integer variable
 *
 * Returns:
 * 0 on success, nonzero otherwise
 */
static gint
z_policy_dict_ptr_set_value(ZPolicyDict *self G_GNUC_UNUSED, ZPolicyDictEntry *e G_GNUC_UNUSED, ZPolicyObj *new G_GNUC_UNUSED)
{
  return 0;
}



/******************************************************************************
 * ZPolicyDict core
 */

/**
 * z_policy_dict_wrap:
 * @self: ZPolicyDict instance
 * @wrapper: a Python object that uses @self as its dictionary
 *
 * This function stores a borrowed reference to @wrapper in @self. This
 * means that ZPolicyDict assumes that the destruction of @wrapper
 * automatically destroys @self as well as no further references are
 * possible after that point, as self->wrapper will become stale.
 *
 * This borrowed reference is used to resolve variable aliases.
 **/
void
z_policy_dict_wrap(ZPolicyDict *self, ZPolicyObj *wrapper)
{
  self->wrapper = wrapper;
}

/**
 * z_policy_dict_unwrap:
 * @self: ZPolicyDict instance
 * @wrapper: wrapper to unwrap from
 *
 * This function unassigns @wrapper from this dictionary. It is useful when
 * the same dictionary is attached to another Python object.
 **/
void
z_policy_dict_unwrap(ZPolicyDict *self, ZPolicyObj *wrapper)
{
  g_assert(self->wrapper == wrapper);
  self->wrapper = NULL;
}

/**
 * z_policy_dict_get_value:
 * @self: ZPolicyDict instance
 * @is_config: whether this variable query is at config time or not
 * @name: name of the variable
 *
 * This function can be used to "get" a value from this dictionary, and is
 * used by various Python extension types (like ZPolicyStruct or ZProxy) to
 * implement their "getattr" method.
 **/
ZPolicyObj *
z_policy_dict_get_value(ZPolicyDict *self, gboolean is_config, const gchar *name)
{
  ZPolicyDictEntry *e;

  e = g_hash_table_lookup(self->vars, name);
  
  if (e)
    {
      if ((is_config && (e->flags & Z_VF_CFG_READ)) ||
          (!is_config && (e->flags & Z_VF_READ)))
        {
          if (e->flags & Z_VF_OBSOLETE)
            {
              z_log(NULL, CORE_POLICY, 3, "Fetching obsolete attribute; name='%s'", name);
            }
          return e->type_funcs->get_value(self, e);
        }
      else
        {
          z_log(NULL, CORE_POLICY, 3, "Attribute cannot be read; config='%d', name='%s'", is_config, name);
        }
    }
  return NULL;
}

/**
 * z_policy_dict_set_value:
 * @self: ZPolicyDict instance
 * @is_config: whether this variable query is at config time or not
 * @name: name of the variable
 * @new_value: new value of the variable
 *
 * This function can be used to "set" a value in this dictionary. It is
 * used by various Python extension types (like ZPolicyStruct or ZProxy) to
 * implement their "setattr" method.
 **/
gint 
z_policy_dict_set_value(ZPolicyDict *self, gboolean is_config, const gchar *name, ZPolicyObj *new_value)
{
  ZPolicyDictEntry *e;

  e = g_hash_table_lookup(self->vars, name);
  
  if (e)
    {
      if ((is_config && (e->flags & Z_VF_CFG_WRITE)) ||
          (!is_config && (e->flags & Z_VF_WRITE)))
        {
          if (e->flags & Z_VF_OBSOLETE)
            {
              z_log(NULL, CORE_POLICY, 3, "Changing obsolete attribute; name='%s'", name);
            }
          return e->type_funcs->set_value(self, e, new_value);
        }
      else
        {
          z_log(NULL, CORE_POLICY, 3, "Attribute cannot be written; config='%d', name='%s'", is_config, name);
          return -1;
        }
    }
  return 1;
}

/**
 * z_policy_dict_insert_values:
 * @key:
 * @entry:
 * @user_data:
 *
 * This function is used to iterate through the dictionary hash and generate
 * a Python dictionary with the results. It is used to implement the
 * "__dict__" hash of the object.
 **/
static void
z_policy_dict_insert_values(gpointer key, gpointer entry G_GNUC_UNUSED, gpointer user_data)
{
  gpointer *params = (gpointer *) user_data;
  ZPolicyDict *self = params[0];
  ZPolicyObj *dict = params[1];
  ZPolicyObj *value;

  value = z_policy_dict_get_value(self, FALSE, (gchar *) key);
  PyDict_SetItemString(dict, (gchar *) key, value);
  z_policy_var_unref(value);
  
}

/**
 * z_policy_dict_get_dict:
 * @self: ZPolicyDict instance
 *
 * This function constructs and returns a Python dictionary object which
 * represents the dictionary. It can be used to peek into the dictionary
 * internals using dir(object).
 **/
ZPolicyObj *
z_policy_dict_get_dict(ZPolicyDict *self)
{
  ZPolicyObj *dict, *proxy_dict;
  gpointer params[2];

  dict = PyDict_New();
  params[0] = self;
  params[1] = dict;
  g_hash_table_foreach(self->vars, z_policy_dict_insert_values, params);
  proxy_dict = PyDictProxy_New(dict);
  z_policy_var_unref(dict);

  return proxy_dict;
}


ZPolicyDictType z_policy_dict_types[] =
{
  [Z_VT_NONE]    = { NULL, NULL, NULL, NULL },
  [Z_VT_INT]     = { z_policy_dict_int_parse_args, z_policy_dict_int_get_value, z_policy_dict_int_set_value, NULL },
  [Z_VT_INT8]    = { z_policy_dict_int_parse_args, z_policy_dict_int_get_value, z_policy_dict_int_set_value, NULL },
  [Z_VT_INT16]   = { z_policy_dict_int_parse_args, z_policy_dict_int_get_value, z_policy_dict_int_set_value, NULL },
  [Z_VT_INT32]   = { z_policy_dict_int_parse_args, z_policy_dict_int_get_value, z_policy_dict_int_set_value, NULL },
  [Z_VT_STRING]  = { z_policy_dict_string_parse_args, z_policy_dict_string_get_value, z_policy_dict_string_set_value, z_policy_dict_string_free },
  [Z_VT_CSTRING] = { z_policy_dict_string_parse_args, z_policy_dict_string_get_value, z_policy_dict_string_set_value, z_policy_dict_string_free },
  [Z_VT_METHOD]  = { z_policy_dict_method_parse_args, z_policy_dict_method_get_value, NULL, z_policy_dict_method_free },
  [Z_VT_OBJECT]  = { z_policy_dict_object_parse_args, z_policy_dict_object_get_value, z_policy_dict_object_set_value, z_policy_dict_object_free },
  [Z_VT_IP]      = { z_policy_dict_ip_parse_args, z_policy_dict_ip_get_value, z_policy_dict_ip_set_value, z_policy_dict_ip_free },
  [Z_VT_IP6]     = { z_policy_dict_ip_parse_args, z_policy_dict_ip_get_value, z_policy_dict_ip_set_value, z_policy_dict_ip_free },
  [Z_VT_ALIAS]   = { z_policy_dict_alias_parse_args, z_policy_dict_alias_get_value, z_policy_dict_alias_set_value, NULL },
  [Z_VT_HASH]    = { z_policy_dict_hash_parse_args, z_policy_dict_hash_get_value, NULL, z_policy_dict_hash_free },
  [Z_VT_DIMHASH] = { z_policy_dict_dimhash_parse_args, z_policy_dict_dimhash_get_value, NULL, z_policy_dict_dimhash_free },
  [Z_VT_CUSTOM]  = { z_policy_dict_custom_parse_args, z_policy_dict_custom_get_value, z_policy_dict_custom_set_value, z_policy_dict_custom_free },
  [Z_VT_PTR]     = { z_policy_dict_ptr_parse_args, z_policy_dict_ptr_get_value, z_policy_dict_ptr_set_value, NULL },
};

static void 
z_policy_dict_register_va(ZPolicyDict *self, ZVarType var_type, va_list args)
{
  ZPolicyDictEntry *e;
  va_list args_copy;

  g_assert((guint) var_type < sizeof(z_policy_dict_types) / sizeof(z_policy_dict_types[0]));

  e = g_new0(ZPolicyDictEntry, 1);
  e->name = g_strdup(va_arg(args, gchar *));
  e->flags = va_arg(args, guint);
  e->type = var_type;
  e->type_funcs = &z_policy_dict_types[var_type];

  g_assert((e->flags & (Z_VF_WRITE+Z_VF_CFG_WRITE)) == 0 || e->type_funcs->set_value);
  g_assert((e->flags & (Z_VF_READ+Z_VF_CFG_READ)) == 0 || e->type_funcs->get_value);

  va_copy(args_copy, args);
  e->type_funcs->parse_args(self, e, args_copy);
  va_end(args_copy);
  
  g_hash_table_insert(self->vars, (gchar *) e->name, e);

}

/**
 * z_policy_dict_register:
 * @self: ZPolicyDict instance 
 * @var_type: type of the variable to register
 *
 * This is a vararg function that implements registering variables in the
 * dictionary. The type of the variable determines the remaining arguments.
 * See the type specific parse_args function for more information.
 **/
void 
z_policy_dict_register(ZPolicyDict *self, ZVarType var_type, ...)
{
  va_list args;

  va_start(args, var_type);
  z_policy_dict_register_va(self, var_type, args);
  va_end(args);
}

/**
 * z_policy_dict_set_app_data:
 * @self: ZPolicyDict instance
 * @data: user_data pointer to be associated with @self
 * @data_free: destroy notify callback for @data
 *
 * Each ZPolicyDict instance has an associated "application data",
 * particularly useful when variables reference memory areas within some
 * kind of data structure directly. The application data will not be freed
 * as long as any data references can be made through the dictionary.
 **/
void
z_policy_dict_set_app_data(ZPolicyDict *self, gpointer data, GDestroyNotify data_free)
{
  g_assert(self->app_data == NULL);

  self->app_data = data;
  self->app_data_free = data_free;
}

/**
 * z_policy_dict_get_app_data:
 * @self: ZPolicyDict instance
 *
 * Return the current application data pointer.
 **/
gpointer
z_policy_dict_get_app_data(ZPolicyDict *self)
{
  return self->app_data;
}

static void
z_policy_dict_call_iter(gpointer key, gpointer value G_GNUC_UNUSED, gpointer user_data)
{
  gpointer *args = user_data;
  ZPolicyDict *self = args[0];
  ZPolicyDictIterFunc iter = args[1];

  iter(self, (const gchar *) key, args[2]);
}

void
z_policy_dict_iterate(ZPolicyDict *self, ZPolicyDictIterFunc iter, gpointer user_data)
{
  gpointer args[3] = { self, iter, user_data };
  
  g_hash_table_foreach(self->vars, z_policy_dict_call_iter, args);
}

/**
 * z_policy_dict_new:
 * 
 * ZPolicyDict constructor, prepares the dictionary for variable registrations.
 **/
ZPolicyDict *
z_policy_dict_new(void)
{
  ZPolicyDict *self = g_new0(ZPolicyDict, 1);
  
  z_refcount_set(&self->ref_cnt, 1);
  self->vars = g_hash_table_new_full(g_str_hash, g_str_equal, NULL, (GDestroyNotify) z_policy_dict_entry_free);
  return self;
}

/**
 * z_policy_dict_ref:
 * @self: ZPolicyDict instance
 *
 * Increase the reference counter for @self.
 **/
ZPolicyDict *
z_policy_dict_ref(ZPolicyDict *self)
{
  z_refcount_inc(&self->ref_cnt);
  return self;
}

/**
 * z_policy_dict_unref:
 * @self: ZPolicyDict instance
 *
 * Decrement the reference counter for @self and free the data structure if
 * it reaches zero.
 **/
void
z_policy_dict_unref(ZPolicyDict *self)
{
  /* NOTE: requires the python state to be locked... */
  if (self && z_refcount_dec(&self->ref_cnt))
    {
      if (self->app_data && self->app_data_free)
        {
          self->app_data_free(self->app_data);
        }
      g_free(self);
    }
}

/**
 * z_policy_dict_destroy:
 * @self: ZPolicyDict instance
 * 
 * Start disposing the dictionary by breaking possible circular references. 
 * This function must be called exactly once for each dictionary. See the
 * notes in the top of the file for more information.
 **/
void
z_policy_dict_destroy(ZPolicyDict *self)
{
  g_assert(self->vars);
  g_hash_table_destroy(self->vars);
  self->vars = NULL;
  z_policy_dict_unref(self);
}
