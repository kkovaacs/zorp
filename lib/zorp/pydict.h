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

#ifndef ZORP_PYDICT_H_INCLUDED
#define ZORP_PYDICT_H_INCLUDED

#include <zorp/zorp.h>
#include <zorp/policy.h>

typedef struct _ZPolicyDict ZPolicyDict;

typedef enum 
{
  Z_VT_NONE     = 0,    /* end of argument list */
  Z_VT_INT,	        /* variable is an int */
  Z_VT_INT8,            /* variable is an int8 */
  Z_VT_INT16,	        /* variable is an int16 */
  Z_VT_INT32,	        /* variable is an int32 */
  Z_VT_STRING,	        /* variable is a string, represented as a GString */
  Z_VT_CSTRING,         /* variable is a string, represented as a C character buffer and size */
  Z_VT_IP,              /* variable is an ip address, represented as struct in_addr */
  Z_VT_IP6,             /* variable is an ipv6 address, represented as struct in6_addr */
  Z_VT_OBJECT,	        /* variable is a policy object */
  Z_VT_HASH,	        /* variable is a hash */
  Z_VT_METHOD,          /* variable is a method */
  Z_VT_CUSTOM,	        /* variable is something, requests are processed via a function call */
  Z_VT_DIMHASH,         /* variable is a multidimensional hash */
  Z_VT_ALIAS,	        /* variable is an alias of another variable */
  Z_VT_PTR,             /* variable is a generic pointer */
} ZVarType;

enum
{
  /* access modes */
  Z_VF_READ       = 0x0001,
  Z_VF_WRITE      = 0x0002,
  Z_VF_RW         = 0x0003,
  Z_VF_CFG_READ   = 0x0004,
  Z_VF_CFG_WRITE  = 0x0008,
  Z_VF_CFG_RW     = 0x000C,

  /* other flags */
  Z_VF_OBSOLETE   = 0x0010,
  /* */
  Z_VF_DUP        = 0x0020, /* dup value to an internal storage, requires Z_VF_CONST */
  Z_VF_LITERAL    = 0x0040, /* value is specified as a value instead of a pointer pointing somewhere else */
  Z_VF_CONSUME    = 0x0080, /* value should be freed by ZPolicyDict */

  /* type specific flags */
  Z_VF_IP_STR     = 0x0100, /* represent an IP address as string */
  Z_VF_INT_NET    = 0x0200  /* represent integer in network byte order */
};

typedef ZPolicyObj *(*ZPolicyDictMethodFunc)(gpointer user_data, ZPolicyObj *args, ZPolicyObj *kw);
typedef void (*ZPolicyDictIterFunc)(ZPolicyDict *self, const gchar *name, gpointer user_data);

void z_policy_dict_wrap(ZPolicyDict *self, ZPolicyObj *wrapper);
void z_policy_dict_unwrap(ZPolicyDict *self, ZPolicyObj *wrapper);
ZPolicyObj *z_policy_dict_get_value(ZPolicyDict *self, gboolean is_config, const gchar *name);
gint z_policy_dict_set_value(ZPolicyDict *self, gboolean is_config, const gchar *name, ZPolicyObj *new_value);
ZPolicyObj *z_policy_dict_get_dict(ZPolicyDict *self);
void  z_policy_dict_register(ZPolicyDict *self, ZVarType first_var, ...);
void z_policy_dict_set_app_data(ZPolicyDict *self, gpointer data, GDestroyNotify data_free);
gpointer z_policy_dict_get_app_data(ZPolicyDict *self);
void z_policy_dict_iterate(ZPolicyDict *self, ZPolicyDictIterFunc iter, gpointer user_data);

ZPolicyDict *z_policy_dict_new(void);
ZPolicyDict *z_policy_dict_ref(ZPolicyDict *self);
void z_policy_dict_unref(ZPolicyDict *self);
void z_policy_dict_destroy(ZPolicyDict *self);

#endif

