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
 * $Id: szig.h,v 1.6 2003/09/24 09:56:42 bazsi Exp $
 *
 ***************************************************************************/

#ifndef ZORP_SZIG_H_INCLUDED
#define ZORP_SZIG_H_INCLUDED

#include <zorp/zorp.h>

/* these values are copied to Python, change carefully */
enum
{
  Z_SZIG_THREAD_START = 0,
  Z_SZIG_THREAD_STOP,
  Z_SZIG_TICK,
  Z_SZIG_COUNTED_IP,
  Z_SZIG_CONNECTION_PROPS,
  Z_SZIG_CONNECTION_STOP,
  Z_SZIG_AUDIT_START,
  Z_SZIG_AUDIT_STOP,
  Z_SZIG_RELOAD,
  Z_SZIG_AUTH_PENDING_BEGIN,
  Z_SZIG_AUTH_PENDING_FINISH,
  Z_SZIG_SERVICE_COUNT,
  Z_SZIG_MAX
};

/* these values are copied to Python, change carefully */
enum
{
  Z_SZIG_TYPE_NOTINIT = 0,
  Z_SZIG_TYPE_LONG,
  Z_SZIG_TYPE_TIME,
  Z_SZIG_TYPE_STRING,
  Z_SZIG_TYPE_PROPS,
  Z_SZIG_TYPE_CONNECTION_PROPS
};

#define Z_SZIG_MAX_PROPS 16

typedef gint ZSzigEvent;
typedef struct _ZSzigValue ZSzigValue;
typedef struct _ZSzigNode ZSzigNode;
typedef struct _ZSzigProps ZSzigProps;
typedef struct _ZSzigServiceProps ZSzigServiceProps;

/*
 * NOTE: this could be represented as a nested structure of ZSzigProps,
 * however it is special cased for speed.
 */
struct _ZSzigServiceProps
{
  gchar *name;
  gint instance_id;
  gushort sec_conn_id;
  gushort related_id; 
  gint string_count;
  gchar *string_list[Z_SZIG_MAX_PROPS * 2];
};

struct _ZSzigProps
{
  gchar *name;
  gint value_count;
  gchar *name_list[Z_SZIG_MAX_PROPS];
  ZSzigValue *value_list[Z_SZIG_MAX_PROPS];
};


struct _ZSzigValue
{
  gint type;
  union
  {
    glong long_value;
    GTimeVal time_value;
    GString *string_value;
    ZSzigProps props_value;
    ZSzigServiceProps service_props;
  } u;
};

/**
 * ZSzigNode:
 *
 * A node in the result tree.
 **/
struct _ZSzigNode
{
  gchar *name;

  ZSzigValue value;
  gpointer agr_data;
  GDestroyNotify agr_notify;

  GPtrArray *children;
};

typedef void (*ZSzigEventHandler)(ZSzigNode *node, ZSzigEvent ev, ZSzigValue *param, gpointer user_data);

void z_szig_register_handler(ZSzigEvent ev, ZSzigEventHandler func, const gchar *node_name, gpointer user_data);
void z_szig_unregister_handler(ZSzigEvent ev, ZSzigEventHandler func);

void z_szig_event(ZSzigEvent ev, ZSzigValue *param);

void z_szig_init(const gchar *instance_name);

ZSzigValue *z_szig_value_new_long(glong val);
ZSzigValue *z_szig_value_new_time(GTimeVal *val);
ZSzigValue *z_szig_value_new_string(const gchar *val);
void z_szig_value_add_connection_prop(ZSzigValue *v, const gchar *name, const gchar *value);
ZSzigValue *z_szig_value_new_connection_props(const gchar *service, gint instance_id, gushort sec_conn_id, gushort related_id, const gchar *name, ...);
void z_szig_value_add_prop(ZSzigValue *v, const gchar *name, ZSzigValue *value);
ZSzigValue *z_szig_value_new_props(const gchar *name, const gchar *first_prop, ...);
void z_szig_value_free(ZSzigValue *v, gboolean free_inst);

ZSzigNode *z_szig_tree_lookup(const gchar *node_name, gboolean create, ZSzigNode **parent, gint *parent_ndx);

#endif
