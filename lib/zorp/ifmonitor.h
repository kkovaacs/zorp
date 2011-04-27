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
 * $Id: zorp.h,v 1.39 2004/07/05 07:59:55 bazsi Exp $
 *
 ***************************************************************************/

#ifndef ZORP_IFMONITOR_H_INCLUDED
#define ZORP_IFMONITOR_H_INCLUDED

#include <zorp/zorp.h>

typedef enum
{
  Z_IFC_REMOVE,
  Z_IFC_ADD,
} ZIfChangeType;

typedef void (*ZIfmonWatchFunc)(const gchar *iface, ZIfChangeType change, gint family, void *addr, gpointer user_data);
typedef struct _ZIfmonWatch ZIfmonWatch;

gboolean z_ifmon_watch_iface_matches(ZIfmonWatch *w, const gchar *if_name);
ZIfmonWatch *z_ifmon_register_watch(const gchar *iface, gint family, ZIfmonWatchFunc callback, gpointer user_data, GDestroyNotify user_data_destroy);
void z_ifmon_unregister_watch(ZIfmonWatch *watch);

typedef void (*ZIfmonGroupWatchFunc)(guint32 group, ZIfChangeType change, const gchar *if_name, gpointer user_data);
typedef struct _ZIfmonGroupWatch ZIfmonGroupWatch;

ZIfmonGroupWatch *z_ifmon_register_group_watch(guint32 group, ZIfmonGroupWatchFunc callback, gpointer user_data, GDestroyNotify user_data_destroy);
void z_ifmon_unregister_group_watch(ZIfmonGroupWatch *watch);

const void *z_ifmon_get_primary_address_by_name(const gchar *iface, gint family);
const void *z_ifmon_get_primary_address(guint ifindex, gint family);

gboolean z_ifmon_get_ifindex(const gchar *iface, guint *if_index);

guint z_ifmon_get_iface_flags(guint ifindex);


void z_ifmon_init(void);
void z_ifmon_destroy(void);


#endif
