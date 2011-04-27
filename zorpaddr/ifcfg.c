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
 * Author  : Panther
 * Auditor :
 * Last audited version:
 * Notes:
 *
 ***************************************************************************/

#include "zorpaddr.h"
#include "ping.h"

#include <zorp/log.h>
#include <zorp/ifmonitor.h>

#include <net/if.h>
#include <sys/ioctl.h>
#include <linux/rtnetlink.h>
#include <arpa/inet.h>

#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>

/* interfaces is used at all time but temp_interfaces is only during config reloading */
static GHashTable *interfaces = NULL;
static GHashTable *tmp_interfaces = NULL;

ZorpAddrData config;

static gboolean ifcfg_reloading = FALSE;

static void  z_ifcfg_update_group_preferences(const ZorpAddrInterface *iface);

/**
 * z_ifcfg_iface_watch:
 * @ifname: name of the interface which IP address changed
 * @change: not used
 * @family: not used
 * @addr: not used
 * @user_data: not used
 *
 * If an IP address added or removed from the interface's address list, or the inferface goes up/down
 * the appropriate changes happen in the shared memory and in the ping_thread.
 *
 * If the interface goes down OR its primary address is NULL (or 0.0.0.0), the ping must be stopped,
 * and the corresponding address in shmem reflects this: it's 0.0.0.0 in these cases.
 */
static void
z_ifcfg_iface_watch(const gchar *ifname, ZIfChangeType change, gint family G_GNUC_UNUSED,
                    void *addr G_GNUC_UNUSED, gpointer user_data G_GNUC_UNUSED)
{
  ZorpAddrInterface    *iface           = z_ifcfg_get_iface(ifname);
  const struct in_addr *primary_address = NULL;
  ZPingUpdateData      *update_data     = NULL;
  guint flags;

  if (NULL == iface || ! (iface->status & Z_IFCFG_IFINDEX))
    return;

  flags = z_ifmon_get_iface_flags(iface->if_index);

  update_data = g_new0(ZPingUpdateData, 1);
  update_data->iface = iface;
  update_data->action = Z_PING_REMOVE;                /* default value */

  if (flags & IFF_UP)
    {
      primary_address = z_ifmon_get_primary_address(iface->if_index, AF_INET);
      z_log(NULL, CORE_INFO, 4, "Interface is up; if_name='%s', change='%s', primary_address='%s'",
            ifname, (change == Z_IFC_REMOVE ? "REMOVE" : "ADD"),
            (primary_address ? inet_ntoa(*primary_address) : "-"));
      if (primary_address && primary_address->s_addr)
        update_data->action = iface->address.s_addr ? Z_PING_UPDATE : Z_PING_ADD;
    }
  else
    {
      z_log(NULL, CORE_INFO, 4, "Interface is down; if_name='%s'", ifname);
    }

  z_ping_add_update_data(update_data);
  z_ifcfg_set_ip_address(iface, primary_address);
  z_ifcfg_update_group_preferences(iface);
}

static ZorpIfaceData *
z_ifcfg_add_and_get_iface_data(const gchar *groupname, const gchar *ifname, gint *groupnum)
{
  guint  i , j;
  ZorpIfaceData *iface_data;

  *groupnum = -1;

  for (i = 0; i!= config.group_num; ++i)
    {
      if (!strcmp(groupname, config.groups[i].name))
        {
          *groupnum = i;
          break;
        }
    }

  if (-1 == *groupnum)
    {
      if (config.group_num == Z_LB_POLICY_MAX)
        {
          z_log(NULL, CORE_ERROR, 1, "Maximum number of available policies is reached at '%s'", groupname);
          return NULL;
        }

      *groupnum = config.group_num;
      ++config.group_num;

      strncpy(config.groups[*groupnum].name, groupname, Z_LB_POLICY_NAME_MAX);

    }
  for (j = 0, i = *groupnum; j != config.groups[i].iface_num; ++j)
    {
      if (!strcmp(ifname, config.groups[i].ifaces[j].iface->name))
        {
          return &config.groups[i].ifaces[j];
          break;
        }
    }

  if (config.groups[i].iface_num == Z_LB_IFACE_MAX)
    {
      z_log(NULL, CORE_ERROR, 1, "Maximum number of available interfaces is reached at '%s' in '%s'",
            ifname, groupname);
      return NULL;
    }

  ++config.groups[i].iface_num;
  iface_data = &config.groups[i].ifaces[ config.groups[i].iface_num -1 ];
  iface_data->group = i;
  iface_data->index = j;
  iface_data->status = Z_IFCFG_ALIVE;
  return iface_data;
}

ZorpIfaceData *
z_ifcfg_grp_add_iface(const gchar *groupname, const gchar *ifname)
{
  ZorpAddrInterface  *iface;
  ZorpIfaceData      *data;
  gint               groupnum;

  z_log(NULL, CORE_DEBUG, 8, "Adding interface '%s' in group '%s'", ifname, groupname);

  if ((iface = z_ifcfg_get_iface(ifname)) == NULL)
    {
      iface = g_new0(ZorpAddrInterface, 1);
      iface->speed = -1;
      iface->watch = z_ifmon_register_watch(ifname, AF_INET, z_ifcfg_iface_watch, 0, 0);
      strncpy(iface->name, ifname, Z_LB_POLICY_NAME_MAX - 1);
      iface->status  = Z_IFCFG_ALIVE;       /* ping works; default (requires Z_IFCFG_UP!!) */
      g_hash_table_insert(interfaces, g_strdup(ifname), iface);
   }

  data = z_ifcfg_add_and_get_iface_data(groupname, ifname, &groupnum);

  if (! data)
    return NULL;

  data->iface = iface;

  iface->iface_data[iface->iface_data_num] = data;
  ++iface->iface_data_num;

  return data;
}

ZorpAddrInterface *
z_ifcfg_get_iface(const gchar *name)
{
  ZorpAddrInterface *iface = g_hash_table_lookup(interfaces, name);

  if (!iface && tmp_interfaces)
    {
      iface = g_hash_table_lookup(tmp_interfaces, name);
      if (iface)
        {
          /* reloading */
          g_hash_table_insert(interfaces, g_strdup(name), iface);
          g_hash_table_remove(tmp_interfaces, name);
        }
    }
  return iface;
}

void
z_ifcfg_set_ip_address(ZorpAddrInterface *iface, const struct in_addr *address)
{
  guint i;

  iface->address.s_addr = address ? address->s_addr : 0;

  if (iface->address.s_addr)
    iface->status |= Z_IFCFG_UP;
  else
    iface->status &= ~Z_IFCFG_UP;

  for (i = 0; i != iface->iface_data_num; ++i)
     z_shmem_update_ip_address(iface->iface_data[i]->group, iface->iface_data[i]->index, iface->address.s_addr);
  z_shmem_validate();
}

void
z_ifcfg_set_preference(ZorpIfaceData *data, guint32 preference)
{
  data->percent = data->status & Z_IFCFG_ALIVE ? preference : 0;
  z_shmem_update_preference(data->group, data->index, data->percent);
}

static void
z_ifcfg_update_group_preference(guint groupid)
{
  ZorpAddrGroup *group;
  guint i;
  gdouble psum = 0.0;    /* sum of preferences */

  if (!config.valid)
    return;

  group = &config.groups[groupid];

  for (i = 0; i!=group->iface_num; ++i)
    if (group->ifaces[i].iface->status & Z_IFCFG_UP)
      psum += group->ifaces[i].user_pref;

  for (i = 0; i!=group->iface_num; ++i)
    {
      guint old_pref = group->ifaces[i].real_pref;
      if (group->ifaces[i].iface->status & Z_IFCFG_UP)
        group->ifaces[i].real_pref = group->ifaces[i].user_pref * 100 / psum;
      else
        group->ifaces[i].real_pref = 0;

      z_log(NULL, CORE_INFO, 5, "Interface preference changed; group_name='%s', if_name='%s', "
            "old_pref='%u', new_pref='%u', user_pref='%d'",
            group->name, group->ifaces[i].iface->name,old_pref, group->ifaces[i].real_pref,
            group->ifaces[i].user_pref);
    }
}

static void
z_ifcfg_update_group_preferences(const ZorpAddrInterface *iface)
{
  guint i;
  for (i=0; i != iface->iface_data_num; ++i)
    z_ifcfg_update_group_preference(iface->iface_data[i]->group);
}

static void
z_ifcfg_update_all_group_preferences_cb(gpointer key G_GNUC_UNUSED, gpointer value, gpointer user_data G_GNUC_UNUSED)
{
  z_ifcfg_update_group_preferences(value);
}

void
z_ifcfg_update_all_group_preferences(void)
{
  g_hash_table_foreach(interfaces, z_ifcfg_update_all_group_preferences_cb, NULL);
}

void
z_ifcfg_update_cb(gpointer key, gpointer value, gpointer user_data)
{
  ZorpAddrInterface *iface = (ZorpAddrInterface *)value;
  guint flags;

  if (iface && !(iface->status & Z_IFCFG_IFINDEX))
    {
      guint ifindex;
      *(gboolean *)user_data = FALSE;

      if (z_ifmon_get_ifindex(iface->name, &ifindex))
        {
          iface->if_index = ifindex;

          iface->status |= Z_IFCFG_IFINDEX;
          {
            const struct in_addr* primary_address = z_ifmon_get_primary_address(iface->if_index, AF_INET);
            z_ifcfg_set_ip_address(iface, primary_address);
          }
        }
    }

   if (iface && iface->status & Z_IFCFG_IFINDEX)
    {
       flags = z_ifmon_get_iface_flags(iface->if_index);

       if (flags & IFF_UP)
         {
           const struct in_addr* primary_address = z_ifmon_get_primary_address(iface->if_index, AF_INET);
           z_log(NULL, CORE_INFO, 4, "Interface is up; if_name='%s', primary_address='%s'",
                                     (gchar *)key,
                                     (primary_address ? inet_ntoa(*primary_address) : "-"));
      
           if (primary_address && primary_address->s_addr)
             {
               ZPingUpdateData *update_data = update_data = g_new0(ZPingUpdateData, 1);
               update_data->iface = iface;
               update_data->action = Z_PING_ADD;
               z_ping_add_update_data(update_data);
             }
         }
       else
         {
           z_log(NULL, CORE_INFO, 4, "Interface is down; if_name='%s'", (gchar *)key);
         }
    }
}

gboolean
z_ifcfg_update()
{
  gboolean verdict = TRUE;

  g_hash_table_foreach(interfaces, z_ifcfg_update_cb, &verdict);
  return verdict;
}

static void
z_ifcfg_destroy_iface(gpointer data)
{
  ZorpAddrInterface *iface =  (ZorpAddrInterface *)data;
  z_ifmon_unregister_watch(iface->watch);
  g_free(iface);
}

/* required because glib 2.12+ is not used (..._remove_all)*/
static inline gboolean
z_ifcfg_clear_cb(gpointer key G_GNUC_UNUSED,
                 gpointer value,
                 gpointer user_data G_GNUC_UNUSED)
{
  z_ifcfg_destroy_iface(value);
  return TRUE;
}

void
z_ifcfg_clear(void)
{
  if (interfaces) {
#if 0
    /* requires: glib 2.12 */
    g_hash_table_remove_all(interfaces);
#endif
    g_hash_table_foreach_remove(interfaces, z_ifcfg_clear_cb, 0);
  }

  memset(&config, 0, sizeof(ZorpAddrData));
}

void
z_ifcfg_init(void)
{
  z_ifcfg_clear();

  interfaces = g_hash_table_new_full(g_str_hash, g_str_equal, g_free, NULL);
}

void
z_ifcfg_destroy(void)
{
  z_ifcfg_reload_finish(FALSE);
  z_ifcfg_clear();
  if (interfaces)
    g_hash_table_destroy(interfaces);
}

void
z_ifcfg_reload_cb(gpointer key G_GNUC_UNUSED, gpointer value, gpointer user_data G_GNUC_UNUSED)
{
  ZorpAddrInterface *iface = (ZorpAddrInterface *)value;
  const struct in_addr *primary_address = NULL;
  ZPingUpdateData      *update_data     = NULL;
  guint flags;

  if (NULL == iface || ! (iface->status & Z_IFCFG_IFINDEX))
    return;

  flags = z_ifmon_get_iface_flags(iface->if_index);

  if (flags & IFF_UP)
    {
      primary_address = z_ifmon_get_primary_address(iface->if_index, AF_INET);
      if (primary_address && primary_address->s_addr)
        {
          update_data = g_new0(ZPingUpdateData, 1);
          update_data->iface = iface;
          update_data->action = Z_PING_ADD;
          z_ping_add_update_data(update_data);
        }
    }
}

void
z_ifcfg_reload_start(void)
{
  ifcfg_reloading = TRUE;
  if (interfaces)
    {
      tmp_interfaces = interfaces;
      interfaces = NULL;
      interfaces = g_hash_table_new_full(g_str_hash, g_str_equal, NULL, NULL);
    }
}

/**
 * z_ifcfg_reload_finish:
 * @notify_ping: TRUE if the pinger thread needs to be notified
 *
 * If notify_ping is FALSE, frees tmp_interfaces.
 * If it is TRUE, additionally all interfaces which up and
 * have IP address, will generate an event to the pinger thread.
 *
 */
void
z_ifcfg_reload_finish(gboolean notify_ping)
{
  if (!ifcfg_reloading)
    return;

  if (notify_ping)
     g_hash_table_foreach(interfaces, z_ifcfg_reload_cb, 0);

  if (tmp_interfaces)
    {
      GHashTable *tmp_table = tmp_interfaces;
      tmp_interfaces = NULL;
      g_hash_table_foreach_remove(tmp_table, z_ifcfg_clear_cb, 0);
      g_hash_table_destroy(tmp_table);
    }
}

