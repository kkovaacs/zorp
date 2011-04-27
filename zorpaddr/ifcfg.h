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

#ifndef ZORP_ZORPADDR_IFCFG_INCLUDED
#define ZORP_ZORPADDR_IFCFG_INCLUDED

#include <zorp/linebalance.h>
#include <zorp/ifmonitor.h>

#include <netinet/in.h>

#define Z_I_STATS_MAX      30
#define Z_I_PING_HOST_MAX   5

/* Interface status.
 *
 * NOTE: Z_IFCFG_ALIVE is special. It is _unset_ if and only if the pinging doesn't work
 * in the ping_thread but at least the bind() works on the IP address of the interface.
 */
enum zifcfgstatus{
  Z_IFCFG_NONE = 0,          /* uninitialized */
  Z_IFCFG_IFINDEX = 1,       /* ifindex already set */
  Z_IFCFG_UP = 2,            /* up and has IP address */
  Z_IFCFG_ALIVE = 4,         /* set if ping does _not_ work on this interface  _or_ at least one host is pingable */
  Z_IFCFG_PING = 8,          /* set if ping works on this interface */
};

typedef struct _ZorpIfaceStats
{
  guint64 tbytes;  /* transfered bytes */
  guint64 rbytes;  /* received bytes */
  gint   aspeed;   /* avalable (remaining) speed. Always >= 0 */
} ZorpIfaceStats;

typedef struct _ZorpIfaceData ZorpIfaceData;

typedef struct _ZorpAddrInterface
{
  gchar           name[Z_LB_POLICY_NAME_MAX];
  gint            speed;
  struct in_addr address;
  ZIfmonWatch    *watch;

  gint            scount;      /* stats count */
  gint            snext;       /* next available, _unused_ */
  ZorpIfaceStats  stats[Z_I_STATS_MAX + 1];

  guint           iface_data_num;              /* group count, it belongs to */
  ZorpIfaceData  *iface_data[Z_LB_POLICY_MAX]; /* groups this interface belongs to */
  guint           if_index;
  enum zifcfgstatus  status;
} ZorpAddrInterface;

struct _ZorpIfaceData
{
  gint                user_pref;  /* recommended by user */
  guint32             real_pref;  /* real preference calculated from user_pref */
  guint32             percent;    /* percent, preference used by zorp via shmem */
  gboolean            enabled;    /* true if address is valid, etc. */
  /* FIXME: Is this needed? */
  ZorpAddrInterface  *iface;      /* interface of current structure */
  gint                group;      /* policy number */
  gint                index;      /* interface index in the group */
  enum zifcfgstatus   status;     /* Z_IFCFG_ALIVE is set or unset depending on the ping thread */
};

typedef struct _ZorpAddrGroup
{
  gchar           name[Z_LB_POLICY_NAME_MAX];
  guint           iface_num;
  ZorpIfaceData   ifaces[Z_LB_IFACE_MAX];
  guint           host_num;
  struct in_addr  hosts[Z_I_PING_HOST_MAX];
} ZorpAddrGroup;

/* Similar to the structure with additional members */
typedef struct _ZorpAddrData
{
  guint          group_num;
  ZorpAddrGroup groups[Z_LB_POLICY_MAX];
  guint32       last_timestamp;      /* Last known timestamp in shmem, next must be larger */
  gboolean      valid;
} ZorpAddrData;

/* init & destroy */
void z_ifcfg_init(void);
void z_ifcfg_destroy(void);
gboolean z_ifcfg_update();

/* get & add */
ZorpAddrInterface *z_ifcfg_get_iface(const gchar *name);
ZorpIfaceData *z_ifcfg_grp_add_iface(const gchar *group, const gchar *ifname);

/* set members */
void z_ifcfg_set_ip_address(ZorpAddrInterface *iface, const struct in_addr *addr);
void z_ifcfg_set_preference(ZorpIfaceData *data, guint32 preference);

void z_ifcfg_set_live(ZorpAddrInterface, gboolean value);

void z_ifcfg_update_all_group_preferences(void);

void z_ifcfg_reload_start();
void z_ifcfg_reload_finish(gboolean notify_ping);
#endif
