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

#include <zorp/log.h>

#include <netinet/in.h>
#include <arpa/inet.h>

#include <stdio.h>
#include <stdlib.h>

extern gint refresh_rate;

extern ZorpAddrData config;

static void
z_stats_update_impl(ZorpAddrInterface *iface,
                    const gchar *received,
                    const gchar *sent)
{
  gint snext = iface->snext;
  gint current = (Z_I_STATS_MAX /*+ 1*/ + snext/* -1*/) % (Z_I_STATS_MAX + 1);

  iface->stats[snext].tbytes = atoi(sent);
  iface->stats[snext].rbytes = atoi(received);
  if (iface->scount)
    iface->stats[snext].aspeed =  iface->speed -
      (
       (iface->stats[snext].rbytes + iface->stats[snext].tbytes) -
       (iface->stats[current].rbytes + iface->stats[current].tbytes)
      ) * 10 / (double)refresh_rate;
  else
    iface->stats[snext].aspeed = iface->speed;
  if (iface->stats[snext].aspeed < 0)
    iface->stats[snext].aspeed  = 0;

  iface->snext = (iface->snext + 1) % (Z_I_STATS_MAX + 1);
  if (iface->scount < Z_I_STATS_MAX)
    ++iface->scount;
}

static void
z_stats_update_get_string(char **ppc, char **ptr)
{
  while (' ' == **ppc || '\t' == **ppc)
    ++(*ppc);

  *ptr = *ppc;
  while (!(' ' == **ppc || '\t' == **ppc))
    ++(*ppc);

  **ppc = 0;
  ++(*ppc);
}

static void
z_stats_update_skip_string(char **ppc, int count)
{
  int i;
  for (i=0; i!=count;++i)
    {
      while (' ' == **ppc || '\t' == **ppc)
        ++(*ppc);
      while (!(' ' == **ppc || '\t' == **ppc))
        ++(*ppc);
    }
}

static guint64
z_stats_update_prefs_iface(const ZorpAddrInterface *iface)
{
  gint i;
  guint count = 0;
  guint64 aspeed = 0;
  aspeed = 0;

  if (iface->scount < Z_I_STATS_MAX)
    {
      for (i = 0; i != Z_I_STATS_MAX + 1; ++i)
        {
          if (i < iface->scount)
            {
              aspeed += iface->stats[i].aspeed;
              ++count;
             }
          else
            {
              break;
            }
        }
    }
  else
    {
      for (i = 0; i!= iface->scount; ++i)
        {
          if (i != iface->snext)
            {
              aspeed += iface->stats[i].aspeed;
              ++count;
            }
        }
    }

  if (count <= 0)
    count = 1;

  return aspeed / count;
}

static void
z_stats_update_prefs(gpointer user_data G_GNUC_UNUSED)
{
  guint32 i, j;
  gdouble aspeeds[Z_LB_IFACE_MAX];
  gdouble default_speeds[Z_LB_IFACE_MAX];

  for (i = 0; i != config.group_num; ++i)
    {
      gdouble aspeed_sum = 0.0;
      guint count = 0;
      gdouble pref_speed_sum = 0.0;
      gdouble *actual_speeds = 0;

      /* Calculate available speeds
       If at least one interface is alive and summary of speeds is zero, use the speed
       specified by the user instead of the calculated 0 (this is: default_speed)
       The interface' status is only checked once because pinger thread may change the value
       before this function finishes
      */
      for (j = 0; j != config.groups[i].iface_num; ++j)
        {
          if (config.groups[i].ifaces[j].status & Z_IFCFG_ALIVE)
           {
             aspeeds[j] = z_stats_update_prefs_iface(config.groups[i].ifaces[j].iface);
             aspeed_sum += aspeeds[j];
             default_speeds[j] = config.groups[i].ifaces[j].iface->speed;
             ++count;
           }
          else
           {
	     aspeeds[j] = 0.0;
             default_speeds[j] = 0.0;
           }
        }

      /* Calculates denominator */
      for (j = 0; j!= config.groups[i].iface_num; ++j)
        {
          pref_speed_sum += ((count && aspeed_sum == 0.0) ? default_speeds[j] : aspeeds[j])
                            * config.groups[i].ifaces[j].real_pref;
        }

      /* If there is an alive interface, actual_speed will be used (simplier code) */
      if (count && aspeed_sum == 0.0)
        actual_speeds = default_speeds;
      else
        actual_speeds = aspeeds;

      if (count && pref_speed_sum)
        for (j = 0; j != config.groups[i].iface_num; ++j)
          {
            gdouble aspeed = 100 *config.groups[i].ifaces[j].real_pref
                             * actual_speeds[j]  / pref_speed_sum;

            /* if aspeed is not zero, it is converted to a non-zero integer */
            z_ifcfg_set_preference(&config.groups[i].ifaces[j], aspeed >= 1.0 ? aspeed : 1);
            z_log(NULL, CORE_DEBUG, 8, "Updated preference: group: '%s', iface: '%s', pref: '%lf'",
	      config.groups[i].name, config.groups[i].ifaces[j].iface->name, aspeed);
          }
      else
        for (j = 0; j != config.groups[i].iface_num; ++j)
          {
            z_ifcfg_set_preference(&config.groups[i].ifaces[j], 0);
            z_log(NULL, CORE_DEBUG, 8, "Updated preference: group: '%s', iface: '%s', pref: '0'",
	      config.groups[i].name, config.groups[i].ifaces[j].iface->name);
          }
    }
}

void
z_stats_update(z_stats_update_cb callback, gpointer user_data)
{
  FILE *f;
  int   line = 0;
  char *ifname;
  char *received;
  char *sent;
  char *pc;

  static char    buffer[1024];
  ZorpAddrInterface *iface;

  f = fopen("/proc/net/dev", "r");
  if (NULL == f)
    {
      z_llog(CORE_ERROR, 2, "Unable to open '/proc/net/dev'");
      return;
    }

  z_shmem_invalidate();
  while (fgets(buffer, 1024, f) != NULL)
    {
      if (++line < 3)
        continue;

      pc = buffer;
      while (' ' == *pc) ++pc;
      ifname = pc;
      while (':' != *pc) ++pc;
      *pc = 0; ++pc;
      z_stats_update_get_string(&pc, &received);
      z_stats_update_skip_string(&pc, 7);
      z_stats_update_get_string(&pc, &sent);

      iface = z_ifcfg_get_iface(ifname);
      if (iface)
        z_stats_update_impl(iface, received, sent);

    }

  fclose(f);
  if (callback)
    (callback)(user_data);
  else
    z_stats_update_prefs(user_data);

  z_shmem_validate();
}
