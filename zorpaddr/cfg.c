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

#include <zorp/misc/cfgparse.h>
#include <zorp/log.h>

#include <string.h>
#include <stdio.h>
#include <stdlib.h>

#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>

#include <netdb.h>

static ZParser *global_parser;
extern ZorpAddrData config;

/* Used at config checking */
static ZParser *new_parser = NULL;

gint refresh_rate = 10;

static ZParserTag taglist[]  =
{
  { "main", "refresh", G_TYPE_INT, TRUE },
  { NULL, "interfaces", G_TYPE_STRING, FALSE },
  { NULL, "speed", G_TYPE_INT, FALSE },
  Z_PARSER_TAG_END,
};

typedef struct _ZCfgOpts
{
  gboolean        has_error;        /* TRUE if an error occured.*/
  gint            iface_count;
  ZorpIfaceData  *iface_data[Z_LB_IFACE_MAX];  /* loaded ifaces */
  guint           pref_sum;                    /* sum of all preferences in the current group */
  gboolean        check_only;                  /* TRUE if config cannot be changed (e.g. at reload) */
  gchar          *iface_names[Z_LB_IFACE_MAX]; /* Must be freed */
} ZCfgOpts;

gboolean
z_cfg_init(const gchar *config_file)
{
  GError * error = NULL;
  g_return_val_if_fail(config_file != NULL, FALSE);

  /* read all configs */
  global_parser = z_parser_new("main", taglist);
  if (!z_parser_read_file(global_parser, config_file, &error))
    {
      z_log(NULL, CORE_ERROR, 1, "Unable to parse configuration file;");
      return FALSE;
    }
  return TRUE;
}

void
z_cfg_destroy(void)
{
  z_parser_unref(global_parser);
}

static gboolean
z_cfg_parse_iface(ZParser *self, const gchar *group, const gchar *iface_str, ZCfgOpts *opts)
{
  gchar         **iface_np;
  ZorpIfaceData  *diface;
  gint            pref = -1;
  gint            speed = 0;
  gint           i;

  if (! *iface_str)
    return TRUE;

  if (opts->has_error)
    return FALSE;

  iface_np = g_strsplit(iface_str, ":", 0);

  if (!iface_np || ! *iface_np || ! **iface_np)
    {
      opts->has_error = TRUE;
      z_log(NULL, CORE_ERROR, 1, "Interface name is not set; group='%s'", group);
      g_strfreev(iface_np);
      return FALSE;
    }

  if (iface_np[1] && *iface_np[1])
    {
      pref = atoi(iface_np[1]);
    }
  else
    {
      z_log(NULL, CORE_ERROR, 1, "Preference is not set; interface='%s', group='%s', pref='%d'",
                                 *iface_np, group, pref);
      opts->has_error = TRUE;
      g_strfreev(iface_np);
      return FALSE;
    }

  if (pref > 100 || pref <= 0)
    {
      z_log(NULL, CORE_ERROR, 1, "Preference (percentage) must be an integer between 1 and 100; "
                                 "interface='%s', group='%s', pref='%d'",
                                 *iface_np, group, pref);
      opts->has_error = TRUE;
      g_strfreev(iface_np);
      return FALSE;
    }

  z_parser_get_int(self, *iface_np, "speed", &speed);

  if (speed <= 0)
    {
      z_log(NULL, CORE_ERROR, 1, "Interface speed must be set and must be above 0 byte per sec; interface='%s' speed='%d'",
                                  *iface_np, speed);
      opts->has_error = TRUE;
      g_strfreev(iface_np);
      return FALSE;
    }

  /* Check for dupliceted interface */
  for (i = 0; i!= opts->iface_count; ++i)
    {
      if (!strcmp(opts->iface_names[i], *iface_np))
        {
          z_log(NULL, CORE_ERROR, 1, "Interface already exists in the group; interface='%s', group='%s'",
                                     *iface_np, group );
          opts->has_error = TRUE;
          return FALSE;
        }
    }

  if (!opts->check_only)
    {
      diface = z_ifcfg_grp_add_iface(group, *iface_np);

      if (!diface)
        return FALSE;

      diface->iface->speed = speed;
      diface->user_pref = pref;

      opts->pref_sum += pref;
      opts->iface_data[opts->iface_count] = diface;
    }

  opts->iface_names[opts->iface_count] = g_strdup(*iface_np);
  ++opts->iface_count;

  g_strfreev(iface_np);

  return TRUE;
}

static void
z_cfg_parse_hosts(ZParser *self, gchar *section, struct in_addr *addresses, int *address_count)
{
  const gchar  *host_list;
  gchar       **hosts;
  gchar       **current_host;

  *address_count = 0;

  if (!z_parser_get_string(self, section, "hosts", &host_list))
    return;

  hosts = g_strsplit(host_list, " ", 0);

  for (current_host = hosts; *current_host; ++current_host)
    {
      struct hostent *h;
      if ((*current_host)[0] == 0)
        continue;

      if (*address_count == Z_I_PING_HOST_MAX)
        {
          z_log(NULL, CORE_ERROR, 2, "Too many ping hosts specified; maximum='%d'", Z_I_PING_HOST_MAX);
          break;
        }

      h = gethostbyname(*current_host);
      if (!h)
        {
          switch (h_errno)
            {
              case HOST_NOT_FOUND:
                z_log(NULL, CORE_INFO, 4, "Error during gethostbyname; host='%s', error='The specified host is unknown'", *current_host);
                break;
              case NO_ADDRESS:
                z_log(NULL, CORE_INFO, 4, "Error during gethostbyname: host='%s', error='The requested name is valid but does not have an IP address.'", *current_host);
                break;
              case NO_RECOVERY:
                z_log(NULL, CORE_INFO, 4, "Error during gethostbyname: host='%s', error='A non-recoverable name server error occurred.'", *current_host);
                break;
              case TRY_AGAIN:
                z_log(NULL, CORE_INFO, 4, "Error during gethostbyname: host='%s', error='A temporary error occurred on an authoritative name server.  Try again later.'", *current_host);
                break;
              default:
                z_log(NULL, CORE_INFO, 4, "Error during gethostbyname: host='%s', error='Unknown error'", *current_host);
                break;
            }
          z_log(NULL, CORE_INFO, 4, "Invalid host sepcified; group='%s', host='%s'", section, *current_host);
          continue;
        }
      addresses[*address_count].s_addr = (*(struct in_addr*)(h->h_addr_list[0])).s_addr;

      if (addresses[*address_count].s_addr)
          ++*address_count;

      z_log(NULL, CORE_INFO, 4, "Added host for pinging; group='%s', hostname='%s', address='%s'",
            section, h->h_name, inet_ntoa(*(struct in_addr*)(h->h_addr_list[0])));
    }
  if (!(*address_count))
    {
      /* FIXME: Jobb megfogalmazas */
      z_log(NULL, CORE_INFO, 4, "No valid IP address found for pingable hosts; group='%s'", section);
      z_log(NULL, CORE_INFO, 4, "All interface are selectable that are in up state; group='%s'", section);
    }
  g_strfreev(hosts);
}

static void
z_cfg_parser_cb(ZParser *self, gchar *section, gpointer user_data)
{
  const gchar *iface_list = NULL;
  gchar **ifaces;
  gchar **current_iface;
  gint i;

  struct in_addr addresses[Z_I_PING_HOST_MAX];
  gint address_count;

  ZorpAddrGroup *group;

  ZCfgOpts *opts = (ZCfgOpts *) user_data;

  if (opts->has_error)
    return;

  if (!z_parser_get_string(self, section, "interfaces", &iface_list))
    {
      opts->has_error = TRUE;
      z_log(NULL, CORE_ERROR, 1, "Unable to get interface list; group='%s'", section);
      return;
    }
  if (!iface_list || ! *iface_list)
    {
      opts->has_error = TRUE;
      z_log(NULL, CORE_ERROR, 1, "Interface list is empty; group='%s'", section);
      return;
    }

  z_cfg_parse_hosts(self, section, addresses, &address_count);
  opts->iface_count = 0;
  opts->pref_sum = 0;
  memset(opts->iface_names, 0, sizeof(opts->iface_names));

  ifaces = g_strsplit(iface_list, " ", 0);

  for (current_iface = ifaces; *current_iface; ++current_iface)
    {
      if (!z_cfg_parse_iface(self, section, *current_iface, opts))
        break;
    }

  if (!opts->pref_sum)
    opts->pref_sum = 100;

  if (!opts->check_only)
    {
      double norm = 100.0 / opts->pref_sum;

      /* normalize the preference values */
      for (i = 0; i != opts->iface_count; ++i)
        opts->iface_data[i]->user_pref *= norm;
    }

  g_strfreev(ifaces);

  for (i = 0; i!= opts->iface_count; ++i)
    g_free(opts->iface_names[i]);

  if (G_UNLIKELY(!opts->iface_count))
    {
      opts->has_error = TRUE;
      z_log(NULL, CORE_ERROR, 1, "Interface list is empty; group='%s'", section);
      return;
    }

  if (!opts->check_only)
    {
      group = &config.groups[opts->iface_data[0]->group];
      group->host_num = address_count;
      memcpy(group->hosts, addresses, sizeof(addresses));
    }
}

static gboolean
z_cfg_setup_impl(ZParser *self, gboolean check)
{
  ZCfgOpts cb_opts;
  memset(&cb_opts, 0, sizeof(ZCfgOpts));

  cb_opts.check_only = check;

  if (check && z_parser_get_int(self, "main", "refresh", &refresh_rate))
    {
      if (refresh_rate <= 0)
        refresh_rate  = 10;
      if (refresh_rate > 30)
        refresh_rate = 30;
    }

  z_parser_foreach_type(self, "group", z_cfg_parser_cb, &cb_opts);

  if (cb_opts.has_error)
    return FALSE;

  if (!check)
    config.valid = TRUE;

  return TRUE;
}

gboolean
z_cfg_check(const gchar *config_file)
{
  GError *error = NULL;
  g_return_val_if_fail(config_file != NULL, FALSE);

  /* read all configs */
  new_parser = z_parser_new("main", taglist);
  if (!z_parser_read_file(new_parser, config_file, &error))
    {
      z_log(NULL, CORE_ERROR, 1, "Unable to read configuration file; reason='%s'",
                  error ? error->message : "Unknown");
      if (new_parser)
        z_parser_destroy(new_parser);
      return FALSE;
    }
  return z_cfg_setup_impl(new_parser, TRUE);
}

gboolean
z_cfg_setup(void)
{
  return z_cfg_setup_impl(global_parser, FALSE);
}

/**
 * z_cfg_reload:
 * @config_file: The configuration file to be loaded
 *
 * Reloads everything. First z_cfg_check() must be called, if it is
 * successful, new_parser global variable is not null, also reload
 * can be completed.
 *
 * The old configruration can be destroyed except the interfaces with
 * their statistics in file ifcfg.c, which must be preserved until reload
 * finishes.
 *
 * The order of module reloading is:
 *  - interface configuration (for preserving old data and indicating reload start)
 *  - main configuration
 *  - shared memory
 *  - finishing interface configuration (to destroy remaining old data)
 * At this point the statistics updating uses the new date also it is independent from
 * reloading
 *
 * Returns: TRUE if successfully reloaded, FALSE otherwise
 *
 */
gboolean
z_cfg_reload(void)
{
  if (!new_parser)
    {
      z_log(NULL, CORE_ERROR, 1, "New configuration is not loaded;");
      return FALSE;
    }

  z_ifcfg_reload_start();
  global_parser = new_parser;
  new_parser = NULL;

  memset(&config, 0, sizeof(config));
  /* NOTE: may skip z_ifcfg_reload_finish() */
  if (z_cfg_setup() == FALSE)
    return FALSE;

  z_shmem_reload();
  z_shmem_validate();

  z_ifcfg_reload_finish(TRUE);

  z_ifcfg_update_all_group_preferences();

  return TRUE;
}
