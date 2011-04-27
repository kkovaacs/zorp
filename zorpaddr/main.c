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

#include <zorp/misc/cfgfile.h>
#include <zorp/process.h>
#include <zorp/log.h>
#include <zorp/zorp.h>
#include <zorp/thread.h>

#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <string.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <signal.h>

#define ZORPADDR_CONFIG_FILE  ZORP_SYSCONFDIR "/zorpaddr.cfg"

gchar *cfgname = ZORPADDR_CONFIG_FILE;

extern gint refresh_rate;

gint term_received = 0;

static GOptionEntry zorpaddr_options[] =
{
  { "config",     'c',                          0, G_OPTION_ARG_STRING,   &cfgname,              "Config file", "<filename>" },
  { NULL,             0,                     0,                   0, NULL,                  NULL, NULL }
};

void
z_sigusr1_handler(int signo G_GNUC_UNUSED)
{
  usr1_received = 1;
}

void
z_sigusr2_handler(int signo G_GNUC_UNUSED)
{
  usr2_received = 1;
}

void
z_sigterm_handler(int signo G_GNUC_UNUSED)
{
  term_received = 1;
}

/**
 * z_zorpaddr_main_loop:
 *
 * Stats update (in shmem) + config reload on SIGUSR1 with ping restart.
 */
static void
z_zorpaddr_main_loop(void)
{
  useconds_t rr = refresh_rate * 100000;
  gboolean ifaces_initialized = FALSE;
  main_loop = g_main_loop_new(NULL, TRUE);

  while (!term_received && g_main_loop_is_running(main_loop))
    {
      g_main_context_iteration(NULL, FALSE);
      if (usr1_received)
        {
          usr1_received = 0;
          if (z_cfg_check(cfgname))
            {
              z_ping_destroy();
              if (!z_cfg_reload())
                {
                  z_log(NULL, CORE_ERROR, 1, "Unable to reload configuration;");
                  break;
                }
              ifaces_initialized = FALSE;
            }
          else
            {
              z_log(NULL, CORE_ERROR, 1, "The new configuration is invalid, cannot be loaded;");
            }
        }
      if (!ifaces_initialized)
        {
          ifaces_initialized = TRUE;
          z_ping_init();
          z_ifcfg_update();    
        }
      z_stats_update(0, 0);
      usleep(rr);
    }
  g_main_loop_unref(main_loop);
}

int main(int argc, char **argv)
{
  const gchar *pid_file = NULL;
  gchar pid_file_buf[128];
  GOptionContext *ctx;
  gboolean foreground = FALSE;
  GError * error = NULL;

  instance_name = "zorpaddr";
  z_process_set_argv_space(argc, argv);
  z_log_set_defaults(3, TRUE, FALSE, NULL);

  ctx = g_option_context_new("zorp");
  z_libzorpll_add_option_groups(ctx, 0);
  g_option_context_add_main_entries(ctx, zorpaddr_options, NULL);
  if (!g_option_context_parse(ctx, &argc, &argv, &error))
    {
      fprintf(stderr, "%s: %s", instance_name, error ? error->message : "Unknown error");
      exit(1);
    }
  g_option_context_free(ctx);

  if (argc > 1)
    {
      fprintf(stderr, "%s: Invalid arguments.\n", instance_name);
      return 1;
    }

  if (!z_log_get_use_syslog())
    foreground = TRUE;

  if (pid_file == NULL)
    {
      g_snprintf(pid_file_buf, sizeof(pid_file_buf), "zorpaddr.pid");
      pid_file = pid_file_buf;
    }

  z_process_set_pidfile_dir(ZORP_PID_FILE_DIR);
  z_process_set_pidfile(pid_file);
  z_process_set_name(instance_name);

  if (foreground)
    z_process_set_mode(Z_PM_FOREGROUND);

  z_process_set_working_dir(ZORP_PID_FILE_DIR);

  /* NOTE: if startup fails, z_process_start() prints an appropriate
   * error to stderr and exits the process */
  z_process_start();

  z_log_init("zorpaddr", ZLF_SYSLOG);

  z_thread_init();

  if (!z_cfg_init(cfgname))
    {
      z_llog(CORE_ERROR, 0, "Unable to load configuration file");
      z_process_startup_failed(1, TRUE);
      exit(1);
    }

  z_ifcfg_init();
  z_ifmon_init();

  error = NULL;
  if (!z_cfg_setup())
    {
      z_llog(CORE_ERROR, 0, "Unable to set up interface configuration");
      z_process_startup_failed(1, TRUE);
      exit(1);
    }

  z_shmem_init();

  signal(SIGUSR1, z_sigusr1_handler),
  signal(SIGUSR2, z_sigusr2_handler),
  signal(SIGTERM, z_sigterm_handler),
  signal(SIGINT, z_sigterm_handler),

  z_process_startup_ok(),
  z_zorpaddr_main_loop();
  z_ping_destroy();

  z_process_finish();

  z_ifmon_destroy();
  z_log_destroy();
  z_shmem_destroy();
  z_cfg_destroy();
  z_thread_destroy();

  return 0;
}
