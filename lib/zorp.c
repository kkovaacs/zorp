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
 * $Id: zorp.c,v 1.15 2004/07/05 07:59:55 bazsi Exp $
 *
 * Author  : Bazsi
 * Auditor :
 * Last audited version:
 * Notes:
 *
 ***************************************************************************/

#include <zorp/zorp.h>
#include <zorp/log.h>


#include <zorp/zpython.h>
#include <zorp/policy.h>
#include <zorp/szig.h>
#include <zorp/notification.h>
#include <zorp/pyaudit.h>

#include <zorp/blob.h>
#include <zorp/process.h>



GMainLoop *main_loop;
gint exit_code = 0;
guint32 startup_id;
const gchar *instance_name;

/* FIXME: the code in this module was straightly copied from main.c and as
 * such does not really fit into a library. Some generalization would be
 * appropriate. */

gboolean usr1_received = 0;
gboolean usr2_received = 0;
static gboolean term_received = 0;


static gboolean hup_received = 0;
static gboolean reload_result = FALSE;

/**
 * NOTE: this must either be called from a signal handler (in which case
 * called_from_sighandler must be TRUE, or from a non-main thread as it tries to
 * communicate via the main thread using a condition variable.
 **/
void
z_main_loop_initiate_reload(gboolean called_from_sighandler)
{
  hup_received = TRUE;
  if (!called_from_sighandler)
    {
      g_main_context_wakeup(NULL);
    }
}

gboolean
z_main_loop_get_last_reload_result(void)
{
  return reload_result;
}

void
z_main_loop_initiate_termination(gboolean called_from_sighandler)
{
  term_received = TRUE;
  if (!called_from_sighandler)
    g_main_context_wakeup(NULL);
}

void
z_read_global_params(ZPolicy *policy)
{
  z_policy_acquire_main(policy);

  z_policy_var_parse_str(z_global_getattr("config.blob.temp_directory"), (gchar **) &z_blob_system_default_tmpdir);
  z_policy_var_parse_int64(z_global_getattr("config.blob.max_disk_usage"), &z_blob_system_default_max_disk_usage);
  z_policy_var_parse_size(z_global_getattr("config.blob.max_mem_usage"), &z_blob_system_default_max_mem_usage);
  z_policy_var_parse_size(z_global_getattr("config.blob.lowat"), &z_blob_system_default_lowat);
  z_policy_var_parse_size(z_global_getattr("config.blob.hiwat"), &z_blob_system_default_hiwat);
  z_policy_var_parse_size(z_global_getattr("config.blob.noswap_max"), &z_blob_system_default_noswap_max);
  z_policy_release_main(policy);
}

gboolean
z_load_policy(const gchar *policy_file, gchar const **instance_policy_list)
{
  ZPolicy *policy;
  ZPolicy *old_policy;

  policy = z_policy_new(policy_file);
  if (!z_policy_boot(policy) || !z_policy_load(policy))
    {
      /*LOG
	This message indicates that Zorp was unable to load the policy.
	It is likely that the policy has any kind of syntactical problem.
	Check the traceback in the log to find out where the problem occurs.
       */
      z_log(NULL, CORE_ERROR, 0, "Error booting & parsing policy;");
      z_policy_deinit(policy, instance_policy_list);
      z_policy_unref(policy);
      return FALSE;
    }
  old_policy = current_policy;
  current_policy = policy;
  if (!z_policy_init(policy, instance_policy_list))
    {
      /* FIXME: deinit bad new configuration */
      current_policy = old_policy;
      z_policy_deinit(policy, instance_policy_list);
      z_policy_unref(policy);
      /*LOG
	This message indicates that Zorp was unable to initialize the policy.
       */
      z_log(NULL, CORE_ERROR, 0, "Error initializing policy;");
      return FALSE;
    }
  else if (old_policy != NULL)
    {
      /* FIXME: deinit old configuration */
      z_policy_deinit(old_policy, instance_policy_list);
      z_policy_unref(old_policy);
    }
  return TRUE;
}

static void
z_generate_policy_load_event(const gchar *policy_file, gboolean reload_result)
{
  struct stat st;
  time_t policy_stamp;

  if (reload_result)
    {
      if (stat(policy_file, &st) < 0)
        policy_stamp = (time_t) -1;
      else
        policy_stamp = st.st_mtime;

      z_szig_event(Z_SZIG_RELOAD, 
           z_szig_value_new_props("policy", 
                                  "file", z_szig_value_new_string(policy_file), 
                                  "file_stamp", z_szig_value_new_long(policy_stamp), 
                                  "reload_stamp", z_szig_value_new_long(time(NULL)), 
                                  NULL));
    }
}

void
z_main_loop(const gchar *policy_file, const gchar *instance_name, gchar const **instance_policy_list)
{
  gint new_verbosity;
  
  if (!z_load_policy(policy_file, instance_policy_list))
    {
      /*LOG
	This message indicates that the loading of the initial policy failed, because of some policy problem.
	Check the log to find out where the problem occurs.
       */
      z_log(NULL, CORE_ERROR, 0, "Error loading initial policy, exiting;");
      /* hack to let our messages get out */
      sleep(1);
      exit_code = 2;
      return;
    }
  /* signal successful start */
  z_process_startup_ok();
  
  /* z_process_startup_ok() closes the inherited stderr, we need to open our
   * own to see messages written to stderr */
  
  if (z_log_get_use_syslog())
    z_log_enable_stderr_redirect(TRUE);

  if (term_received)
    z_main_loop_quit(0);
    
  z_read_global_params(current_policy);
  z_blob_system_default_init();

  z_generate_policy_load_event(policy_file, TRUE);

  while (g_main_loop_is_running(main_loop))
    {
      g_main_context_iteration(NULL, TRUE);

      if (usr1_received)
        {
          usr1_received = 0;
          z_log_change_verbose_level(1, 1, &new_verbosity);
          z_mem_trace_stats();
        }
      if (usr2_received)
        {
          usr2_received = 0;
          z_log_change_verbose_level(-1, 1, &new_verbosity);
        }
      if (hup_received)
	{
	  /*LOG
	    This message reports that Zorp caught a HUP signal and tries to reload its policy.
	   */
	  z_log(NULL, CORE_INFO, 0, "Reloading policy; policy_file='%s', instance_name='%s'", policy_file, instance_name);
	  if (!z_load_policy(policy_file, instance_policy_list))
	    {
	      /*LOG
		This message indicates that Zorp was unable to load the new policy, and reverts to the old one.
		Check the logs to find out where the error occurs in the new policy.
	       */
	      z_log(NULL, CORE_ERROR, 0, "Error reloading policy, reverting to old;");
	      reload_result = FALSE;
	    }
          else
            {
              reload_result = TRUE;
            }
	  hup_received = 0;
	  z_generate_policy_load_event(policy_file, reload_result);
	}
      if (term_received)
        {
          z_main_loop_quit(0);
          break;
        }
    }


  z_policy_cleanup(current_policy, instance_policy_list);

  z_blob_system_default_destroy();
}

/**
 * z_main_loop_quit:
 * @rc exit code
 *
 * Set the exit code to the specified value and tell glib to exit the main loop
 */
void
z_main_loop_quit(int rc)
{
  z_enter();
  exit_code = rc;
  g_main_quit(main_loop);
  z_return();
}

void
z_main_loop_init(void)
{
  main_loop = g_main_loop_new(NULL, TRUE);
}

void
z_main_loop_destroy(void)
{
  if (main_loop)
    {
      g_main_loop_unref(main_loop);
      main_loop = NULL;
    }
}
