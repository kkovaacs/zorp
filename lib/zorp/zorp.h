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

#ifndef ZORP_H_INCLUDED
#define ZORP_H_INCLUDED

#ifdef _XOPEN_SOURCE
#undef _XOPEN_SOURCE
#endif

#ifdef _POSIX_C_SOURCE
#undef _POSIX_C_SOURCE
#endif

#include <Python.h>
#include <zorp/zorplibconfig.h>
#include <zorpconfig.h>
#include <glib.h>
#include <zorp/misc.h>
#include <zorp/memtrace.h>


#define ZORP_POLICY_FILE	ZORP_SYSCONFDIR "/policy.py"
#define ZORP_POLICY_BOOT_FILE	ZORP_DATADIR "/policy.boot"
#define ZORP_AUTH_CERT_FILE	ZORP_SYSCONFDIR "/zorp.crt"
#define ZORP_AUTH_KEY_FILE	ZORP_SYSCONFDIR "/zorp.key"
#define ZORP_STATE_DIR          ZORP_STATEDIR
#define ZORP_PID_FILE_DIR       ZORP_PIDFILEDIR
#define ZORP_SZIG_SOCKET_NAME      ZORP_PID_FILE_DIR "zorpctl"

#define MAX_SESSION_ID		128
#define DEADLOCK_CHECKER_DEFAULT_TIMEOUT  60

#define CORE_POLICY    "core.policy"
#define CORE_AUDIT     "core.audit"
#define CORE_VIOLATION "core.violation"

#if SIZEOF_VOID_P == 4
#   define G_GPOINTER_FORMAT "08" G_GSIZE_MODIFIER "x"
#elif SIZEOF_VOID_P == 8
#   define G_GPOINTER_FORMAT "016" G_GSIZE_MODIFIER "x"
#else
#   error "Can't find suitable printf format for pointers"
#endif

extern GMainLoop *main_loop;
extern gint exit_code;
extern gboolean usr1_received;
extern gboolean usr2_received;
extern guint32 startup_id;
extern const gchar *instance_name;


void z_main_loop_initiate_reload(gboolean called_from_sighandler);
gboolean z_main_loop_get_last_reload_result(void);

void z_main_loop_initiate_termination(gboolean called_from_sighandler);

void z_main_loop(const gchar *policy_file, const gchar *instance_name, gchar const **instance_policy_list);
void z_main_loop_quit(int exit_code);
void z_main_loop_init(void);
void z_main_loop_destroy(void);

void z_log_set_fake_session_id(const gchar *instance_name G_GNUC_UNUSED);

#if GLIB_MINOR_VERSION < 8
# define G_GNUC_NULL_TERMINATED
#endif

#if GLIB_MINOR_VERSION < 10
# define G_GNUC_WARN_UNUSED_RESULT
#endif

#endif
