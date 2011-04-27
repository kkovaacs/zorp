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
 * $Id: main.c,v 1.27 2004/07/01 16:55:25 bazsi Exp $
 *
 * Author  : bazsi
 * Auditor : 
 * Last version : 
 * Notes   :
 *
 ***************************************************************************/
#include "zorpctl.h"
#include "szig.h"

#include <sys/types.h>
#include <sys/time.h>
#include <sys/resource.h>
#include <signal.h>

#include <time.h>
#include <wait.h>
#include <syslog.h>
#include <stdio.h>
#include <unistd.h>
#include <stdlib.h>
#include <string.h>
#include <ctype.h>
#include <fcntl.h>
#include <stdarg.h>
#include <errno.h>
#include <sys/stat.h>
#include <glib.h>

#include <grp.h>
#include <pwd.h>

#include <zorp/misc.h>

#define ZORP ZORP_LIBDIR    "/zorp"

#if 1
#define ZORP_INSTANCES_CONF ZORP_SYSCONFDIR "/instances.conf"
#define ZORP_ZORPCTL_CONF   ZORP_SYSCONFDIR "/zorpctl.conf"
#else
#define ZORP_INSTANCES_CONF  "instances.conf"
#define ZORP_ZORPCTL_CONF    "zorpctl.conf"
#endif

#define UNUSED __attribute__((unused))

#define MAX_ZORPCTL_LINE_LENGTH 4096

#ifndef MAX
#  define MAX(a,b) ((a) < (b) ? (b) : (a))
#endif

/* Refer a string or the constant "(null)" if it's NULL
 * This is the default behaviour on Linux when printf()ing NULL, but on Solaris
 * it triggers a SIGSEGV
 */
#define SAFE_STR(n) ((n) ? (n) : "(null)")
#define SAFE_STR_EMPTY(n) ((n) ? (n) : "")

/* Currently the only flag for z_process_status_instance() */
#define ZORPCTL_STATUS_VERBOSE  1

typedef struct _ZInstance ZInstance;

struct _ZInstance
{
  ZInstance *next;
  char *name;
  char **zorp_argv;
  int zorp_argc;
  char **zorpctl_argv;
  int zorpctl_argc;
  
  int auto_restart;
  int process_limit;
  int enable_core;
  int no_auto_start;
};

typedef struct _ZCommand ZCommand;
struct _ZCommand
{
  char *cmd;
  int (*func)(int argc, char *argv[]);
  char *help;
};

ZInstance *instances;
extern ZCommand commands[];

typedef struct
{
    int pid;                    /* %d The process id.*/
    char comm[4096];            /* %s The filename of the executable, in parentheses. */
    char state;                 /* %c R=running, S=sleeping, D=disk sleep, Z=zombie, T=traced/stopped, W=paging. */
    int ppid;                   /* %d The PID of the parent. */
    int pgrp;                   /* %d The process group ID of the process. */
    int session;                /* %d The session ID of the process. */
    int tty_nr;                 /* %d The tty the process uses. */
    int tpgid;                  /* %d The process group ID of the process which currently owns the tty that the process is connected to. */
    unsigned long flags;        /* %lu The kernel flags word of the process. For bit meanings, see the PF_* defines in <linux/sched.h>. */
    unsigned long minflt;       /* %lu The number of minor faults the process has made which have not required loading a memory page from disk. */
    unsigned long cminflt;      /* %lu The number of minor faults that the process's waited-for children have made. */
    unsigned long majflt;       /* %lu The number of major faults the process has made which have required loading a memory page from disk. */
    unsigned long cmajflt;      /* %lu The number of major faults that the process's waited-for children have made. */
    unsigned long utime;        /* %lu The number of jiffies that this process has been scheduled in user mode. */
    unsigned long stime;        /* %lu The number of jiffies that this process has been scheduled in kernel mode. */
    long cutime;                /* %ld The number of jiffies that this process's waited-for children have been scheduled in user mode. (See also times(2).) */
    long cstime;                /* %ld The number of jiffies that this process's waited-for children have been scheduled in kernel mode. */
    long priority;              /* %ld The standard nice value, plus fifteen.  The value is never negative in the kernel. */
    long nice;                  /* %ld The nice value ranges from 19 (nicest) to -19 (not nice to others). */
    long _dummyzero;            /* %ld  This value is hard coded to 0 as a placeholder for a removed field. */
    long itrealvalue;           /* %ld The time in jiffies before the next SIGALRM is sent to the process due to an interval timer. */
    unsigned long starttime;    /* %lu The time in jiffies the process started after system boot. */
    unsigned long vsize;        /* %lu Virtual memory size in bytes. */
    long rss;                   /* %ld Resident Set Size: number of pages the process has in real memory, minus 3 for administrative purposes. */
    unsigned long rlim;         /* %lu Current limit in bytes on the rss of the process (usually 4294967295 on i386). */
    unsigned long startcode;    /* %lu The address above which program text can run. */
    unsigned long endcode;      /* %lu The address below which program text can run. */
    unsigned long startstack;   /* %lu The address of the start of the stack. */
    unsigned long kstkesp;      /* %lu The current value of esp (stack pointer), as found in the kernel stack page for the process. */
    unsigned long kstkeip;      /* %lu The current EIP (instruction pointer). */
    unsigned long signal;       /* %lu The bitmap of pending signals (usually 0). */
    unsigned long blocked;      /* %lu The bitmap of blocked signals (usually 0, 2 for shells). */
    unsigned long sigignore;    /* %lu The bitmap of ignored signals. */
    unsigned long sigcatch;     /* %lu The bitmap of catched signals. */
    unsigned long wchan;        /* %lu This is the "channel" in which the process is waiting. */
    unsigned long nswap;        /* %lu Number of pages swapped - not maintained. */
    unsigned long cnswap;       /* %lu Cumulative nswap for child processes. */
    int exit_signal;            /* %d Signal to be sent to parent when we die. */
    int processor;              /* %d CPU number last executed on. */
} ZProcInfo;

int
z_get_jiffies_per_sec(void)
{
  static int jiffies_per_sec = -1;
  FILE *f;
  char buf[1024], *p;
  double idle_jiffies = 0, idle_sec = 0;
  int i;

  if (jiffies_per_sec > 0)
    return jiffies_per_sec; /* speedup by calculating only once */
  
  f = fopen("/proc/stat", "r");
  if (!f)
    return 0;
  while (fgets(buf, 1023, f))
    {
      buf[1023] = '\0';
      if (!strncmp("cpu ", buf, 4))
        {
          p = buf;
          for (i = 0; *p && (i < 4); i++)
            {
              while (*p && (*p != ' '))
                p++; /* skip non-whsp */
              while (*p && (*p == ' '))
                p++; /* skip whsp */
            }
          if ((i != 4) || !*p)
            break;

          idle_jiffies = atof(p);
          break;
        }
    }
  fclose(f);
  if (idle_jiffies <= 0)
    return 0;

  f = fopen("/proc/uptime", "r");
  if (!f || !fgets(buf, 1023, f))
    return 0;
  buf[1023] = '\0';
  p = buf;
  while (*p && (*p != ' '))
    p++; /* skip non-whsp */
  while (*p && (*p == ' '))
    p++; /* skip whsp */
  if (*p)
    idle_sec = atof(p);
  fclose(f);
  if (idle_sec <= 0)
    return 0;

  jiffies_per_sec = (int)((5 + (idle_jiffies / idle_sec)) / 10)*10;
  return jiffies_per_sec;
}

unsigned long
z_get_uptime(void)
{
  FILE *f;
  unsigned long i = 0;

  f = fopen("/proc/uptime", "r");
  if (f)
    {
      /* Fancy call to fscanf to avoid unused return value warning. */
      if (fscanf(f, "%lu", &i)) { };
      fclose(f);
    }
  return i;
}

int
z_get_proc_info(int pid, ZProcInfo *pi)
{
  FILE *f;
  char filename[64];
  int fieldnum;

  if ((pid <= 0) || !pi)
    return -1;
  
  sprintf(filename, "/proc/%d/stat", pid);
  f = fopen(filename, "r");
  if (!f)
    return -2;

  fieldnum = fscanf(f, "%d %s %c %d %d %d %d %d %lu %lu %lu %lu %lu %lu %lu "
                    "%ld %ld %ld %ld %ld %ld %lu %lu %ld %lu %lu %lu %lu %lu "
                    "%lu %lu %lu %lu %lu %lu %lu %lu %d %d",
                    &pi->pid, pi->comm, &pi->state, &pi->ppid, &pi->pgrp,
                    &pi->session, &pi->tty_nr, &pi->tpgid, &pi->flags,
                    &pi->minflt, &pi->cminflt, &pi->majflt, &pi->cmajflt,
                    &pi->utime, &pi->stime, &pi->cutime, &pi->cstime,
                    &pi->priority, &pi->nice, &pi->_dummyzero, &pi->itrealvalue,
                    &pi->starttime, &pi->vsize, &pi->rss, &pi->rlim,
                    &pi->startcode, &pi->endcode, &pi->startstack, &pi->kstkesp,
                    &pi->kstkeip, &pi->signal, &pi->blocked, &pi->sigignore,
                    &pi->sigcatch, &pi->wchan, &pi->nswap, &pi->cnswap,
                    &pi->exit_signal, &pi->processor);
  fclose(f);
  return (fieldnum != 39); /* 0 on success */
}


static int auto_restart = 1;
static int start_wait_timeout = 10;
static double stop_check_delay = 0.1;
static int stop_check_timeout = 5;
static int process_limit_reserve = 64;
static int process_limit_threshold = -1;
static int process_limit_min = 256;
static int process_limit_sum = 0;
static int check_perms = 1;
static char *zorp_append_args = NULL;
static char *zorpctl_append_args = NULL;
static char *pidfile_dir = ZORP_PIDFILEDIR, *pidfile_dir_owner = NULL, *pidfile_dir_group = NULL, *pidfile_dir_perm = NULL;
static char *config_dir = ZORP_SYSCONFDIR, *config_dir_owner = "root", *config_dir_group = "zorp", *config_dir_perm = "0750";
static char delayed_errors[16384];
static int sigalarm_received = 0;

/* obsolete config variables */
static int start_check_timeout = -1;
static int auto_restart_time_threshold = -1; /* obsolete */
static int auto_restart_max_count = -1;       /* obsolete */
static double auto_restart_delay = -1.0;         /* obsolete */

static inline void
chomp(char *line)
{
  int len = strlen(line);
  
  if (line[len-1] == '\n')
    line[len-1] = 0;
}

static inline char *
strduplen(char *line, int len)
{
  char *res;
  res = malloc(len + 1);
  strncpy(res, line, len+1);
  res[len] = 0;
  return res;
}

/**
 * csvescape:
 * @input: string to add escaping to
 * @buf: result buffer
 *
 * Escapes ; and \ characters to provide a proper CSV output
 * escaping various characters.
 **/
static gchar *
csvescape(const gchar *input, gchar **buf)
{
  const guchar *src;
  GString *dst;

  dst = g_string_sized_new(32);
  for (src = (guchar *)input; *src; src++)
    {
      if (*src == ';' || *src == '\\')
        {
          g_string_append_printf(dst, "\\%c", *src);
        }
      else
        {
          g_string_append_c(dst, *src);
        }
    }

  *buf = dst->str;
  return g_string_free(dst, FALSE);
}

static void
z_sigalarm_handler(int signo UNUSED)
{
  sigalarm_received = 1;
  signal(SIGALRM, z_sigalarm_handler);
}

static inline void
z_alarm_request(int seconds)
{
  sigalarm_received = 0;
  alarm(seconds);
}

static inline int
z_alarm_fired(void)
{
  return sigalarm_received;
}

static inline void
z_setup_signals(void)
{
  siginterrupt(SIGALRM, 1);
  signal(SIGALRM, z_sigalarm_handler);
}

static void
z_error(int delay, const char *format, ...)
{
  char buf[1024];
  va_list args;
  
  va_start(args, format);
  if (delay)
    {
      gsize len = vsnprintf(buf, sizeof(buf), format, args) + 1;
      strncat(delayed_errors, buf, sizeof(delayed_errors) - strlen(delayed_errors) - len - 1);
    }
  else
    {
      vfprintf(stderr, format, args);
    }
  va_end(args);
}

static void
z_dump_errors(void)
{
  if (delayed_errors[0])
    {
      fprintf(stderr, "\nThe following errors occurred so far:\n%s\n", delayed_errors);
      delayed_errors[0] = 0;
    }
}

static int
z_instance_running(ZInstance *inst, pid_t *pid, int *stale)
{
  FILE *pidfile;
  char buf[256];
  
  *stale = 0;
  snprintf(buf, sizeof(buf), "%s/zorp-%s.pid", pidfile_dir, inst->name);
  pidfile = fopen(buf, "r");
  if (!pidfile)
    {
      return 0;
    }
  
  if (!fgets(buf, sizeof(buf), pidfile))
    {
      fclose(pidfile);
      *stale = 1;
      return 0;
    }
  *pid = atoi(buf);
  fclose(pidfile);
  if (!(*pid))
    {
      /* invalid pid, pid 0 */
      *stale = 1;
      return 0;
    }
  if (kill(*pid, SIGCONT) == 0)
    {
      /* still running */
      return 1;
    }
  /* stale pidfile */
  *stale = 1;
  return 0;
}

static void 
z_instance_remove_stale_pidfile(ZInstance *inst)
{
  char buf[256];
  
  snprintf(buf, sizeof(buf), "%s/zorp-%s.pid", pidfile_dir, inst->name);
  unlink(buf);
}

static void
z_instance_free(ZInstance *inst)
{
  free(inst->name);
  if (inst->zorp_argv)
    free(inst->zorp_argv);
  if (inst->zorpctl_argv)
    free(inst->zorpctl_argv);
  free(inst);
}

static int
z_check_instance_name(char *name)
{
  int i;
  for (i = 0; name[i]; i++)
    {
      if (!isalnum(name[i]) && name[i] != '_')
        return 0;
    }
  return isalpha(name[0]);
}

static int
z_check_dir(char *dir, char *owner, char *group, char *perm, int create)
{
  struct passwd *pw = getpwnam(owner);
  struct group *gr = group ? getgrnam(group) : NULL;
  uid_t uid = -1;
  gid_t gid = -1;
  mode_t mode = perm ? strtol(perm, NULL, 8) : 0700;
  struct stat st;
  
  if (pw)
    uid = pw->pw_uid;
  if (gr)
    gid = gr->gr_gid;
  if (gid == (gid_t) -1 && pw)
    gid = pw->pw_gid;
  
  if (uid == (gid_t) -1 || gid == (gid_t) -1)
    {
      z_error(0, "Owner/group not found, owner='%s', group='%s'\n", 
                 SAFE_STR(owner), SAFE_STR(group));
      return 0;
    }
  if (stat(dir, &st) < 0)
    {
      if (create)
        {
          if ((mkdir(dir, mode) >= 0) && (chown(dir, uid, gid) >= 0) && (chmod(dir, mode) >= 0))
            return 1;
          z_error(0, "Error creating directory, dir='%s', uid='%d', gid='%d', mode='%o', error='%s'\n", dir, uid, gid, perm, strerror(errno));
        }
      return 0;
    }
  if (owner && st.st_uid != uid)
    return 0;
  if (group && st.st_gid != gid)
    return 0;
  if (perm && ((st.st_mode & 07777) != mode))
    return 0;
  return 1;
}

static void
z_check_pidfile_dir(void)
{
  if (pidfile_dir_owner || pidfile_dir_group || pidfile_dir_perm)
    {
      z_check_dir(pidfile_dir, pidfile_dir_owner, pidfile_dir_group, pidfile_dir_perm, 1);
    }
}

static int
z_check_config_dir(void)
{
  if (check_perms)
    {
      if (!z_check_dir(config_dir, config_dir_owner, config_dir_group, config_dir_perm, 0))
        {
          z_error(0, "Config directory has invalid permissions, expected: dir='%s', owner='%s', group='%s', perm='%s'\n", config_dir, SAFE_STR(config_dir_owner), SAFE_STR(config_dir_group), SAFE_STR(config_dir_perm));
          return 0;
        }
    }
  return 1;
}

static int
z_parse_args(ZInstance *inst, char *zorp_args, char *zorpctl_args)
{
  static int process_limit = 0;
  static int no_auto_start = 0, enable_core = 0;
  static GOptionEntry zorpctl_options[] =
    {
        { "auto-restart", 'A', 0, G_OPTION_ARG_NONE, &auto_restart, NULL, NULL },
        { "no-auto-restart", 'a', G_OPTION_FLAG_REVERSE, G_OPTION_ARG_NONE, &auto_restart, NULL, NULL },
        { "no-auto-start", 'S', 0, G_OPTION_ARG_NONE, &no_auto_start, NULL, NULL },
        { "process-limit", 'p', 0, G_OPTION_ARG_INT, &process_limit, NULL, NULL },
        { "enable-core", 'c', 0, G_OPTION_ARG_NONE, &enable_core, NULL, NULL },
        { NULL, 0, 0, 0, NULL, NULL, NULL }
    };
  static int threads = 1000;
  static GOptionEntry zorp_options[] =
    {
        { "threads", 't', 0, G_OPTION_ARG_INT, &threads, NULL, NULL },
        { NULL, 0, 0, 0, NULL, NULL, NULL }
    };
  int res = 0;
  char *buf = NULL;
  GOptionContext *ctx = NULL;
  
  IGNORE_UNUSED_RESULT(asprintf(&buf, "%s --as %s %s %s", ZORP, inst->name, zorp_args, SAFE_STR_EMPTY(zorp_append_args)));
  if (!g_shell_parse_argv(buf,  &inst->zorp_argc, &inst->zorp_argv, NULL))
    {
      z_error(1, "Invalid zorp argument list: %s\n", zorp_args);
      goto finish;
    }
  g_free(buf);

  IGNORE_UNUSED_RESULT(asprintf(&buf, "zorpctl %s %s", SAFE_STR_EMPTY(zorpctl_args), SAFE_STR_EMPTY(zorpctl_append_args)));
  if (!g_shell_parse_argv(buf,  &inst->zorpctl_argc, &inst->zorpctl_argv, NULL))
    {
      z_error(1, "Invalid zorpctl argument list: %s\n", zorpctl_args);
      goto finish;
    }
  g_free(buf);
  buf = NULL;

  if (inst->zorp_argv)
    {
      ctx = g_option_context_new(NULL);
      g_option_context_add_main_entries(ctx, zorp_options, NULL);
      g_option_context_set_ignore_unknown_options(ctx, TRUE);
      g_option_context_set_help_enabled(ctx, FALSE);
      if (!g_option_context_parse(ctx, &inst->zorp_argc, &inst->zorp_argv, NULL))
        goto finish;

      g_option_context_free(ctx);      

      /* NOTE: we need to reconstruct the command line as
       * g_option_context_parse() removes parsed entries, such as --threads
       *
       * FIXME: this leaks memory.
       * */
      
      IGNORE_UNUSED_RESULT(asprintf(&buf, "%s --as %s %s %s", ZORP, inst->name, zorp_args, SAFE_STR_EMPTY(zorp_append_args)));
      if (!g_shell_parse_argv(buf,  &inst->zorp_argc, &inst->zorp_argv, NULL))
        {
          z_error(1, "Invalid zorp argument list: %s\n", zorp_args);
          goto finish;
        }
      g_free(buf);
      buf = NULL;

      ctx = NULL;
      process_limit_sum += threads + 5;
    }
    
  inst->auto_restart = auto_restart;
  inst->process_limit = process_limit = MAX(process_limit_min, threads + 5);
    
  inst->process_limit = MAX(process_limit_min, threads + 5);
 
  if (inst->zorpctl_argv)
    {
      ctx = g_option_context_new(NULL);
      g_option_context_add_main_entries(ctx, zorpctl_options, NULL);
      g_option_context_set_ignore_unknown_options(ctx, TRUE);
      g_option_context_set_help_enabled(ctx, FALSE);
      if (!g_option_context_parse(ctx, &inst->zorpctl_argc, &inst->zorpctl_argv, NULL))
        goto finish;

      g_option_context_free(ctx);
      ctx = NULL;
      inst->auto_restart = auto_restart;
      inst->process_limit = process_limit;
      inst->no_auto_start = no_auto_start;
      inst->enable_core = enable_core;

      if (inst->zorpctl_argc > 1)
        {
          z_error(1, "Junk found at the end of the arg list: %s\n", inst->zorpctl_argv[1]);
          goto finish;
        }
    }
  res = 1;

finish:
  if (buf)
    g_free(buf);
  if (ctx)
    g_option_context_free(ctx);
  return res;
}

static int
z_parse_instances(void)
{
  FILE *instf;
  char line[MAX_ZORPCTL_LINE_LENGTH];
  ZInstance *inst, **last = &instances;
  int len, i;
  char *dashdash, *zorp_args, *zorpctl_args;

  instances = NULL;  
  instf = fopen(ZORP_INSTANCES_CONF, "r");
  if (!instf)
    {
      /*LOG
       *This message indicates that Zorp was unable to open the instances file.
       *Check the permissions of your instances file.
       */
      z_error(1, "Error opening instances file: %s\n", ZORP_INSTANCES_CONF);
      return 0;
    }
  while (fgets(line, sizeof(line), instf))
    {
      chomp(line);
      if (line[0] == 0 || line[0] == '#')
        continue;
      len = strlen(line);
      inst = calloc(sizeof(ZInstance), 1);
      i = 0;
      while (i < len && !isspace(line[i]))
        i++;
      inst->name = strduplen(line, i);
      if (!z_check_instance_name(inst->name))
        {
          z_error(1, "Invalid instance name: %s\n", inst->name);
          z_instance_free(inst);
          return 0;
        }
      while (i < len && isspace(line[i]))
        i++;
      dashdash = strstr(&line[i], " -- ");
      if (dashdash)
        {
          zorp_args = strduplen(&line[i], dashdash - &line[i]);
          zorpctl_args = strdup(dashdash + 4);
        }
      else
        {
          zorp_args = strdup(&line[i]);
          zorpctl_args = NULL;
        }
      
      if (!z_parse_args(inst, zorp_args, zorpctl_args))
        {
          z_error(1, "Invalid argument list at instance: %s\n", inst->name);
          z_instance_free(inst);
          return 0;
        }
      free(zorp_args);
      free(zorpctl_args);
      
      inst->next = *last;
      *last = inst;
      last = &inst->next;
    }
  return 1;
}

static ZInstance *
z_search_instance(char *name)
{
  ZInstance *p;
  for (p = instances; p; p = p->next)
    {
      if (strcmp(name, p->name) == 0)
        return p;
    }
  return NULL;
}

static int
z_parse_config_line_int(char *var, char *name, char *value, int *result)
{
  if (strcmp(name, var) == 0)
    {
      char quote = value[0];
      char *end;
      
      if (quote == '"' || quote == '\'')
        {
          *result = strtol(value + 1, &end, 10);
          if (*end != quote)
            return 0;
        }
      else
        {
          *result = strtol(value, &end, 10);
          if (*end != 0)
            return 0;
        }
      return 1;
    }
  return 0;
}

static int
z_parse_config_line_double(char *var, char *name, char *value, double *result)
{
  if (strcmp(name, var) == 0)
    {
      char quote = value[0];
      char *end;
      
      if (quote == '"' || quote == '\'')
        {
          *result = strtod(value + 1, &end);
          if (*end != quote)
            return 0;
        }
      else
        {
          *result = strtod(value, &end);
          if (*end != 0)
            return 0;
        }
      return 1;
    }
  return 0;
}

static int
z_parse_config_line_str(char *var, char *name, char *value, char **result)
{
  if (strcmp(name, var) == 0)
    {
      char quote = value[0];
      
      if (quote == '"' || quote == '\'')
        {
          char *p, *dst;
          
          *result = malloc(strlen(value));
          dst = *result;
          for (p = value + 1; *p; p++)
            {
              if (*p == '\\')
                {
                  *dst = *(p+1);
                  p++;
                }
              else if (*p == quote)
                {
                  break;
                }
              else
                {
                  *dst = *p;
                }
              dst++;
            }
          if (*p != 0 && *(p+1))
            {
              /* invalid quotation marks */
              free(*result);
              *result = NULL;
              return 0;
            }
          *dst = 0;
        }
      else
        *result = strdup(value);
      return 1;
    }
  return 0;
}

static int
z_parse_config(void)
{
  FILE *cfgf;
  char line[256], *value, *name, *eq;
  int lineno = 0;
  int res = 1;
  
  cfgf = fopen(ZORP_ZORPCTL_CONF, "r");
  if (!cfgf)
    return 0;
    
  while (fgets(line, sizeof(line), cfgf))
    {
      lineno++;
      chomp(line);
      if (line[0] == 0 || line[0] == '#')
        continue;
      eq = strchr(line, '=');
      if (!eq)
        {
          z_error(0, "Invalid zorpctl.conf line at %d: %s\n", lineno, line);
          return 0;
        }
      *eq = 0;
      value = eq + 1;
      name = line;
      
      if (!(z_parse_config_line_int("AUTO_RESTART", name, value, &auto_restart) ||
            z_parse_config_line_int("AUTO_RESTART_TIME_THRESHOLD", name, value, &auto_restart_time_threshold) ||
            z_parse_config_line_int("AUTO_RESTART_MAX_COUNT", name, value, &auto_restart_max_count) ||
            z_parse_config_line_double("AUTO_RESTART_DELAY", name, value, &auto_restart_delay) ||
            z_parse_config_line_int("START_CHECK_TIMEOUT", name, value, &start_check_timeout) || 
            z_parse_config_line_int("START_WAIT_TIMEOUT", name, value, &start_wait_timeout) || 
            z_parse_config_line_double("STOP_CHECK_DELAY", name, value, &stop_check_delay) ||
            z_parse_config_line_int("STOP_CHECK_TIMEOUT", name, value, &stop_check_timeout) ||
            z_parse_config_line_int("PROCESS_LIMIT_THRESHOLD", name, value, &process_limit_threshold) ||
            z_parse_config_line_int("PROCESS_LIMIT_RESERVE", name, value, &process_limit_reserve) ||
	    z_parse_config_line_int("PROCESS_LIMIT_MIN", name, value, &process_limit_min) ||
            z_parse_config_line_int("CHECK_PERMS", name, value, &check_perms) ||
            z_parse_config_line_str("CONFIG_DIR", name, value, &config_dir) ||
            z_parse_config_line_str("CONFIG_DIR_OWNER", name, value, &config_dir_owner) ||
            z_parse_config_line_str("CONFIG_DIR_GROUP", name, value, &config_dir_group) ||
            z_parse_config_line_str("CONFIG_DIR_MODE", name, value, &config_dir_perm) ||
            z_parse_config_line_str("APPEND_ARGS", name, value, &zorp_append_args) ||
            z_parse_config_line_str("ZORP_APPEND_ARGS", name, value, &zorp_append_args) ||
            z_parse_config_line_str("ZORPCTL_APPEND_ARGS", name, value, &zorpctl_append_args) ||
            z_parse_config_line_str("PIDFILE_DIR", name, value, &pidfile_dir) ||
            z_parse_config_line_str("PIDFILE_DIR_OWNER", name, value, &pidfile_dir_owner) ||
            z_parse_config_line_str("PIDFILE_DIR_GROUP", name, value, &pidfile_dir_group) ||
            z_parse_config_line_str("PIDFILE_DIR_MODE", name, value, &pidfile_dir_perm)))
        {
          z_error(0, "Unknown zorpctl.conf directive at %d: %s\n", lineno, line);
          res = 0;
        }
    }
  if (process_limit_threshold != -1)
    {
      z_error(0, "The use of PROCESS_LIMIT_THRESHOLD in zorpctl.conf is deprecated, its value is ignored\n");
      res = 0;
    }
  if (auto_restart_time_threshold != -1 || auto_restart_max_count != -1 || start_check_timeout != -1 || auto_restart_delay != -1.0)
    {
      z_error(0, "The use of AUTO_RESTART_DELAY, AUTO_RESTART_TIME_THRESHOLD, AUTO_RESTART_MAX_COUNT and START_CHECK_TIMEOUT in zorpctl.conf is deprecated, their values are ignored\n");
      res = 0;
    }
  return res;
}

/**
 * z_parse_line_item:
 * @pp[in,out]: A pointer to the first character in a buffer where the parser should start.
 *              It will point to the next item if any.
 * @prefix[in]: The prefix of the value which should be read. (OPTIONAL)
 * @item[out]: This parameter will contain the parsed item. More specially a pointer to the
 *             starting place of the item in the @pp.
 *
 * This function get the value part of specially crafted string buffer which contains <key> <value> pairs.
 * This function will alter the @pp buffer. It will insert NUL characters into it.
 * The prefix is optional. The items should be separated by whitespaces and no escaping is allowed.
 * If
 *
 * Returns: TRUE  on successful read and targeted item's length > 0, and
 */
static gboolean
z_parse_kzorp_entry_item(gchar **pp, const gchar *prefix, char **item)
{
  gchar *p = *pp;
  gsize prefix_len = 0;
  gboolean eol = FALSE;

  if (! *p)
    return FALSE;

  if (prefix)
    prefix_len = strlen(prefix);

  if (prefix_len)
    {
      if (strncmp(p, prefix, prefix_len))
        return FALSE;
    }

  p += prefix_len;

  *item = p;

  while (*p != ' ' && *p != '\t' && *p != 0)
    ++p;

  if (*p)
    {
      while (*p == ' ' || *p == '\t')
        *p++ = 0;

      if (! *p)
        eol = TRUE;
    }

  *pp = p;

  return **item || !eol;
}

/**
 * z_process_kzorp_entries:
 * @ins:       Zorp Instance
 * @user_data: not used
 *
 * This function parses the '/proc/net/nf_kzorp' file line by line, or if it doesn't
 * exist writes an error message and immediately returns.
 *
 * Returns: 0 on error, 1 otherwise
 */
static int
z_process_kzorp_entries(ZInstance *ins, gpointer user_data G_GNUC_UNUSED)
{
  gchar buffer[4096];
  gchar *p;
  FILE *file;
  gboolean initialized = FALSE;
  gint res = 0;

  gchar *dpt, *svc, *szone, *czone, *tmp;
  gchar *proto, *src, *dst, *src2, *dst2;
  gchar *sport, *dport, *sport2, *dport2;
  gchar *state, *instance, *sid;

  if ((file = fopen("/proc/net/nf_kzorp", "r")) == NULL)
    {
      z_error(0, "Unable to open /proc/net/nf_kzorp. Kernel is too old or kzorp is not loaded.\n");
      goto error;
    }

  while (!feof(file))
    {
      if (!fgets(buffer, 4096, file))
        {
          z_error(0, "Error while reading from /proc/net/nf_kzorp.\n");
          fclose(file);
          goto error;
        }

      p = buffer;

      if (!z_parse_kzorp_entry_item(&p, "instance=", &instance) ||
          /* different service */
          strcmp(instance, ins->name) ||
          !z_parse_kzorp_entry_item(&p, "sid=", &sid) ||
          !z_parse_kzorp_entry_item(&p, "dpt=", &dpt) ||
          !z_parse_kzorp_entry_item(&p, "svc=", &svc) ||
          !z_parse_kzorp_entry_item(&p, "czone=", &czone) ||
          !z_parse_kzorp_entry_item(&p, "szone=", &szone) ||
          !z_parse_kzorp_entry_item(&p, NULL, &tmp) ||
          !z_parse_kzorp_entry_item(&p, NULL, &tmp) ||
          !z_parse_kzorp_entry_item(&p, NULL, &proto) ||
          /* skip these */
          !z_parse_kzorp_entry_item(&p, NULL, &tmp) ||
          !z_parse_kzorp_entry_item(&p, NULL, &tmp))
        continue;

      if (!strcmp(proto, "tcp"))
        {
          if (!z_parse_kzorp_entry_item(&p, NULL, &state) ||
               strcmp(state, "ESTABLISHED"))
            continue;
        }

      if (!z_parse_kzorp_entry_item(&p, "src=", &src) ||
          !z_parse_kzorp_entry_item(&p, "dst=", &dst) ||
          !z_parse_kzorp_entry_item(&p, "sport=", &sport) ||
          !z_parse_kzorp_entry_item(&p, "dport=", &dport) ||
           /* skip these */
          !z_parse_kzorp_entry_item(&p, NULL, &tmp) ||
          !z_parse_kzorp_entry_item(&p, NULL, &tmp) ||
          /* It is the other direction. Source and destination are switched */
          !z_parse_kzorp_entry_item(&p, "src=", &src2) ||
          !z_parse_kzorp_entry_item(&p, "dst=", &dst2) ||
          !z_parse_kzorp_entry_item(&p, "sport=", &sport2) ||
          !z_parse_kzorp_entry_item(&p, "dport=", &dport2))
        continue;

      if (!initialized)
        {
          printf("zorp.conns.%s: None\n", svc);
          initialized = TRUE;
        }

      printf("zorp.conns.%s.%s: None\n", svc, sid);
      printf("zorp.conns.%s.%s.0: None\n", svc, sid);
      printf("zorp.conns.%s.%s.0.0: None\n", svc, sid);
      printf("zorp.conns.%s.%s.0.0.client_address: AF_INET(%s:%s)\n", svc, sid, src, sport);
      printf("zorp.conns.%s.%s.0.0.client_local: AF_INET(%s:%s)\n", svc, sid, dst, dport);
      printf("zorp.conns.%s.%s.0.0.client_zone: %s\n", svc, sid, czone);
      printf("zorp.conns.%s.%s.0.0.proxy_class: PFService\n", svc, sid);
      printf("zorp.conns.%s.%s.0.0.server_address: AF_INET(%s:%s)\n", svc, sid, src2, sport2);
      printf("zorp.conns.%s.%s.0.0.server_local: AF_INET(%s:%s)\n", svc, sid, dst2, dport2);
      printf("zorp.conns.%s.%s.0.0.server_zone: %s\n", svc, sid, szone);
      printf("zorp.conns.%s.%s.0.0.session_id: svc/%s:%s\n", svc, sid, svc, sid);
      printf("zorp.conns.%s.%s.0.0.protocol: %s\n", svc, sid, proto);
    }

  fclose(file);

  res = 1;

error:
  return res;
}


static int 
z_get_counter(ZInstance *inst, const char *var_name)
{
  ZSzigContext *ctx;
  char result[256];
  int success, thread_count;
  
  ctx = z_szig_context_new(inst->name);
  if (!ctx)
    return -1;
  
  success = z_szig_get_value(ctx, var_name, result, sizeof(result));
  z_szig_context_destroy(ctx);

  if (!success)
    return -1;
  thread_count = strtol(result, NULL, 10);
  return thread_count;
}

static int
z_get_thread_count(ZInstance *inst)
{
  return z_get_counter(inst, "zorp.stats.threads_running");
}

static void
z_setup_limits(ZInstance *inst)
{
  struct rlimit limit;
  
#ifdef RLIMIT_NPROC
  limit.rlim_cur = limit.rlim_max = MAX(inst->process_limit, process_limit_sum + process_limit_reserve);
  setrlimit(RLIMIT_NPROC, &limit);
#endif
}

static int
z_start_instance(ZInstance *inst)
{
  pid_t child;
  int status;
  int res = 1;
  
  child = fork();
  if (child == 0)
    {
      char **new_zorp_argv;
      
      new_zorp_argv = malloc((inst->zorp_argc + 6) * sizeof(char *));
      memcpy(new_zorp_argv, inst->zorp_argv, (inst->zorp_argc + 1) * sizeof(char *));
      inst->zorp_argv = new_zorp_argv;
      if (inst->enable_core)
        {
          inst->zorp_argv[inst->zorp_argc++] = "--enable-core";
        }
      if (!inst->auto_restart)
        {
          inst->zorp_argv[inst->zorp_argc++] = "--process-mode";
          inst->zorp_argv[inst->zorp_argc++] = "background";
        }
      inst->zorp_argv[inst->zorp_argc] = NULL;
 
      z_setup_limits(inst);
      setsid();
      execvp(ZORP, inst->zorp_argv);
      exit(1);
    }
  if (start_wait_timeout)
    {
      z_alarm_request(start_wait_timeout);
      if (waitpid(child, &status, 0) < 0)
        {
          res = 0;
          if (z_alarm_fired())
            {
              /* timed out */
              z_error(1, "Timeout waiting for Zorp instance to start up, instance='%s'\n", inst->name);
            }
        }
      else if (status != 0)
        { 
          z_error(1, "Zorp instance startup failed, instance='%s', rc='%d'\n", inst->name, status);
          res = 0;
        }
    }
  return res;
}

static int
z_process_start_instance(ZInstance *inst, void *user_data UNUSED)
{
  int stale;
  pid_t pid;
  
  if (z_instance_running(inst, &pid, &stale))
    {
      return 0;
    }
  if (stale)
    z_instance_remove_stale_pidfile(inst);

  if (!inst->no_auto_start)
    return z_start_instance(inst);
  return 1;
}

static int
z_process_force_start_instance(ZInstance *inst, void *user_data UNUSED)
{
  inst->no_auto_start = 0;
  return z_process_start_instance(inst, user_data);
}

static int
z_process_stop_instance(ZInstance *inst, void *user_data)
{
  int stale, killed;
  int signo = (long) user_data;
  time_t prev_check, now;
  pid_t pid;
  
  if (!z_instance_running(inst, &pid, &stale))
    {
      return 0;
    }
  if (stale)
    {
      z_instance_remove_stale_pidfile(inst);
    }
  else
    {
      kill(pid, signo);
      
      prev_check = now = time(NULL);
      killed = !z_instance_running(inst, &pid, &stale);
      for (killed = 0; (now - prev_check) < stop_check_timeout; now = time(NULL))
        {
          usleep((unsigned long)(stop_check_delay * 1e6));
          if ((killed = !z_instance_running(inst, &pid, &stale)))
            break;
        }
      if (!killed)
        {
          z_error(1, "Zorp instance did not exit in time (instance='%s', pid='%d', signo='%d', timeout='%d')\n", SAFE_STR(inst->name), pid, signo, stop_check_timeout);
          return 0;
        }
      if (signo == SIGKILL)
        z_instance_remove_stale_pidfile(inst);
    }

  return 1;
}


static int
z_process_restart_instance(ZInstance *inst, void *user_data)
{
  z_process_stop_instance(inst, user_data);
  return z_process_start_instance(inst, user_data);
}

static int
z_process_signal_instance(ZInstance *inst, void *user_data)
{
  int stale;
  int signo = (long) user_data;
  pid_t pid;
  
  if (!z_instance_running(inst, &pid, &stale))
    {
      return 0;
    }
  kill(pid, signo);
  return 1;
}

static int
z_process_status_instance(ZInstance *inst, void *user_data)
{
  int stale;
  pid_t pid;
  time_t starttime;
  int *status_flags = (int *) user_data;
  ZSzigContext *ctx;
  char result[16384];
  char policy_file[256];
  time_t timestamp_szig = 0, timestamp_stat = 0, timestamp_reload = 0;
  
  printf("Instance %s: ", inst->name);
  if (!z_instance_running(inst, &pid, &stale))
    {
      if (stale)
        {
          printf("stale pidfile, pid %d\n", pid);
        }
      else
        {
          printf("not running\n");
        }
      return 1;
    }
  ctx = z_szig_context_new(inst->name);
  if (ctx)
    {
      struct stat st;
      
      result[0] = '\0';
      if (!z_szig_get_value(ctx, "zorp.info.policy.file", policy_file, sizeof(policy_file)) || memcmp(result, "None", 4) == 0)
        goto szig_error;
      if (!stat(policy_file, &st))
        timestamp_stat = st.st_mtime;
        
      if (!z_szig_get_value(ctx, "zorp.info.policy.file_stamp", result, sizeof(result)) || memcmp(result, "None", 4) == 0)
        goto szig_error;
      
      timestamp_szig = (time_t)atol(result);

      if (!z_szig_get_value(ctx, "zorp.info.policy.reload_stamp", result, sizeof(result)) || memcmp(result, "None", 4) == 0)
        goto szig_error;
      
      timestamp_reload = (time_t)atol(result);
    }
  else
    goto szig_error;
    
  printf("running, %s%d threads active, pid %d\n", 
         (timestamp_stat != timestamp_szig) ? "policy NOT reloaded, " : "",
         z_get_thread_count(inst), pid);
  if (status_flags && (*status_flags & ZORPCTL_STATUS_VERBOSE))
    {
      char starttime_str[32], loadedtime_str[32];
      double jps, realtime, usertime, systime;
      int realmin, usermin, sysmin;
      ZProcInfo pi;
      
      memset(&pi, 0, sizeof(ZProcInfo));
      z_get_proc_info(pid, &pi);
      jps = z_get_jiffies_per_sec();
      
      usertime = pi.utime / jps;
      usermin = (int)(usertime / 60);
      usertime -= (usermin * 60);
      
      systime = pi.stime / jps;
      sysmin = (int)(systime / 60);
      systime -= (sysmin * 60);
      
      realtime = usertime + systime;
      realmin = (int)(realtime / 60);
      realtime -= (realmin * 60);
      
      starttime = time(NULL) - z_get_uptime() + (pi.starttime / jps);
      strftime(starttime_str, sizeof(starttime_str) - 1, "%Y-%m-%d %H:%M:%S", localtime(&starttime));
      strftime(loadedtime_str, sizeof(loadedtime_str) - 1, "%Y-%m-%d %H:%M:%S", localtime(&timestamp_reload));
      
      printf("  started at: %s\n", starttime_str);
      printf("  policy: file=%s, loaded=%s\n", policy_file, loadedtime_str);
      printf("  cpu: real=%02d:%06.3lf, user=%02d:%06.3lf, sys=%02d:%06.3lf\n",
             realmin, realtime, usermin, usertime, sysmin, systime);
      printf("  memory: vsz=%lu, rss=%ld\n", pi.vsize >> 10, pi.rss << 2);
    }

  goto exit;
szig_error:
  printf("error querying SZIG information\n");

exit:
  if (ctx)
    z_szig_context_destroy(ctx);
  return 1;  
}

static void
z_szig_walk_details(ZSzigContext *ctx, const char *root, gboolean csv, const char *instance_name, int level)
{
  char result[16384];
  const char *root_basename = strrchr(root, '.');
  gchar *escaped_name;

  ++root_basename;

  /* 0: <root>
     1: <root>.ssh
     2: <root>.ssh.1
     3: <root>.ssh.1.0
     4: <root>.ssh.1.0.0
     5: <root>.ssh.1.0.0.param
  */

  if (!csv && level == 1)
    printf("%s:\n", root_basename);
  else if (!csv && level == 2)
    printf(" %s:\n", root_basename);

  z_szig_get_child(ctx, root, result, sizeof(result));
  if (strcmp(result, "None") != 0)
    {
      /* walk all children, deep first */
      z_szig_walk_details(ctx, result, csv, instance_name, level + 1);

      /* siblings */
      z_szig_get_sibling(ctx, result, result, sizeof(result));
      while (strcmp(result, "None") != 0)
        {
          z_szig_walk_details(ctx, result, csv, instance_name, level + 1);
          z_szig_get_sibling(ctx, result, result, sizeof(result));
        }
    }

  if (csv && level == 4)
    {
      printf("\n");
    }
  else if (level == 5)
    {
      z_szig_get_value(ctx, root, result, sizeof(result));
      if (csv)
        {
          printf("%s=%s;", root_basename, csvescape(result, &escaped_name));
          g_free(escaped_name);
        }
      else
        printf("   %s: %s\n", root_basename, result);
    }
}

static int
z_process_authorize_list(ZInstance *inst, void *user_data)
{
  ZSzigContext *ctx;
  gboolean csv = *(gboolean*)user_data;
  
  if (!csv)
    printf("Instance %s:\n", inst->name);
  ctx = z_szig_context_new(inst->name);
  if (ctx)
    z_szig_walk_details(ctx, "zorp.authorization.pending", csv, inst->name, 0);
  else
    goto szig_error;

  goto exit;
szig_error:
  printf("error querying SZIG information\n");

exit:
  if (ctx)
    z_szig_context_destroy(ctx);
  return 1;
}


static int
z_process_authorize(ZInstance *inst, void *user_data)
{
  int stale;
  pid_t pid;
  ZSzigContext *ctx;
  char result[16384];
  gchar **params = (gchar **) user_data;

  printf("Instance %s: ", inst->name);
  if (!z_instance_running(inst, &pid, &stale))
    {
      if (stale)
        {
          printf("stale pidfile, pid %d\n", pid);
        }
      else
        {
          printf("not running\n");
        }
      return 1;
    }
  ctx = z_szig_context_new(inst->name);
  if (ctx)
    {
      gboolean accept = params[0] != NULL;

      z_szig_authorize(ctx, params[ accept ? 0 : 1 ], accept, params[2], result, sizeof(result));
      printf("%s\n", result);
    }
  else
    goto szig_error;

  goto exit;
szig_error:
  printf("error querying SZIG information\n");

exit:
  if (ctx)
    z_szig_context_destroy(ctx);
  return 1;
}


static void
z_print_empty_result(char *status, pid_t pid, char *qry_strings[])
{
  int i;
  
  printf("\"%s\";", status);
  if (pid > 0)
    printf("%d", pid);
  for (i = 0; qry_strings[i]; i++)
    {
      putc(';', stdout);
    }
  putc('\n', stdout);
}


static void
z_szig_walk(ZSzigContext *ctx, const char *root)
{
  char result[16384];
  
  z_szig_get_value(ctx, root, result, sizeof(result));
  printf("%s: %s\n", root, result);
  z_szig_get_child(ctx, root, result, sizeof(result));
  if (strcmp(result, "None") != 0)
    {
      /* walk all children, deep first */
      z_szig_walk(ctx, result);
      
      /* siblings */
      z_szig_get_sibling(ctx, result, result, sizeof(result));
      while (strcmp(result, "None") != 0)
        {
          z_szig_walk(ctx, result);
          z_szig_get_sibling(ctx, result, result, sizeof(result));
      
        }
    }
}

static int
z_process_szig_walk_instance(ZInstance *inst, void *user_data)
{
  ZSzigContext *ctx;
  char *root = (char *) user_data;
  
  printf("Instance %s: ", inst->name);
  ctx = z_szig_context_new(inst->name);
  if (!ctx)
    {
      printf("not running\n");
      z_szig_context_destroy(ctx);
      return 0;
    }
  else
    {
      printf("walking\n");
    }
  
  z_szig_walk(ctx, root);
  z_szig_context_destroy(ctx);
  
  return 1;
}

static int
z_process_conns_walk_instance(ZInstance *inst, void *user_data G_GNUC_UNUSED)
{
  ZSzigContext *ctx;
  
  ctx = z_szig_context_new(inst->name);
  if (ctx)
    z_szig_walk_details(ctx, "zorp.conns", TRUE, inst->name, 0);
  else
    goto szig_error;

  goto exit;
szig_error:
  printf("error querying SZIG information\n");

exit:
  if (ctx)
    z_szig_context_destroy(ctx);
 
  return 1;
}

static int
z_process_log_func(ZInstance *inst, char *cmd, char *param)
{
  ZSzigContext *ctx;						
  int res = 0;							
                                                                
  ctx = z_szig_context_new(inst->name);				
  if (ctx)							
    {								
      if (z_szig_logging(ctx, cmd, param, NULL, 0))		
        res = 1;						
      z_szig_context_destroy(ctx);				
    }
  else
    {
      z_error(1, "Error connecting to Zorp SZIG socket, instance='%s', error='%s'\n", inst->name, strerror(errno));
    }
    
  return res;
}

static int
z_process_log_vinc_instance(ZInstance *inst, void *user_data UNUSED)
{
  return z_process_log_func(inst, "VINC", "1");
}

static int
z_process_log_vdec_instance(ZInstance *inst, void *user_data UNUSED)
{
  return z_process_log_func(inst, "VDEC", "1");
}

static int
z_process_log_vset_instance(ZInstance *inst, void *user_data)
{
  char buf[16];
  
  snprintf(buf, sizeof(buf), "%d", *(int *) user_data);
  
  return z_process_log_func(inst, "VSET", buf);
}

static int
z_process_log_logspec_instance(ZInstance *inst, void *user_data)
{
  return z_process_log_func(inst, "SETSPEC", (char *) user_data);
}

static int
z_process_log_status_instance(ZInstance *inst, void *user_data UNUSED)
{
  ZSzigContext *ctx;
  int res = 0;
  char verb_level[16];
  char spec[128];

  ctx = z_szig_context_new(inst->name);
  if (ctx)
    {
      if (z_szig_logging(ctx, "VGET", "", verb_level, sizeof(verb_level)))
        res = 1;
      if (!res || !z_szig_logging(ctx, "GETSPEC", "", spec, sizeof(spec)))
        res = 0;
      if (res)
        {
          printf("Instance: %s: verbose_level='%s', logspec='%s'\n", inst->name, verb_level, spec);
        }
      z_szig_context_destroy(ctx);
    }
  if (!res)
    {
      printf("Instance: %s, error querying log information\n", inst->name);
    }
  return res;
}

/* DEADLOCKCHECK command */
static int
z_process_deadlockcheck_func(ZInstance *inst, char *cmd)
{
  ZSzigContext *ctx;
  int res = 0;

  ctx = z_szig_context_new(inst->name);
  if (ctx)
    {
      z_szig_deadlockcheck(ctx, cmd, NULL, 0);
      res = 1;
      z_szig_context_destroy(ctx);
    }
  else
    {
      z_error(1, "Error connecting to Zorp SZIG socket, instance='%s', error='%s'\n", inst->name, strerror(errno));
    }

  return res;
}

static int
z_process_deadlockcheck_enable_instance(ZInstance *inst, void *user_data UNUSED)
{
  return z_process_deadlockcheck_func(inst, "ENABLE");
}

static int
z_process_deadlockcheck_disable_instance(ZInstance *inst, void *user_data UNUSED)
{
  return z_process_deadlockcheck_func(inst, "DISABLE");
}

static int
z_process_deadlockcheck_status_instance(ZInstance *inst, void *user_data UNUSED)
{
  ZSzigContext *ctx;
  int res = 0;
  char timeout[16];

  ctx = z_szig_context_new(inst->name);
  if (ctx)
    {
      if (z_szig_deadlockcheck(ctx, "GET", timeout, sizeof(timeout)))
        res = 1;
      if (res)
        {
          printf("Instance: %s: deadlockcheck='%s'\n", inst->name, timeout);
        }
      z_szig_context_destroy(ctx);
    }
  if (!res)
    {
      printf("Instance: %s, error querying deadlock checker information\n", inst->name);
    }
  return res;
}

static inline int
z_process_reload_inline(ZInstance *inst, gboolean suppress_message)
{
  ZSzigContext *ctx;						
  int res = 0;							
                                                                
  ctx = z_szig_context_new(inst->name);				
  if (ctx)							
    {								
      if (z_szig_reload(ctx, NULL, NULL, 0) &&
          z_szig_reload(ctx, "RESULT", NULL, 0))
        res = 1;
      z_szig_context_destroy(ctx);				
    }
  else
    {
      if (!suppress_message)
        z_error(1, "Error connecting to Zorp SZIG socket, instance='%s'", inst->name);
    }
    
  return res;
}

static inline int
z_process_reload(ZInstance *inst, void *user_data UNUSED)
{
  int res;
  res = z_process_reload_inline(inst, FALSE);
  
  return res;
}

static inline int
z_process_reload_or_restart(ZInstance *inst, void *user_data UNUSED)
{
  int res = 0;
  
  res = z_process_reload_inline(inst, TRUE);
  if ( res != 1)
    {
      if (!z_process_restart_instance(inst, NULL))
        {
          z_error(1, "Both reload and restart failed, instance='%s'", inst->name);
          res = 0;
        }
      else
        {
          res = 1;
        }
    }
  return res;
}

static inline int
z_process_coredump(ZInstance *inst, void *user_data UNUSED)
{
  int res = 0;
  ZSzigContext *ctx;

  ctx = z_szig_context_new(inst->name);
  if (ctx)
    {
      res = z_szig_coredump(ctx);

      z_szig_context_destroy(ctx);
    }

  if (!res)
    {
      printf("Instance: %s, error creating core dump\n", inst->name);
    }

  return res;
}

static int
z_process_args(char *ident, int argc, char *argv[], int (*func)(ZInstance *inst, void *user_data), void *user_data, int display_instances) G_GNUC_WARN_UNUSED_RESULT;

static int
z_process_args_withmsg( const char * msg, 
char *ident, int argc, char *argv[], int (*func)(ZInstance *inst, void *user_data), void *user_data, int display_instances)
{
  int res;
  printf("%s", msg);
  res = z_process_args(ident, argc, argv, func, user_data, display_instances);
  printf("\n");
  return res;
}


static int
z_process_args(char *ident, int argc, char *argv[], int (*func)(ZInstance *inst, void *user_data), void *user_data, int display_instances)
{
  ZInstance *inst;
  int success_all = 1;
  int i;

  if (argc == 0)
    {
      for (inst = instances; inst; inst = inst->next)
        {
          int success = func(inst, user_data);
          success_all &= !!success;
          if (display_instances)
            printf("%s%s", inst->name, success ? " " : "! ");
        }
    }
  else
    {    
      if (argv[0][0] == '@')
        {
          FILE *inst_list;
          gchar inst_buf[128];
          /* list of instances is in a file */
          
          inst_list = fopen(&argv[0][1], "r");
          if (inst_list)
            {
              while (fgets(inst_buf, sizeof(inst_buf), inst_list))
                {
                  int success = 0;
                  chomp(inst_buf);
                  inst = z_search_instance(inst_buf);
                  if (!inst)
                    {
                      z_error(1, "%s: No such instance: %s\n", ident, inst_buf);
                      success_all = 0;
                    }
                  else
                    {
                      success = func(inst, user_data);
                      success_all &= !!success;
                    }
                  if (display_instances)
                    printf("%s%s", inst_buf, success ? " " : "! ");
                  
                }
              fclose(inst_list);
            }
          else
            {
              z_error(1, "Error opening instance list file: %s.", &argv[0][1]);
              success_all = 0;
            }
        }
      else
        {
          for (i = 0; i < argc; i++)
            {
              int success = 0;
              inst = z_search_instance(argv[i]);
              if (!inst)
                {
                  z_error(1, "%s: No such instance: %s\n", ident, argv[i]);
                  success_all = 0;
                }
              else
                {
                  success = func(inst, user_data);
                  success_all &= !!success;
                }
              if (display_instances)
                printf("%s%s", argv[i], success ? " " : "! ");
            }
        }
    }
  return success_all ? 0 : 1;
}

/* command implementations */

static int
z_cmd_start(int argc, char *argv[])
{
  return z_process_args_withmsg("Starting Zorp Firewall Suite: ",
    "start", argc-2, &argv[2], z_process_start_instance, NULL, 1);
}

static int
z_cmd_force_start(int argc, char *argv[])
{
  return z_process_args_withmsg("Starting Zorp Firewall Suite: ",
    "start", argc-2, &argv[2], z_process_force_start_instance, NULL, 1);
}

static int
z_cmd_stop(int argc, char *argv[])
{
  return z_process_args_withmsg("Stopping Zorp Firewall Suite: ",
    "stop", argc-2, &argv[2], z_process_stop_instance, (void *) SIGTERM, 1);
}

static int
z_cmd_force_stop(int argc, char *argv[])
{
  return z_process_args_withmsg("Stopping Zorp Firewall Suite: ",
    "stop", argc-2, &argv[2], z_process_stop_instance, (void *) SIGKILL, 1);
}

static int
z_cmd_restart(int argc, char *argv[])
{
  return z_process_args_withmsg("Restarting Zorp Firewall Suite: ",
    "restart", argc-2, &argv[2], z_process_restart_instance, (void *) SIGTERM, 1);
}

static int
z_cmd_force_restart(int argc, char *argv[])
{
  return z_process_args_withmsg("Restarting Zorp Firewall Suite: ",
    "restart", argc-2, &argv[2], z_process_restart_instance, (void *) SIGKILL, 1);
}

static int
z_cmd_reload(int argc, char *argv[])
{
  return z_process_args_withmsg("Reloading Zorp Firewall Suite: ",
    "reload", argc-2, &argv[2], z_process_reload, NULL, 1);
}

static int
z_cmd_reload_or_restart(int argc, char *argv[])
{
  return z_process_args_withmsg("Reloading or Restarting Zorp Firewall Suite: ",
    "reload-or-restart", argc-2, &argv[2], z_process_reload_or_restart, NULL, 1);
}

static int
z_cmd_coredump(int argc, char *argv[])
{
  return z_process_args_withmsg("Creating Zorp core dumps: ",
    "coredump", argc - 2, &argv[2], z_process_coredump, NULL, 1);
}

static int
z_cmd_status(int argc, char *argv[])
{
  int processed_args = 2;
  int status_flags = 0;
  
  if ((argc > processed_args) && (strcmp("-v", argv[processed_args]) == 0 || strcmp("--verbose", argv[processed_args]) == 0))
    {
      status_flags = ZORPCTL_STATUS_VERBOSE;
      processed_args++;
    }
  return z_process_args("status", argc - processed_args, &argv[processed_args], z_process_status_instance, &status_flags, 0);
}

static int
z_cmd_authorize(int argc, char *argv[])
{
  int res = 0;
  GOptionContext *ctx;
  GError *error = NULL;

  gchar *auth_accept_sid  = NULL;
  gchar *auth_reject_sid  = NULL;
  gchar *auth_instance    = NULL;
  gchar *auth_description = NULL;
  gboolean auth_list_pending    = FALSE;
  gboolean auth_list_csv        = FALSE;

  GOptionEntry authorize_options[] =
  {
    { "list-pending", 'l',  0, G_OPTION_ARG_NONE,   &auth_list_pending, "Lists sessions for pending authorization",       NULL },
    { "csv",          'c',  0, G_OPTION_ARG_NONE,   &auth_list_csv,     "Generates output of list-pending in csv format", NULL },
    { "accept",       'a',  0, G_OPTION_ARG_STRING, &auth_accept_sid,   "Accepts authorization request",                  "<session id>" },
    { "reject",       'r',  0, G_OPTION_ARG_STRING, &auth_reject_sid,   "Rejects authorization request",                  "<session id>" },
    { "description",  'd',  0, G_OPTION_ARG_STRING, &auth_description,  "Description of accept/reject for logging ",      "<description>" },
    { "instance",     'i',  0, G_OPTION_ARG_STRING, &auth_instance,     "Proxy instance which the session belongs to",    "<instance name>" },
    { NULL,            0,   0, 0,                   0,                  NULL,                                             NULL },
  };

  --argc;
  ++argv;
  ctx = g_option_context_new(NULL);
  g_option_context_add_main_entries(ctx, authorize_options, NULL);
  if (!g_option_context_parse(ctx, &argc, &argv, &error))
    {
      fprintf(stderr, "zorpctl authorize: %s\n", error ? error->message : "Unknown error");
      return 1;
    }
  g_option_context_free(ctx);

  if (auth_list_csv)
    auth_list_pending = TRUE;

  if (auth_accept_sid || auth_reject_sid)
    {
      if (auth_list_pending)
        {
          fprintf(stderr, "zorpctl authorize: -l and -c cannot be used with -a or -c\n");
          return 1;
        }
      if (!auth_instance)
        {
          fprintf(stderr, "zorpctl authorize: proxy instance is not specified\n");
          return 1;          
        }
      if (!auth_description)
        {
          fprintf(stderr, "zorpctl authorize: description is not specified\n");
          return 1;          
        }
    } /* if list-pending is used, description and instance parameters are ignored */
  else
    auth_list_pending = TRUE;

  if (auth_accept_sid && auth_reject_sid)
    {
      fprintf(stderr, "zorpctl authorize: both reject and accept cannot be used\n");
      return 1;          
    }

  if (auth_list_pending)
    {
      if (auth_instance)
        {
          char *procargv[2] = { auth_instance, NULL };
          res = z_process_args("authorize_list",  1, procargv, z_process_authorize_list, (void *)&auth_list_csv, 0);
        }
      else
        res = z_process_args("authorize_list",  0, 0, z_process_authorize_list, (void *)&auth_list_csv, 0);
    }
  else
    {
      char *procargv[2] = { auth_instance, NULL };
      char *params[3] = { auth_accept_sid, auth_reject_sid, auth_description };
      res = z_process_args("authorize",  1, procargv,  z_process_authorize, (void *)params, 0);
    }

  return res;
}


static int
z_cmd_version(int argc UNUSED, char *argv[] UNUSED)
{
  execl(ZORP, ZORP, "--version", NULL);
  return 0;
}


static int
z_cmd_inclog(int argc, char *argv[])
{
  return z_process_args_withmsg("Raising Zorp loglevel: ",
    "inclog", argc-2, &argv[2], z_process_signal_instance, (void *) SIGUSR1, 1);
}

static int
z_cmd_declog(int argc, char *argv[])
{
  return z_process_args_withmsg("Lowering Zorp loglevel: ",
      "declog", argc-2, &argv[2], z_process_signal_instance, (void *) SIGUSR2, 1);
}

static int 
z_cmd_log(int argc, char *argv[])
{
  static int verbose_set = 0;
  static const char *logspec = NULL;
  static gboolean inc_verbosity = FALSE, dec_verbosity=FALSE;
  static GOptionEntry log_options[] =
    {
        { "vinc", 'i', 0, G_OPTION_ARG_NONE, &inc_verbosity, "Increment verbosity level by one", NULL },
        { "vdec", 'd', 0, G_OPTION_ARG_NONE, &dec_verbosity, "Decrement verbosity level by one", NULL },
        { "vset", 's', 0, G_OPTION_ARG_INT, &verbose_set, "Set verbosity level", "<verbosity>" },
        { "log-spec", 'S', 0, G_OPTION_ARG_STRING, &logspec, "Set log specification", "<logspec>" },
        { NULL, 0, 0, 0, NULL, NULL, NULL }
    };

  int res = 1;
  GOptionContext *ctx = g_option_context_new(NULL);

  g_option_context_add_main_entries(ctx, log_options, NULL);
  g_option_context_set_ignore_unknown_options(ctx, FALSE);
  g_option_context_set_help_enabled(ctx, TRUE);
  argc--;
  argv++;
  if (!g_option_context_parse(ctx, &argc, &argv, NULL))
    {
      z_error(0, "zorpctl log: Invalid argument encountered, use -? or --help for usage details\n");
      g_option_context_free(ctx);
      return 0;
    }
  argc--;
  argv++;

  if (inc_verbosity || dec_verbosity || verbose_set || logspec)
    printf("Changing Zorp log settings: ");

  if (inc_verbosity)
    res = z_process_args("log", argc, argv, z_process_log_vinc_instance, NULL, 1);
  else if (dec_verbosity)
    res = z_process_args("log", argc, argv, z_process_log_vdec_instance, NULL, 1);
  else if (verbose_set)
    res = z_process_args("log", argc, argv, z_process_log_vset_instance, &verbose_set, 1);
  else if (logspec)
    res = z_process_args("log", argc, argv, z_process_log_logspec_instance, (char *) logspec, 1);
  else
    res = z_process_args("log", argc, argv, z_process_log_status_instance, NULL, 0);

  if (inc_verbosity || dec_verbosity || verbose_set || logspec)
    printf("\n");

  g_option_context_free(ctx);
  return res;
}

static int
z_cmd_deadlockcheck(int argc, char *argv[])
{
  static gboolean enable_check = FALSE, disable_check = FALSE;
  static GOptionEntry deadlockcheck_options[] =
    {
        { "enable", 'e', 0, G_OPTION_ARG_NONE, &enable_check, "Enable deadlock checking", NULL },
        { "disable", 'd', 0, G_OPTION_ARG_NONE, &disable_check, "Disable deadlock checking", NULL },
        { NULL, 0, 0, 0, NULL, NULL, NULL }
    };

  int res = 1;
  GOptionContext *ctx = g_option_context_new(NULL);

  g_option_context_add_main_entries(ctx, deadlockcheck_options, NULL);
  g_option_context_set_ignore_unknown_options(ctx, FALSE);
  g_option_context_set_help_enabled(ctx, TRUE);
  argc--;
  argv++;
  if (!g_option_context_parse(ctx, &argc, &argv, NULL))
    {
      z_error(0, "zorpctl deadlockcheck: Invalid argument encountered, use -? or --help for usage details\n");
      g_option_context_free(ctx);
      return 0;
    }
  argc--;
  argv++;

  if (enable_check || disable_check)
    printf("Changing Zorp deadlock checking settings: ");

  if (enable_check)
    res = z_process_args("deadlockcheck", argc, argv, z_process_deadlockcheck_enable_instance, NULL, 1);
  else if (disable_check)
    res = z_process_args("deadlockcheck", argc, argv, z_process_deadlockcheck_disable_instance, NULL, 1);
  else
    res = z_process_args("deadlockcheck", argc, argv, z_process_deadlockcheck_status_instance, NULL, 0);

  if (enable_check || disable_check)
    printf("\n");

  g_option_context_free(ctx);
  return res;
}

static int
z_cmd_szig(int argc, char *argv[])
{
  static gboolean action_walk;
  static const char *root = "zorp";
  static GOptionEntry szig_options[] =
    {
        { "walk", 'w', 0, G_OPTION_ARG_NONE, &action_walk, "Walk the specified tree", NULL },
        { "root", 'r', 0, G_OPTION_ARG_STRING, &root, "Set the root node of the walk operation", "<node>" },
        { NULL, 0, 0, 0, NULL, NULL, NULL }
    };

  int res;
  GOptionContext *ctx = g_option_context_new(NULL);

  g_option_context_add_main_entries(ctx, szig_options, NULL);
  g_option_context_set_ignore_unknown_options(ctx, FALSE);
  g_option_context_set_help_enabled(ctx, TRUE);
  argc--;
  argv++;
  if (!g_option_context_parse(ctx, &argc, &argv, NULL))
    {
      z_error(0, "zorpctl szig: Invalid argument encountered, use -? or --help for usage details\n");
      g_option_context_free(ctx);
      return 0;
    }
  argc--;
  argv++;
  /* currently only the default -w action is supported, but there may be more in the future */

  res = z_process_args("szig", argc, argv, z_process_szig_walk_instance, (void *) root, 0);
  g_option_context_free(ctx);

  if (!res)
    res = z_process_args("szig", argc, argv, z_process_kzorp_entries, 0, 0);
  return res;
}

static int
z_cmd_conns(int argc, char *argv[])
{
  return z_process_args("conns", argc-2, &argv[2], z_process_conns_walk_instance, NULL, 0);
}

static int 
z_cmd_usage(int argc UNUSED, char *argv[] UNUSED)
{
  int i;
  
  printf("Syntax\n"
         "  %s <command>\n\n"
         "The following commands are available:\n\n", argv[0]);
  for (i = 0; commands[i].cmd; i++)
    printf("%-18s  %s\n", commands[i].cmd, commands[i].help);
  return 0;
}


ZCommand commands[] = 
{  
  { "start", z_cmd_start,          "Starts the specified Zorp instance(s)" },
  { "force-start", z_cmd_force_start,"Starts the specified Zorp instance(s) even if they are disabled" },
  { "stop",  z_cmd_stop,           "Stops the specified Zorp instance(s)" },
  { "force-stop",  z_cmd_force_stop,"Forces the specified Zorp instance(s) to stop (SIGKILL)" },
  { "restart", z_cmd_restart,      "Restart the specified Zorp instance(s)" },
  { "force-restart", z_cmd_force_restart,      "Forces the specified Zorp instance(s) to restart (SIGKILL)" },
  { "reload", z_cmd_reload,        "Reload the specified Zorp instance(s)" },
  { "reload-or-restart", z_cmd_reload_or_restart,        "Reload or restart the specified Zorp instance(s)" },
  { "coredump", z_cmd_coredump,    "Create core dumps of the specified Zorp instance(s)" },
  { "status", z_cmd_status,        "Status of the specified Zorp instance(s).\n"
                                   "\t\t    For additional information use status -v or --verbose option" },
  { "authorize", z_cmd_authorize,  "Lists and manages authorizations" },
  { "version", z_cmd_version,      "Display Zorp version information" },
  { "inclog",  z_cmd_inclog,       "Raise the specified Zorp instance(s) log level by one" },
  { "declog",  z_cmd_declog,       "Lower the specified Zorp instance(s) log level by one" },
  { "log",  z_cmd_log,             "Change and query Zorp log settings" },
  { "deadlockcheck",  z_cmd_deadlockcheck,             "Change and query Zorp deadlock checking settings" },
  { "szig",  z_cmd_szig,           "Display internal information from the given Zorp instance(s)" },
  { "conns", z_cmd_conns,          "List the active connections" },
  { "help",  z_cmd_usage,          "Display this screen" },
  { NULL, NULL, NULL }
};

int 
main(int argc, char *argv[])
{
  int i;
  ZCommand *cmd = NULL;
  int rc = 0;
  int config_ok = 1;

  setvbuf(stdout, NULL, _IONBF, 0);
  z_setup_signals();
  config_ok &= !!z_parse_config();
  config_ok &= !!z_parse_instances();
  
  z_check_pidfile_dir();
  if (!z_check_config_dir())
    return 1;
  
  if (argc < 2)
    {
      z_cmd_usage(argc, argv);
      return 1;
    }
  
  if ((argv[1][0] == '-') && (argv[1][1]=='-'))
    argv[1] += 2;

  for (i = 0; commands[i].cmd; i++)
    {
      if (strcmp(commands[i].cmd, argv[1]) == 0)
        {
          cmd = &commands[i];
          break;
        }
    }
  if (cmd)
    {
      rc = cmd->func(argc, argv);
    }
  else
    {
      z_error(0, "Invalid command: %s\n", argv[1]);
      rc = 1;
    }
  
  z_dump_errors();
  return rc ? rc : !config_ok;
}
