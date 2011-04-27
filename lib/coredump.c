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
 ***************************************************************************/

#include <errno.h>
#include <sys/types.h>
#include <unistd.h>
#include <time.h>
#include <glib.h>
#include <zorp/log.h>
#include <zorpconfig.h>

#ifdef HAVE_GOOGLE_COREDUMPER_H

#include <google/coredumper.h>

int
z_coredump_create(void)
{
  int res;
  GString *filename;

  filename = g_string_new("zorp_");
  g_string_append_printf(filename, "%ld-%d.core", time(NULL), getpid());

  /* Our $CWD is usually /var/run/zorp, we are supposed to be able to write there */
  res = WriteCoreDump(filename->str);
  if (res == -1)
    {
      z_log(NULL, CORE_DEBUG, 3, "Failed to create core file; filename='%s', error='%s'",
            filename->str, g_strerror(errno));
    }

  g_string_free(filename, TRUE);

  return res;
}

#else /* HAVE_GOOGLE_COREDUMPER_H */

int
z_coredump_create(void)
{
  z_log(NULL, CORE_DEBUG, 3, "Creating core dumps not supported;");
  return -ENOTSUP;
}

#endif
