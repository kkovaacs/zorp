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

#include <zorp/zorp.h>
#include <zorp/kzorp-kernel.h>
#include <zorp/log.h>

#include <netinet/ip.h>

gboolean
z_kzorp_get_lookup_result(gint fd, struct z_kzorp_lookup_result *result)
{
  socklen_t size = sizeof(*result);

  z_enter();

  if (getsockopt(fd, SOL_IP, SO_KZORP_RESULT, result, &size) < 0)
    {
      z_log(NULL, CORE_ERROR, 3, "Error querying KZorp lookup result; fd='%d', error='%s'", fd, g_strerror(errno));
      z_return(FALSE);
    }

  z_return(TRUE);
}
