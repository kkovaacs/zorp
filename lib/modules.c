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
 * $Id: modules.c,v 1.13 2004/01/05 10:54:26 bazsi Exp $
 *
 * Author  : Bazsi
 * Auditor :
 * Last audited version:
 * Notes:
 *
 ***************************************************************************/

#include <zorp/zorp.h>
#include <zorp/log.h>
#include <gmodule.h>

#define G_MODULE_ERROR_SAFE() (g_module_error() ? g_module_error() : "(null)")

/**
 * z_load_module:
 * @modname: name of the module to load
 *
 * This function opens the module specified by @modname as a shared object
 * and initializes it by calling its zorp_module_init function.
 * 
 * Returns TRUE on success
 **/
gint
z_load_module(gchar *modname)
{
  GModule *m;
  gchar *buf;
  gint (*modinit)(void) __attribute__((may_alias));

  z_enter();
  buf = g_module_build_path(ZORP_LIBDIR, modname);
  m = g_module_open(buf, 0);
  if (m &&
      g_module_symbol(m, "zorp_module_init", (gpointer *) &modinit) &&
      modinit())
    {
      /*LOG
        This message serves informational purposes, and indicates that
        the given module was successfully loaded from the given shared
        object.
       */
      z_log(NULL, CORE_DEBUG, 8, "Module successfully loaded; module='%s', file='%s'", modname, buf);
      g_free(buf);
      z_return(TRUE);
    }

  /*LOG
    This message indicates that loading a proxy module failed.
   */
  z_log(NULL, CORE_ERROR, 1, "Module loading failed; module='%s', file='%s', error='%s'", modname, buf, G_MODULE_ERROR_SAFE());
  g_free(buf);
  z_return(FALSE);
}
