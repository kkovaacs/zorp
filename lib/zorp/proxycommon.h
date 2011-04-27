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
 * Author: Laszlo Attila Toth
 *
 ***************************************************************************/

#ifndef ZORP_PROXY_COMMON_H_INCLUDED
#define ZORP_PROXY_COMMON_H_INCLUDED


/* a two-way connection between streams */

/* endpoint indexes */
enum
{
  EP_CLIENT,
  EP_SERVER,
  EP_MAX
};

#define EP_OTHER(ep) (1-(ep))
#define EP_STR(ep)   ((ep) == EP_CLIENT ? "client" : "server")

enum
{
  EP_DIR_IN,
  EP_DIR_OUT,
  EP_DIR_MAX
};

#define EP_DIR_OTHER(ep) (1-(ep))
#define EP_DIR_STR(ep)   ((ep) == EP_DIR_IN ? "input" : "output")

typedef struct _ZProxy ZProxy;

#endif
