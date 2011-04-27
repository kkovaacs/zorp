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
 * $Id: pydispatch.h,v 1.1 2002/09/05 10:19:49 bazsi Exp $
 *
 ***************************************************************************/

#ifndef ZORP_PYDISPATCH_H_INCLUDED
#define ZORP_PYDISPATCH_H_INCLUDED

#include <zorp/zpython.h>
#include <zorp/pystruct.h>
#include <zorp/dispatch.h>

typedef struct _ZPolicyDispatchBind ZPolicyDispatchBind;

ZDispatchBind *
z_policy_dispatch_bind_get_db(ZPolicyObj *self);

static inline gboolean
z_policy_dispatch_bind_check(ZPolicyObj *self)
{
  return z_policy_struct_check(self, Z_PST_DB_SOCKADDR) || z_policy_struct_check(self, Z_PST_DB_IFACE) || z_policy_struct_check(self, Z_PST_DB_IFACE_GROUP);
}

void z_policy_dispatch_module_init(void);

#endif

