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

#ifndef ZORP_ZORPADDR_ZSHMEM_H_INCLUDED
#define ZORP_ZORPADDR_ZSHMEM_H_INCLUDED

#include <zorp/linebalance.h>

#include <linux/types.h>

void z_shmem_clear(void);
void z_shmem_reload(void);
void z_shmem_init(void);
void z_shmem_destroy();
void z_shmem_update_ip_address(guint32 group, guint32 iface, __be32 addr);
void z_shmem_update_preference(guint32 group, guint32 iface, gint preference);
void z_shmem_invalidate();
void z_shmem_validate();
#endif
