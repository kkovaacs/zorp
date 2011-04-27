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
 * $Id$
 *
 * Author  : Bazsi
 * Auditor : 
 * Last audited version:
 * Notes:
 *
 ***************************************************************************/

#ifndef ZORP_PYSTRUCT_H_INCLUDED
#define ZORP_PYSTRUCT_H_INCLUDED

#include <zorp/zorp.h>
#include <zorp/policy.h>
#include <zorp/pydict.h>

typedef struct _ZPolicyStruct ZPolicyStruct;

enum
{
  Z_PST_NONE = 0,
  /* shared type for multiple PyStructs, cannot be distinguished from Python */
  Z_PST_SHARED,
  Z_PST_SOCKADDR,
  Z_PST_SOCKADDR_INET,
  Z_PST_SOCKADDR_INET6,
  Z_PST_SOCKADDR_UNIX,
  Z_PST_DISPATCH_BIND,
  Z_PST_DB_SOCKADDR,
  Z_PST_DB_IFACE,
  Z_PST_DB_IFACE_GROUP,
  Z_PST_PROXY_GROUP,
  Z_PST_MAX,
};

typedef ZPolicyObj *(*ZPolicyStructFormatFunc)(ZPolicyObj *s);

void z_policy_struct_set_format(ZPolicyObj *s, ZPolicyStructFormatFunc format);
gboolean z_policy_struct_check(ZPolicyObj *s, gint type);
void z_policy_struct_set_is_config(ZPolicyObj *s, gboolean is_config);
ZPolicyDict *z_policy_struct_get_dict(ZPolicyObj *s);
ZPolicyDict *z_policy_struct_release_dict(ZPolicyObj *s);
ZPolicyObj *z_policy_struct_new(ZPolicyDict *dict, gint type);

ZPolicyObj *z_policy_struct_get_type_object(gint type);
void z_policy_struct_module_init(void);

#endif

