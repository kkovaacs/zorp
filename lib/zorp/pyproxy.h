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
 * $Id: pyproxy.h,v 1.8 2003/07/16 07:45:40 bazsi Exp $
 *
 ***************************************************************************/

#ifndef ZORP_PYPROXY_H_INCLUDED
#define ZORP_PYPROXY_H_INCLUDED

#include <zorp/zpython.h>
#include <zorp/thread.h>
#include <zorp/proxy.h>

typedef struct _ZPolicyProxy ZPolicyProxy;

extern PyTypeObject z_policy_proxy_type;

gboolean z_policy_proxy_bind_implementation(PyObject *self);
ZProxy *z_policy_proxy_get_proxy(PyObject *obj);

void z_policy_proxy_module_init(void);

static inline gboolean 
z_policy_proxy_check(ZPolicyObj *s)
{
  return PyObject_TypeCheck(s, &z_policy_proxy_type);
}

#endif

