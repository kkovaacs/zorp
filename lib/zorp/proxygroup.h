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
 * $Id: proxy.h,v 1.82 2004/06/11 12:57:39 bazsi Exp $
 *
 ***************************************************************************/

#ifndef ZORP_PROXYGROUP_H_INCLUDED
#define ZORP_PROXYGROUP_H_INCLUDED

#include <zorp/zorp.h>
#include <zorp/proxy.h>
#include <zorp/poll.h>

GMainContext *z_proxy_group_get_context(ZProxyGroup *self);
ZPoll *z_proxy_group_get_poll(ZProxyGroup *self);
gboolean z_proxy_group_start_session(ZProxyGroup *self, ZProxy *proxy);
void z_proxy_group_stop_session(ZProxyGroup *self, ZProxy *proxy);
gboolean z_proxy_group_iteration(ZProxyGroup *self);
void z_proxy_group_wakeup(ZProxyGroup *self);

ZProxyGroup *z_proxy_group_new();
void z_proxy_group_orphan(ZProxyGroup *self);
ZProxyGroup *z_proxy_group_ref(ZProxyGroup *self);
void z_proxy_group_unref(ZProxyGroup *self);


#endif
