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

#ifndef ZORP_PROXYSTACK_H_INCLUDED
#define ZORP_PROXYSTACK_H_INCLUDED

#include <zorp/proxy.h>

typedef struct _ZStackedProxy ZStackedProxy;

enum
{
  Z_SPF_HALF_DUPLEX=0x0001
};

/* structure describing a stacked proxy instance */
struct _ZStackedProxy
{
  ZRefCount ref_cnt;
  GStaticMutex destroy_lock;
  gboolean destroyed;
  guint32 flags;
  ZStream *downstreams[EP_MAX];
  ZStream *control_stream;
  ZProxy *proxy;
  ZProxy *child_proxy;
};

enum
{
  Z_STACK_PROXY = 1,
  Z_STACK_PROGRAM = 2,
  Z_STACK_REMOTE = 3,
  Z_STACK_PROVIDER = 4,
  Z_STACK_CUSTOM = 5,
};

gboolean z_proxy_stack_remote_handshake(ZSockAddr *sa, const gchar *stack_info, ZStream **client, ZStream **server, ZStream **control, guint32 *stack_flags);
gboolean z_proxy_stack_object(ZProxy *self, ZPolicyObj *stack_obj, ZStackedProxy **stacked, ZPolicyDict *stack_info);

ZStackedProxy *z_stacked_proxy_new(ZStream *client_stream, ZStream *server_stream, ZStream *control_stream, ZProxy *proxy, ZProxy *child_proxy, guint32 flags);
void z_stacked_proxy_destroy(ZStackedProxy *self);

#endif
