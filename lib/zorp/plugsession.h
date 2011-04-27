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
 * $Id: plugsession.h,v 1.4 2003/05/28 12:18:57 bazsi Exp $
 *
 ***************************************************************************/
#ifndef ZORP_PLUGSESSION_H_INCLUDED
#define ZORP_PLUGSESSION_H_INCLUDED

#include <zorp/zorp.h>
#include <zorp/poll.h>
#include <zorp/proxystack.h>

typedef struct _ZPlugSession ZPlugSession;

typedef struct _ZPlugSessionData
{
  gint timeout;
  gboolean copy_to_server, copy_to_client;
  gboolean shutdown_soft;
  guint buffer_size;
  guint packet_stats_interval_time, packet_stats_interval_packet;
  
  gboolean (*packet_stats)(ZPlugSession *self, 
                           guint64 client_bytes, guint64 client_pkts, 
                           guint64 server_bytes, guint64 server_pkts,
                           gpointer user_data);
  void (*finish)(ZPlugSession *self, gpointer user_data);
} ZPlugSessionData;

gboolean z_plug_session_start(ZPlugSession *self, ZPoll *poll);
void z_plug_session_cancel(ZPlugSession *self);
void z_plug_session_register_vars(ZPlugSession *self, ZPolicyDict *dict);

ZPlugSession *
z_plug_session_new(ZPlugSessionData *session_data, 
                   ZStream *client_stream, 
                   ZStream *server_stream, 
                   ZStackedProxy *stacked,
                   gpointer user_data);

void z_plug_session_destroy(ZPlugSession *self);

ZPlugSession *z_plug_session_ref(ZPlugSession *self);
void z_plug_session_unref(ZPlugSession *self);


#endif
