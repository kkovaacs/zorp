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

#ifndef ZORP_DGRAM_H_INCLUDED
#define ZORP_DGRAM_H_INCLUDED

#include <zorp/zorp.h>
#include <zorp/zobject.h>
#include <zorp/listen.h>
#include <zorp/connect.h>

extern ZClass ZDGramListener__class;

gboolean z_dgram_init(gint sysdep_tproxy);

ZListener *
z_dgram_listener_new(const gchar *session_id,
                     ZSockAddr *local,
                     guint32 sock_flags,
                     gint rcvbuf,
                     ZAcceptFunc callback,
                     gpointer user_data);


extern ZClass ZDGramConnector__class;

static inline ZConnector *
z_dgram_connector_new(const gchar *session_id,
                      ZSockAddr *local,
                      ZSockAddr *remote,
                      guint32 sock_flags,
                      ZConnectFunc callback,
                      gpointer user_data,
                      GDestroyNotify destroy_data)
{
  return z_connector_new(Z_CLASS(ZDGramConnector), session_id, SOCK_DGRAM, local, remote, sock_flags, callback, user_data, destroy_data);
}


#endif
