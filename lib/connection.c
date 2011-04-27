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
 * $Id: connection.c,v 1.10 2003/10/09 07:38:29 bazsi Exp $
 *
 * Author  : SaSa
 * Auditor :
 * Last audited version:
 * Notes:
 *
 ***************************************************************************/

#include <zorp/connection.h>
#include <zorp/dispatch.h>

#include <string.h>

/*
 * The ZConnection structure is used by ZAttach and ZDispatch to return
 * connection related information. It basically contains the address of the
 * peer the local bound address and the stream which can be used to
 * communicate with the peer.
 */

/* support functions for ZConnection */
/**
 * z_connection_new:
 *
 * Construct a new ZConnection instance and return a pointer to it.
 **/
ZConnection *
z_connection_new(void)
{
  return g_new0(ZConnection, 1);
}

/**
 * z_connection_format:
 * @conn: ZConnection instance
 * @buf: buffer to put output into
 * @buflen: size of @buf
 *
 * This function creates a textual representation of the ZConnection. It
 * puts its output into @buf ensuring that the output's size does not exceed
 * @buflen.
 * 
 * Returns: the address of the first character in @buf
 **/
gchar *
z_connection_format(ZConnection *conn, gchar *buf, gint buflen)
{
  gchar buf_remote[MAX_SOCKADDR_STRING], buf_local[MAX_SOCKADDR_STRING], buf_dest[MAX_SOCKADDR_STRING];
  
  if (!conn)
    {
      g_strlcpy(buf, "conn='NULL'", buflen);
      return buf;
    }
  
  if (conn->remote)
    z_sockaddr_format(conn->remote, buf_remote, sizeof(buf_remote));
  else
    strcpy(buf_remote, "NULL");
  if (conn->local)
    z_sockaddr_format(conn->local, buf_local, sizeof(buf_local));
  else
    strcpy(buf_local, "NULL");
  if (conn->dest)
    z_sockaddr_format(conn->dest, buf_dest, sizeof(buf_dest));
  else
    strcpy(buf_dest, "NULL");
  g_snprintf(buf, buflen, "protocol='%d', remote='%s', local='%s', dest='%s'", conn->protocol, buf_remote, buf_local, buf_dest);
  return buf;
}

/**
 * z_connection_destroy:
 * @conn: ZConnection instance
 * @close: specifies whether connection to the peer should be closed
 *
 * This function destructs and frees a ZConnection instance.
 **/
void
z_connection_destroy(ZConnection *conn, gboolean close)
{
  if (close)
    z_stream_close(conn->stream, NULL);
  z_sockaddr_unref(conn->remote);
  z_sockaddr_unref(conn->local);
  z_sockaddr_unref(conn->dest);
  z_dispatch_bind_unref(conn->dispatch_bind);
  z_stream_unref(conn->stream);
  g_free(conn);
}
