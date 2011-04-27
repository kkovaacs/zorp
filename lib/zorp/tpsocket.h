/***************************************************************************
 *
 * Copyright (c) 2000, 2001, 2002 BalaBit IT Ltd, Budapest, Hungary
 * All rights reserved.
 *
 * $Id: tpsocket.h,v 1.8 2004/02/18 09:05:29 sasa Exp $
 *
 * Author  : Bazsi
 * Auditor :
 * Last audited version:
 * Notes:
 *
 ***************************************************************************/

#ifndef ZORP_TPROXY_H_INCLUDED
#define ZORP_TPROXY_H_INCLUDED

#include <zorp/socket.h>

extern const gchar *auto_bind_ip;

gboolean z_tp_socket_init(gint sysdep_tproxy);

int z_tp_assign(int fd, in_addr_t faddr, guint16 fport);
int z_tp_set_flags(int fd, int flags);
int z_tp_get_flags(int fd, int *flags);
int z_tp_connect(int fd, in_addr_t faddr, guint16 fport);
int z_tp_query(int fd, in_addr_t *faddr, guint16 *fport);
int z_tp_alloc(int fd);


#endif
