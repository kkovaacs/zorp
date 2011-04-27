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
 * Stream like operations for datagram based protocols.
 *
 * Author  : Bazsi
 * Auditor :
 * Last audited version:
 * Notes:
 *
 ***************************************************************************/

#include <zorp/dgram.h>
#include <zorp/streamfd.h>
#include <zorp/log.h>
#include <zorp/io.h>
#include <zorp/tpsocket.h>
#include <zorp/cap.h>
#include <zorp/sysdep.h>

#if ENABLE_NETFILTER_TPROXY

#if ENABLE_NETFILTER_TPROXY_V12_FALLBACK
#define in_tproxy in_tproxy_v12
#include <zorp/nfiptproxy-kernel.h>
#undef in_tproxy
#endif

#include <zorp/nfiptproxy-kernelv2.h>

#endif

#define ZDS_LISTEN	0x0001
#define ZDS_ESTABLISHED	0x0002

typedef struct _ZDgramSocketFuncs
{
  gint (*open)(guint flags, ZSockAddr *remote, ZSockAddr *local, guint32 sock_flags, gint tos, GError **error);
  gboolean (*setup)(gint fd, guint flags, gint tos);
  GIOStatus (*recv)(gint fd, ZPktBuf **pack, ZSockAddr **from, ZSockAddr **to, gint *tos, gboolean peek, GError **error);
} ZDgramSocketFuncs;


/* Wrapper functions calling the underlying OS specific routines */

static ZDgramSocketFuncs *dgram_socket_funcs;

/**
 * z_dgram_socket_open:
 *
 * Generic dgram_socket_open, will use the enabled one of _l22_, _nf_ or _ipf_.
 */
static gint 
z_dgram_socket_open(guint flags, ZSockAddr *remote, ZSockAddr *local, guint32 sock_flags, gint tos, GError **error)
{
  return dgram_socket_funcs->open(flags, remote, local, sock_flags, tos, error);
}

/**
 * z_dgram_socket_setup:
 *
 * Generic dgram_socket_setup, will use the system dependent implementation _l22_ or _nf_.
 */
static gboolean
z_dgram_socket_setup(gint fd, guint flags, gint tos)
{
  return dgram_socket_funcs->setup(fd, flags, tos);
}

/**
 * z_dgram_socket_recv:
 *
 * Generic dgram_socket_recv, will use the enabled one of _l22_, _nf_ or _ipf_.
 */
GIOStatus 
z_dgram_socket_recv(gint fd, ZPktBuf **pack, ZSockAddr **from, ZSockAddr **to, gint *tos, gboolean peek, GError **error)
{
  return dgram_socket_funcs->recv(fd, pack, from, to, tos, peek, error);
}

/* OS dependant low-level functions */

#if ENABLE_LINUX22_TPROXY || ENABLE_NETFILTER_LINUX22_FALLBACK

/**
 * z_l22_dgram_socket_open:
 * @flags: Additional flags: ZDS_LISTEN for incoming, ZDS_ESTABLISHED for outgoing socket
 * @remote: Address of the remote endpoint
 * @local: Address of the local endpoint
 * @sock_flags: Flags for binding, see 'z_bind' for details
 * @error: not used
 *
 * Create a new UDP socket - Linux 2.2 ipf version.
 *
 * Returns:
 * -1 on error, socket descriptor otherwise
 */
gint
z_l22_dgram_socket_open(guint flags, ZSockAddr *remote, ZSockAddr *local, guint32 sock_flags, gint tos, GError **error G_GNUC_UNUSED)
{
  gint fd;
  
  z_enter();
  fd = socket(z_map_pf(local->sa.sa_family), SOCK_DGRAM, 0);
  if (fd < 0)
    {
      /*LOG
        This message indicate that Zorp failed opening a new socket.
        It is likely that Zorp reached some resource limit.
       */
      z_log(NULL, CORE_ERROR, 3, "Error opening socket; error='%s'", g_strerror(errno));
      close(fd);
      z_return(-1);
    }

  if (!z_dgram_socket_setup(fd, flags, tos))
    {
      /* z_dgram_socket_setup() already issued a log message */
      close(fd);
      z_return(-1);
    }
  
  if (flags & ZDS_LISTEN)
    {
      if (z_bind(fd, local, sock_flags) != G_IO_STATUS_NORMAL)
        {
          /* z_bind already issued a log message */
          close(fd);
          z_return(-1);
        }
    }
  else if (flags & ZDS_ESTABLISHED)
    {
      if (local && z_bind(fd, local, sock_flags) != G_IO_STATUS_NORMAL)
        {
          close(fd);
          z_return(-1);
        }
      if (connect(fd, &remote->sa, remote->salen) == -1)
        {
          /*LOG
            This message indicates that Zorp was unable to establish a UDP connection.
           */
          z_log(NULL, CORE_ERROR, 3, "Error connecting UDP socket (l22); error='%s'", g_strerror(errno));
          close(fd);
          z_return(-1);
        }
    }
  z_return(fd);
}

/**
 * z_l22_dgram_socket_setup:
 * @fd: Socket descriptor to set up
 * @flags: Flags for binding, see 'z_bind' for details
 *
 * Returns:
 * FALSE if the setup operation failed, TRUE otherwise
 */
gboolean
z_l22_dgram_socket_setup(gint fd, guint flags, gint tos)
{
  gint tmp = 1;

  z_enter();
  setsockopt(fd, SOL_SOCKET, SO_REUSEADDR, &tmp, sizeof(tmp));
  tmp = 1;
  setsockopt(fd, SOL_SOCKET, SO_BROADCAST, &tmp, sizeof(tmp));
  if (flags & ZDS_LISTEN)
    {
#if ZORPLIB_ENABLE_TOS
      /* enable receiving TOS on this socket */
      tmp = 1;
      if (setsockopt(fd, SOL_IP, IP_RECVTOS, &tmp, sizeof(tmp)) < 0)
        {
          z_log(NULL, CORE_ERROR, 3, "Error during setsockopt(SOL_IP, IP_RECVTOS); error='%s'", g_strerror(errno));
          z_return(FALSE);
        }
#endif
    }
  else if (flags & ZDS_ESTABLISHED)
    {
      /* set TOS of packets sent from this socket */
      z_fd_set_our_tos(fd, tos);
    }
  z_return(TRUE);
}

/**
 * z_l22_dgram_socket_recv:
 * @fd: Socket descriptor to read from
 * @packet: The received packet
 * @from_addr: Address of the remote endpoint
 * @to_addr: Address of the local endpoint
 * @error: not used
 *
 * Receive data from an UDP socket and encapsulate it in a ZPktBuf.
 * Provides address information about the source and destination of
 * the packet. - Linux 2.2 ipf version.
 *
 * Returns:
 * The status of the operation
 */
GIOStatus
z_l22_dgram_socket_recv(gint fd, ZPktBuf **packet, 
                    ZSockAddr **from_addr, ZSockAddr **to_addr, 
                    gint *tos,
                    gboolean peek,
                    GError **error G_GNUC_UNUSED)
{
  struct sockaddr_in from;
  gchar buf[65536], ctl_buf[64];
  struct msghdr msg;
  struct iovec iov;
  struct cmsghdr *cmsg;
  gint rc;
  
  z_enter();
  memset(&msg, 0, sizeof(msg));
  msg.msg_name = &from;
  msg.msg_namelen = sizeof(from);
  msg.msg_controllen = sizeof(ctl_buf);
  msg.msg_control = ctl_buf;
  msg.msg_iovlen = 1;
  msg.msg_iov = &iov;
  iov.iov_base = buf;
  iov.iov_len = sizeof(buf);
  do
    {                
      rc = recvmsg(fd, &msg, MSG_PROXY | (peek ? MSG_PEEK : 0));
    }
  while (rc < 0 && errno == EINTR);
  
  if (rc < 0)
    z_return(errno == EAGAIN ? G_IO_STATUS_AGAIN : G_IO_STATUS_ERROR);

  *packet = z_pktbuf_new();
  z_pktbuf_copy(*packet, buf, rc);
  *from_addr = z_sockaddr_inet_new2(&from);
  if (to_addr)
    {
      if (((struct sockaddr_in *) &from.sin_zero)->sin_family)
        {
          *to_addr = z_sockaddr_inet_new2((struct sockaddr_in *) &from.sin_zero);
        }
      else
        {
          struct sockaddr_in to;
          socklen_t tolen = sizeof(to);
          
          getsockname(fd, (struct sockaddr *) &to, &tolen);
          *to_addr = z_sockaddr_inet_new2(&to);
        }
    }
  if (tos)
    {
      for (cmsg = CMSG_FIRSTHDR(&msg); cmsg; cmsg = CMSG_NXTHDR(&msg, cmsg))
        {
          if (cmsg->cmsg_level == SOL_IP && cmsg->cmsg_type == IP_TOS)
            {
              *tos = *(guchar *) CMSG_DATA(cmsg);
              break;
            }
        }
    }
  z_return(G_IO_STATUS_NORMAL);
  
}

ZDgramSocketFuncs z_l22_dgram_socket_funcs = 
{
  z_l22_dgram_socket_open,
  z_l22_dgram_socket_setup,
  z_l22_dgram_socket_recv
};

#endif

#if ENABLE_NETFILTER_TPROXY

#include <zorp/nfiptproxy-kernelv2.h>

#ifndef IP_RECVORIGADDRS_V12
#define IP_RECVORIGADDRS_V12 16
#define IP_ORIGADDRS_V12     17
#endif

#endif


#if ENABLE_NETFILTER_TPROXY || ENABLE_IPFILTER_TPROXY
static gint z_nf_recvorigaddrs_opt = -1;

#if ENABLE_NETFILTER_TPROXY
static gint z_nf_origaddrs_opt = -1;
#endif /* ENABLE_NETFILTER_TPROXY */


/**
 * z_nf_dgram_socket_open:
 * @flags: Additional flags: ZDS_LISTEN for incoming, ZDS_ESTABLISHED for outgoing socket
 * @remote: Address of the remote endpoint
 * @local: Address of the local endpoint
 * @sock_flags: Flags for binding, see 'z_bind' for details
 * @error: not used
 *
 * Create a new UDP socket - netfilter tproxy version
 * FIXME: some words about the difference
 *
 * Returns:
 * -1 on error, socket descriptor otherwise
 */
gint
z_nf_dgram_socket_open(guint flags, ZSockAddr *remote, ZSockAddr *local, guint32 sock_flags, gint tos, GError **error G_GNUC_UNUSED)
{
  gint fd;
  guint32 ip;
  guint16 port;
  
  z_enter();
  g_assert(local != NULL);
  fd = socket(z_map_pf(local->sa.sa_family), SOCK_DGRAM, 0);
  if (fd < 0)
    {
      /*LOG
        This message indicate that Zorp failed opening a new socket.
        It is likely that Zorp reached some resource limit.
       */
      z_log(NULL, CORE_ERROR, 3, "Error opening socket; error='%s'", g_strerror(errno));
      close(fd);
      z_return(-1);
    }

  if (!z_dgram_socket_setup(fd, flags, tos))
    {
      /* z_dgram_socket_setup() already issued a log message */
      close(fd);
      z_return(-1);
    }
  
  if (flags & ZDS_LISTEN)
    {
      if (z_bind(fd, local, sock_flags) != G_IO_STATUS_NORMAL)
        z_return(-1); /* z_bind already issued a log message */
      if ((z_tp_query(fd, NULL, NULL) != -1) &&
          (z_tp_set_flags(fd, ITP_LISTEN | ITP_UNIDIR) < 0))
        {
          /*LOG
            This message indicates that the setsockopt failed, and Zorp can not listen on a foreign address.
            */
          z_log(NULL, CORE_ERROR, 3, "Error during setsockopt(SOL_IP, IP_TPROXY_FLAGS, ITP_LISTEN | ITP_UNIDIR); error='%s'", g_strerror(errno));
          close(fd);
          z_return(-1);
        }
    }
  else if (flags & ZDS_ESTABLISHED)
    {
      struct sockaddr_in local_sa;
      socklen_t local_salen = sizeof(local_sa);

      if (z_bind(fd, local, sock_flags) != G_IO_STATUS_NORMAL)
        {
          close(fd);
          z_return(-1);
        }

      /* NOTE: we use connect instead of z_connect, as we do tproxy calls ourselves */
      if (connect(fd, &remote->sa, remote->salen) < 0)
        {
          /*LOG
            This message indicates that UDP connection failed.
           */
          z_log(NULL, CORE_ERROR, 3, "Error connecting UDP socket (nf); error='%s'", g_strerror(errno));
          close(fd);
          z_return(-1);
        }

      /* get fully specified bind address (local might have a wildcard port number) */
      if (getsockname(fd, (struct sockaddr *) &local_sa, &local_salen) < 0)
        {
          /*LOG
            This message indicates that Zorp was unable to query the local address.
          */
          z_log(NULL, CORE_ERROR, 3, "Error querying local address (nf); error='%s'", g_strerror(errno));
          close(fd);
          z_return(-1);
        }

      /* test if it was a foreign address: an assignment exists and is not mark only */
      if ((z_tp_query(fd, &ip, &port) != -1) &&
          ((local_sa.sin_addr.s_addr != ip) || (local_sa.sin_port != port)))
        {
          z_tp_connect(fd, ((struct sockaddr_in *) &remote->sa)->sin_addr.s_addr, ((struct sockaddr_in *) &remote->sa)->sin_port);
          if (z_tp_set_flags(fd, ITP_ESTABLISHED) < 0)
            {
              /*LOG
               */
              z_log(NULL, CORE_ERROR, 3, "Error during setsockopt(SOL_IP, IP_TPROXY_FLAGS, ITP_ESTABLISHED); error='%s'", g_strerror(errno));
              close(fd);
              z_return(-1);
            }
        }
    } /* flags & ZDS_ESTABLISHED */
  z_return(fd);
}

/**
 * z_nf_dgram_socket_setup:
 * @fd: Socket descriptor to set up
 * @flags: Flags for binding, see 'z_bind' for details
 *
 * Returns:
 * FALSE if the setup operation failed, TRUE otherwise
 */
gboolean
z_nf_dgram_socket_setup(gint fd, guint flags, gint tos)
{
  gint tmp = 1;

  z_enter();
  setsockopt(fd, SOL_SOCKET, SO_REUSEADDR, &tmp, sizeof(tmp));
  tmp = 1;
  setsockopt(fd, SOL_SOCKET, SO_BROADCAST, &tmp, sizeof(tmp));
  if (flags & ZDS_LISTEN)
    {
      tmp = 1;
      if (z_nf_recvorigaddrs_opt != -1 && setsockopt(fd, SOL_IP, z_nf_recvorigaddrs_opt, &tmp, sizeof(tmp)) < 0)
        {
          /*LOG
            This message indicates that the setsockopt failed.
          */
          z_log(NULL, CORE_ERROR, 3, "Error during setsockopt(SOL_IP, IP_RECVORIGADDRS); error='%s'", g_strerror(errno));
          z_return(FALSE);
        }
#if ZORPLIB_ENABLE_TOS
      tmp = 1;
      if (setsockopt(fd, SOL_IP, IP_RECVTOS, &tmp, sizeof(tmp)) < 0)
        {
          z_log(NULL, CORE_ERROR, 3, "Error during setsockopt(SOL_IP, IP_RECVTOS); error='%s'", g_strerror(errno));
          z_return(FALSE);
        }
#endif
    }
  else if (flags & ZDS_ESTABLISHED)
    {
      z_fd_set_our_tos(fd, tos);
    }
  z_return(TRUE);
}

#endif /* ENABLE_NETFILTER_TPROXY || ENABLE_IPFILTER_TPROXY */

#if ENABLE_NETFILTER_TPROXY

/**
 * z_nf_dgram_socket_recv:
 * @fd: Socket descriptor to read from
 * @packet: The received packet
 * @from_addr: Address of the remote endpoint
 * @to_addr: Address of the local endpoint
 * @error: not used
 *
 * Receive data from an UDP socket and encapsulate it in a ZPktBuf.
 * Provides address information about the source and destination of
 * the packet. - netfilter tproxy version.
 * FIXME: some words about the difference
 *
 * Returns:
 * The status of the operation
 */
GIOStatus
z_nf_dgram_socket_recv(gint fd, ZPktBuf **packet, ZSockAddr **from_addr, ZSockAddr **to_addr, gint *tos, gboolean peek, GError **error G_GNUC_UNUSED)
{
  struct sockaddr_in from, to;
  gchar buf[65536], ctl_buf[64];
  struct msghdr msg;
  struct cmsghdr *cmsg;
  struct iovec iov;
  gint rc;
  
  z_enter();
  memset(&msg, 0, sizeof(msg));
  msg.msg_name = &from;
  msg.msg_namelen = sizeof(from);
  msg.msg_controllen = sizeof(ctl_buf);
  msg.msg_control = ctl_buf;
  msg.msg_iovlen = 1;
  msg.msg_iov = &iov;
  iov.iov_base = buf;
  iov.iov_len = sizeof(buf);
  do
    {
      rc = recvmsg(fd, &msg, peek ? MSG_PEEK : 0);
    }
  while (rc < 0 && errno == EINTR);
  
  if (rc < 0)
    z_return(errno == EAGAIN ? G_IO_STATUS_AGAIN : G_IO_STATUS_ERROR);

  *packet = z_pktbuf_new();
  z_pktbuf_copy(*packet, buf, rc);
  if (from_addr || to_addr || tos)
    {
      if (from_addr)
        *from_addr = NULL;
      if (to_addr)
        *to_addr = NULL;
      if (tos)
        *tos = -1;

      for (cmsg = CMSG_FIRSTHDR(&msg); cmsg; cmsg = CMSG_NXTHDR(&msg,cmsg))
        {
          if (to_addr && cmsg->cmsg_level == SOL_IP && cmsg->cmsg_type == z_nf_origaddrs_opt)
            {
              struct in_origaddrs *ioa = (struct in_origaddrs *) CMSG_DATA(cmsg);

              if (ioa->ioa_dstaddr.s_addr && ioa->ioa_dstport)
                {
                  to.sin_family = AF_INET;
                  to.sin_addr = ioa->ioa_dstaddr;
                  to.sin_port = ioa->ioa_dstport;
                  *to_addr = z_sockaddr_inet_new2(&to);
                }

              /* override source address returned by recvmsg */
              if (ioa->ioa_srcaddr.s_addr && ioa->ioa_srcport)
                {
                  from.sin_family = AF_INET;
                  from.sin_addr = ioa->ioa_srcaddr;
                  from.sin_port = ioa->ioa_srcport;
                }
            }
          else if (tos && cmsg->cmsg_level == SOL_IP && cmsg->cmsg_type == IP_TOS)
            {
              memcpy(tos, CMSG_DATA(cmsg), sizeof(*tos));
            }
        }

      if (to_addr && *to_addr == NULL)
        {
          struct sockaddr_in to;
          socklen_t tolen = sizeof(to);
                             
          getsockname(fd, (struct sockaddr *) &to, &tolen);
          *to_addr = z_sockaddr_inet_new2(&to);
        }

      if (from_addr)
        *from_addr = z_sockaddr_inet_new2(&from);
    }
  z_return(G_IO_STATUS_NORMAL);
  
}

ZDgramSocketFuncs z_nf_dgram_socket_funcs = 
{
  z_nf_dgram_socket_open,
  z_nf_dgram_socket_setup,
  z_nf_dgram_socket_recv
};

#endif /* ENABLE_NETFILTER_TPROXY */


/**
 * z_dgram_init:
 * @sysdep_tproxy: Required functionality to use: Z_SD_TPROXY_[LINUX22|NETFILTER_V12|NETFILTER_V20]
 *
 * Module initialisation, initialises the function table according to the
 * requested transparency method.
 *
 * Returns:
 * TRUE on success
 */
gboolean
z_dgram_init(gint sysdep_tproxy)
{
  z_enter();
  switch (sysdep_tproxy)
    {
#if ENABLE_LINUX22_TPROXY
    case Z_SD_TPROXY_LINUX22:
      dgram_socket_funcs = &z_l22_dgram_socket_funcs;
      break;
#endif
#if ENABLE_NETFILTER_TPROXY
    case Z_SD_TPROXY_NETFILTER_V12:
      z_nf_recvorigaddrs_opt = IP_RECVORIGADDRS_V12;
      z_nf_origaddrs_opt = IP_ORIGADDRS_V12;
      dgram_socket_funcs = &z_nf_dgram_socket_funcs;
      break;
      
    case Z_SD_TPROXY_NETFILTER_V20:
    case Z_SD_TPROXY_NETFILTER_V30:
      z_nf_recvorigaddrs_opt = IP_RECVORIGADDRS;
      z_nf_origaddrs_opt = IP_ORIGADDRS;
      
    case Z_SD_TPROXY_NETFILTER_V40:
      dgram_socket_funcs = &z_nf_dgram_socket_funcs;
      break;
#endif
    default:
      /*LOG
        This message indicates that Zorp was compiled without the required transparency support for UDP, or bad 
        transparency support was specified on command line.
        Check your "instances.conf" or your kernel tproxy capabilities.
       */
      z_log(NULL, CORE_ERROR, 0, "Required transparency support not compiled in (UDP); sysdep_tproxy='%d'", sysdep_tproxy);
      z_return(FALSE);
    }
  z_return(TRUE);
} 

/* Datagram listener */

typedef struct _ZDGramListener 
{
  ZListener super;
  gint rcvbuf;
  gint session_limit;
} ZDGramListener;

ZClass ZDGramListener__class;

static gint
z_dgram_listener_open_listener(ZListener *s)
{
  ZDGramListener *self = Z_CAST(s, ZDGramListener);
  gint fd;

  z_enter();
  fd = z_dgram_socket_open(ZDS_LISTEN, NULL, s->bind_addr, s->sock_flags, -1, NULL);
  if (fd == -1)
    {
      /*LOG
        This message indicate that the creation of a new socket failed
        for the given reason. It is likely that the system is running low
        on memory, or the system is running out of the available fds.
       */
      z_log(s->session_id, CORE_ERROR, 2, "Cannot create socket; error='%s'", g_strerror(errno));
      z_return(-1);
    }
  z_fd_set_nonblock(fd, 1);
  if (self->rcvbuf &&
      setsockopt(fd, SOL_SOCKET, SO_RCVBUF, &self->rcvbuf, sizeof(self->rcvbuf)) < 0)
    {
      z_log(s->session_id, CORE_ERROR, 2, "Cannot set receive buffer size on listening datagram socket; error='%s'", g_strerror(errno));
      close(fd);
      z_return(-1);
    }

  if (z_getsockname(fd, &s->local, s->sock_flags) != G_IO_STATUS_NORMAL)
    {
      z_log(s->session_id, CORE_ERROR, 2, "Cannot query local address of listening datagram socket; error='%s'", g_strerror(errno));
      close(fd);
      z_return(-1);
    }
  z_return(fd);
}

static GIOStatus
z_dgram_listener_accept_connection(ZListener *self, ZStream **fdstream, ZSockAddr **client, ZSockAddr **dest)
{
  gint newfd;
  GIOStatus res;
  ZSockAddr *from = NULL, *to = NULL;
  gint tos;
  ZPktBuf *packet;
  static gboolean udp_accept_available = TRUE;
  cap_t saved_caps;

  z_enter();
  /* FIXME: using accept() on UDP sockets requires kernel extension */
  if (udp_accept_available)
    {
      saved_caps = cap_save();
      cap_enable(CAP_NET_ADMIN);
      cap_enable(CAP_NET_BIND_SERVICE);
      res = z_accept(self->fd, &newfd, client, self->sock_flags);
      if (res != G_IO_STATUS_NORMAL)
        {
          if (errno == EOPNOTSUPP)
            {
              cap_restore(saved_caps);
              udp_accept_available = FALSE;
              goto no_udp_accept;
            }
          else
            {
              if (errno != EAGAIN)
                z_log(self->session_id, CORE_ERROR, 1, "Error accepting on listening dgram socket; fd='%d', error='%s'", self->fd, g_strerror(errno));
              cap_restore(saved_caps);
              z_return(res);
            }
        }

      cap_restore(saved_caps);

      /* this socket behaves like a listening one when we're reading the first packet to
       * determine the original destination address */
      if (!z_dgram_socket_setup(newfd, ZDS_LISTEN, 0))
        {
          close(newfd);
          z_return(G_IO_STATUS_ERROR);
        }

      /* we are not allowed to block on this operation, as due to a
       * race condition it's possible that accept() returns an fd
       * which has nothing in its queue */
      z_fd_set_nonblock(newfd, 1);
      *dest = NULL;
      res = z_dgram_socket_recv(newfd, &packet, &from, &to, &tos, TRUE, NULL);
      if (res == G_IO_STATUS_AGAIN)
        {
          z_log(self->session_id, CORE_ERROR, 4, "No datagram messages are available in accepted socket; error='%s'", g_strerror(errno));
          close(newfd);
          z_return(G_IO_STATUS_ERROR);
        }

      if (res != G_IO_STATUS_NORMAL)
        {
          z_log(self->session_id, CORE_ERROR, 3, "Error determining original destination address for datagram connection; error='%s'", g_strerror(errno));
          res = G_IO_STATUS_NORMAL;
        }
      else
        {
          z_pktbuf_unref(packet);
          *dest = to;
        }

      z_fd_set_nonblock(newfd, 0);
      /* once we have the original address we set up the socket for establised mode;
       * this includes setting the TOS to the appropriate value */
      if (!z_dgram_socket_setup(newfd, ZDS_ESTABLISHED, tos))
        {
          res = G_IO_STATUS_ERROR;
          goto error_after_recv;
        }
      z_sockaddr_unref(from);
      *fdstream = z_stream_fd_new(newfd, "");
    }
  else
    {
 no_udp_accept:
      *client = NULL;
      *dest = NULL;
      res = z_dgram_socket_recv(self->fd, &packet, &from, &to, &tos, FALSE, NULL);
      /* FIXME: fetch all packets in the receive buffer to be able to stuff
       * all to the newly created socket */
      if (res == G_IO_STATUS_ERROR || from == NULL || to == NULL || packet == NULL)
        {
          z_log(self->session_id, CORE_ERROR, 1, "Error receiving datagram on listening stream; fd='%d', error='%s'", self->fd, g_strerror(errno));
        }
      else
        {
          newfd = z_dgram_socket_open(ZDS_ESTABLISHED, from, to, ZSF_MARK_TPROXY, tos, NULL);
          if (newfd < 0)
            {
              z_log(self->session_id, CORE_ERROR, 3, "Error creating session socket, dropping packet; error='%s'", g_strerror(errno));
              res = G_IO_STATUS_ERROR;
            }
          else
            {
              *fdstream = z_stream_fd_new(newfd, "");
              if (*fdstream && !z_stream_unget_packet(*fdstream, packet, NULL))
                {
                  z_pktbuf_unref(packet);
                  z_log(self->session_id, CORE_ERROR, 3, "Error creating session socket, dropping packet;");
                  close(newfd);
                }
              else
                {
                  *client = z_sockaddr_ref(from);
                  *dest = z_sockaddr_ref(to);
                }
            }
          z_sockaddr_unref(from);
          z_sockaddr_unref(to);
        }
    }
  z_return(res);

error_after_recv:
  if (*dest != NULL)
    {
      z_sockaddr_unref(*dest);
      *dest = NULL;
    }
  z_sockaddr_unref(from);
  close(newfd);
  z_return(res);
}

ZListener *
z_dgram_listener_new(const gchar *session_id,
                     ZSockAddr *local,
                     guint32 sock_flags,
                     gint rcvbuf,
                     ZAcceptFunc callback,
                     gpointer user_data)
{
  ZDGramListener *self;
  
  self = Z_CAST(z_listener_new(Z_CLASS(ZDGramListener), session_id, local, sock_flags, callback, user_data), ZDGramListener);
  if (self)
    {  
      self->rcvbuf = rcvbuf;
      self->session_limit = 10;
    }
  return &self->super;
}

ZListenerFuncs z_dgram_listener_funcs = 
{
  {
    Z_FUNCS_COUNT(ZListener),
    NULL,
  },
  z_dgram_listener_open_listener,
  z_dgram_listener_accept_connection
};

ZClass ZDGramListener__class = 
{
  Z_CLASS_HEADER,
  .super_class = Z_CLASS(ZListener),
  .name = "ZDGramListener",
  .size = sizeof(ZDGramListener),
  .funcs = &z_dgram_listener_funcs.super
};


/* datagram connector */

static ZConnectorFuncs z_dgram_connector_funcs =
{
  {
    Z_FUNCS_COUNT(ZConnector),
    NULL,
  }
};
    
ZClass ZDGramConnector__class =
{
  Z_CLASS_HEADER,
  .super_class = Z_CLASS(ZConnector),
  .name = "ZDGramConnector",
  .size = sizeof(ZConnector),
  .funcs = &z_dgram_connector_funcs.super
};
