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
 * $Id: tpsocket.c,v 1.54 2004/05/06 08:57:08 sasa Exp $
 *
 * Author  : Bazsi
 * Auditor :
 * Last audited version:
 * Notes:
 *
 ***************************************************************************/

#include <zorp/zorp.h>
#include <zorp/socket.h>
#include <zorp/tpsocket.h>
#include <zorp/log.h>
#include <zorp/cap.h>
#include <zorp/sysdep.h>

#include <string.h>
#include <stdlib.h>

#if ENABLE_NETFILTER_TPROXY

#define in_tproxy in_tproxy_v12
#include <zorp/nfiptproxy-kernel.h>
#undef in_tproxy

#include <zorp/nfiptproxy-kernelv2.h>

#endif

const gchar *auto_bind_ip = "1.2.3.4";

static gint sysdep_tproxy;

static gint
z_tp_autobind(gint fd, unsigned short port)
{
  struct sockaddr_in sa;
  socklen_t salen = sizeof(sa);
  struct in_addr ab_addr;
  static unsigned short last_port = 1024;
  gint remaining = 0;
  gint reuse, res;
  socklen_t reuse_size = sizeof(reuse);
  gboolean success = FALSE;
  
  z_enter();
  memset(&sa, 0, sizeof(sa));
  z_inet_aton(auto_bind_ip, &ab_addr);
  if (getsockname(fd, (struct sockaddr *) &sa, &salen) != -1)
    {
      /* already bound */
      if (sa.sin_family == AF_INET && sa.sin_addr.s_addr == ab_addr.s_addr)
        z_return(0);
    }
  
  sa.sin_family = AF_INET;
  sa.sin_addr = ab_addr;
  z_inet_aton(auto_bind_ip, &sa.sin_addr);
  if (port >= 1024 || port == 0)
    {
      if (port == 0)
        port = last_port;
      remaining = 65535 - 1024;
    }

  if (getsockopt(fd, SOL_SOCKET, SO_REUSEADDR, &reuse, &reuse_size) < 0)
    reuse = 0;

  if (reuse)
    {
      gint off = 0;
      setsockopt(fd, SOL_SOCKET, SO_REUSEADDR, &off, sizeof(off));
    }

  do
    {
      sa.sin_port = htons(port);
      res = bind(fd, (struct sockaddr *) &sa, sizeof(sa));
      if (res >= 0)
        {
          /* NOTE: If the bind is successful we still have to increase the port number */
          success = TRUE;
        }
      else if (errno != EADDRINUSE)
        {
          break;
        }
      
      /* Note: port++ statement cannot be refactorized because
       * for ports over 1024 we need to handle the overflow case.
       */
      if (port < 513)
        {
          port++;
          if (port == 513)
            break;
        }
      else if (port < 1024)
        {
          port++;
          if (port == 1024)
            break;
        }
      else
        {
          port++;
          if (port == 0)
            port = 1024;
          last_port = port;
          remaining--;
          if (remaining == 0)
            break;
        }
    }
  while (!success);

  if (reuse)
    {
      gint on = 1;
      gint saved_errno = errno;
      setsockopt(fd, SOL_SOCKET, SO_REUSEADDR, &on, sizeof(on));
      errno = saved_errno;
    }
  
  if (!success)
    {
      /*LOG
        This message indicates that the bind syscall failed for the given reason.
       */
      z_log(NULL, CORE_ERROR, 3, "Error autobinding transparent socket; fd='%d', ip='%s', error='%s'", fd, auto_bind_ip, g_strerror(errno));
      errno = EADDRNOTAVAIL;
      z_return(-1);
    }
  z_return(0);
}

#if ENABLE_NETFILTER_TPROXY || ENABLE_IPFILTER_TPROXY

# if ENABLE_IPFILTER_TPROXY
# else

static gint map_sockopts[] = 
{
  [TPROXY_VERSION] = -1,
  [TPROXY_ASSIGN] = IP_TPROXY_ASSIGN,
  [TPROXY_UNASSIGN] = IP_TPROXY_UNASSIGN,
  [TPROXY_QUERY] = IP_TPROXY_QUERY,
  [TPROXY_FLAGS] = IP_TPROXY_FLAGS,
  [TPROXY_ALLOC] = -2,
  [TPROXY_CONNECT] = -2
};

# endif

static gint
z_tp_set_tproxy_opt(int fd, gint op, void *param, socklen_t paramlen)
{  
  z_enter();

# if ENABLE_NETFILTER_TPROXY
  if (sysdep_tproxy == Z_SD_TPROXY_NETFILTER_V20 ||
      sysdep_tproxy == Z_SD_TPROXY_NETFILTER_V30)
    {
      struct in_tproxy tp20;

      g_assert(sizeof(tp20.v) >= (guint) paramlen);
      tp20.op = op;
      if (param)
        memcpy(&tp20.v, param, paramlen);
      z_return(setsockopt(fd, SOL_IP, IP_TPROXY, &tp20, sizeof(tp20)));
    }
  else
#endif
    {
      /* TProxy 1.2 and IPFilter tproxy */
      gint ip_op = map_sockopts[op];
      if (ip_op >= 0)
        {
          z_leave();
          return setsockopt(fd, SOL_IP, ip_op, param, paramlen);
        }
      else if (ip_op == -1)
        {
          z_leave();
          errno = ENOPROTOOPT;
          return -1;
        }
      z_leave();
      return 0;
    }
  z_leave();
  return -1;
}

static gint
z_tp_get_tproxy_opt(int fd, gint op, void *param, socklen_t *paramlen)
{
  z_enter();

# if ENABLE_NETFILTER_TPROXY
  if (sysdep_tproxy == Z_SD_TPROXY_NETFILTER_V20 ||
      sysdep_tproxy == Z_SD_TPROXY_NETFILTER_V30) 
    {
      struct in_tproxy tp20;
      socklen_t tp20size = sizeof(tp20);
      gint res;
      
      g_assert(sizeof(tp20.v) >= (guint) *paramlen);
      tp20.op = op;
      res = getsockopt(fd, SOL_IP, IP_TPROXY, &tp20, &tp20size);
      g_assert(tp20size == sizeof(tp20));
      if (res >= 0)
        memcpy(param, &tp20.v, *paramlen);
      z_return(res);
    }
  else
# endif
    {
      /* TProxy 1.2 and IPFilter tproxy */
      gint ip_op = map_sockopts[op];
      if (ip_op >= 0)
        {
          z_leave();
          return getsockopt(fd, SOL_IP, ip_op, param, paramlen);
        }
      else if (ip_op == -1)
        {
          z_leave();
          errno = ENOPROTOOPT;
          return -1;
        }
      z_leave();
      return 0;
    }
  z_leave();
  return -1;
}

/*
 * Assign to foreign address
 */
int
z_tp_assign(int fd, in_addr_t faddr, guint16 fport)
{
  struct in_tproxy_addr itpa;
  int ret;

  z_enter();  
  itpa.faddr.s_addr = faddr;
  itpa.fport = fport;
  ret = z_tp_set_tproxy_opt(fd, TPROXY_ASSIGN, &itpa, sizeof(itpa));
  z_return(ret);
}

int
z_tp_set_flags(int fd, int flags)
{
  int ret;
  
  z_enter();
  ret = z_tp_set_tproxy_opt(fd, TPROXY_FLAGS, &flags, sizeof(flags));
  z_return(ret);
}

int
z_tp_get_flags(int fd, int *flags)
{
  socklen_t flagslen = sizeof(*flags);
  int ret;
  
  z_enter();
  ret = z_tp_get_tproxy_opt(fd, TPROXY_FLAGS, flags, &flagslen);
  z_return(ret);
}

int
z_tp_query(int fd, in_addr_t *faddr, guint16 *fport)
{
  struct in_tproxy_addr itpa;
  socklen_t itplen;
  int ret = -1;

  z_enter();
  itplen = sizeof(itpa);
  ret = z_tp_get_tproxy_opt(fd, TPROXY_QUERY, &itpa, &itplen);
  if (ret != -1)
    {
      if (faddr)
        *faddr = itpa.faddr.s_addr;
  
      if (fport)
        *fport = itpa.fport;
    }
  z_return(ret);
}

int
z_tp_connect(int fd, in_addr_t faddr, guint16 fport)
{
  struct in_tproxy_addr itpa;
  int ret;
  
  z_enter();
  itpa.fport = fport;
  itpa.faddr.s_addr = faddr;
  ret = z_tp_set_tproxy_opt(fd, TPROXY_CONNECT, &itpa, sizeof(itpa));
  z_return(ret);
}

int
z_tp_alloc(int fd)
{
  int ret;
  
  z_enter();
  ret = z_tp_set_tproxy_opt(fd, TPROXY_ALLOC, NULL, 0);
  z_return(ret);
}

static gint
z_do_tp_bind(gint fd, struct sockaddr *sa, socklen_t salen, guint32 sock_flags)
{
  struct sockaddr_in *sinp = (struct sockaddr_in *) sa;
  
  z_enter();
  if (sa->sa_family != AF_INET)
    z_return(z_do_ll_bind(fd, sa, salen, sock_flags));
        
  if (z_do_ll_bind(fd, sa, salen, sock_flags) != -1)
    {
      /* we could bind successfully, it was a local address */
      if (sock_flags & ZSF_MARK_TPROXY &&
          ((struct sockaddr_in *) sa)->sin_addr.s_addr != 0)
        {
          /* we don't want NAT, only that -m tproxy matches our session */
          if (z_tp_assign(fd, 0, 0) == -1)
    	    {
    	      /*LOG
    	        This message indicates that setsockopt() syscall failed for
		the given reason.  It is likely that your kernel does not
		have tproxy support.
    	       */
              z_log(NULL, CORE_ERROR, 3, "Error in set_tproxy_opt(TPROXY_ASSIGN), netfilter-tproxy support required; fd='%d', error='%m'", fd);
              z_return(0);
            }
        }
      z_return(0);
    }

  if (errno != EADDRNOTAVAIL)
    z_return(-1);
  /* we couldn't bind because the address was not available, try transparent proxy tricks */
  
  /*
   * NOTE: this code depends on Netfilter/TProxy behaviour, that is it
   * assumes that the NAT code will try to match the NATed port with the
   * original source port.
   *
   * 'loose' binding means that we don't really care about the specific port
   * chosen, we only want to make sure that privileged port remains
   * privileged on the server side. In this case the autobind port is bound
   * appropriately and the NAT code will choose a matching port when
   * calculating the SNAT mapping.
   * 
   * Otherwise we are absolutely sure that we want a specific port, even if
   * it clashes. In this case it does not matter what our autobind port is,
   * we specify a single foreign port as solution.
   */
  if (z_tp_autobind(fd, !(sock_flags & ZSF_LOOSE_BIND) ? 0 : ntohs(sinp->sin_port)) == -1)
    z_return(-1); /* autobind was not successful either */
  if (z_tp_assign(fd, sinp->sin_addr.s_addr, (sock_flags & ZSF_LOOSE_BIND) ? 0 : sinp->sin_port) == -1) 
    {
      /*LOG
        This message indicates that setsockopt() syscall failed for the given reason.
       */
      z_log(NULL, CORE_ERROR, 3, "Error in setsockopt(SOL_IP, IP_TPROXY_ASSIGN), netfilter-tproxy support required; fd='%d', error='%m'", fd);
      z_return(-1);
    }
  z_return(0);
}

static gint
z_do_tp_listen(gint fd, gint backlog, guint32 sock_flags)
{
  int flags;
  
  z_enter();
  if (z_do_ll_listen(fd, backlog, !!(sock_flags & ZSF_ACCEPT_ONE)) == -1)
    z_return(-1);
  if (z_tp_get_flags(fd, &flags) == -1)
    {
      /* this is not a real problem, as it might mean that this socket is
         a unix domain socket */
      z_return(0);
    }

  flags = ITP_LISTEN;
  if (z_tp_set_flags(fd, flags) == -1)
    {
      /*LOG
        This message indicates that setsockopt() syscall failed for the given reason.
       */
      z_log(NULL, CORE_ERROR, 3, "Error in setsockopt(SOL_IP, IP_TPROXY_FLAGS), netfilter-tproxy support required; fd='%d', error='%m'", fd);
      z_return(-1);
    }
  z_return(0);
}

static gint
z_do_tp_connect(gint fd, struct sockaddr *sa, socklen_t salen, guint32 sock_flags G_GNUC_UNUSED)
{
  unsigned int flags;
  
  if (sa->sa_family != AF_INET || z_tp_query(fd, NULL, NULL) == -1)
    {
      return z_do_ll_connect(fd, sa, salen, sock_flags);
    }
  if (z_tp_connect(fd, ((struct sockaddr_in *) sa)->sin_addr.s_addr, ((struct sockaddr_in *) sa)->sin_port) == -1)
    {
      /*LOG
        This message indicates that setsockopt() syscall failed for the given reason.
       */
      z_log(NULL, CORE_ERROR, 3, "Error in setsockopt(SOL_IP, IP_TPROXY_CONNECT), netfilter-tproxy support required; fd='%d', error='%m'", fd);
      return -1;
    }
  
  flags = ITP_CONNECT;
  if (z_tp_set_flags(fd, flags) == -1) 
    {
      /*LOG
        This message indicates that setsockopt() syscall failed for the given reason.
       */
      z_log(NULL, CORE_ERROR, 3, "Error in setsockopt(SOL_IP, IP_TPROXY_FLAGS), netfilter-tproxy support required; fd='%d', error='%m'", fd);
      return -1;
    }
  return z_do_ll_connect(fd, sa, salen, sock_flags);
}

# if ENABLE_NETFILTER_TPROXY

#  ifndef SO_ORIGINAL_DST
#define SO_ORIGINAL_DST 80
#  endif

static gint
z_do_ll_getdestname(gint fd, struct sockaddr *sa, socklen_t *salen, guint32 sock_flags G_GNUC_UNUSED)
{
  return getsockname(fd, sa, salen);
}

static gint
z_do_tp_getdestname(gint fd, struct sockaddr *sa, socklen_t *salen, guint32 sock_flags G_GNUC_UNUSED)
{
  struct sockaddr_in *sin = (struct sockaddr_in *) sa;
  socklen_t sinlen;
  
  if (*salen < sizeof(*sin))
    {
      errno = -EINVAL;
      return -1;
    }
  
  sinlen = sizeof(*sin);
  if (getsockopt(fd, SOL_IP, SO_ORIGINAL_DST, sin, &sinlen) >= 0)
    {
      *salen = sinlen;
      return 0;
    }
  /* Linux 2.2 fallback */
  return z_do_ll_getdestname(fd, sa, salen, sock_flags);
}

# endif
  
static gint
z_do_tp_getsockname(gint fd, struct sockaddr *sa, socklen_t *salen, guint32 sock_flags)
{
  in_addr_t faddr;
  guint16 fport;
  struct sockaddr_in *sin = (struct sockaddr_in *) sa;
  gboolean allocated = FALSE;
  
  do
    {
      if (z_tp_query(fd, &faddr, &fport) == -1) //getsockopt(fd, SOL_IP, IP_TPROXY_QUERY, &itp, &itplen) == -1)
        {
          return z_do_ll_getsockname(fd, sa, salen, sock_flags);
        }
      if (*salen < sizeof(*sin))
        {
          errno = EFAULT;
          return -1;
        }
      sin->sin_family = AF_INET;
      sin->sin_addr.s_addr = faddr;
      sin->sin_port = fport;
      *salen = sizeof(*sin);
      if (sin->sin_port == 0 && !allocated)
        {
          allocated = TRUE;
          if (z_tp_alloc(fd) == -1) //setsockopt(fd, SOL_IP, IP_TPROXY_ALLOC, NULL, 0) == -1)
            {
              z_log(NULL, CORE_ERROR, 3, "Error in setsockopt(SOL_IP, IP_TPROXY_ALLOC), netfilter-tproxy support required; fd='%d', error='%m'", fd);
              return -1;
            }
        }
      else
        break;
    }
  while (1);
  return 0;
}

static ZSocketFuncs z_tp_socket_funcs = 
{
  z_do_tp_bind,
  z_do_ll_accept,
  z_do_tp_connect,
  z_do_tp_listen,
  z_do_tp_getsockname,
  z_do_ll_getpeername,
  z_do_tp_getdestname
};

#ifndef IP_FREEBIND
#define IP_FREEBIND 15
#endif

#ifndef IP_TRANSPARENT
#define IP_TRANSPARENT 19
#endif

static gint
z_do_tp40_bind(gint fd, struct sockaddr *sa, socklen_t salen, guint32 sock_flags)
{
  gint on = 1, res;
  
  z_enter();
  if (sock_flags & ZSF_TRANSPARENT || sock_flags & ZSF_MARK_TPROXY)
    {
      if (setsockopt(fd, SOL_IP, IP_TRANSPARENT, &on, sizeof(on)) < 0)
        setsockopt(fd, SOL_IP, IP_FREEBIND, &on, sizeof(on));
    }
  res = z_do_ll_bind(fd, sa, salen, sock_flags);
  z_return(res);
}

static ZSocketFuncs z_tp40_socket_funcs =
{
  z_do_tp40_bind,
  z_do_ll_accept,
  z_do_ll_connect,
  z_do_ll_listen,
  z_do_ll_getsockname,
  z_do_ll_getpeername,
  z_do_ll_getdestname
};

#endif


gboolean
z_tp_socket_init(gint sysdep_tproxyp)
{
  /* Linux22 doesn't need any magic */
  gboolean res = TRUE;
  
  sysdep_tproxy = sysdep_tproxyp;

#if ENABLE_NETFILTER_TPROXY || ENABLE_IPFILTER_TPROXY
  if (sysdep_tproxy == Z_SD_TPROXY_NETFILTER_V12 ||
      sysdep_tproxy == Z_SD_TPROXY_NETFILTER_V20 ||
      sysdep_tproxy == Z_SD_TPROXY_NETFILTER_V30 ||
      sysdep_tproxy == Z_SD_TPROXY_IPF)
    {
      gint fd;
      
      fd = socket(PF_INET, SOCK_STREAM, 0);
      if (!auto_bind_ip || z_tp_autobind(fd, 0) == -1)
        {
	  /*LOG
	    This message indicates that Zorp was unable to bind to the dummy interface.
	   */
          z_log(NULL, CORE_ERROR, 3, "Binding to dummy interface failed, please create one and pass --autobind-ip parameter; autobind='%s'", auto_bind_ip);
          res = FALSE;
        }
      else
        {
          socket_funcs = &z_tp_socket_funcs;
        }
      close(fd);
    }
  else if (sysdep_tproxy == Z_SD_TPROXY_NETFILTER_V40)
    {
      socket_funcs = &z_tp40_socket_funcs;
    }
  else
#endif
  if (sysdep_tproxy != Z_SD_TPROXY_LINUX22)
    {
      /*LOG
	This message indicates that the required transparency support was not found.
	Check your kernel configuration, or please contact your Zorp support for assistance.
       */
      z_log(NULL, CORE_ERROR, 0, "Required transparency support not compiled in (TCP); sysdep_tproxy='%d'", sysdep_tproxy);
      res = FALSE;
    }
  return res;
}
