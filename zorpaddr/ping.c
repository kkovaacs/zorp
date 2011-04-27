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
 * Author  : Panther
 * Auditor :
 * Last audited version:
 * Notes:
 *
 ***************************************************************************/

#include "ping.h"
#include "ifcfg.h"

#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <sys/time.h>
#include <netinet/ip.h>
#include <unistd.h>
#include <errno.h>
#include <sys/poll.h>
#include <assert.h>
#include <stdlib.h>
#include <fcntl.h>
#include <linux/icmp.h>

#include <glib/gasyncqueue.h>

#include <zorp/log.h>
#include <zorp/thread.h>

#define ICMP_PAYLOAD              8
#define PING_IFACE_MAX            Z_LB_POLICY_MAX * Z_LB_IFACE_MAX

#if PING_IFACE_MAX == 1
# error Z_LB_POLICY_MAX or Z_LB_IFACE_MAX must be greater than 1
#endif

/*
 * Types
 */

typedef struct _ZPingGroup
{
  ZorpAddrGroup * group;
  guint    iface_index;                /* X-reference: interface index in the group */
  gboolean online[Z_I_PING_HOST_MAX];  /* group->hosts[..] is pingable or not */
  guint    online_num;                 /* if zero, this group is down (in fact, actual interface) */
  struct timeval last_seen[Z_I_PING_HOST_MAX];
} ZPingGroup;

typedef struct _ZPingInterface
{
  ZorpAddrInterface *iface;
  ZPingGroup         groups[Z_LB_POLICY_MAX];
  guint              group_num;
  struct in_addr     current_address;
  guint              index;
  guint              sequence_no;
} ZPingInterface;

typedef struct _ZPingConfig
{
  guint           iface_num;                                 /* in 0..PING_IFACE_MAX */
  ZPingInterface  ifaces[PING_IFACE_MAX];
  struct pollfd   pollfds[PING_IFACE_MAX];
} ZPingConfig;

/*
 * Variables
 */
extern ZorpAddrData config;

static ZPingConfig pingconfig;

/* Event queue for ping thread. NULL means no running thread */
static GAsyncQueue *ping_event_queue = NULL;

static gboolean ping_thread_running = FALSE;

/* ICMP packet sequence numbers: least significant bits are reserved, their value is
 in range 0..PING_IFACE_MAX and sequence_num_offset holds the next 2-power number. */
static guint sequence_number_offset;
static guint sequence_number_offset_bits;

/*
 * Forward declarations
 */
static void  z_ping_destroy_thread(void);

static int
in_cksum(u_short *addr, int len)
{
  register int nleft = len;
  register u_short *w = addr;
  register int sum = 0;
  u_short answer = 0;

  /* FIXME: endianness handling ??? */

  /*
   * Our algorithm is simple, using a 32 bit accumulator (sum), we add
   * sequential 16 bit words to it, and at the end, fold back all the
   * carry bits from the top 16 bits into the lower 16 bits.
   */
  while (nleft > 1)
    {
      sum += *w++;
      nleft -= 2;
    }

  /* mop up an odd byte, if necessary */
  if (nleft == 1)
    {
      *(u_char *) (&answer) = *(u_char *) w;
      sum += answer;
    }

  /* add back carry outs from top 16 bits to low 16 bits */
  sum = (sum >> 16) + (sum & 0xffff);	/* add hi 16 to low 16 */
  sum += (sum >> 16);		/* add carry */
  answer = ~sum;		/* truncate to 16 bits */
  return answer;
}

static gint64
diff_time(struct timeval *t1, struct timeval *t2)
{
  return (guint64)(t1->tv_sec - t2->tv_sec) * G_USEC_PER_SEC + (t1->tv_usec - t2->tv_usec);
}

/**
 * send_ping:
 * @raw_sock: the ICMP socket
 * @seq: sequence number of the packet
 * @addr: IPv4 address of the destination
 *
 * Sends an ICMP echo request packet
 *
 * Returns: return value of the sendto() function
 *
 */
static int
send_ping(int raw_sock, int seq, int addr)
{
  struct sockaddr_in to;
  char sendbuf[sizeof(struct icmphdr) + ICMP_PAYLOAD];
  struct icmphdr *icp = (void *) sendbuf;

  to.sin_family = AF_INET;
  to.sin_addr.s_addr = addr;

  icp->type = ICMP_ECHO;
  icp->code = 0;
  icp->checksum = 0;
  icp->un.echo.sequence = seq;
  icp->un.echo.id = getpid();
  icp->checksum = in_cksum((u_short *) icp, sizeof(sendbuf));
#if 0
  gettimeofday(&pending_packets[seq].sent, NULL);
#endif
  return sendto(raw_sock, sendbuf, sizeof(sendbuf), 0, (struct sockaddr *) &to, sizeof(to)) > 0;
}

static int
recv_packet(ZPingInterface *iface)
{
  struct sockaddr_in from;
  char recvbuf[2048];
  struct iphdr *ip = (void *) recvbuf;
  struct icmphdr *icp;
  socklen_t fromlen = sizeof(from);
  int raw_sock = pingconfig.pollfds[iface->index].fd;
  int last_seq_sent = iface->sequence_no;

  int rc = recvfrom(raw_sock, recvbuf, sizeof(recvbuf), 0,
                    (struct sockaddr *) &from, &fromlen);
  if (rc < 0)
    return (errno == EINTR) || (errno == EAGAIN);

  if (rc == 0)
    return 1;

  icp = (void *) (recvbuf + (ip->ihl << 2));
  if (icp->type == ICMP_ECHOREPLY && icp->un.echo.id == getpid())
    {
      int seq = icp->un.echo.sequence;
      if (last_seq_sent >= seq)
        {
          guint grp, host;
           /* our packet */
          assert(seq >= 0);

          for (grp = 0; grp!=iface->group_num;++grp)
            for (host = 0; host != iface->groups[grp].group->host_num; ++host)
              if (iface->groups[grp].group->hosts[host].s_addr == from.sin_addr.s_addr)
                gettimeofday(&iface->groups[grp].last_seen[host], NULL);
        }
    }
  return 1;
}

/**
 * z_ping_icmp_sock_init:
 * @saddr: IP address for bind(). big-endian as in struct in_addr
 *
 * Creates and set up an ICMP socket.
 *
 * Returns: Newly created socket or -1 on error
 *
 */
static int
z_ping_icmp_sock_init(guint saddr)
{
  int icmp_sock = -1;
  struct sockaddr_in source;
  int one = 1;
  struct icmp_filter filt;

  if (G_UNLIKELY(!saddr))
    {
      z_log(NULL, CORE_ERROR, 4, "Invalid source address (0.0.0.0)");
      return -1;
    }

  icmp_sock = socket(AF_INET, SOCK_RAW, IPPROTO_ICMP);
  if (G_UNLIKELY(icmp_sock == -1))
    {
      z_log(NULL, CORE_ERROR, 2, "Unable to create ICMP socket");
      perror("open ICMP socket");
      return -1;
    }

  source.sin_port = 0;
  source.sin_addr.s_addr = saddr;

  if (G_UNLIKELY(bind(icmp_sock, (struct sockaddr*) &source, sizeof(source)) == -1))
    {
      z_log(NULL, CORE_ERROR, 2, "Unable to bind to local address: '%s'", inet_ntoa(source.sin_addr));
      return -1;
    }

  if (setsockopt(icmp_sock, SOL_IP, IP_RECVERR, (char *)&one, sizeof(one)))
    z_log(NULL, CORE_INFO, 6, "The kernel seems old");

  filt.data = ~((1<<ICMP_SOURCE_QUENCH)|
                 (1<<ICMP_DEST_UNREACH)|
                 (1<<ICMP_TIME_EXCEEDED)|
                 (1<<ICMP_ECHOREPLY));
  if (setsockopt(icmp_sock, SOL_RAW, ICMP_FILTER,  (char*)&filt, sizeof(filt)) == -1)
    z_log(NULL, CORE_INFO, 4, "Unable to set ICMP_FILTER socket option");

  return icmp_sock;
}

inline static void
z_ping_setup_pollfd(struct pollfd *pfd, const ZPingInterface *iface)
{
  pfd->fd = z_ping_icmp_sock_init(iface->current_address.s_addr);
  pfd->events = POLLIN;

  if (pfd->fd == -1)
    z_log(NULL, CORE_ERROR, 3, "unable to initialize ICMP socket on interface '%s'", iface->iface->name);
  else
   iface->iface->status |= Z_IFCFG_PING;
}

inline static void
z_ping_shutdown_pollfd(struct pollfd *pfd)
{
  if (pfd->fd == -1)
    return;
  close(pfd->fd);
  pfd->fd = -1;
}

static void
z_ping_event_update(ZorpAddrInterface *iface)
{
  guint if_idx;

  if (!pingconfig.iface_num)
    {
      z_log(NULL, CORE_INFO, 2, "Update event: Trying to update a non-added interface");
      return;
    }

  for (if_idx = 0; if_idx != pingconfig.iface_num; ++if_idx)
    {
      if (pingconfig.ifaces[if_idx].iface == iface)
        break;
    }

  if (if_idx == pingconfig.iface_num)
    {
      z_log(NULL, CORE_INFO, 2, "Update event: Trying to update a non-added interface");
      return;
    }

  if (pingconfig.ifaces[if_idx].iface->address.s_addr == pingconfig.ifaces[if_idx].current_address.s_addr)
    return;

  /* restart socket */
  z_ping_shutdown_pollfd(&pingconfig.pollfds[if_idx]);

  pingconfig.ifaces[if_idx].current_address.s_addr = iface->address.s_addr;

  /* Currently ping does not yet work */
  iface->status &= ~Z_IFCFG_ALIVE;

  z_ping_setup_pollfd(&pingconfig.pollfds[if_idx], &pingconfig.ifaces[if_idx]);
}

static void
z_ping_event_add(ZorpAddrInterface *iface)
{
  ZPingInterface *pingiface = &pingconfig.ifaces[pingconfig.iface_num];
  guint i;

  /* Try to set up the socket. If it fails, the interface won't be used by
    this thread */
  pingiface->index = pingconfig.iface_num;
  pingiface->iface = iface;
  pingiface->current_address.s_addr = iface->address.s_addr;
  pingiface->sequence_no = pingiface->index + sequence_number_offset;

  z_ping_setup_pollfd(&pingconfig.pollfds[pingconfig.iface_num], pingiface);

  if (pingconfig.pollfds[pingconfig.iface_num].fd != -1)
    {
      z_log(NULL, CORE_INFO, 6, "Interface added, accessible host list cleared; iface='%s'", iface->name);
      ++pingconfig.iface_num;
    }
  else
    {
      z_log(NULL, CORE_INFO, 4, "Interface couldn't added, icmp bind (setup) failed; iface='%s'", iface->name);
      z_log(NULL, CORE_INFO, 4, "Interface is marked as alive in all groups; iface='%s'", iface->name);

      for (i = 0; i != iface->iface_data_num; ++i)
        {
          iface->iface_data[i]->status |= Z_IFCFG_ALIVE;
          iface->iface_data[i]->status &= ~Z_IFCFG_PING;
        }

      return;
    }

  for (i = 0; i != iface->iface_data_num; ++i)
    {
      pingiface->groups[pingiface->group_num].group = &config.groups[iface->iface_data[i]->group];
      /* XXX: By default all host is inaccessible. If interface changes occure too often
       * this is probably problematic. */
      pingiface->groups[pingiface->group_num].online_num = 0;
      memset(pingiface->groups[pingiface->group_num].online, 0,
             sizeof(pingiface->groups[pingiface->group_num].online));
      memset(pingiface->groups[pingiface->group_num].last_seen, 0,
             sizeof(pingiface->groups[pingiface->group_num].last_seen));
      pingiface->groups[pingiface->group_num].iface_index = iface->iface_data[i]->index;

      /* Currently ping does not yet work but there is a socket for it */
      iface->iface_data[i]->status &= ~Z_IFCFG_ALIVE;
      iface->iface_data[i]->status |= Z_IFCFG_PING;
      z_log(NULL, CORE_INFO, 4, "Interface is marked as down; name='%s', group='%s'",
            iface->name, pingiface->groups[pingiface->group_num].group->name);
      ++pingiface->group_num;
    }
}

static void
z_ping_event_remove(ZorpAddrInterface *iface)
{
  guint if_idx;

  if (!pingconfig.iface_num)
    {
      z_log(NULL, CORE_INFO, 2, "Trying to remove a non-added interface; iface='%s'", iface->name);
      return;
    }
  for (if_idx = 0; if_idx != pingconfig.iface_num; ++if_idx)
    {
      if (pingconfig.ifaces[if_idx].iface == iface)
        break;
    }

  if (if_idx == pingconfig.iface_num)
    {
      z_log(NULL, CORE_INFO, 2, "Trying to remove a non-added interface; iface='%s'", iface->name);
      return;
    }

  z_ping_shutdown_pollfd(&pingconfig.pollfds[if_idx]);

  if (if_idx + 1 != pingconfig.iface_num)
    {
      memmove(pingconfig.ifaces + if_idx,
             pingconfig.ifaces + if_idx + 1,
             (pingconfig.iface_num - if_idx) * sizeof(ZPingInterface));
      memmove(pingconfig.pollfds + if_idx,
             pingconfig.pollfds + if_idx + 1,
             (pingconfig.iface_num - if_idx) * sizeof(struct pollfd));
    }
  --pingconfig.iface_num;
}

/**
 * z_ping_iface_send_ping: send a ping packet to all hosts
 * @iface: the interface
 *
 * Send a ping packet to all hosts in the groups of the interface.
 * If a host exists in multiple groups, multiple packets will be send.
 */
inline static void
z_ping_iface_send_ping(ZPingInterface * iface)
{
 guint grp, j;
 iface->sequence_no += sequence_number_offset;

 for (grp = 0; grp != iface->group_num; ++grp)
  {
    for (j = 0; j != iface->groups[grp].group->host_num; ++j)
      {
        send_ping(pingconfig.pollfds[iface->index].fd,
                  iface->sequence_no,
                  iface->groups[grp].group->hosts[j].s_addr);
      }
  }
}

static void
z_ping_send_pings(void)
{
  guint i;

  for (i = 0; i != pingconfig.iface_num; ++i)
    z_ping_iface_send_ping(&pingconfig.ifaces[i]);
}

static void
z_ping_update_stats(void)
{
  guint i, grp, host;

  for (i = 0; i != pingconfig.iface_num; ++i)
    {
      if (pingconfig.pollfds[i].revents & POLLIN)
          recv_packet(&pingconfig.ifaces[i]);

      for (grp = 0; grp != pingconfig.ifaces[i].group_num; ++grp)
        {
          /* Used as a temporary variable to let the current value if 'online_num'
             untouched during calculating the new value  */
          guint up_count = 0;
          guint old_up_count = pingconfig.ifaces[i].groups[grp].online_num;
          struct timeval current_time;

          if (!pingconfig.ifaces[i].groups[grp].group->host_num)
            continue;

          gettimeofday(&current_time, NULL);

          for (host = 0; host !=  pingconfig.ifaces[i].groups[grp].group->host_num; ++host)
            {
              if (diff_time(&current_time, &pingconfig.ifaces[i].groups[grp].last_seen[host]) <= 10 * G_USEC_PER_SEC)
                {
                  pingconfig.ifaces[i].groups[grp].online[host] = TRUE;
                  ++up_count;
                }
              else
                {
                  pingconfig.ifaces[i].groups[grp].online[host] = FALSE;
                }
            }

          pingconfig.ifaces[i].groups[grp].online_num = up_count;

          if (up_count)
            {
              if (!old_up_count)
                z_log(NULL, CORE_INFO, 4, "Interface is alive; name='%s', group '%s'",
                      pingconfig.ifaces[i].iface->name,
                      pingconfig.ifaces[i].groups[grp].group->name);
              pingconfig.ifaces[i].groups[grp].group->ifaces[pingconfig.ifaces[i].groups[grp].iface_index].status  |= Z_IFCFG_ALIVE;
}
          else
            {
              if (old_up_count)
                z_log(NULL, CORE_INFO, 4, "Interface is down; name='%s', group '%s'",
                      pingconfig.ifaces[i].iface->name,
                      pingconfig.ifaces[i].groups[grp].group->name);
              pingconfig.ifaces[i].groups[grp].group->ifaces[pingconfig.ifaces[i].groups[grp].iface_index].status  &= ~Z_IFCFG_ALIVE;
            }
        }
    }
}

/**
 * z_pingthread_main_func:
 * @funcarg: not used
 *
 *  Managing event queue:
 *   - STOP event
 *   - ADD/REMOVE/UPDATE: passed to another function:_change on the interface
 *
 * Returns: nothing (NULL)
 *
 */
gpointer
z_ping_thread_main_func(gpointer funcarg G_GNUC_UNUSED)
{
  ZPingUpdateData *event = NULL;
  int status;
  struct timeval current_time, start_time, next_send_time;

  ping_thread_running = TRUE;

  gettimeofday(&start_time, NULL);
  next_send_time.tv_sec = start_time.tv_sec;
  next_send_time.tv_usec = start_time.tv_usec;

  sequence_number_offset =  1;
  sequence_number_offset_bits =  0;

  while( sequence_number_offset <= PING_IFACE_MAX)
    {
      sequence_number_offset <<= 1;
      ++sequence_number_offset_bits;
    }

  while (1)
    {
      event = g_async_queue_try_pop(ping_event_queue);
      if (event)
        {
          if (event->action == Z_PING_STOP)
            {
              z_trace(NULL, "Thread stopping event;");
              break;
            }
          else
            switch (event->action)
              {
              case Z_PING_ADD:
                z_trace(NULL, "Interface add event;");
                z_ping_event_add(event->iface);
                break;
              case Z_PING_UPDATE:
                z_trace(NULL, "Interface update event;");
                z_ping_event_update(event->iface);
                break;
              case Z_PING_REMOVE:
                z_trace(NULL, "Interface remove event;");
                z_ping_event_remove(event->iface);
                break;
              default:
                z_trace(NULL, "Unknown interface event;");
                break;
              }
          g_free(event);
        }

        gettimeofday(&current_time, NULL);

        if (diff_time(&next_send_time, &current_time) <= 0)
          {
            z_ping_send_pings();
            ++next_send_time.tv_sec;
          }

        status = poll(pingconfig.pollfds, pingconfig.iface_num, 100);
        z_ping_update_stats();
        if (status > 0)
          usleep(2000);
    }

  if (event)
    g_free(event);
  z_ping_destroy_thread();
  ping_thread_running = FALSE;
  return NULL;
}

void
z_ping_add_update_data(ZPingUpdateData *update_data)
{
  if (!ping_event_queue)
    return;
  g_async_queue_push(ping_event_queue, update_data);
}

/**
 * z_ping_init:
 *
 * Check whether or not the config file contains ping info.
 * If not: SKIP.
 * If does:
 *     - creates an asynchronous queue of messages
 *     - starts a new thread
 */
void
z_ping_init(void)
{
  gboolean need_start = FALSE;
  guint i;

  pingconfig.iface_num = 0;

  for (i = 0; i != config.group_num; ++i)
    {
      if (config.groups[i].host_num)
        {
          need_start = TRUE;
          break;
        }
    }

  if (!need_start)
    {
      z_log(NULL, CORE_INFO, 6, "Ping thread doesn't need to be started;");
      return;
    }
  else
    {
      z_log(NULL, CORE_INFO, 6, "Ping thread will be started;");
    }

  ping_event_queue = g_async_queue_new();
  z_thread_new("pinger_thread", z_ping_thread_main_func, NULL);
}

/**
 * z_ping_destroy_nowait:
 *
 * Sends a STOP event to the ping thread to let it terminate.
 */
void
z_ping_destroy_nowait(void)
{
  ZPingUpdateData *data;
  if (!ping_event_queue)
    return;

  data = g_new0(ZPingUpdateData, 1);
  data->action = Z_PING_STOP;

  z_log(NULL, CORE_INFO, 6, "Sending termination request event to pinger thread;");
  z_ping_add_update_data(data);
  pingconfig.iface_num = 0;
}

/**
 * z_ping_destroy:
 *
 * Calls z_ping_destroy_nowait() and then waits until it doesn't finish.
 */
void
z_ping_destroy(void)
{
  z_ping_destroy_nowait();

  while (ping_thread_running)
    usleep(0.0005);
}

static void
z_ping_destroy_thread(void)
{
  GAsyncQueue *tmp_que = ping_event_queue;
  ping_event_queue = NULL;

  ZPingUpdateData *data;

  /* consume all remaining data */
  while ((data = g_async_queue_try_pop(tmp_que)))
    g_free(data);

  g_async_queue_unref(tmp_que);
}

