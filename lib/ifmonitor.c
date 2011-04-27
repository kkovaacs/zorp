#include <zorp/ifmonitor.h>
#include <zorp/log.h>
#include <zorp/socketsource.h>

#include <sys/types.h>
#include <sys/socket.h>
#include <linux/netlink.h>
#include <linux/rtnetlink.h>
#include <net/if.h>

typedef void (*ZNetlinkEventHandlerFunc)(const gchar *msg, gsize msg_len);

typedef struct _ZNetlinkEventHandler
{
  guint16 event;
  ZNetlinkEventHandlerFunc callback;
} ZNetlinkEventHandler;

static GSource *netlink_source;
static gint netlink_fd;
static guint32 netlink_seq;
static GList *netlink_event_handlers;
static gboolean netlink_initialized = FALSE;

/* rtnetlink requests */

gboolean
z_rtnetlink_request_dump(gint type, gint family)
{
  struct 
  {
    struct nlmsghdr h;
    struct rtgenmsg g;
  } nlreq;
  struct sockaddr_nl nladdr;

  memset(&nladdr, 0, sizeof(nladdr));
  nladdr.nl_family = AF_NETLINK;

  memset(&nlreq, 0, sizeof(nlreq));
  nlreq.h.nlmsg_len = sizeof(nlreq);
  nlreq.h.nlmsg_type = type;
  nlreq.h.nlmsg_flags = NLM_F_REQUEST | NLM_F_ROOT | NLM_F_DUMP;
  nlreq.h.nlmsg_seq = netlink_seq++;
  nlreq.h.nlmsg_pid = getpid();
  nlreq.g.rtgen_family = family;
  if (sendto(netlink_fd, (void *) &nlreq, sizeof(nlreq), 0, (struct sockaddr *) &nladdr, sizeof(nladdr)) < 0)
    return FALSE;

  return TRUE;
}

/* generic netlink code */

/* not safe to call from parallel threads */
gboolean
z_netlink_register(gint event, ZNetlinkEventHandlerFunc callback)
{
  ZNetlinkEventHandler *h;

  h = g_new0(ZNetlinkEventHandler, 1);
  h->event = event;
  h->callback = callback;

  netlink_event_handlers = g_list_prepend(netlink_event_handlers, h);
  return TRUE;
}

static gboolean
z_netlink_process_responses(gboolean timed_out G_GNUC_UNUSED, gpointer user_data G_GNUC_UNUSED)
{
  gchar data[4096];
  gssize data_len;
  gsize len;
  struct nlmsghdr *h;
  GList *p;

  data_len = recv(netlink_fd, data, sizeof(data), 0);
  if (data_len < 0)
    {
      z_log(NULL, CORE_ERROR, 1, "Error receiving netlink message; error='%s'", g_strerror(errno));
      return FALSE;
    }

  h = ((struct nlmsghdr *) &data);
  len = data_len;
  while (NLMSG_OK(h, len))
    {
      for (p = netlink_event_handlers; p; p = g_list_next(p))
        {
          ZNetlinkEventHandler *handler = (ZNetlinkEventHandler *) p->data;
          
          if (handler->event == h->nlmsg_type)
            {
              handler->callback((gchar *) h, h->nlmsg_len);
            }
        }
      h = NLMSG_NEXT(h, len);
    }

  return TRUE;
}

void
z_netlink_init(void)
{
  struct sockaddr_nl nladdr;

  netlink_seq = time(NULL);

  netlink_fd = socket(PF_NETLINK, SOCK_DGRAM, NETLINK_ROUTE);
  if (netlink_fd < 0)
    {
      z_log(NULL, CORE_ERROR, 1, "Error opening netlink socket, interface information will not be available; error='%s'", g_strerror(errno));
      return;
    }
  memset(&nladdr, 0, sizeof(nladdr));
  nladdr.nl_family = AF_NETLINK;

  /* FIXME: the exact groups we want to be notified about might change
     depending on the users of this netlink interface */

  nladdr.nl_groups = RTMGRP_IPV4_IFADDR|RTMGRP_LINK;
  if (bind(netlink_fd, (struct sockaddr *) &nladdr, sizeof(nladdr)) < 0)
    {
      z_log(NULL, CORE_ERROR, 1, "Error binding netlink socket, interface information will not be available; error='%s'", g_strerror(errno));
      close(netlink_fd);
      return;
    }

  netlink_source = z_socket_source_new(netlink_fd, G_IO_IN, -1);

  g_source_set_callback(netlink_source, (GSourceFunc) z_netlink_process_responses, NULL, NULL);
  g_source_attach(netlink_source, NULL);
  
  netlink_initialized = TRUE;
}

void
z_netlink_destroy(void)
{
  if (netlink_initialized)
    {
      g_source_destroy(netlink_source);
      g_source_unref(netlink_source);
      netlink_source = NULL;
      close(netlink_fd);
      netlink_initialized = FALSE;
    }
  /* FIXME: free netlink_event_handlers */
}

/* interface address monitoring */

#define Z_IFNAME_MAX IF_NAMESIZE
#define Z_IFADDR_MAX 256

typedef struct ZIfaceInfo
{
  guint index;
  gchar name[Z_IFNAME_MAX];
  guint32 group;
  guint32 flags;
  guint16 in4_address_count;
  struct in_addr in4_addresses[Z_IFADDR_MAX];
} ZIfaceInfo;

struct _ZIfmonWatch
{
  gchar iface_name[Z_IFNAME_MAX];
  gint family;
  ZIfmonWatchFunc callback;
  gpointer user_data;
  GDestroyNotify user_data_destroy;
};

struct _ZIfmonGroupWatch
{
  guint32 group;
  ZIfmonGroupWatchFunc callback;
  gpointer user_data;
  GDestroyNotify user_data_destroy;
};

static GHashTable *iface_hash;
static GList *iface_watches;
static GList *iface_group_watches;
static GStaticMutex iface_watches_lock;
static GStaticMutex iface_group_watches_lock;

static gboolean
match_by_name(guint *ifindex G_GNUC_UNUSED, ZIfaceInfo *info, gchar *iface_name)
{
  return strcmp(info->name, iface_name) == 0;
}

static ZIfaceInfo *
z_ifmon_find_by_name(const gchar *iface_name)
{
  return (ZIfaceInfo *) g_hash_table_find(iface_hash, (GHRFunc) match_by_name, (gchar *) iface_name);
}


static void
z_ifmon_call_watchers_unlocked(const gchar *iface, ZIfChangeType change, gint family, void *addr)
{
  GList *p, *p_next;
  
  for (p = iface_watches; p; p = p_next)
    {
      ZIfmonWatch *w = (ZIfmonWatch *) p->data;

      p_next = g_list_next(p);
      if (strcmp(w->iface_name, iface) == 0 && (!family || w->family == family))
        {
          w->callback(w->iface_name, change, family, addr, w->user_data);
        }
    }
}

static void
z_ifmon_call_watchers(const gchar *iface, ZIfChangeType change, gint family, void *addr)
{
  g_static_mutex_lock(&iface_watches_lock);
  z_ifmon_call_watchers_unlocked(iface, change, family, addr);
  g_static_mutex_unlock(&iface_watches_lock);    
}


static void
z_ifmon_iterate_addrs(ZIfaceInfo *info, ZIfChangeType change)
{
  gint i;

  if (!info)
    return;

  g_static_mutex_lock(&iface_watches_lock);
  for (i = 0; i < info->in4_address_count; i++)
    {
      z_ifmon_call_watchers_unlocked(info->name, change, AF_INET, &info->in4_addresses[i]);
    }
  g_static_mutex_unlock(&iface_watches_lock);    
}


gboolean
z_ifmon_watch_iface_matches(ZIfmonWatch *w, const gchar *if_name)
{
  return strcmp(w->iface_name, if_name) == 0;
}

static inline void
z_ifmon_watch_free(ZIfmonWatch *watch)
{
  if (watch->user_data_destroy)
    watch->user_data_destroy(watch->user_data);
  g_free(watch);
  
}

ZIfmonWatch *
z_ifmon_register_watch(const gchar *iface, gint family, ZIfmonWatchFunc callback, gpointer user_data, GDestroyNotify user_data_destroy)
{
  ZIfmonWatch *w = g_new0(ZIfmonWatch, 1);
  ZIfaceInfo *info;
  
  g_strlcpy(w->iface_name, iface, sizeof(w->iface_name));
  w->callback = callback;
  w->family = family;
  w->user_data = user_data;
  w->user_data_destroy = user_data_destroy;

  /* add all already registered addresses */
  info = z_ifmon_find_by_name(iface);
  if (info && info->flags & IFF_UP)
    {
      gint i;
      
      for (i = 0; i < info->in4_address_count; i++)
        {
          callback(iface, Z_IFC_ADD, AF_INET, &info->in4_addresses[i], user_data);
        }
    }
 
  g_static_mutex_lock(&iface_watches_lock);
  iface_watches = g_list_prepend(iface_watches, w);
  g_static_mutex_unlock(&iface_watches_lock);
  
  return w;
}

void
z_ifmon_unregister_watch(ZIfmonWatch *watch)                         
{
  ZIfaceInfo *info;
  
  info = z_ifmon_find_by_name(watch->iface_name);
  if (info && info->flags & IFF_UP)
    {
      gint i;
      
      for (i = 0; i < info->in4_address_count; i++)
        {
          watch->callback(watch->iface_name, Z_IFC_REMOVE, AF_INET, &info->in4_addresses[i], watch->user_data);
        }
    }
  g_static_mutex_lock(&iface_watches_lock);
  iface_watches = g_list_remove(iface_watches, watch);
  g_static_mutex_unlock(&iface_watches_lock);
  z_ifmon_watch_free(watch);
}

typedef struct _ZIfmonGroupIterState
{
  guint32 group;
  ZIfChangeType change;
  ZIfmonGroupWatch *watch;
} ZIfmonGroupIterState;

static void
z_ifmon_iterate_by_group(guint *ifindex G_GNUC_UNUSED, ZIfaceInfo *info, ZIfmonGroupIterState *state)
{
  if (info->group == state->group)
    {
      state->watch->callback(info->group, state->change, info->name, state->watch->user_data);
    }
}

static void
z_ifmon_call_group_watchers_unlocked(guint32 group, ZIfChangeType change, const gchar *if_name)
{
  GList *p, *p_next;
  
  for (p = iface_group_watches; p; p = p_next)
    {
      ZIfmonGroupWatch *w = (ZIfmonGroupWatch *) p->data;

      p_next = g_list_next(p);
      if (w->group == group)
        {
          w->callback(group, change, if_name, w->user_data);
        }
    }
}

static void
z_ifmon_call_group_watchers(guint32 group, ZIfChangeType change, const gchar *if_name)
{
  g_static_mutex_lock(&iface_group_watches_lock);
  z_ifmon_call_group_watchers_unlocked(group, change, if_name);
  g_static_mutex_unlock(&iface_group_watches_lock);    
}

static void
z_ifmon_iterate_ifaces(guint32 group, ZIfmonGroupWatch *watch, ZIfChangeType change)
{
  ZIfmonGroupIterState state;
  
  state.change = change;
  state.group = group;
  state.watch = watch;
  g_hash_table_foreach(iface_hash, (GHFunc) z_ifmon_iterate_by_group, &state);
}

static inline void
z_ifmon_group_watch_free(ZIfmonGroupWatch *watch)
{
  if (watch->user_data_destroy)
    watch->user_data_destroy(watch->user_data);
  g_free(watch);
  
}

ZIfmonGroupWatch *
z_ifmon_register_group_watch(guint32 group, ZIfmonGroupWatchFunc callback, gpointer user_data, GDestroyNotify user_data_destroy)
{
  ZIfmonGroupWatch *w = g_new0(ZIfmonGroupWatch, 1);
  
  w->group = group;
  w->callback = callback;
  w->user_data = user_data;
  w->user_data_destroy = user_data_destroy;
 
  g_static_mutex_lock(&iface_group_watches_lock);
  iface_group_watches = g_list_prepend(iface_group_watches, w);
  g_static_mutex_unlock(&iface_group_watches_lock);
  /* add all already registered interfaces */
  z_ifmon_iterate_ifaces(group, w, Z_IFC_ADD);
  return w;
}

void
z_ifmon_unregister_group_watch(ZIfmonGroupWatch *watch)                         
{
  g_static_mutex_lock(&iface_group_watches_lock);
  iface_watches = g_list_remove(iface_watches, watch);
  g_static_mutex_unlock(&iface_group_watches_lock);
  z_ifmon_group_watch_free(watch);
}

#ifndef IFLA_IFGROUP
#define IFLA_IFGROUP 20
#endif

/**
 * Parse ifinfomsg netlink message.
 *
 * @param[in] msg netlink message
 * @param[in] msg_len length of message
 * @param[out] if_index interface index
 * @param[out] if_name interface name, only set if the message contains it, otherwise NULL
 * @param[out] if_flags interface flags
 * @param[out] if_group interface group, only set if the message contains it, otherwise 0
 *
 * @note We assume no interface can have a group of 0 so we use that to signal that it has no group. The reason for this assumption is:
 * <pre>
 * # ip link set ipsec3 group 0
 * Error: argument "0" is wrong: "group" value is invalid
 * </pre>
 *
 * @returns TRUE on success
 **/
static inline gboolean
z_ifmon_parse_ifinfo(const gchar *msg, gsize msg_len, guint *if_index, const gchar **if_name, guint16 *if_flags, guint32 *if_group)
{
  struct nlmsghdr *h = (struct nlmsghdr *) msg;
  struct ifinfomsg *ifi;
  struct rtattr *rta;
  gint len;

  /* netlink header */
  if (!NLMSG_OK(h, msg_len))
    return FALSE;

  /* ifinfo header */
  ifi = NLMSG_DATA(h);
  *if_index = ifi->ifi_index;
  *if_flags = ifi->ifi_flags;

  /* attribute list */
  rta = IFLA_RTA(ifi);
  len = IFLA_PAYLOAD(h);

  /* make sure we don't return garbage */
  *if_name = NULL;
  *if_group = 0;

  while (RTA_OK(rta, len))
    {
      switch (rta->rta_type)
        {
        case IFLA_IFNAME:
          *if_name = (gchar *) RTA_DATA(rta);
          break;
        case IFLA_IFGROUP:
          *if_group = *(guint32 *) RTA_DATA(rta);
          break;
        }
      rta = RTA_NEXT(rta, len);
    }
  if (len != 0)
    {
      z_log(NULL, CORE_ERROR, 1, "Error parsing ifinfomsg netlink message;");
      return FALSE;
    }

  return TRUE;
}

static inline gboolean
z_ifmon_parse_ifaddr(const gchar *msg, gsize msg_len, guint *ifa_index, guint *ifa_family, const gchar **ifa_addr)
{
  struct nlmsghdr *h = (struct nlmsghdr *) msg;
  struct ifaddrmsg *ifa;
  struct rtattr *rta;
  gint len;

  /* netlink header */
  if (!NLMSG_OK(h, msg_len))
    return FALSE;

  /* ifaddr header */
  ifa = NLMSG_DATA(h);
  *ifa_index = ifa->ifa_index;
  *ifa_family = ifa->ifa_family;

  /* attribute list */
  rta = IFA_RTA(ifa);
  len = IFA_PAYLOAD(h);

  while (RTA_OK(rta, len))
    {
      switch (rta->rta_type)
        {
        case IFA_LOCAL:
          *ifa_addr = (gchar *) RTA_DATA(rta);
          break;
        }
      rta = RTA_NEXT(rta, len);
    }
  if (len != 0)
    {
      z_log(NULL, CORE_ERROR, 1, "Error parsing ifaddrmsg netlink message;");
      return FALSE;
    }
  
  return TRUE;
}

static void
z_ifmon_add_iface(const gchar *msg, gsize msg_len)
{
  const gchar *if_name = NULL;
  gchar old_ifname[Z_IFNAME_MAX];
  guint32 if_index;
  guint16 if_flags;
  guint32 if_group;
  gboolean new = FALSE;
  ZIfaceInfo *info;
  gboolean old_iface_changed, new_iface_changed;

  if (!z_ifmon_parse_ifinfo(msg, msg_len, &if_index, &if_name, &if_flags, &if_group))
    return;
  /**
   * @note If no interface group is given in the message, if_group is set to 0 by z_ifmon_parse_ifinfo.
   * Since we create the new ZIfaceInfo instance with g_new0, it is zeroed and so its group is zeroed.
   * This means the group check below won't call group watchers if there's no group.
   **/


  info = g_hash_table_lookup(iface_hash, &if_index);
  if (!info)
    {
      info = g_new0(ZIfaceInfo, 1);
      info->index = if_index;
      g_hash_table_insert(iface_hash, &info->index, info);
      new = TRUE;
    }

  /* interface is changed if:
   *  - it is new
   *  - has its name changed (then both old and new iface is changed)
   *  - has its UP flags changed
   */

  /* interface was renamed, old_iface refers to the old name */
  old_iface_changed = !new && if_name && strcmp(info->name, if_name) != 0;
  /* interface with the new/current name was changed */
  new_iface_changed = new || ((info->flags & IFF_UP) != (guint32) (if_flags & IFF_UP)) || old_iface_changed;

  /* send notification */
  if (old_iface_changed)
    {
      /* interface was renamed, remove all IPs associated with old
       * name, provided it was in UP state */

      if (info->flags & IFF_UP)
        z_ifmon_iterate_addrs(info, Z_IFC_REMOVE);
    }

  /* update information */
  g_strlcpy(old_ifname, info->name, sizeof(old_ifname));
  if (if_name)
    g_strlcpy(info->name, if_name, sizeof(info->name));
  info->flags = if_flags;

  if (new_iface_changed)
    {
      if (new)
        {
          /* new interface, immediately in UP state, is it possible at all? */
          if (info->flags & IFF_UP)
            z_ifmon_iterate_addrs(info, Z_IFC_ADD);
        }
      else if (old_iface_changed)
        {
          /* interface was renamed, all add IPs associated with new name, if the interface is up */
          if (info->flags & IFF_UP)
            z_ifmon_iterate_addrs(info, Z_IFC_ADD);
        }
      else if ((info->flags & IFF_UP) == 0)
        {
          /* interface was downed */
          z_ifmon_iterate_addrs(info, Z_IFC_REMOVE);
        }
      else if ((info->flags & IFF_UP) != 0)
        {
          /* interface was upped */
          z_ifmon_iterate_addrs(info, Z_IFC_ADD);
        }
    }
  /* see note below z_ifmon_parse_ifinfo call on why this works if there's no group */
  if (info->group != if_group)
    {
      /* interface group change, remove the old assignment, add the new */
      if (info->group)
        z_ifmon_call_group_watchers(info->group, Z_IFC_REMOVE, info->name);
      info->group = if_group;
      z_ifmon_call_group_watchers(info->group, Z_IFC_ADD, info->name);
    }
    
  if (new)
    {
      z_rtnetlink_request_dump(RTM_GETADDR, PF_PACKET);
      z_log(NULL, CORE_INFO, 4, "Interface added; if_index='%d', if_name='%s', if_flags='%d'", if_index, if_name ? if_name : "unknown", if_flags);
    }
  else
    {
      z_log(NULL, CORE_INFO, 4, "Interface info updated; if_index='%d', if_name='%s', if_flags='0x%x', if_group='0x%x'", if_index, if_name ? if_name : info->name, if_flags, info->group);
    }
}

static void
z_ifmon_del_iface(const gchar *msg, gsize msg_len)
{
  ZIfaceInfo *info;
  guint if_index;
  const gchar *if_name;
  guint32 if_group;
  guint16 if_flags;

  if (!z_ifmon_parse_ifinfo(msg, msg_len, &if_index, &if_name, &if_flags, &if_group))
    return;

  info = g_hash_table_lookup(iface_hash, &if_index);
  if (!info)
    {
      z_log(NULL, CORE_ERROR, 1, "Interface removal message received, but no such interface known; if_index='%d', if_name='%s'", if_index, if_name ? if_name : "unknown");
      return;
    }
  z_log(NULL, CORE_INFO, 4, "Interface removed; if_index='%d', if_name='%s', if_group='0x%x'", info->index, info->name, info->group);
  if ((info->flags & IFF_UP) != 0)
    z_ifmon_iterate_addrs(info, Z_IFC_REMOVE);
  if (info->group)
    z_ifmon_call_group_watchers(info->group, Z_IFC_REMOVE, info->name);
  g_hash_table_remove(iface_hash, &if_index);
}

static void
z_ifmon_change_iface_addr(const gchar *msg, gsize msg_len)
{
  gint nl_type = ((struct nlmsghdr *) msg)->nlmsg_type;
  guint ifa_index;
  guint ifa_family;
  const gchar *ifa_addr = NULL;
  struct in_addr *ina;
  ZIfaceInfo *info;
  gchar buf[32];
  gint i;

  if (!z_ifmon_parse_ifaddr(msg, msg_len, &ifa_index, &ifa_family, &ifa_addr))
    return;

  if (ifa_family != AF_INET)
    return;

  info = g_hash_table_lookup(iface_hash, &ifa_index);
  if (!info)
    {
      z_log(NULL, CORE_INFO, 4, "Interface address message received, but no such interface known; if_index='%d'", ifa_index);
      return;
    }
  ina = (struct in_addr *) ifa_addr;
  for (i = 0; i < info->in4_address_count; i++)
    {
      if (info->in4_addresses[i].s_addr == ina->s_addr)
        break;
    }
  if (i == info->in4_address_count)
    {
      /* not found */
      if (nl_type == RTM_NEWADDR)
        {
          if (i >= Z_IFADDR_MAX)
            {
              z_log(NULL, CORE_ERROR, 1, "Maximum number of addresses assigned to single interface is reached; ifaddr_max='%d'", Z_IFADDR_MAX);
              return;
            }
          info->in4_addresses[i] = *ina;
          info->in4_address_count++;
          z_log(NULL, CORE_INFO, 4, "Address added to interface; if_name='%s', if_addr='%s'", info->name, z_inet_ntoa(buf, sizeof(buf), *ina));
          if (info->flags & IFF_UP)
            z_ifmon_call_watchers(info->name, Z_IFC_ADD, AF_INET, (gchar *) ina);
        }
      else if (nl_type == RTM_DELADDR)
        {
          z_log(NULL, CORE_ERROR, 1, "Address removal message referred to a non-existent address;");
        }
    }
  else
    {
      /* found */
      if (nl_type == RTM_DELADDR)
        {
          z_log(NULL, CORE_INFO, 4, "Address removed from interface; if_name='%s', if_addr='%s'", info->name, z_inet_ntoa(buf, sizeof(buf), *ina));
          memmove(info->in4_addresses + i, info->in4_addresses + i + 1, (info->in4_address_count - i) * sizeof(info->in4_addresses[0]));
          info->in4_address_count--;
          if (info->flags & IFF_UP)
            z_ifmon_call_watchers(info->name, Z_IFC_REMOVE, AF_INET, (gchar *) ina);
        }
    }
}


static const void*
z_ifmon_get_primary_address_impl(const ZIfaceInfo *info, gint family)
{
  if (info == NULL ||
      family != AF_INET ||
      info->in4_address_count == 0)
    {
      return NULL;
    }

  return info->in4_addresses;
}
const void *
z_ifmon_get_primary_address_by_name(const gchar *iface, gint family)
{
  return z_ifmon_get_primary_address_impl(z_ifmon_find_by_name(iface), family);

}

const void *
z_ifmon_get_primary_address(guint ifindex, gint family)
{
  return z_ifmon_get_primary_address_impl(g_hash_table_lookup(iface_hash, &ifindex), family);

}

gboolean
z_ifmon_get_ifindex(const gchar *iface, guint *if_index)
{
 ZIfaceInfo *info = z_ifmon_find_by_name(iface);

  if (info)
  {
    *if_index = info->index;
    return TRUE;
  }
  return FALSE;
}

guint
z_ifmon_get_iface_flags(guint ifindex)
{
  ZIfaceInfo *info = g_hash_table_lookup(iface_hash, &ifindex);
  
  return info ? info->flags : 0;
}

void
z_ifmon_init(void)
{
  z_netlink_init();

  iface_hash = g_hash_table_new_full(g_int_hash, g_int_equal, NULL, g_free);

  z_netlink_register(RTM_NEWLINK, z_ifmon_add_iface);
  z_netlink_register(RTM_DELLINK, z_ifmon_del_iface);
  z_netlink_register(RTM_NEWADDR, z_ifmon_change_iface_addr);
  z_netlink_register(RTM_DELADDR, z_ifmon_change_iface_addr);

  z_rtnetlink_request_dump(RTM_GETLINK, PF_INET);
}

void
z_ifmon_destroy(void)
{
  z_netlink_destroy();
}
