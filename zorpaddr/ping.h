#ifndef ZORP_PING_H_INCLUDED
#define ZORP_PING_H_INCLUDED

#include "ifcfg.h"

enum z_ping_action {
  Z_PING_STOP,           /* Extremal value indicating last item  in the queue */
  Z_PING_ADD,            /* New interface */
  Z_PING_REMOVE,         /* Interface is down or has no IP address */
  Z_PING_UPDATE,         /* Primary IP address propably changed */
};

/* this is added to an asynchronous queue */
typedef struct _ZPingUpdateData
{
  enum z_ping_action action;
  ZorpAddrInterface *iface;
} ZPingUpdateData;

void z_ping_add_update_data(ZPingUpdateData *data);

void z_ping_init(void);
void z_ping_destroy(void);

void z_ping_destroy_nowait(void);

#endif
