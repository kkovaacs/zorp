/*
 * Transparent proxy support for Linux/iptables
 *
 * Copyright (c) 2002 BalaBit IT Ltd.
 * Author: Balázs Scheidler 
 *
 * This code is under GPLv2.
 */

#ifndef _IP_TPROXY_OLD_H
#define _IP_TPROXY_OLD_H

#ifdef __KERNEL__
#include <linux/types.h>
#include <linux/in.h>
#else
#include <netinet/in.h>
#endif

/* 
 * used in setsockopt(SOL_IP, IP_TPROXY_*) should not collide 
 * with values in <linux/in.h> 
 */
#define IP_TPROXY_ASSIGN   20
#define IP_TPROXY_UNASSIGN 21
#define IP_TPROXY_QUERY    22
#define IP_TPROXY_FLAGS    23
#define IP_TPROXY_ALLOC    24
#define IP_TPROXY_CONNECT  25

/* bitfields in IP_TPROXY_FLAGS */
#define ITP_CONNECT     0x00000001
#define ITP_LISTEN      0x00000002
#define ITP_ESTABLISHED 0x00000004

#define ITP_ONCE        0x00010000
#define ITP_MARK        0x00020000
#define ITP_APPLIED     0x00040000
#define ITP_UNIDIR      0x00080000

/* structure passed to setsockopt(SOL_IP, IP_TPROXY) */
struct in_tproxy {
	struct in_addr itp_faddr;
	u_int16_t itp_fport;
};

#endif
