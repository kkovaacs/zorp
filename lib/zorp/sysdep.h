/***************************************************************************
 *
 * Copyright (c) 2000, 2001 BalaBit IT Ltd, Budapest, Hungary
 * All rights reserved.
 *
 * $Id: sysdep.h,v 1.11 2004/02/18 09:05:29 sasa Exp $
 *
 ***************************************************************************/

#ifndef ZORP_SYSDEP_H_INCLUDED
#define ZORP_SYSDEP_H_INCLUDED

#include <zorp/zorp.h>

#define Z_SD_TPROXY_LINUX22       1
#define Z_SD_TPROXY_NETFILTER_V12 2
#define Z_SD_TPROXY_IPF           3
#define Z_SD_TPROXY_NETFILTER_V20 4
#define Z_SD_TPROXY_NETFILTER_V30 5
#define Z_SD_TPROXY_NETFILTER_V40 6

gboolean z_sysdep_init(const gchar *sysdep_tproxy_arg);
void z_sysdep_destroy(void);

#endif
