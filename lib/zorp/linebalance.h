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

#ifndef ZORP_LINEBALANCE_H_INCLUDED
#define ZORP_LINEBALANCE_H_INCLUDED

#include <glib/gtypes.h>

/* NOTE: For the meaning of this defines please see
 * http://specwiki.balabit/ZorpLineBalance.
 * And please keep it being syncronized.
 */
#define Z_LB_SHMEM_NAME "/zorpaddr"
#define Z_LB_SHMEM_SIZE 9808
#define Z_LB_POLICY_NAME_MAX 256
#define Z_LB_POLICY_MAX 31
#define Z_LB_IFACE_MAX 7

typedef struct _ZorpBalanceIface
{
  guint32  ip;
  guint32  pref;
} ZorpBalanceIface;

/* An inteface in a policy (group) */
typedef struct _ZorpBalancePolicyInterface
{
  guint32 ipaddr;
  gint32 percent;
} ZorpBalancePolicyInterface;

typedef struct _ZorpBalancePolicy
{
  gchar name[Z_LB_POLICY_NAME_MAX];
  guint32 iface_num;
  ZorpBalancePolicyInterface ifaces[Z_LB_IFACE_MAX];
} ZorpBalancePolicy;

typedef struct _ZorpBalanceStruct
{
  guint32 timestamp;
  guint32 policy_num;
  ZorpBalancePolicy policies[Z_LB_POLICY_MAX];
} ZorpBalanceStruct;

/* This data type is mapped to the shared memory */
typedef struct _ZorpBalanceShmemData
{
  guint32           size;
  ZorpBalanceStruct data;
  guint32           checksum;
} ZorpBalanceShmemData;

#endif
