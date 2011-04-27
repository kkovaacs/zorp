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

#include "zshmem.h"
#include "ifcfg.h"

#include <zorp/log.h>

#include <sys/types.h>
#include <sys/mman.h>
#include <fcntl.h>
#include <time.h>

static void        *mmapped = NULL;
static int          shm_fd;
extern ZorpAddrData config;

static void
z_shmem_copy_data(void)
{
  guint32 i, j;
  ZorpBalanceShmemData *mapped = (ZorpBalanceShmemData *)mmapped;
  ZorpBalanceStruct *data;

  if (!mmapped)
    return;

  data = &mapped->data;

  if (!config.valid)
    {
      z_shmem_invalidate();
      return;
    }

  mapped->size = Z_LB_SHMEM_SIZE;
  data->policy_num = config.group_num;

  for (i=0; i!=config.group_num; ++i)
    {
      strcpy(data->policies[i].name, config.groups[i].name);
      data->policies[i].iface_num = config.groups[i].iface_num;

      for (j=0; j!=config.groups[i].iface_num; ++j)
        {
          data->policies[i].ifaces[j].ipaddr  = config.groups[i].ifaces[j].iface->address.s_addr;
          data->policies[i].ifaces[j].percent = config.groups[i].ifaces[j].real_pref;
        }
    }

  z_shmem_validate();
}

void
z_shmem_reload(void)
{
  if (mmapped)
    memset(mmapped, 0, sizeof (ZorpBalanceShmemData));
  z_shmem_copy_data();
}

void
z_shmem_clear(void)
{
  memset(mmapped, 0, sizeof(ZorpBalanceShmemData));
  z_shmem_invalidate();
}

static void *
z_shmem_get_shmem(void)
{
  char c = 0;
  void *mapped = NULL;

  if (mmapped)
    return mmapped;

  if (-1 == (shm_fd = shm_open(Z_LB_SHMEM_NAME, O_RDWR|O_CREAT, 00644)))
    if (-1 == (shm_fd = shm_open(Z_LB_SHMEM_NAME, O_RDWR, 00644)))
      goto exit_error;

  if (-1 == lseek(shm_fd, Z_LB_SHMEM_SIZE-1, SEEK_SET))
    goto exit_error;

  if (-1 == write(shm_fd,&c , 1))
    goto exit_error;

  if (MAP_FAILED == (mapped = mmap(NULL, Z_LB_SHMEM_SIZE, PROT_READ|PROT_WRITE,
                                   MAP_SHARED, shm_fd, 0)))
    goto exit_error;

  return mapped;
exit_error:
  if (shm_fd != -1)
    {
      close(shm_fd);
    }
  z_log(NULL, CORE_ERROR, 4, "Couldn't open shared memory;");
  return NULL;
}

void
z_shmem_init(void)
{
  mmapped = z_shmem_get_shmem();
  if (mmapped)
    z_shmem_copy_data();
}

void z_shmem_destroy(void)
{
  z_shmem_invalidate();
  if (mmapped)
    munmap(mmapped, Z_LB_SHMEM_SIZE);
  close(shm_fd);
}

void z_shmem_update_ip_address(guint32 group, guint32 iface, __be32 addr)
{
  if (NULL == mmapped)
    return;
  ((ZorpBalanceShmemData *)mmapped)->data.policies[group].ifaces[iface].ipaddr = addr;
}

void z_shmem_update_preference(guint32 group, guint32 iface, gint preference)
{
  if (NULL == mmapped)
    return;

  ((ZorpBalanceShmemData *)mmapped)->data.policies[group].ifaces[iface].percent = preference;
}

void
z_shmem_invalidate()
{
  ZorpBalanceShmemData *mapped = (ZorpBalanceShmemData *)mmapped;

  if (!mapped)
    return;

  mapped->data.timestamp = 0;
  mapped->size = -1;
}

void
z_shmem_validate()
{
  guint32 current_time;
  gint i;
  gint checksum = 0;
  ZorpBalanceShmemData *mapped = (ZorpBalanceShmemData *)mmapped;

  if (!mmapped)
    return;

  current_time = time(NULL);
  mapped->data.timestamp = current_time > mapped->data.timestamp ? current_time : mapped->data.timestamp + 1;

  mapped->size = Z_LB_SHMEM_SIZE;

  for (i = 0; i != Z_LB_SHMEM_SIZE - 4; ++i)
    checksum += ((gchar *)mmapped)[i];

  mapped->checksum = checksum;
}
