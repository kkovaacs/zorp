/*
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
 */

#ifndef RADIX_H_INCLUDED
#define RADIX_H_INCLUDED

#include <glib.h>
#include <stdio.h>

#define MAX_VALUES 16
#define MAX_KEYLEN 254
#define MAX_CATEGORIES 254

typedef guint8 RIValue;
typedef struct _RINode RINode;

/* num_children: a node can have at most 256 different children due
 * to the pigeonhole principle: if a node has 256 different children,
 * meaning that they have distinct prefixes. Any new nodes to be added
 * would share a prefix of at least 1 characters with an already
 * existing node. The two colliding nodes would become a children node
 * of a new node having the common prefix as key.
 *
 * As the \0 character is not allowed in keys, the actual number of
 * possible children nodes is 255, thus guint8 is enough to store the
 * num_children value.
 */

struct _RINode
{
  gchar *key;
  RINode **children;
  RIValue values[MAX_VALUES];
  gint32 size;
  guint8 keylen;
  guint8 num_values;
  guint8 num_children;
};

RINode *ri_new_empty_node(const gchar *key);
RINode *ri_new_node(const gchar *key, RIValue value);
void ri_free_node(RINode *node);
gint ri_insert_node(RINode *root, const gchar *key, gint keylen, RIValue value);

gboolean ri_serialize(RINode *root, FILE *f);

#endif

