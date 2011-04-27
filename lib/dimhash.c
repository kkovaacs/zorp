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
 * $Id: dimhash.c,v 1.15 2003/04/11 14:44:59 sasa Exp $
 *
 * Author  : SaSa
 * Auditor :
 * Last audited version:
 * Notes:
 *
 ***************************************************************************/

#include <zorp/dimhash.h>
#include <zorp/log.h>

#include <string.h>

/*
 * ZDimHashTable - Multi-dimensional hash table
 *
 * Similar to the linear hashes where the elements are (key, value) pairs,
 * but here the key is a vector, so the values occupy an N-dimensional space,
 * where N is the length of the key vector.
 * 
 * Operations of this class include creating/destroying such tables (providing
 * the ability of using custom deallocator functions for values),
 * inserting into and deleting from the tables, searching for an exact match
 * of a key vector (it may even contain unspecified elements), and recursive
 * searching also.
 * 
 */


/**
 * z_dim_hash_key_free:
 * @num Number of dimensions (==key parts)
 * @key Key vector
 *
 * Deallocates a key vector
 */
void
z_dim_hash_key_free(int num, gchar **key)
{
  int i;
  
  z_enter();
  for (i = 0; i < num; i++)
    {
      if (key[i])
        g_free(key[i]);
    }
  g_free(key);
  z_return();
}


/**
 * z_dim_hash_nextstep:
 * @key Key to alter
 * @flags Flag that specify the required modification
 *
 * Helper for z_dim_hash_table_rec_search:
 * Alter key according to flags. If flags is DIMHASH_WILDCARD, then clear key,
 * if it's DIMHASH_CONSUME, then trim the last character only.
 *
 * Returns: Whether the operation was possible
 */
static gboolean
z_dim_hash_nextstep(gchar *key, guint flags)
{
  gboolean ret;
  
  z_enter();
  if (!flags || (*key == 0))
    z_return(FALSE);
  
  switch (flags)
    {
    case DIMHASH_WILDCARD:
      *key = 0;
      ret = TRUE;
      break;
      
    case DIMHASH_CONSUME:
      key[strlen(key)-1] = 0;
      ret = TRUE;
      break;
      
    default:
      ret = FALSE;
      break;
    }
  z_return(ret);
}


/**
 * z_dim_hash_table_makekey:
 * @new_key Destination of the composite key
 * @key_len Length of the destination buffer
 * @self Not used
 * @num Number of dimensions (key parts)
 * @key_parts Keys for dimensions, empty string or "*" means 'not specified'
 *
 * Creates a composite key from the dimensional key parts. The composite key
 * is a '::'-separated concatenation of the parts.
 * 
 * Returns: TRUE on success, FALSE if the destination buffer is too short
 */
static gboolean
z_dim_hash_table_makekey(gchar *new_key, guint key_len, ZDimHashTable *self G_GNUC_UNUSED, guint num, gchar **key_parts)
{
  guint keylen;
  guint i;
  
  z_enter();
  keylen = 0;
  for (i = 0; i < num; i++)
    keylen += strlen(key_parts[i]);
  
  memset(new_key, 0, key_len);
  if (keylen > key_len)
    z_return(FALSE);
  
  if (key_parts[0][0] != 0 && (key_parts[0][1] != 0 || key_parts[0][0] != '*'))
    strcpy(new_key, key_parts[0]);

  for (i = 1; i < num; i++)
    {
      strcat(new_key, "::");
      if (key_parts[i][0] != 0 && (key_parts[i][1] != 0 || key_parts[i][0] != '*'))
        strcat(new_key, key_parts[i]);
    }
  z_return(TRUE);
}


/**
 * z_dim_hash_table_rec_search:
 * @self ZDimHashTable to search in
 * @num Number of specified keys
 * @num Depth of recursivity, the index of the currently processed key (internal)
 * @keys The current state of the key vector that's searched for
 * @save_keys The original key vector to search for
 *
 * Performs a recursive (depth) search for a key vector.
 * First it tries to find an exact match, then processes the last key according
 * to the flags of self (either DIMHASH_WILDCARD=wipe it at once or
 * DIMHASH_CONSUME=shrink it char-by-char), and tries to find a match.
 * If no match found, performs the same on the one-but-last and the last key,
 * and so on.
 *
 * Returns: NULL if no matching entry found, the first matching entry otherwise
 */
static gpointer *
z_dim_hash_table_rec_search(ZDimHashTable *self, guint num, guint i, gchar **keys, gchar **save_keys)
{
  gpointer *ret;
  gchar key[DIMHASH_MAX_KEYNUM * (DIMHASH_MAX_KEYSIZE + 2) + 1];
  guint keylen = DIMHASH_MAX_KEYNUM * (DIMHASH_MAX_KEYSIZE + 2) + 1;

  z_enter();
  if (i < num)
    {
      strcpy(keys[i], save_keys[i]);
      ret = z_dim_hash_table_rec_search(self, num, i + 1, keys, save_keys);
      while (!ret && z_dim_hash_nextstep(keys[i], self->flags[i]))
        ret = z_dim_hash_table_rec_search(self, num, i + 1, keys, save_keys);
      z_return(ret);
    }
  if (z_dim_hash_table_makekey(key, keylen, self, num, keys) &&
      (key != NULL))
    {
      ret = g_hash_table_lookup(self->hash, key);
      z_return(ret);
    }
  z_return(NULL);
}


/**
 * z_dim_hash_table_new:
 * @minnum Minimal number of specified dimensions for operations 
 * @num Number of dimensions
 * @vararg Flags for the dimensions
 *
 * Create a new ZDimHashTable instance
 * The flags of the dimensions may be either DIMHASH_WILDCARD or DIMHASH_CONSUME,
 * specifying what modifications shall be performed on the key when doing a
 * recursive search (see z_dim_hash_table_rec_search).
 */
ZDimHashTable *
z_dim_hash_table_new(guint minnum, guint num, ...)
{
  guint i;
  va_list l;
  ZDimHashTable *self = g_new0(ZDimHashTable, 1);
  
  z_enter();
  self->keynum = num;
  self->minkeynum = minnum;
  self->flags = g_new0(guint, num);
  va_start(l, num);
  for(i = 0; i < num; i++)
    self->flags[i] = va_arg(l, guint);
  va_end(l);
  self->hash = g_hash_table_new(g_str_hash, g_str_equal);
  z_return(self);
}


/**
 * z_dim_hash_table_free_item:
 * @key The composite key of the hash entry
 * @value The value of the hash entry
 * @user_data The function to use for freeing the value
 *
 * Helper for 'z_dim_hash_table_free', called during the hash traversal.
 * Frees a hash entry, using 'user_data' for deallocating the value and 'g_free'
 * for the key.
 *
 * Returns: Always TRUE -> requests the deletion of the entry
 */
static gboolean
z_dim_hash_table_free_item(gpointer key, gpointer value, gpointer user_data)
{
  gboolean (*fn)(void *) = user_data;

  z_enter();
  fn(value);
  g_free(key);
  z_return(TRUE);
}


/**
 * z_dim_hash_table_free:
 * @self The ZDimHashTable instance to free
 * @func The function to use for freeing the values in the hash
 *
 * Iterates through the hash and frees all values using 'func'
 */
void
z_dim_hash_table_free(ZDimHashTable *self, ZDimHashFreeFunc func)
{
  z_enter();
  if (func)
    g_hash_table_foreach_remove(self->hash, z_dim_hash_table_free_item, func);
  g_hash_table_destroy(self->hash);
  g_free(self->flags);
  g_free(self);
  z_return();
}

/**
 * z_dim_hash_table_lookup:
 * @self The ZDimHashTable to search in
 * @num Number of dimensions (keys) specified
 * @keys The key vector to search for
 *
 * Search an entry of the hash that matches the specified key vector.
 * Empty strings and "*" are treated as non-specified elements.
 *
 * Returns:
 * NULL if too many or too few keys are specified or no matching entry found,
 * a pointer to the matching entry otherwise.
 */
gpointer
z_dim_hash_table_lookup(ZDimHashTable *self, guint num, gchar **keys)
{
  gchar key[DIMHASH_MAX_KEYNUM * (DIMHASH_MAX_KEYSIZE + 2) + 1];
  guint keylen = DIMHASH_MAX_KEYNUM * (DIMHASH_MAX_KEYSIZE + 2) + 1;
  gpointer *ret = NULL;
  
  z_enter();
  if (self->minkeynum > num || self->keynum < num)
    z_return(NULL);
  if (z_dim_hash_table_makekey(key, keylen, self, num, keys))
    ret = g_hash_table_lookup(self->hash, key);
  z_return(ret);
}


/**
 * z_dim_hash_table_delete:
 * @self ZDimHashTable instance to delete from
 * @num Number of specified keys
 * @keys Key vector
 * @func The function to use for freeing entry values
 *
 * Delete the matching entry from the hash 
 */ 
void
z_dim_hash_table_delete(ZDimHashTable *self, guint num, gchar **keys, ZDimHashFreeFunc func)
{
  gchar key[DIMHASH_MAX_KEYNUM * (DIMHASH_MAX_KEYSIZE + 2) + 1];
  guint keylen = DIMHASH_MAX_KEYNUM * (DIMHASH_MAX_KEYSIZE + 2) + 1;
  gpointer orig_key;
  gpointer value;

  z_enter();
  if (self->keynum < num || self->minkeynum > num)
    z_return();
  
  if (z_dim_hash_table_makekey(key, keylen, self, num, keys) &&
      g_hash_table_lookup_extended(self->hash, key, &orig_key, &value))
    {
      g_hash_table_remove(self->hash, key);
      func(value);
      g_free(orig_key);
    }
  z_return();
}


/**
 * z_dim_hash_table_insert:
 * @self ZDimHashTable instance to insert into
 * @value The value to insert
 * @num Number of specified keys
 * @keys Key vector
 *
 * Insert an entry into the hash
 */ 
void
z_dim_hash_table_insert(ZDimHashTable *self, gpointer value, guint num, gchar **keys)
{
  gchar key[DIMHASH_MAX_KEYNUM * (DIMHASH_MAX_KEYSIZE + 2) + 1];
  guint keylen = DIMHASH_MAX_KEYNUM * (DIMHASH_MAX_KEYSIZE + 2) + 1;
  gchar *new_key;
  
  z_enter();
  if (self->keynum < num || self->minkeynum > num)
    z_return();
  
  if (z_dim_hash_table_makekey(key, keylen, self, num, keys))
    {
      new_key = g_strdup(key);
      g_hash_table_insert(self->hash, new_key, value);
    }
  z_return();
}


/**
 * z_dim_hash_table_search:
 * @self ZDimHashTable instance to search in
 * @num Number of specified keys
 * @keys Key vector
 *
 * Searches self for an entry whose key matches the specified key vector
 *
 * Returns: NULL if error happened or no match found, or a pointer to the
 * matching entry
 */
gpointer
z_dim_hash_table_search(ZDimHashTable *self, guint num, gchar **keys)
{
  gchar *save_keys[DIMHASH_MAX_KEYNUM];
  gpointer *ret = NULL;
  guint i;

  z_enter();  
  if (self->keynum < num || self->minkeynum > num)
    z_return(NULL);
  
  for (i = 0; i < num; i++)
    {
      save_keys[i] = alloca(DIMHASH_MAX_KEYSIZE);
      strncpy(save_keys[i], keys[i], DIMHASH_MAX_KEYSIZE - 1);
      save_keys[i][DIMHASH_MAX_KEYSIZE-1] = 0;
    }
  while (num > 0)
    {
      ret = z_dim_hash_table_rec_search(self, num, 0, save_keys, keys);
      if (ret)
        break;
      num--;
    }
  z_return(ret);
}
