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
 * $Id: pystream.h,v 1.5 2002/08/22 05:56:35 sasa Exp $
 *
 ***************************************************************************/

#ifndef ZORP_PYSTREAM_H_INCLUDED
#define ZORP_PYSTREAM_H_INCLUDED

#include <zorp/zpython.h>
#include <zorp/stream.h>

/*+

  ZPolicyStream is the Python interface to ZStream.

  +*/
typedef struct _ZPolicyStream
{
  PyObject_HEAD
  ZStream *stream;
} ZPolicyStream;

extern PyTypeObject z_policy_stream_type;

#define z_policy_stream_check(ob) ((ob)->ob_type == &z_policy_stream_type)

void z_policy_stream_module_init(void);

PyObject *z_policy_stream_new(ZStream *Stream);

static inline ZStream *
z_policy_stream_get_stream(PyObject *s)
{
  ZPolicyStream *self = (ZPolicyStream *) s;
  
  g_assert(z_policy_stream_check(s));
  return z_stream_ref(self->stream);
}

#endif

