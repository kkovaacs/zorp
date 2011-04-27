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
 * $Id: zpython.h,v 1.26 2004/07/02 10:03:34 bazsi Exp $
 *
 ***************************************************************************/

#ifndef ZORP_ZPYTHON_H_INCLUDED
#define ZORP_ZPYTHON_H_INCLUDED

#include <zorp/zorp.h>

#if PY_MAJOR_VERSION == 2 && PY_MINOR_VERSION == 4
#  define Z_PYTYPE_TRAILER_COMMON 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0
#  ifdef COUNT_ALLOCS
#    define Z_PYTYPE_TRAILER_COUNT_ALLOCS , 0, 0, 0, 0
#  else
#    define Z_PYTYPE_TRAILER_COUNT_ALLOCS
#  endif
#  define Z_PYTYPE_TRAILER Z_PYTYPE_TRAILER_COMMON Z_PYTYPE_TRAILER_COUNT_ALLOCS
#elif PY_MAJOR_VERSION == 2 && PY_MINOR_VERSION == 5
#  define Z_PYTYPE_TRAILER_COMMON 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0
#  ifdef COUNT_ALLOCS
#    define Z_PYTYPE_TRAILER_COUNT_ALLOCS , 0, 0, 0, 0, 0
#  else
#    define Z_PYTYPE_TRAILER_COUNT_ALLOCS
#  endif
#  define Z_PYTYPE_TRAILER Z_PYTYPE_TRAILER_COMMON Z_PYTYPE_TRAILER_COUNT_ALLOCS
#elif PY_MAJOR_VERSION == 2 && PY_MINOR_VERSION == 6
#  define Z_PYTYPE_TRAILER_COMMON 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0
#  ifdef COUNT_ALLOCS
#    define Z_PYTYPE_TRAILER_COUNT_ALLOCS , 0, 0, 0, 0, 0
#  else
#    define Z_PYTYPE_TRAILER_COUNT_ALLOCS
#  endif
#  define Z_PYTYPE_TRAILER Z_PYTYPE_TRAILER_COMMON Z_PYTYPE_TRAILER_COUNT_ALLOCS
#elif PY_MAJOR_VERSION == 2 && PY_MINOR_VERSION == 3
#  define Z_PYTYPE_TRAILER 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0
#else
#  define Z_PYTYPE_TRAILER
#endif

#if PY_MAJOR_VERSION == 2 && PY_MINOR_VERSION >= 5
#  define Z_PYMAPPING_LENFUNC_TYPE lenfunc
#  define Z_PYTHON_SIZE_TYPE gssize
#else
#  define Z_PYMAPPING_LENFUNC_TYPE inquiry
#  define Z_PYTHON_SIZE_TYPE int
#endif

gboolean z_python_init(void);
gboolean z_python_destroy(void);
void z_python_lock(void);
void z_python_unlock(void);


#endif
