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
 * $Id: zpython.c,v 1.82 2004/04/14 16:53:13 bazsi Exp $
 *
 * Author  : Bazsi
 * Auditor : 
 * Last audited version: 
 * Notes:
 *
 ***************************************************************************/

#include <zorp/zpython.h>

static PyThreadState *initial_thread;

/**
 * z_python_init:
 *
 * Initialize the low level Python-Zorp interface. Called by the Python
 * policy implementation.
 *
 * Returns: TRUE if initialization was successful
 **/
gboolean
z_python_init(void)
{
  char buf[2048];

  if (getenv("PYTHONPATH") == NULL)
    {
      g_snprintf(buf, sizeof(buf), "PYTHONPATH=%s", ZORP_DATADIR "/pylib");
    }
  else
    {
      g_snprintf(buf, sizeof(buf), "PYTHONPATH=%s:%s", ZORP_DATADIR "/pylib", getenv("PYTHONPATH"));
    }
  putenv(buf);
  PySys_AddWarnOption("ignore:hex/oct constants > sys.maxint will return positive values in Python 2.4 and up:FutureWarning");
  PySys_AddWarnOption("ignore:x<<y losing bits or changing sign will return a long in Python 2.4 and up:FutureWarning");
  PySys_AddWarnOption("ignore:Non-ASCII character:DeprecationWarning");
  Py_Initialize();
  PyEval_InitThreads();
  
  
  initial_thread = PyEval_SaveThread();
  return TRUE;
}

/**
 * z_python_destroy:
 *
 * This function deinitializes the Python interpreter, it should be called
 * at program teardown.
 *
 * Returns TRUE if deinitialization was successful.
 **/
gboolean
z_python_destroy(void)
{
  if (initial_thread)
    {
      PyEval_AcquireThread(initial_thread);
      Py_Finalize();
    }
  return TRUE;
}

/**
 * z_python_lock:
 *
 * Lock the python interpreter, without setting the current thread pointer.
 **/
void 
z_python_lock(void)
{
  PyEval_AcquireLock();
}

/**
 * z_python_unlock:
 *
 * Unlock the python interpreter.
 **/
void 
z_python_unlock(void)
{
  PyEval_ReleaseLock();
}

