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
 * Author: Bazsi, Panther
 * Auditor:
 * Last audited version:
 * Notes:
 *
 ***************************************************************************/

#include <zorp/pyx509.h>
#include  <zorp/zpython.h>

#include <zorp/log.h>

#include <openssl/pem.h>

#define PROXY_SSL_EXTRACT_PEM(s, l, r) \
  ({ void *p; BIO *bio = BIO_new_mem_buf(s, l); p = r(bio, NULL, NULL, NULL); BIO_free(bio); p; })

typedef struct _ZorpCertificate
{
  PyObject_HEAD
  X509 *cert;
} ZorpCertificate;

static PyTypeObject z_py_zorp_certificate_type;

static PyObject *
z_py_zorp_certificate_new(X509 *cert)
{
  ZorpCertificate *self;

  if (cert)
    {

      self = PyObject_New(ZorpCertificate, &z_py_zorp_certificate_type);
      self->cert = cert;
      CRYPTO_add(&cert->references,1,CRYPTO_LOCK_X509);
      return (PyObject *) self;
    }
  else
    {
      Py_XINCREF(Py_None);
      return Py_None;
    }
}

static PyObject *
z_py_zorp_certificate_getattr(PyObject *o, char *name)
{
  ZorpCertificate *self = (ZorpCertificate *) o;
  PyObject *res = NULL;
  BIO *bio;
  guint len;
  gchar *mem;
  gchar buf[512];

  if (strcmp(name, "blob") == 0)
    {
      bio = BIO_new(BIO_s_mem());

      PEM_write_bio_X509(bio, self->cert);
      len = BIO_get_mem_data(bio, &mem);
      res = PyString_FromStringAndSize(mem, len);

      BIO_free(bio);
    }
  else if (strcmp(name, "issuer") == 0)
    {
      X509_NAME_oneline(X509_get_issuer_name(self->cert), buf, sizeof(buf));
      res = PyString_FromString(buf);
    }
  else if (strcmp(name, "subject") == 0)
    {
      X509_NAME_oneline(X509_get_subject_name(self->cert), buf, sizeof(buf));
      res = PyString_FromString(buf);
    }
  else if (strcmp(name, "serial") == 0)
    {
      ASN1_INTEGER *cert_serial;

      cert_serial = X509_get_serialNumber(self->cert);
      if (cert_serial)
        {
          res = PyInt_FromLong(ASN1_INTEGER_get(cert_serial));
        }
    }
  else
    {
      PyErr_SetString(PyExc_AttributeError, "Attribute not found");
    }
  return res;
}

static void
z_py_zorp_certificate_free(ZorpCertificate *self)
{
  X509_free(self->cert);
  PyObject_Del(self);
}

static PyTypeObject z_py_zorp_certificate_type =
{
  PyObject_HEAD_INIT(&PyType_Type)
  0,
  "Zorp Certificate",
  sizeof(ZorpCertificate),
  0,
  (destructor) z_py_zorp_certificate_free,
  0,                                  /* tp_print */
  z_py_zorp_certificate_getattr,      /* tp_getattr */
  0,                                  /* tp_setattr */
  0,                                  /* tp_compare */
  0,                                  /* tp_repr */
  0,                                  /* tp_as_number */
  0,                                  /* tp_as_sequence */
  0,                                  /* tp_as_mapping */
  0,                                  /* tp_hash */
  0,                                  /* tp_call */
  0,                                  /* tp_str */
  0,                                  /* tp_getattro */
  0,                                  /* tp_setattro */
  0,                                  /* tp_as_buffer */
  0,                                  /* flags */
  "ZorpCertificate class for Zorp",   /* docstring */
  0, 0, 0, 0,
  Z_PYTYPE_TRAILER
};

typedef struct _ZorpCRL
{
  PyObject_HEAD
  X509_CRL *crl;
} ZorpCRL;

static PyTypeObject z_py_zorp_crl_type;

static PyObject *
z_py_zorp_crl_new(X509_CRL *crl)
{
  ZorpCRL *self;

  self = PyObject_New(ZorpCRL, &z_py_zorp_crl_type);
  self->crl = crl;
  CRYPTO_add(&crl->references,1,CRYPTO_LOCK_X509_CRL);
  return (PyObject *) self;
}

static PyObject *
z_py_zorp_crl_getattr(PyObject *o, char *name)
{
  ZorpCRL *self = (ZorpCRL *) o;
  PyObject *res = NULL;
  BIO *bio;
  guint len;
  gchar *mem;
  gchar buf[512];

  if (strcmp(name, "blob") == 0)
    {
      bio = BIO_new(BIO_s_mem());

      PEM_write_bio_X509_CRL(bio, self->crl);
      len = BIO_get_mem_data(bio, &mem);
      res = PyString_FromStringAndSize(mem, len);

      BIO_free(bio);
    }
  else if (strcmp(name, "issuer") == 0)
    {
      X509_NAME_oneline(X509_CRL_get_issuer(self->crl), buf, sizeof(buf));
      res = PyString_FromString(buf);
    }
  else
    {
      PyErr_SetString(PyExc_AttributeError, "Attribute not found");
    }
  return res;
}

static void
z_py_zorp_crl_free(ZorpCRL *self)
{
  X509_CRL_free(self->crl);
  PyObject_Del(self);
}

static PyTypeObject z_py_zorp_crl_type =
{
  PyObject_HEAD_INIT(&PyType_Type)
  0,
  "Zorp CRL",
  sizeof(ZorpCRL),
  0,
  (destructor) z_py_zorp_crl_free,
  0,                                  /* tp_print */
  z_py_zorp_crl_getattr,              /* tp_getattr */
  0,                                  /* tp_setattr */
  0,                                  /* tp_compare */
  0,                                  /* tp_repr */
  0,                                  /* tp_as_number */
  0,                                  /* tp_as_sequence */
  0,                                  /* tp_as_mapping */
  0,                                  /* tp_hash */
  0,                                  /* tp_call */
  0,                                  /* tp_str */
  0,                                  /* tp_getattro */
  0,                                  /* tp_setattro */
  0,                                  /* tp_as_buffer */
  0,                                  /* flags */
  "ZorpCRL class for Zorp",           /* docstring */
  0, 0, 0, 0,
  Z_PYTYPE_TRAILER
};

typedef struct _ZorpCertList
{
  PyObject_HEAD
  STACK_OF(X509) *certs;
} ZorpCertList;

static PyTypeObject z_py_zorp_cert_list_type;

static PyObject *
z_py_zorp_cert_list_new(STACK_OF(X509) *certs)
{
  ZorpCertList *self;

  self = PyObject_New(ZorpCertList, &z_py_zorp_cert_list_type);
  self->certs = certs;
  return (PyObject *) self;
}

static void
z_py_zorp_cert_list_free(ZorpCertList *self)
{
  PyObject_Del(self);
}

static Py_ssize_t
z_py_zorp_cert_list_length(ZorpCertList *self)
{
  return sk_X509_num(self->certs);
}

static int
z_py_zorp_cert_list_lookup(ZorpCertList *self, PyObject *ndx)
{
  if (PyInt_Check(ndx))
    {
      /* number */

      if (PyInt_AsLong(ndx) >= 0 && PyInt_AsLong(ndx) < sk_X509_num(self->certs))
        {
          return PyInt_AsLong(ndx);
        }
    }
  else if (PyString_Check(ndx))
    {
      gchar buf[512];
      int i;

      for (i = 0; i < sk_X509_num(self->certs); i++)
        {
          X509_NAME_oneline(X509_get_subject_name(sk_X509_value(self->certs, i)), buf, sizeof(buf));
          if (strcmp(buf, PyString_AsString(ndx)) == 0)
            {
              return i;
            }
        }
    }
  return -1;
}

static PyObject *
z_py_zorp_cert_list_subscript(ZorpCertList *self, PyObject *ndx)
{
  int i;

  i = z_py_zorp_cert_list_lookup(self, ndx);
  if (i == -1)
    {
      PyErr_SetString(PyExc_KeyError, "Certificate not found.");
      return NULL;
    }
  return z_py_zorp_certificate_new(sk_X509_value(self->certs, i));
}

static gint
z_py_zorp_cert_list_ass_subscript(ZorpCertList *self, PyObject *ndx, PyObject *new)
{
  X509 *cert = NULL;
  int i;

  if (new)
    {
      if (PyString_Check(new))
        {
          /* new-ban pem, berakni az i. helyere */
          cert = PROXY_SSL_EXTRACT_PEM(PyString_AsString(new), PyString_Size(new), PEM_read_bio_X509);
        }

      if (!cert)
        {
          PyErr_SetString(PyExc_TypeError, "Certificates must be specified as strings in PEM format");
          return -1;
        }
    }

  i = z_py_zorp_cert_list_lookup(self, ndx);

  if (i != -1)
    {
      X509 *tmp;
      X509 *p = sk_X509_value(self->certs, i);
      tmp = sk_X509_delete(self->certs, i);
      X509_free(p);
   }

  if (cert)
    {
      if (X509_find_by_subject(self->certs, X509_get_subject_name(cert)))
        {
          X509_free(cert);
          PyErr_SetString(PyExc_ValueError, "Trying to add a duplicate certificate.");
          return -1;
        }

      sk_X509_push(self->certs, cert);
    }
  return 0;
}

static PyMappingMethods z_py_zorp_cert_list_mapping =
{
  (Z_PYMAPPING_LENFUNC_TYPE) z_py_zorp_cert_list_length,
  (binaryfunc) z_py_zorp_cert_list_subscript,
  (objobjargproc) z_py_zorp_cert_list_ass_subscript
};

static PyTypeObject z_py_zorp_cert_list_type =
{
  PyObject_HEAD_INIT(&PyType_Type)
  0,
  "Zorp Certificate List",
  sizeof(ZorpCertList),
  0,
  (destructor) z_py_zorp_cert_list_free,
  0,                                  /* tp_print */
  0,                                  /* tp_getattr */
  0,                                  /* tp_setattr */
  0,                                  /* tp_compare */
  0,                                  /* tp_repr */
  0,                                  /* tp_as_number */
  0,                                  /* tp_as_sequence */
  &z_py_zorp_cert_list_mapping,        /* tp_as_mapping */
  0,                                  /* tp_hash */
  0,                                  /* tp_call */
  0,                                  /* tp_str */
  0,                                  /* tp_getattro */
  0,                                  /* tp_setattro */
  0,                                  /* tp_as_buffer */
  0,                                  /* flags */
  "ZorpCertList class for Zorp",   /* docstring */
  0, 0, 0, 0,
  Z_PYTYPE_TRAILER
};

typedef struct _ZorpCertNameList
{
  PyObject_HEAD
  STACK_OF(X509_NAME) *cert_names;
} ZorpCertNameList;

static PyTypeObject z_py_zorp_cert_name_list_type;

static PyObject *
z_py_zorp_cert_name_list_new(STACK_OF(X509_NAME) *cert_names)
{
  ZorpCertNameList *self;

  self = PyObject_New(ZorpCertNameList, &z_py_zorp_cert_name_list_type);
  self->cert_names = cert_names;
  return (PyObject *) self;
}

static void
z_py_zorp_cert_name_list_free(ZorpCertNameList *self)
{
  PyObject_Del(self);
}

static Py_ssize_t
z_py_zorp_cert_name_list_length(ZorpCertNameList *self)
{
  return sk_X509_num(self->cert_names);
}

static int
z_py_zorp_cert_name_list_lookup(ZorpCertNameList *self, PyObject *ndx)
{
  if (PyInt_Check(ndx))
    {
      /* number */

      if (PyInt_AsLong(ndx) >= 0 && PyInt_AsLong(ndx) < sk_X509_NAME_num(self->cert_names))
        {
          return PyInt_AsLong(ndx);
        }
    }
  else if (PyString_Check(ndx))
    {
      gchar buf[512];
      int i, num;

      num = sk_X509_NAME_num(self->cert_names);
      for (i = 0; i < num; i++)
        {
          X509_NAME_oneline(sk_X509_NAME_value(self->cert_names, i), buf, sizeof(buf));
          if (strcmp(buf, PyString_AsString(ndx)) == 0)
            {
              return i;
            }
        }
    }
  return -1;
}

static PyObject *
z_py_zorp_cert_name_list_subscript(ZorpCertNameList *self, PyObject *ndx)
{
  gchar buf[1024];
  int i;

  i = z_py_zorp_cert_name_list_lookup(self, ndx);
  if (i == -1)
    {
      PyErr_SetString(PyExc_KeyError, "Certificate not found.");
      return NULL;
    }
  /* FIXME: return it as a string */
  X509_NAME_oneline(sk_X509_NAME_value(self->cert_names, i), buf, sizeof(buf));
  return PyString_FromString(buf);
}

static PyMappingMethods z_py_zorp_cert_name_list_mapping =
{
  (Z_PYMAPPING_LENFUNC_TYPE) z_py_zorp_cert_name_list_length,
  (binaryfunc) z_py_zorp_cert_name_list_subscript,
  (objobjargproc) NULL
};

static PyTypeObject z_py_zorp_cert_name_list_type =
{
  PyObject_HEAD_INIT(&PyType_Type)
  0,
  "Zorp Certificate Name List",
  sizeof(ZorpCertNameList),
  0,
  (destructor) z_py_zorp_cert_name_list_free,
  0,                                  /* tp_print */
  0,                                  /* tp_getattr */
  0,                                  /* tp_setattr */
  0,                                  /* tp_compare */
  0,                                  /* tp_repr */
  0,                                  /* tp_as_number */
  0,                                  /* tp_as_sequence */
  &z_py_zorp_cert_name_list_mapping,        /* tp_as_mapping */
  0,                                  /* tp_hash */
  0,                                  /* tp_call */
  0,                                  /* tp_str */
  0,                                  /* tp_getattro */
  0,                                  /* tp_setattro */
  0,                                  /* tp_as_buffer */
  0,                                  /* flags */
  "ZorpCertNameList class for Zorp",   /* docstring */
  0, 0, 0, 0,
  Z_PYTYPE_TRAILER
};

typedef struct _ZorpCRLList
{
  PyObject_HEAD
  STACK_OF(X509_CRL) *crls;
} ZorpCRLList;

static PyTypeObject z_py_zorp_crl_list_type;

static PyObject *
z_py_zorp_crl_list_new(STACK_OF(X509_CRL) *crls)
{
  ZorpCRLList *self;

  self = PyObject_New(ZorpCRLList, &z_py_zorp_crl_list_type);
  self->crls = crls;
  return (PyObject *) self;
}

static void
z_py_zorp_crl_list_free(ZorpCRLList *self)
{
  PyObject_Del(self);
}

static Py_ssize_t
z_py_zorp_crl_list_length(ZorpCRLList *self)
{
  return sk_X509_CRL_num(self->crls);
}

static int
z_py_zorp_crl_list_lookup(ZorpCRLList *self, PyObject *ndx)
{
  if (PyInt_Check(ndx))
    {
      /* number */

      if (PyInt_AsLong(ndx) >= 0 && PyInt_AsLong(ndx) < sk_X509_CRL_num(self->crls))
        {
          return PyInt_AsLong(ndx);
        }
    }
  else if (PyString_Check(ndx))
    {
      gchar buf[512];
      int i;

      for (i = 0; i < sk_X509_CRL_num(self->crls); i++)
        {
          X509_NAME_oneline(X509_CRL_get_issuer(sk_X509_CRL_value(self->crls, i)), buf, sizeof(buf));
          if (strcmp(buf, PyString_AsString(ndx)) == 0)
            {
              return i;
            }
        }
    }
  return -1;
}

static PyObject *
z_py_zorp_crl_list_subscript(ZorpCRLList *self, PyObject *ndx)
{
  int i;

  i = z_py_zorp_crl_list_lookup(self, ndx);
  if (i == -1)
    {
      PyErr_SetString(PyExc_KeyError, "Certificate not found.");
      return NULL;
    }
  return z_py_zorp_crl_new(sk_X509_CRL_value(self->crls, i));
}

static gint
z_py_zorp_crl_list_ass_subscript(ZorpCRLList *self, PyObject *ndx, PyObject *new)
{
  X509_CRL *crl = NULL;
  int i;

  if (new)
    {
      if (PyString_Check(new))
        {
          /* new-ban pem, berakni az i. helyere */
          crl = PROXY_SSL_EXTRACT_PEM(PyString_AsString(new), PyString_Size(new), PEM_read_bio_X509_CRL);
        }

      if (!crl)
        {
          PyErr_SetString(PyExc_TypeError, "CRLs must be specified as strings in PEM format");
          return -1;
        }
    }

  i = z_py_zorp_crl_list_lookup(self, ndx);

  if (i != -1)
    {
      X509_CRL *tmp;
      X509_CRL *p = sk_X509_CRL_value(self->crls, i);
      tmp = sk_X509_CRL_delete(self->crls, i);
      X509_CRL_free(p);
   }

  if (crl)
    {
#if 0
      if (X509_CRL_find_by_subject(self->crls, X509_CRL_get_issuer(crl)))
        {
          X509_CRL_free(cert);
          PyErr_SetString(PyExc_ValueError, "Trying to add a duplicate certificate.");
          return -1;
        }
#endif
      sk_X509_CRL_push(self->crls, crl);
    }
  return 0;
}

static PyMappingMethods z_py_zorp_crl_list_mapping =
{
  (Z_PYMAPPING_LENFUNC_TYPE) z_py_zorp_crl_list_length,
  (binaryfunc) z_py_zorp_crl_list_subscript,
  (objobjargproc) z_py_zorp_crl_list_ass_subscript
};

static PyTypeObject z_py_zorp_crl_list_type =
{
  PyObject_HEAD_INIT(&PyType_Type)
  0,
  "Zorp CRL List",
  sizeof(ZorpCRLList),
  0,
  (destructor) z_py_zorp_crl_list_free,
  0,                                  /* tp_print */
  0,                                  /* tp_getattr */
  0,                                  /* tp_setattr */
  0,                                  /* tp_compare */
  0,                                  /* tp_repr */
  0,                                  /* tp_as_number */
  0,                                  /* tp_as_sequence */
  &z_py_zorp_crl_list_mapping,        /* tp_as_mapping */
  0,                                  /* tp_hash */
  0,                                  /* tp_call */
  0,                                  /* tp_str */
  0,                                  /* tp_getattro */
  0,                                  /* tp_setattro */
  0,                                  /* tp_as_buffer */
  0,                                  /* flags */
  "ZorpCRLList class for Zorp",   /* docstring */
  0, 0, 0, 0,
  Z_PYTYPE_TRAILER
};

ZPolicyObj *
z_py_ssl_certificate_get(ZProxy *self G_GNUC_UNUSED, gchar *name G_GNUC_UNUSED, gpointer value)
{
  X509 **cert = (X509 **) value;

  return z_py_zorp_certificate_new(*cert);
}

int
z_py_ssl_certificate_set(ZProxy *self G_GNUC_UNUSED, gchar *name G_GNUC_UNUSED, gpointer value, ZPolicyObj *new)
{
  X509 **cert = (X509 **) value;

  if (*cert)
    {
      X509_free(*cert);
      *cert = NULL;
    }
  if (PyString_Check(new))
    {
      (*cert) = PROXY_SSL_EXTRACT_PEM(PyString_AsString(new), PyString_Size(new), PEM_read_bio_X509);
    }
  if (!(*cert))
    {
      PyErr_SetString(PyExc_TypeError, "Certificates must be specified as strings in PEM format.");
      return -1;
    }
  return 0;
}

void
z_py_ssl_certificate_free(gpointer value)
{
  X509 **cert = (X509 **) value;

  X509_free(*cert);
}

ZPolicyObj *
z_py_ssl_privkey_get(ZProxy *self G_GNUC_UNUSED, gchar *name G_GNUC_UNUSED, gpointer value G_GNUC_UNUSED)
{
  return PyString_FromString("Private key retrieval is not supported.");
}

int
z_py_ssl_privkey_set(ZProxy *self, gchar *name G_GNUC_UNUSED, gpointer value, ZPolicyObj *new)
{
  EVP_PKEY **pkey = (EVP_PKEY **) value;
  GString       *passphrase;

  z_proxy_enter(self);
  if (*pkey)
    {
      EVP_PKEY_free(*pkey);
      *pkey = NULL;
    }
  if (PyString_Check(new))
    {
      if (pkey == &self->ssl_opts.local_privkey[EP_CLIENT])
        passphrase = self->ssl_opts.local_privkey_passphrase[EP_CLIENT];
      else if (pkey == &self->ssl_opts.local_privkey[EP_SERVER])
        passphrase = self->ssl_opts.local_privkey_passphrase[EP_SERVER];
      else
        passphrase = NULL;

      /* (*pkey) = PROXY_SSL_EXTRACT_PEM(PyString_AsString(new), PyString_Size(new), PEM_read_bio_PrivateKey); */
      {
        BIO *bio = BIO_new_mem_buf(PyString_AsString(new), PyString_Size(new));
        (*pkey) = PEM_read_bio_PrivateKey(bio, NULL, NULL, passphrase ? passphrase->str : NULL);
        BIO_free(bio);
      }
    }
  if (!(*pkey))
    {
      PyErr_SetString(PyExc_TypeError, "Private keys must be specified as strings in PEM format.");
      z_proxy_return(self, -1);
    }
  z_proxy_return(self, 0);
}

void
z_py_ssl_privkey_free(gpointer value)
{
  EVP_PKEY **pkey = (EVP_PKEY **) value;

  EVP_PKEY_free(*pkey);
}

ZPolicyObj *
z_py_ssl_cert_list_get(ZProxy *self G_GNUC_UNUSED, gchar *name G_GNUC_UNUSED, gpointer value)
{
  STACK_OF(X509) **certlist = (STACK_OF(X509) **) value;

  return z_py_zorp_cert_list_new(*certlist);
}

void
z_py_ssl_cert_list_free(gpointer value)
{
  STACK_OF(X509) **certlist = (STACK_OF(X509) **) value;

  sk_X509_pop_free(*certlist, X509_free);
}

ZPolicyObj *
z_py_ssl_cert_name_list_get(ZProxy *self G_GNUC_UNUSED, gchar *name G_GNUC_UNUSED, gpointer value)
{
  STACK_OF(X509_NAME) **certnamelist = (STACK_OF(X509_NAME) **) value;

  return z_py_zorp_cert_name_list_new(*certnamelist);
}

void
z_py_ssl_cert_name_list_free(gpointer value)
{
  STACK_OF(X509_NAME) **certnamelist = (STACK_OF(X509_NAME) **) value;

  sk_X509_NAME_pop_free(*certnamelist, X509_NAME_free);
}

ZPolicyObj *
z_py_ssl_crl_list_get(ZProxy *self G_GNUC_UNUSED, gchar *name G_GNUC_UNUSED, gpointer value)
{
  STACK_OF(X509_CRL) **crllist = (STACK_OF(X509_CRL) **) value;

  return z_py_zorp_crl_list_new(*crllist);
}

void
z_py_ssl_crl_list_free(gpointer value)
{
  STACK_OF(X509_CRL) **crllist = (STACK_OF(X509_CRL) **) value;

  sk_X509_CRL_pop_free(*crllist, X509_CRL_free);
}
