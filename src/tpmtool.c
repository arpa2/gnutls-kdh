/*
 * Copyright (C) 2010-2012 Free Software Foundation, Inc.
 *
 * Author: Nikos Mavrogiannopoulos
 *
 * This file is part of GnuTLS.
 *
 * GnuTLS is free software: you can redistribute it and/or modify it
 * under the terms of the GNU General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * GnuTLS is distributed in the hope that it will be useful, but
 * WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program.  If not, see
 * <http://www.gnu.org/licenses/>.
 */

#include <config.h>

#include <gnutls/gnutls.h>
#include <gnutls/x509.h>
#include <gnutls/openpgp.h>
#include <gnutls/pkcs12.h>
#include <gnutls/tpm.h>
#include <gnutls/abstract.h>

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <ctype.h>
#include <time.h>
#include <unistd.h>
#include <errno.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <error.h>

/* Gnulib portability files. */
#include <read-file.h>
#include <progname.h>
#include <version-etc.h>

#include "certtool-common.h"
#include "tpmtool-args.h"

static void cmd_parser (int argc, char **argv);
static void tpm_generate(FILE* outfile, unsigned int key_type, unsigned int bits, int reg);
static void tpm_pubkey(const char* url, FILE* outfile);
static void tpm_delete(const char* url, FILE* outfile);
static void tpm_list(FILE* outfile);

static FILE *outfile;
static FILE *infile;
int batch = 0;

static void
tls_log_func (int level, const char *str)
{
  fprintf (stderr, "|<%d>| %s", level, str);
}


int
main (int argc, char **argv)
{
  set_program_name (argv[0]);
  cmd_parser (argc, argv);

  return 0;
}

static void
cmd_parser (int argc, char **argv)
{
  int ret, debug = 0;
  unsigned int optct;
  unsigned int key_type = GNUTLS_PK_UNKNOWN;
  unsigned int bits = 0, reg = 0;
  /* Note that the default sec-param is legacy because several TPMs
   * cannot handle larger keys.
   */
  const char* sec_param = "legacy";
  
  optct = optionProcess( &tpmtoolOptions, argc, argv);
  argc += optct;
  argv += optct;
 
  if (HAVE_OPT(DEBUG))
    debug = OPT_VALUE_DEBUG;

  if (HAVE_OPT(REGISTER))
    reg = 1;

  gnutls_global_set_log_function (tls_log_func);
  gnutls_global_set_log_level (debug);
  if (debug > 1)
    printf ("Setting log level to %d\n", debug);

  if ((ret = gnutls_global_init ()) < 0)
    error (EXIT_FAILURE, 0, "global_init: %s", gnutls_strerror (ret));

  if (HAVE_OPT(OUTFILE))
    {
      outfile = safe_open_rw (OPT_ARG(OUTFILE), 0);
      if (outfile == NULL)
        error (EXIT_FAILURE, errno, "%s", OPT_ARG(OUTFILE));
    }
  else
    outfile = stdout;

  if (HAVE_OPT(INFILE))
    {
      infile = fopen (OPT_ARG(INFILE), "rb");
      if (infile == NULL)
        error (EXIT_FAILURE, errno, "%s", OPT_ARG(INFILE));
    }
  else
    infile = stdin;

  if (HAVE_OPT(SEC_PARAM))
    sec_param = OPT_ARG(SEC_PARAM);
  if (HAVE_OPT(BITS))
    bits = OPT_VALUE_BITS;
  

  if (HAVE_OPT(GENERATE_RSA))
    {
      key_type = GNUTLS_PK_RSA;
      bits = get_bits (key_type, bits, sec_param);
      tpm_generate (outfile, key_type, bits, reg);
    }
  else if (HAVE_OPT(PUBKEY))
    {
      tpm_pubkey (OPT_ARG(PUBKEY), outfile);
    }
  else if (HAVE_OPT(DELETE))
    {
      tpm_delete (OPT_ARG(DELETE), outfile);
    }
  else if (HAVE_OPT(LIST))
    {
      tpm_list (outfile);
    }
  else 
    {
      USAGE(1);
    }
    
  fclose (outfile);

  gnutls_global_deinit ();
}

static void tpm_generate(FILE* outfile, unsigned int key_type, unsigned int bits, int reg)
{
  int ret;
  char* srk_pass, *key_pass;
  gnutls_datum_t privkey, pubkey;
  unsigned int flags = 0;
  
  if (reg)
    flags |= GNUTLS_TPM_REGISTER_KEY;
  
  srk_pass = getpass ("Enter SRK password: ");
  if (srk_pass != NULL)
    srk_pass = strdup(srk_pass);

  key_pass = getpass ("Enter key password: ");
  if (key_pass != NULL)
    key_pass = strdup(srk_pass);
  
  ret = gnutls_tpm_privkey_generate(key_type, bits, srk_pass, key_pass,
                                    GNUTLS_X509_FMT_PEM, &privkey, &pubkey,
                                    flags);

  free(key_pass);
  free(srk_pass);

  if (ret < 0)
    error (EXIT_FAILURE, 0, "gnutls_tpm_privkey_generate: %s", gnutls_strerror (ret));

/*  fwrite (pubkey.data, 1, pubkey.size, outfile);
  fputs ("\n", outfile);*/
  fwrite (privkey.data, 1, privkey.size, outfile);
  fputs ("\n", outfile);
  
  gnutls_free(privkey.data);
  gnutls_free(pubkey.data);
}

static void tpm_delete(const char* url, FILE* outfile)
{
  int ret;
  char* srk_pass;
  
  srk_pass = getpass ("Enter SRK password: ");
  
  ret = gnutls_tpm_privkey_delete(url, srk_pass);
  if (ret < 0)
    error (EXIT_FAILURE, 0, "gnutls_tpm_privkey_delete: %s", gnutls_strerror (ret));

  fprintf (outfile, "Key %s deleted\n", url);
}

static void tpm_list(FILE* outfile)
{
  int ret;
  gnutls_tpm_key_list_t list;
  unsigned int i;
  char* url;
  
  ret = gnutls_tpm_get_registered (&list);
  if (ret < 0)
    error (EXIT_FAILURE, 0, "gnutls_tpm_get_registered: %s", gnutls_strerror (ret));
    
  fprintf(outfile, "Available keys:\n");
  for (i=0;;i++)
    {
      ret = gnutls_tpm_key_list_get_url(list, i, &url, 0);
      if (ret == GNUTLS_E_REQUESTED_DATA_NOT_AVAILABLE)
        break;
      else if (ret < 0)
        error (EXIT_FAILURE, 0, "gnutls_tpm_key_list_get_url: %s", gnutls_strerror (ret));
  
      fprintf(outfile, "\t%u: %s\n", i, url);
      gnutls_free(url);
    }

  fputs ("\n", outfile);
}

static void tpm_pubkey(const char* url, FILE* outfile)
{
  int ret;
  char* srk_pass;
  gnutls_pubkey_t pubkey;
  
  srk_pass = getpass ("Enter SRK password: ");
  if (srk_pass != NULL)
    srk_pass = strdup(srk_pass);

  gnutls_pubkey_init(&pubkey);

  ret = gnutls_pubkey_import_tpm_url(pubkey, url, srk_pass);

  free(srk_pass);

  if (ret < 0)
    error (EXIT_FAILURE, 0, "gnutls_pubkey_import_tpm_url: %s", gnutls_strerror (ret));

  _pubkey_info(outfile, pubkey);

  gnutls_pubkey_deinit(pubkey);
}
