/*
 *      Copyright (C) 2000 Nikos Mavroyanopoulos
 *
 * This file is part of GNUTLS.
 *
 * GNUTLS is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 *
 * GNUTLS is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 59 Temple Place - Suite 330, Boston, MA 02111-1307, USA
 */

#include "gnutls_int.h"
#include "gnutls_errors_int.h"

#ifdef DEBUG
# ifdef __FILE__
#  ifdef __LINE__
#   define gnutls_assert() fprintf(stderr, "GNUTLS_ASSERT: %s:%d\n", __FILE__,__LINE__);
#  else
#   define gnutls_assert() 
#  endif
# else /* __FILE__ defined */
#  define gnutls_assert() 
# endif
#else /* no debug */
# define gnutls_assert() 
#endif

const char* gnutls_strerror(int error);
void gnutls_perror(int error);
int gnutls_error_is_fatal( int error);

#ifdef DEBUG
 void _gnutls_log( const char *fmt, ...);

# ifdef HANDSHAKE_DEBUG
#  define _gnutls_handshake_log _gnutls_log
# else
#  define _gnutls_handshake_log( ...)
# endif

# ifdef IO_DEBUG
#  define _gnutls_io_log _gnutls_log
# else
#  define _gnutls_io_log( ...)
# endif

# ifdef BUFFERS_DEBUG
#  define _gnutls_buffers_log _gnutls_log
# else
#  define _gnutls_buffers_log( ...)
# endif

# ifdef HARD_DEBUG
#  define _gnutls_hard_log _gnutls_log
# else
#  define _gnutls_hard_log( ...)
# endif

# ifdef RECORD_DEBUG
#  define _gnutls_record_log _gnutls_log
# else
#  define _gnutls_record_log( ...)
# endif

# ifdef READ_DEBUG
#  define _gnutls_read_log _gnutls_log
# else
#  define _gnutls_read_log( ...)
# endif

# ifdef WRITE_DEBUG
#  define _gnutls_write_log _gnutls_log
# else
#  define _gnutls_write_log( ...)
# endif

# ifdef X509_DEBUG
#  define _gnutls_x509_log _gnutls_log
# else
#  define _gnutls_x509_log( ...)
# endif

#else
# define _gnutls_log(...)
# define _gnutls_handshake_log( ...)
# define _gnutls_io_log( ...)
# define _gnutls_buffers_log( ...)
# define _gnutls_hard_log( ...)
# define _gnutls_record_log( ...)
# define _gnutls_read_log( ...)
# define _gnutls_write_log( ...)
# define _gnutls_x509_log( ...)
#endif

