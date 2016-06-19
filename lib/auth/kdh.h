/*
 * Copyright (C) 2016 Free Software Foundation, Inc.
 *
 * Author: Tom Vrancken
 *
 * This file is part of GnuTLS.
 *
 * The GnuTLS is free software; you can redistribute it and/or
 * modify it under the terms of the GNU Lesser General Public License
 * as published by the Free Software Foundation; either version 2.1 of
 * the License, or (at your option) any later version.
 *
 * This library is distributed in the hope that it will be useful, but
 * WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * Lesser General Public License for more details.
 *
 * You should have received a copy of the GNU Lesser General Public License
 * along with this program.  If not, see <http://www.gnu.org/licenses/>
 *
 */

#ifndef AUTH_KDH_H
#define AUTH_KDH_H

#include <gnutls_datum.h>

int _gnutls_gen_cert_krb_authenticator( gnutls_session_t session, 
																				gnutls_buffer_st* data );
																				
int _gnutls_proc_cert_krb_authenticator( gnutls_session_t session,
				  uint8_t* data, size_t data_size );
																				
int _gnutls_set_kdh_pms( gnutls_session_t session, 
												gnutls_datum_t* authenticator );
												
#endif
