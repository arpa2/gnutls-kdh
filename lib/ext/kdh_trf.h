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
 * This file is part of the TLS-KDH Ticket Request Flags extension as
 * defined in TODO.
 */

#ifndef EXT_KDH_TRF_H
#define EXT_KDH_TRF_H

#include <gnutls_extensions.h>

//TODO implement: #ifdef ENABLE_KDH

typedef struct gnutls_kdh_trf_st {
	uint32_t krb_flags;
	uint32_t tlskdh_flags;
} gnutls_kdh_trf_st;

extern extension_entry_st ext_mod_kdh_trf;

//TODO implement: #endif
#endif
