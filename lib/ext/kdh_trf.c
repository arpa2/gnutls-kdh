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

#include <gnutls_int.h>
#include <ext/kdh_trf.h>
#include <gnutls_extensions.h>

//TODO implement: ifdef ENABLE_KDH

static int _gnutls_kdh_trf_recv_params( gnutls_session_t session, 
										const uint8_t* data, size_t data_size );
static int _gnutls_kdh_trf_send_params( gnutls_session_t session, 
										gnutls_buffer_st* data );
static int _gnutls_kdh_trf_pack( extension_priv_data_t epriv, 
										gnutls_buffer_st* ps );
static int _gnutls_kdh_trf_unpack( gnutls_buffer_st* ps, 
										extension_priv_data_t* epriv );
static void _gnutls_kdh_trf_deinit( extension_priv_data_t priv );

extension_entry_st ext_mod_kdh_trf = {
	.name = "KDH Ticket Request Flags",
	.type = GNUTLS_EXTENSION_KDH_TRF,
	.parse_type = GNUTLS_EXT_APPLICATION,
	.recv_func = _gnutls_kdh_trf_recv_params,
	.send_func = _gnutls_kdh_trf_send_params,
	.pack_func = _gnutls_kdh_trf_pack,
	.unpack_func = _gnutls_kdh_trf_unpack,
	.deinit_func = _gnutls_kdh_trf_deinit
};


/**
 * Read the Ticket Request Flags as a byte sequence from the IO buffer
 * and decode them to the internal ticket request flags structure.
 * 
 * Returns 0 on success or a negative error code on failure.
 **/
static int
_gnutls_kdh_trf_recv_params( gnutls_session_t session, const uint8_t* data,
                     size_t data_size )
{
	gnutls_kdh_trf_st* trf;
	extension_priv_data_t epriv;
	
	ssize_t len             = data_size;
	const uint8_t* data_idx = data;
	
	// Compare packet length with expected packet length
	DECR_LEN( len, 1 );
	if( data[0] != len ) 
	{
		gnutls_assert();
		return GNUTLS_E_UNEXPECTED_PACKET_LENGTH;
	}
	data_idx += 1;
	
	// Create a struct to hold the values from the buffer
	trf = gnutls_calloc( 1, sizeof( *trf ) );
	if( trf == NULL ) 
	{
		gnutls_assert();
		return GNUTLS_E_MEMORY_ERROR;
	}
	
	// Read octet sequence and convert to TRF structure
	trf->krb_flags    = _gnutls_read_uint32( data );
	data_idx += 4;
	trf->tlskdh_flags = _gnutls_read_uint32( data );
	
	_gnutls_handshake_log
		    ("EXT[%p]: rcvd ticket request flags [krb:%u] [kdh:%u] \n", session,
		     trf->krb_flags, trf->tlskdh_flags);
	
	// Store the flags in our session
	epriv = trf;
	_gnutls_ext_set_session_data( session, GNUTLS_EXTENSION_KDH_TRF, epriv );	
	
  return 0;
}

/**
 * Encode the Ticket Request Flags as a byte sequence onto the IO buffer
 * ready for sending over the wire.
 * 
 * Returns the number of octets written to the buffer on success or a
 * negative error code on failure.
 **/
static int
_gnutls_kdh_trf_send_params( gnutls_session_t session, gnutls_buffer_st* data )
{
	gnutls_kdh_trf_st* trf;
	extension_priv_data_t epriv;
	int ret = 0;
	
	// Retrieve extension data
	ret = _gnutls_ext_get_session_data( session, GNUTLS_EXTENSION_KDH_TRF,
					&epriv );
	// Check for errors
	if( ret < 0 ) return 0;
	
	// Casting
	trf = epriv;
	
	/* Serialize the flags into a sequence of octets
	 * uint8: length of sequence for the flags (1 octet)
	 * uint32: krb_flags (4 octets)
	 * uint32: tlskdh_flags (4 octets)
	 */ 
	ret = _gnutls_buffer_append_prefix( data, 8, 8 );	
	if( ret < 0 ) return gnutls_assert_val( ret );
	
	BUFFER_APPEND_NUM( data, trf->krb_flags );
	BUFFER_APPEND_NUM( data, trf->tlskdh_flags );
	
	_gnutls_handshake_log
		    ("EXT[%p]: sent ticket request flags [krb:%u] [kdh:%u] \n", 
		    session, trf->krb_flags, trf->tlskdh_flags);
	
  return 9; // Total sequence length is 1 + 4 + 4
}

static int
_gnutls_kdh_trf_pack( extension_priv_data_t epriv, gnutls_buffer_st* ps )
{
	int ret; // Here due to macros below
	
	/* Append the extension's internal state to buffer */
	BUFFER_APPEND_NUM( ps, ((gnutls_kdh_trf_st*)epriv)->krb_flags );
	BUFFER_APPEND_NUM( ps, ((gnutls_kdh_trf_st*)epriv)->tlskdh_flags );
   
	return 0;
}

static int
_gnutls_kdh_trf_unpack( gnutls_buffer_st* ps, extension_priv_data_t* epriv )
{
	int ret; // Here due to macros below
	gnutls_kdh_trf_st* trf;
	
	// Create a struct to hold the values from the buffer
	trf = gnutls_calloc( 1, sizeof( *trf ) );
	if( trf == NULL ) 
	{
		gnutls_assert();
		return GNUTLS_E_MEMORY_ERROR;
	}
	
	/* Read the internal state from buffer */
	BUFFER_POP_NUM( ps, trf->krb_flags );
	BUFFER_POP_NUM( ps, trf->tlskdh_flags );
	
	*epriv = trf;
	
  return 0;
  
	error: // Here due to macros above
		gnutls_free(trf);
		return ret;
}

static void _gnutls_kdh_trf_deinit( extension_priv_data_t priv ) 
{
	gnutls_free( priv );
}

/** Extension interface **/

/**
 * gnutls_kdh_trf_get:
 * @session: is a #gnutls_session_t type.
 * @flags: container for the ticket request flags.
 * 
 * This function retrieves the ticket request flags sent by the peer.  
 * If we are operating in server mode then the flags sent by the client 
 * are retrieved.
 * If we are operating in client mode then the flags sent by the server
 * are retrieved.
 * 
 * Returns: On success, %GNUTLS_E_SUCCESS (0) is returned,
 *   otherwise a negative error code is returned.
 * 
 * Since 3.4.7
 **/ 
int gnutls_kdh_trf_get( gnutls_session_t session, gnutls_kdh_trf_t* flags ) {
	
	int ret = 0;
	gnutls_kdh_trf_st* trf;
	extension_priv_data_t epriv;
	
	// Retrieve extension data containing our flags
	ret = _gnutls_ext_get_session_data( session, GNUTLS_EXTENSION_KDH_TRF, &epriv );
	
	// Check for errors
	if( ret < 0 ) 
	{
		gnutls_assert();
		return GNUTLS_E_REQUESTED_DATA_NOT_AVAILABLE;
	}
	
	// Copy data to output container
	trf = epriv; // casting
	*flags = *trf;
	
	return ret;
}

/**
 * gnutls_kdh_trf_set:
 * @session: is a #gnutls_session_t type.
 * @flags: the ticket request flags.
 * 
 * Since 3.4.7
 **/
int gnutls_kdh_trf_set( gnutls_session_t session, gnutls_kdh_trf_t flags ) {
	
	int ret = 0;
	gnutls_kdh_trf_st* trf;
	
	
	/* Copy the flags into some fresh memory and store it in the session´s
	 * extension data. 
	 */ 
	trf = gnutls_calloc( 1, sizeof( *trf ) );
	if( trf == NULL ) 
	{
		gnutls_assert();
		return GNUTLS_E_MEMORY_ERROR;
	}
	
	*trf = flags;
	
	// Store the flags
	_gnutls_ext_set_session_data( session, GNUTLS_EXTENSION_KDH_TRF, trf );
	
	return ret;	
}

//TODO implement: #endif
