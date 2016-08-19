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
 * This file is part of the client_certificate_type extension as
 * defined in RFC7250 (https://tools.ietf.org/html/rfc7250).
 * 
 * The client_certificate_type extension in the client hello indicates
 * the certificate types the client is able to provide to the server,
 * when requested using a certificate_request message.
 */

#include <gnutls_int.h>
#include <ext/client_cert_type.h>
#include <gnutls_extensions.h>
#include "gnutls_errors.h"
#include <gnutls_state.h>
#include <gnutls_datum.h>


static int _gnutls_client_cert_type_recv_params( gnutls_session_t session, 
										const uint8_t* data, size_t data_size );
static int _gnutls_client_cert_type_send_params( gnutls_session_t session, 
										gnutls_buffer_st* data );
static int _gnutls_client_cert_type_pack( extension_priv_data_t epriv, 
										gnutls_buffer_st* ps );
static int _gnutls_client_cert_type_unpack( gnutls_buffer_st* ps, 
										extension_priv_data_t* epriv );
static void _gnutls_client_cert_type_deinit( extension_priv_data_t priv );

inline static int _gnutls_num2cert_type( int num );
inline static int _gnutls_cert_type2num( int cert_type );

extension_entry_st ext_mod_client_cert_type = {
	.name = "Client Certificate Type",
	.type = GNUTLS_EXTENSION_CLIENT_CERT_TYPE,
	.parse_type = GNUTLS_EXT_APPLICATION, //TODO verify choice
	.recv_func = _gnutls_client_cert_type_recv_params,
	.send_func = _gnutls_client_cert_type_send_params,
	.pack_func = _gnutls_client_cert_type_pack,
	.unpack_func = _gnutls_client_cert_type_unpack,
	.deinit_func = _gnutls_client_cert_type_deinit
};


static int _gnutls_client_cert_type_recv_params( gnutls_session_t session, 
										const uint8_t* data, size_t data_size )
{	
	int ret;
	gnutls_datum_t* cert_types;
	gnutls_datum_t* priv;
	extension_priv_data_t epriv;
	gnutls_certificate_type_t cert_type;
	
	uint8_t i, found 				= 0;
	ssize_t len            	= data_size;
	const uint8_t* data_idx = data;

	
	// Compare packet length with expected packet length
	// On a server, compare packet length with expected packet length
	// On a client, ensure that only a single byte was received
	if( _gnutls_server_mode( session ))
	{
		DECR_LEN( len, 1 );
		if( data[0] != len ) 
		{
			gnutls_assert();
			return GNUTLS_E_UNEXPECTED_PACKET_LENGTH;
		}
		data_idx += 1;
	} else
	{
		if( len != 1 )
		{
			gnutls_assert();
			return GNUTLS_E_UNEXPECTED_PACKET_LENGTH;
		}
	}
	
	// Create a struct to hold the values from the buffer
	cert_types = gnutls_calloc( 1, sizeof( *cert_types ) );
	if( cert_types == NULL ) 
	{
		gnutls_assert();
		return GNUTLS_E_MEMORY_ERROR;
	}
	
	// Copy the contents of the buffer to our struct
	_gnutls_set_datum( cert_types, data_idx, len );
	
	if( _gnutls_client_mode( session ) ) // client mode
	{
		/* The server picked one of the offered cert types iff he supports
		 * at least one of them and decided to do a client certificate 
		 * request. If both parties play by the rules then we may only 
		 * receive a cert type that we offered, i.e. one that we support. 
		 * Because the world isn't as beautiful as it may seem, we're going
		 * to check it nevertheless. */
		cert_type = _gnutls_num2cert_type( cert_types->data[0] );
		
		// Check validity of cert type
		if( cert_type < 0 ) 
		{
				gnutls_assert();
				ret = cert_type;
				goto finished;
		}
		
		// Get the cert types that we sent to the server
		ret = _gnutls_ext_get_session_data( session, 
						GNUTLS_EXTENSION_CLIENT_CERT_TYPE, &epriv );
		if( ret < 0 )
		{
			gnutls_assert();
			ret = GNUTLS_E_REQUESTED_DATA_NOT_AVAILABLE; //TODO check, is this the right error code to return here?
			goto finished;
		}
		// Casting
		priv = epriv;
		
		// Check whether what we got back is actually offered by us
		for( i = 0; i < priv->size; i++ )
		{
			if( priv->data[i] == cert_type ) found = 1;
		}
		
		if( found ) {
			// Everything OK, now set the client certificate type
			_gnutls_session_client_cert_type_set( session, cert_type );
			ret = 0;
			goto finished;
		}
		
		ret = GNUTLS_E_UNSUPPORTED_CERTIFICATE_TYPE;
	
	finished:
		_gnutls_free_datum( cert_types );
		gnutls_free( cert_types );
		return ret;
		
	} else // server mode
	{
		// Store the client certificate types in our session
		epriv = cert_types;
		_gnutls_ext_set_session_data( session, GNUTLS_EXTENSION_CLIENT_CERT_TYPE, epriv );
		
		/* We receive a list of supported certificate types that the client
		 * is able to provide when requested via a client certificate
		 * request. This list is sorted by order of preference. We now check
		 * in this order of preference whether we support any of these
		 * certificate types.
		 */
		for( i = 0; i < cert_types->size; i++ ) 
		{
			// Convert to internal representation
			cert_type = _gnutls_num2cert_type( cert_types->data[i] );
		 
			// If we have an invalid cert id then continue to the next
			if( cert_type < 0 ) continue;
		 
			// Check for support of this cert type
			if( _gnutls_session_cert_type_supported( session, cert_type, 
						false, GNUTLS_CTYPE_CLIENT ) == 0 ) 
			{
				found = 1;
				break;
			}
		}
	 
		// We found a matching ctype, we pick this one
		if( found ) {
			_gnutls_session_client_cert_type_set( session, cert_type );
			ret = 0;
		} else {
		
			/* If no supported certificate type can be found we terminate
			 * with a fatal alert of type "unsupported_certificate"
			 * (according to specification rfc7250).
			 */
			ret = GNUTLS_E_UNSUPPORTED_CERTIFICATE_TYPE;
		}
		return ret;
	}
	
}

static int _gnutls_client_cert_type_send_params( gnutls_session_t session, 
										gnutls_buffer_st* data )
{
	int ret;
	uint8_t cert_type, i = 0;
	priority_st* cert_priors;
	gnutls_datum_t* cert_types; // Supported ctypes
	
	
	if( _gnutls_client_mode( session ) ) // Client mode
	{ 
		// For brevity
		cert_priors = &session->internals.priorities.client_cert_type;
		
		/* Retrieve client certificate type priorities if any. If no
		 * priorities are set then the default client certificate type 
		 * initialization values apply. This default is currently set to
		 * x.509 in which case we don't enable this extension.
		 */		  
		if( cert_priors->algorithms > 0) // Priorities are explicitly set
		{ 
			if( cert_priors->algorithms > 1 && 
					cert_priors->priority[0] == DEFAULT_CERT_TYPE ) 
			{
				// Explicitly set but default ctype, so don't send anything
				return 0;
			}
			
			// Initialize our tmp cert list
			cert_types = gnutls_calloc( 1, sizeof( *cert_types ) );
			if( cert_types == NULL ) 
			{
				gnutls_assert();
				return GNUTLS_E_MEMORY_ERROR;
			}
			_gnutls_set_datum( cert_types, NULL, 0 );
			
			/* We are only allowed to send certificate types that we support, 
			 * i.e. have credentials for. Therefor we check this here and 
			 * prune our original list.
			 */
			for( i = 0; i < cert_priors->algorithms; i++ ) 
			{
				if( _gnutls_session_cert_type_supported( session, 
								cert_priors->priority[i], true, 
								GNUTLS_CTYPE_CLIENT ) == 0 ) 
				{
					cert_type = _gnutls_cert_type2num( cert_priors->priority[i] );
					ret 			= _gnutls_datum_append( cert_types, &cert_type, 1 );
					if (ret < 0) {
						// Cleanup
						_gnutls_free_datum( cert_types );
						gnutls_free( cert_types );
						return gnutls_assert_val(ret);
					}
				}
			}
			
			// Also store internally what we are going to send
			_gnutls_ext_set_session_data( session, GNUTLS_EXTENSION_CLIENT_CERT_TYPE, 
					cert_types );
			
			/* Serialize the certificate types into a sequence of octets
			 * uint8: length of sequence of cert types (1 octet)
	     * uint8: cert types (0 <= #octets <= 255)
	     */
			ret = _gnutls_buffer_append_data_prefix( data, 8, 
																							cert_types->data, 
																							cert_types->size );
																							
			// Check for errors and cleanup in case of error
			if (ret < 0) {
				_gnutls_free_datum( cert_types );
				gnutls_free( cert_types );
				return 0;
			} else {
				return cert_types->size + 1;
			}
			
		}
		
	} else // Server mode
	{ 				
		/* Check whether we are going to send a certificate request,
		 * otherwise omit the response
		 */ 
		if( session->internals.send_cert_req != 0 ) 
		{
			// Retrieve negotiated client certificate type and send it
			cert_type = _gnutls_cert_type2num( session->security_parameters.client_cert_type );
			
			ret = gnutls_buffer_append_data( data, &cert_type, 1);
			
			if( ret < 0 ) return gnutls_assert_val( ret );
			
			return 1; // sent one byte
		}		
		
	} 
	
	return 0;
	
}

static int _gnutls_client_cert_type_pack( extension_priv_data_t epriv, 
										gnutls_buffer_st* ps )
{
	int ret; // Here due to macros below
	gnutls_datum_t* priv = epriv;	
	
	/* Append the extension's internal state to buffer */
	BUFFER_APPEND_PFX4( ps, priv->data, priv->size );
		/* We use a 4 byte length prefix here in order to be able to use
		 * the BUFFER_POP_DATUM macro in the unpack function. We could have
		 * used the PFX1 version of the marco but that would have 
		 * complicated matters in the unpack function. 
		 */
   
	return 0;
}

static int _gnutls_client_cert_type_unpack( gnutls_buffer_st* ps, 
										extension_priv_data_t* epriv )
{
	int ret;
	gnutls_datum_t* priv;
	
	// Create a struct to hold the values from the buffer
	priv = gnutls_calloc( 1, sizeof( *priv ) );
	if (priv == NULL) {
		gnutls_assert();
		return GNUTLS_E_MEMORY_ERROR;
	}
	
	// Copy the contents of the buffer to our struct
	BUFFER_POP_DATUM( ps, priv );
	
	// Casting
	*epriv = priv;
	
	return 0;
	
	error:
		gnutls_free( priv );
		return ret;
}

static void _gnutls_client_cert_type_deinit( extension_priv_data_t priv )
{
	_gnutls_free_datum( priv );
	gnutls_free( priv );
}


/** Helper functions **/

/* Maps IANA TLS Certificate Types identifiers to internal
 * certificate type representation.
 */
inline static int _gnutls_num2cert_type( int num )
{
	switch( num ) {
		case 0:
			return GNUTLS_CRT_X509;
		case 1:
			return GNUTLS_CRT_OPENPGP;
		case 2:
			return GNUTLS_CRT_RAW;
		case 224:
			return GNUTLS_CRT_KRB; //TODO update to definite version
		default:
			return GNUTLS_E_RECEIVED_ILLEGAL_PARAMETER;
	}
}

/* Maps internal certificate type representation to
 * IANA TLS Certificate Types identifiers.
 */
inline static int _gnutls_cert_type2num( int cert_type )
{
	switch( cert_type ) {
		case GNUTLS_CRT_X509:
			return 0;
		case GNUTLS_CRT_OPENPGP:
			return 1;
		case GNUTLS_CRT_RAW:
			return 2;
		case GNUTLS_CRT_KRB:
			return 224; //TODO update to definite version
		default:
			return GNUTLS_E_RECEIVED_ILLEGAL_PARAMETER;
	}
}


/** Extension interface **/

/* The interface is defined in gnutls_state.c:
 * Public:
 * - gnutls_client_certificate_type_get
 * 
 * Private:
 * - _gnutls_session_client_cert_type_set
 */
