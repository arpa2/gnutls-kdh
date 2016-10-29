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

#include <auth/kdh.h>
#include "gnutls_errors.h"
#include "gnutls_int.h"
#include <cert.h>
#include <abstract_int.h>
#include <ext/signature.h>

//TODO implement #ifdef ENABLE_KDH

inline static int _gnutls_TLSHashID2KrbChecksumTypeID( uint8_t hashID );
inline static int _gnutls_KrbChecksumTypeID2TLSHashID( int32_t ChksmTypeID );


/* Generate a Kerberos Authenticator message. It conforms to the
 * DigitallySigned struct format.
 * 
 * <HashID (1 byte)
 * ++
 * SigID (1 byte)
 * ++
 * auth_length (2 bytes)
 * ++
 * Authenticator (auth_length bytes)>
 */
int _gnutls_gen_cert_krb_authenticator( gnutls_session_t session, 
																				gnutls_buffer_st* data )
{
	int ret;
	gnutls_pcert_st* apr_cert_list; // kerberos ticket
	gnutls_privkey_t apr_pkey;
	int apr_cert_list_length;
	gnutls_sign_algorithm_t sh_algo; // sign & hash algoritm
	const mac_entry_st* me;
	const sign_algorithm_st* aid;
	uint8_t hash[MAX_HASH_SIZE];
	uint8_t tmp[2]; // to store our sign & hash algo IDs
	gnutls_datum_t dhash;
	gnutls_datum_t enc_authenticator; // encrypted client authenticator
	gnutls_datum_t dec_authenticator; // decrypted client authenticator
	gnutls_certificate_credentials_t cred;
	int32_t krb_checksum_type;
	
	
	// Check whether there are credentials set
	cred = (gnutls_certificate_credentials_t)
	    _gnutls_get_cred( session, GNUTLS_CRD_CERTIFICATE );
	if( cred == NULL )
	{
		gnutls_assert();
		return GNUTLS_E_INSUFFICIENT_CREDENTIALS;
	}	

	/* Retrieve the negotiated certificate. This should be our
	 * kerberos ticket.
	 */
	ret = _gnutls_get_selected_cert( session, &apr_cert_list,
																	&apr_cert_list_length, &apr_pkey ); 
	if( ret < 0 )
	{
		gnutls_assert();
		return ret;
	}

	/* Check whether the certificate with our ticket is set */
	if( apr_cert_list_length > 0 )
	{
		/* Get the prefered signature & hash algorithm. In our case this
		 * should be one of the GNUTLS_SIGN_KDH_* algos. These algos
		 * dictate a kerberos authenticator, as a signature equivalent,
		 * and a specific hash algorithm.
		 */
		// Retrieve a preferred algo from the private key, if one is set.
		sh_algo = _gnutls_privkey_get_preferred_sign_algo( apr_pkey );
		
		if( sh_algo == GNUTLS_SIGN_UNKNOWN || 
				_gnutls_session_sign_algo_enabled( session, sh_algo ) < 0 )
		{
			/* There is no prefered key set in the private key or it is not 
			 * enabled on the client. Therefor choose a matching algorithm 
			 * from the signature_algorithms extension.
			 */
			sh_algo = _gnutls_session_get_sign_algo( session, apr_cert_list );
			if( sh_algo == GNUTLS_SIGN_UNKNOWN )
			{
				gnutls_assert();
				return GNUTLS_E_UNKNOWN_PK_ALGORITHM;
			}
		}
		
		// Set the signature & hash algorithm
		gnutls_sign_algorithm_set_client( session, sh_algo );
		
		/* Convert the internal representation of the signature & hash 
		 * algorithm to a tuple containing the signature and hash 
		 * identifiers from the IANA TLS SignatureAlgorithm and 
		 * HashAlgorithm Registries. We prepend this tuple to the
		 * authenticator in order to comply with the DigitallySigned struct
		 * format. We also need the hash ID to convert it to the
		 * equivalent kerberos checksum type identifier.
		 */
		aid = _gnutls_sign_to_tls_aid( sh_algo );
		if( aid == NULL )
			return gnutls_assert_val( GNUTLS_E_UNKNOWN_ALGORITHM );
			
		// Write our signature & hash algorithm IDs to the buffer (2 bytes)
		tmp[0] = aid->hash_algorithm;
		tmp[1] = aid->sign_algorithm;
		ret = _gnutls_buffer_append_data( data, tmp, 2 );
		if( ret < 0 )
		{
			gnutls_assert();
		}

		/* First we are going to hash all the handshake messages passed
		 * back and forth thusfar, just as for the regular client
		 * certificate verifiy message. However, we are not going to sign
		 * this hash because we don't have a PKI in place.
		 */
		me = hash_to_entry( gnutls_sign_get_hash_algorithm( sh_algo ) );

		ret = _gnutls_hash_fast( (gnutls_digest_algorithm_t)me->id,
											session->internals.handshake_hash_buffer.data,
											session->internals.handshake_hash_buffer.length,
											hash );
		if( ret < 0 )	return gnutls_assert_val(ret);

		// Store our hash as a datum_t type to ease handling
		dhash.data = hash;
		dhash.size = _gnutls_hash_get_algo_len( me );
		
		// Convert TLS hash ID to Kerberos checksum type ID
		krb_checksum_type = _gnutls_TLSHashID2KrbChecksumTypeID( aid->hash_algorithm );
		
		/* We are now going to pass this hash to a callback function that
		 * wraps it into a kerberos authenticator.
		 */
		if( cred->authenticator_encode_callback )
		{
			ret = cred->authenticator_encode_callback( session,
																								&enc_authenticator,
																								&dec_authenticator,
																								&dhash,
																								krb_checksum_type );
			if( ret < 0 ) return gnutls_assert_val( GNUTLS_E_USER_ERROR );			
		} 
		else
		{
			/* No callback was set in order to retrieve an authenticator
			 * so we can't continue the handshake.
			 */
			return gnutls_assert_val( GNUTLS_E_USER_ERROR );
		}
		
		/* Now that we have the authenticator we are going to serialize it
		 * into the output buffer so that it can be transmitted to the 
		 * peer. Our message looks like:
		 * <length++authenticator> where
	   * length = 2 bytes and
	   * certificate = length bytes.
	   */
		ret = _gnutls_buffer_append_data_prefix( data, 16, 
																						enc_authenticator.data,
																						enc_authenticator.size );
		if( ret < 0 )
		{
			gnutls_assert();
			return ret;
		}
																						
		/* For KDH only ciphersuites we have a different premaster secret
		 * computation. We therefor check the negotiated ciphersuite and
		 * adapt the premaster secret computation accordingly.
		 */
		if( _gnutls_cipher_suite_is_kdh( session->security_parameters.cipher_suite ) )
		{
			/* Note: this function should be called after the kx has finished
			 * because it relies on the established DH key (session.key.key).
			 * 
			 * The decrypted Kerberos authenticator will be used as a source
			 * of entropy for the premaster secret computation.
			 */ 
			ret = _gnutls_set_kdh_pms( session, &dec_authenticator );
			
			if( ret < 0 )
			{
				gnutls_assert();
				return ret;
			}
		}
		
		// Cleanup
		_gnutls_free_datum( &enc_authenticator );
		_gnutls_free_datum( &dec_authenticator );
		
		// Log our choice for debugging
		_gnutls_debug_log("sign handshake cert vrfy: picked %s with %s\n",
			  gnutls_sign_algorithm_get_name( sh_algo ),
			  _gnutls_mac_get_name( me ));
		
		// All OK
		return data->length;
		
	} else 
	{
		/* This should not happen since we already sent the ticket in the
		 * client certificate message. */
		return 0;
	}
}


/* Process a Kerberos Authenticator message. It conforms to the
 * DigitallySigned struct format.
 * 
 * <HashID (1 byte)
 * ++
 * SigID (1 byte)
 * ++
 * auth_length (2 bytes)
 * ++
 * Authenticator (auth_length bytes)>
 */
int _gnutls_proc_cert_krb_authenticator( gnutls_session_t session,
				  uint8_t* data, size_t data_size )
{
	int ret;
	int32_t krb_checksum_type;
	gnutls_datum_t dhash; // Computed hash in datum format
	gnutls_datum_t auth_hash; // Hash from the authenticator
	gnutls_datum_t enc_authenticator; // Encrypted client authenticator
	gnutls_datum_t dec_authenticator; // Decrypted client authenticator
	unsigned int auth_len; // Length in bytes of the authenticator	
	gnutls_certificate_credentials_t cred;
	gnutls_sign_algorithm_t sh_algo;
	sign_algorithm_st aid;	
	const mac_entry_st* me;
	uint8_t hash[MAX_HASH_SIZE]; // Computed hash
	uint8_t auth_hash_id; // TLS ID converted from checksum type ID in authenticator
	
	ssize_t dsize  = data_size;
	uint8_t* pdata = data; // Data pointer
	
	
	// Check whether there are credentials set
	cred = (gnutls_certificate_credentials_t)
	    _gnutls_get_cred( session, GNUTLS_CRD_CERTIFICATE );
	if( cred == NULL )
	{
		gnutls_assert();
		return GNUTLS_E_INSUFFICIENT_CREDENTIALS;
	}
	
	/* First we are going to read our authenticator from the buffer
	 * which is formatted according to the DigitallySigned struct. We
	 * therefor first read the signature and hash algorithm tuple and 
	 * then read the authenticator.
	 */	
	// Read the received signature & hash algorithm
	DECR_LEN( dsize, 2 );
	aid.hash_algorithm = pdata[0];
	aid.sign_algorithm = pdata[1];

	sh_algo = _gnutls_tls_aid_to_sign( &aid );
	if( sh_algo == GNUTLS_SIGN_UNKNOWN )
	{
		gnutls_assert();
		return GNUTLS_E_UNSUPPORTED_SIGNATURE_ALGORITHM;
	}
	pdata += 2;
	
	// Check whether it is allowed
	ret = _gnutls_session_sign_algo_enabled( session, sh_algo );
	if( ret < 0 )
	{
		return gnutls_assert_val( ret );
	}
		
	// Set the signature & hash algorithm
	gnutls_sign_algorithm_set_client( session, sh_algo );
	gnutls_sign_algorithm_set_server( session, sh_algo );
	
	// Log the used algorithm
	_gnutls_handshake_log("HSK[%p]: verify cert vrfy: using %s\n",
			      session,
			      gnutls_sign_algorithm_get_name( sh_algo ));

	/* Read the length of our authenticator. Our message looks like:
	 * <length++authenticator> where
	 * length = 2 bytes and
	 * certificate = length bytes.
	 */
	DECR_LEN( dsize, 2 );
	auth_len = _gnutls_read_uint16( pdata );
	pdata += 2;

	// Read our authenticator
	DECR_LEN_FINAL( dsize, auth_len );

	enc_authenticator.data = pdata;
	enc_authenticator.size = auth_len;
	
	/* All data has been received in good order. We are now going to
	 * prepare our data structure that stores the hash. We know how to
	 * initialize this structure because the hash algorithm used for the
	 * hash that is packed inside the authenticator is passed along.
	 */
	// First retrieve the right MAC entry that holds the size of our hash
	me = hash_to_entry( gnutls_sign_get_hash_algorithm( sh_algo ) );
	
	// Set the size of our hash
	auth_hash.size = me->output_size;
	
	// The user will allocate some memory and overwrite/set our pointer
	auth_hash.data = NULL;
	
	/* Initialize the data structure for the decrypted authenticator. It
	 * has the same size as its encrypted counterpart.
	 */
	dec_authenticator.size = auth_len;
	dec_authenticator.data = gnutls_malloc( auth_len );
	
	if( dec_authenticator.data == NULL )
	{
		gnutls_assert();
		return GNUTLS_E_MEMORY_ERROR;
	}
	
	/* Because the authenticator is encrypted with a kerberos key we 
	 * can not retrieve the client certificate verify hash ourselves.
	 * We therefor do a callback in order to retrieve the hash.
	 * Furthermore we retrieve the decrypted authenticator that will be
	 * used in the premaster secret computation for KDH-only ciphersuites.
	 */
	// Check whether a callback has been defined
	if( cred->authenticator_decode_callback )
	{
		ret = cred->authenticator_decode_callback( session,
																							&enc_authenticator,
																							&dec_authenticator,
																							&auth_hash,	
																							&krb_checksum_type );
		if( ret < 0 ) return gnutls_assert_val( GNUTLS_E_USER_ERROR );
	} else
	{
		/* No callback was set in order to retrieve the hash
		 * so we can't continue the handshake.
		 */
		return gnutls_assert_val( GNUTLS_E_USER_ERROR ); 
	}
	
	/* By now we have all the data to start the validation. First we
	 * check whether the checksum type and the hash type match.
	 */
	auth_hash_id = _gnutls_KrbChecksumTypeID2TLSHashID( krb_checksum_type );
	if( aid.hash_algorithm != auth_hash_id )
	{
		gnutls_assert_val( GNUTLS_E_RECEIVED_ILLEGAL_PARAMETER );
	}
	
	/* Then we check whether the hash from the authenticator matches the 
	 * one that we compute ourselves.
	 */
	// Hash all the handshake messages passed back and forth thusfar
	ret = _gnutls_hash_fast( (gnutls_digest_algorithm_t)me->id,
			      session->internals.handshake_hash_buffer.data,
			      session->internals.handshake_hash_buffer_prev_len, hash );
	if( ret < 0 ) return gnutls_assert_val( ret );

	// Store our hash as a datum_t type to ease handling
	dhash.data = hash;
	dhash.size = _gnutls_hash_get_algo_len( me );
	
	// Compare the hash sizes
	if( dhash.size != auth_hash.size )
	{
		return gnutls_assert_val( GNUTLS_E_PK_SIG_VERIFY_FAILED );
	}
	
	// Sizes match, now compare the hashes
	if( memcmp( dhash.data, auth_hash.data, dhash.size ) )
	{
		return gnutls_assert_val( GNUTLS_E_PK_SIG_VERIFY_FAILED );
	}
	
	/* For KDH only ciphersuites we have a different premaster secret
	 * computation. We therefor check the negotiated ciphersuite and
	 * adapt the premaster secret computation accordingly.
	 */
	if( _gnutls_cipher_suite_is_kdh( session->security_parameters.cipher_suite ) )
	{
		/* Note: this function should be called after the kx has finished
		 * because it relies on the established DH key (session.key.key).
		 * 
		 * The decrypted Kerberos authenticator will be used as a source
		 * of entropy for the premaster secret computation.
		 */
		ret = _gnutls_set_kdh_pms( session, &dec_authenticator );
		
		if( ret < 0 )
		{
			gnutls_assert();
			return ret;
		}
	}
	
	// Log the OK status
	_gnutls_handshake_log("HSK[%p]: client cert vrfy: hash is OK.\n",
			      session );
			      
	// Cleanup
	/* Note: auth_hash is contained in the dec_authenticator. By freeing the latter
	 * we automatically free the auth_hash. Freeing auth_hash directly results in
	 * an error and must not be done!
	 */
	_gnutls_free_datum( &dec_authenticator );
			     
	// All OK 
	return 0;
}

/* This function computes the premaster secret that is used for
 * KDH-only ciphersuites. It is based on the established DH key and the
 * client kerberos authenticator in decrypted form.
 * 
 * KDH-only premaster secret: 
 * (uint16) DH key size
 * ++
 * (uint8[]) DH key
 * ++
 * (uint16) Authenticator size
 * ++
 * (uint8[]) Authenticator
 * 
 * The premaster secret will be stored in session.key.key. 
 */
int _gnutls_set_kdh_pms( gnutls_session_t session, 
												gnutls_datum_t* authenticator )
{
	gnutls_datum_t* DH_key;
	gnutls_datum_t PMS; // Premaster secret
	uint8_t* p; // Data pointer
	
	// For brevity
	DH_key = &(session->key.key);
	
	/* Check whether a DH key is set. If no key is set we can not continue
	 * the premaster secret computation.
	 */
	if( DH_key->data == NULL || DH_key->size == 0 )
	{
		gnutls_assert();
		return GNUTLS_E_INVALID_SESSION;
	}
	
	// Calculate the total length of our premaster secret
	PMS.size = 2 + DH_key->size + 2 + authenticator->size;
	
	// Allocate fresh memory for our PMS
	PMS.data = gnutls_malloc( PMS.size );
	if( PMS.data == NULL ) 
	{
		gnutls_assert();
		return GNUTLS_E_MEMORY_ERROR;
	}
	
	/* We now write our premaster secret to memory */
	// Initialize our data pointer
	p = PMS.data;
	// Write the DH key size
	_gnutls_write_uint16( DH_key->size, p );
	p += 2;
	// Copy the already established DH key
	memcpy( p, DH_key->data, DH_key->size );
	p += DH_key->size;
	// Write the authenticator size
	_gnutls_write_uint16( authenticator->size, p );
	p += 2;
	// Write the authenticator
	memcpy( p, authenticator->data, authenticator->size );
	
	// Replace the currently set premaster secret with the new one
	_gnutls_free_key_datum( DH_key );
	DH_key->size = PMS.size;
	DH_key->data = PMS.data;
	
	return GNUTLS_E_SUCCESS;
} 

/* Converts IDs from IANA's TLS HashAlgorithm Registry 
 * to IDs from IANA's Kerberos Checksum Type Numbers.
 * A 0 value means that there is no mapping.
 */
inline static int32_t _gnutls_TLSHashID2KrbChecksumTypeID( uint8_t hashID )
{
	static const uint8_t MAPPING_LEN = 7;
	static const int32_t TLS_KRB_Mapping[] = { //Assume continuous defined values
		0, // none
		0, // md5
		10, // sha1
		-1, // sha224
		-2, // sha256
		-3, // sha384
		-4  // sha512
	};
	
	if( hashID < MAPPING_LEN ) 
	{
		return TLS_KRB_Mapping[ hashID ];
	} else
	{
		return GNUTLS_E_ILLEGAL_PARAMETER;
	}
}

/* Converts IDs from IANA's Kerberos Checksum Type Numbers 
 * to IDs from IANA's TLS HashAlgorithm Registry.
 * A 0 value means that there is no mapping.
 */
inline static int _gnutls_KrbChecksumTypeID2TLSHashID( int32_t ChksmTypeID )
{
	static const int32_t MAPPING_MAX_ID = 18;
	static const uint8_t KRB_TLS_Mapping[] = { //Assume continuous defined values
		0, // Reserved
		0, // CRC32
		0, // rsa-md4
		0, // rsa-md4-des
		0, // des-mac
		0, // des-mac-k
		0, // rsa-md4-des-k
		0, // rsa-md5
		0, // rsa-md5-des
		0, // rsa-md5-des3
		2, // sha1
		0, // Unassigned
		0, // hmac-sha1-des3-kd
		0, // hmac-sha1-des3
		2, // sha1
		0, // hmac-sha1-96-aes128
		0, // hmac-sha1-96-aes256
		0, // cmac-camellia128
		0, // cmac-camellia256
		//--- negative values, i.e. private values
		3, // (-1) sha224
		4, // (-2) sha256
		5, // (-3) sha384
		6 // (-4) sha512
	};
	
	if( ChksmTypeID <= MAPPING_MAX_ID ) 
	{
		/* Negative values are allowed and are reserved for private use.
		 * Let's convert them to positive values in order to be able to use
		 * our array for the mapping. */
		if( ChksmTypeID < 0 )
		{
			ChksmTypeID = MAPPING_MAX_ID - ChksmTypeID;
		}
		
		return KRB_TLS_Mapping[ ChksmTypeID ];
	} else
	{
		return GNUTLS_E_ILLEGAL_PARAMETER;
	}
}

//TODO implement #endif
