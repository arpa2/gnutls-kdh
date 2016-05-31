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

/* REMARK: maybe place this code in a seperate directory in the future?
 * Just like openpgp stuff
 */

/**
 * gnutls_certificate_get_krb_ticket:
 * @cred: is a #gnutls_certificate_credentials_t type.
 * @index: The index of the key to obtain.
 * @ticket: Location to store the ticket.
 *
 * Obtains a Kerberos ticket that has been stored in @cred with 
 * gnutls_certificate_set_krb_ticket(). 
 * 
 * If there is no certificate with the given index,
 * %GNUTLS_E_REQUESTED_DATA_NOT_AVAILABLE is returned. If the certificate
 * with the given index is not a Kerberos ticket, %GNUTLS_E_INVALID_REQUEST 
 * is returned.
 *
 * Returns: %GNUTLS_E_SUCCESS (0) on success, or a negative error code.
 *
 * Since: TODO
 */
int gnutls_certificate_get_krb_ticket( gnutls_certificate_credentials_t cred,
																	unsigned index,
																	gnutls_datum_t* ticket )
{
	// Check for valid index
	if( index >= cred->ncerts ) 
	{
		gnutls_assert();
		return GNUTLS_E_REQUESTED_DATA_NOT_AVAILABLE;
	}
	
	// Check for the correct number of certificates (should be 1)
	if( cred->certs[index].cert_list_length != 1 )
		return GNUTLS_E_INVALID_REQUEST;
	
	// Check for the correct certificate type
	if( cred->certs[index].cert_list[0].type != GNUTLS_CRT_KRB )
	{
		gnutls_assert();
		return GNUTLS_E_INVALID_REQUEST;
	}
		
	// OK, so copy the ticket stored in the certificate
	*ticket = cred->certs[index].cert_list[0].cert;
	
	return GNUTLS_E_SUCCESS;
}																	
																	
															
/** TODO rewrite
 * gnutls_certificate_set_krb_ticket:
 * @cred: is a #gnutls_certificate_credentials_t type.
 * @ticket: contains a Kerberos ticket.
 *
 * This function sets a certificate/private key pair in the
 * gnutls_certificate_credentials_t type.  This function may be
 * called more than once (in case multiple keys/certificates exist
 * for the server).
 *
 * Note that this function requires that the preferred key ids have
 * been set and be used. See gnutls_openpgp_crt_set_preferred_key_id().
 * Otherwise the master key will be used.
 *
 * Returns: On success, %GNUTLS_E_SUCCESS (0) is returned,
 *   otherwise a negative error code is returned.
 **/																
int gnutls_certificate_set_krb_ticket( gnutls_certificate_credentials_t cred,
																	const gnutls_datum_t* ticket );
{
	int ret;
	gnutls_privkey_t privkey;
	gnutls_pcert_st* pcert;

	
	/* GnuTLS' %certificate_credentials_st keeps two data structures for 
	 * certificate / key material.
	 * Field %certs keeps track of the certificates with corresponding 
	 * public keys.
	 * Field %pkey keeps track of the private keys.
	 * These two structures must be kept in sync, i.e.
	 * invariant %pkey[i] corresponds to %certs[i] must hold.
	 * 
	 * A Kerberos ticket can't be split in a public/private part. In order 
	 * to reuse the exisiting certificate structures and corresponding
	 * routines for Kerberos tickets, and to satisfy the aforementioned
	 * invariant, we need to create a dummy private key for every ticket
	 * that we insert into the %certs data structure.
	 */
	
	// Create a dummy private key
	ret = gnutls_privkey_init( &privkey );
	if( ret < 0 ) 
	{
		gnutls_assert();
		return ret;
	}
	/* Set the correct key type so that we are able to distinguish this
	 * dummy key in the future. We are not going to populate it any
	 * further and trying to process it fully in the future might cause
	 * parsing errors if we are not able to tell that this is just a
	 * dummy.
	 */
	privkey->type = GNUTLS_PRIVKEY_KRB;
	
	/* Now we prepare our certificate structure to hold our ticket. */
	// Allocate some memory
	pcert = gnutls_calloc( 1, sizeof( *pcert ) );
	if( pcert == NULL ) 
	{
		gnutls_assert();
		gnutls_privkey_deinit( privkey );
		return GNUTLS_E_MEMORY_ERROR;
	}
	// Copy our ticket to the certificate structure
	gnutls_pcert_import_krb_raw( pcert, ticket, 0 );
	
	// Add the dummy key to the credentials structure
	ret = certificate_credentials_append_pkey( cred, privkey );
	// Add the certificate with our ticket to the credentials structure
	if( ret >= 0 )
		ret = certificate_credential_append_crt_list( cred, NULL, pcert, 1 );
	
	// Check for errors
	if( ret < 0 ) 
	{
		gnutls_assert();
		gnutls_privkey_deinit( privkey );
		gnutls_free( pcert );
		return ret;
	}						   
							   
	// Successfully added a certificate
	cred->ncerts++;
	
	/* NOTE: we don't have to call _gnutls_check_key_cert_match() 
	 * because there is nothing to match in our case.
	 */
	
	// OK
	return GNUTLS_E_SUCCESS;
}						
