/*
 * Copyright (C) 2003-2015 Free Software Foundation, Inc.
 * Copyright (C) 2015 Red Hat, Inc.
 *
 * Author: Nikos Mavrogiannopoulos
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

/* Functions that relate on PKCS7 certificate lists parsing.
 */

#include <gnutls_int.h>
#include <libtasn1.h>

#include <gnutls_datum.h>
#include <gnutls_global.h>
#include <gnutls_errors.h>
#include <common.h>
#include <x509_b64.h>
#include <gnutls/abstract.h>
#include <gnutls/pkcs7.h>

#define SIGNED_DATA_OID "1.2.840.113549.1.7.2"
#define PLAIN_DATA_OID "1.2.840.113549.1.7.1"
#define DIGESTED_DATA_OID "1.2.840.113549.1.7.5"

#define ATTR_MESSAGE_DIGEST "1.2.840.113549.1.9.4"
#define ATTR_SIGNING_TIME "1.2.840.113549.1.9.5"
#define ATTR_CONTENT_TYPE "1.2.840.113549.1.9.3"

static const uint8_t one = 1;

/* Decodes the PKCS #7 signed data, and returns an ASN1_TYPE, 
 * which holds them. If raw is non null then the raw decoded
 * data are copied (they are locally allocated) there.
 */
static int
_decode_pkcs7_signed_data(ASN1_TYPE pkcs7, ASN1_TYPE * sdata)
{
	char oid[MAX_OID_SIZE];
	ASN1_TYPE c2;
	gnutls_datum_t tmp = {NULL, 0};
	int len, result;

	len = sizeof(oid) - 1;
	result = asn1_read_value(pkcs7, "contentType", oid, &len);
	if (result != ASN1_SUCCESS) {
		gnutls_assert();
		return _gnutls_asn2err(result);
	}

	if (strcmp(oid, SIGNED_DATA_OID) != 0) {
		gnutls_assert();
		_gnutls_debug_log("Unknown PKCS7 Content OID '%s'\n", oid);
		return GNUTLS_E_UNKNOWN_PKCS_CONTENT_TYPE;
	}

	if ((result = asn1_create_element
	     (_gnutls_get_pkix(), "PKIX1.pkcs-7-SignedData",
	      &c2)) != ASN1_SUCCESS) {
		gnutls_assert();
		return _gnutls_asn2err(result);
	}

	/* the Signed-data has been created, so
	 * decode them.
	 */
	result = _gnutls_x509_read_value(pkcs7, "content", &tmp);
	if (result < 0) {
		gnutls_assert();
		goto cleanup;
	}

	/* tmp, tmp_size hold the data and the size of the CertificateSet structure
	 * actually the ANY stuff.
	 */

	/* Step 1. In case of a signed structure extract certificate set.
	 */

	result = asn1_der_decoding(&c2, tmp.data, tmp.size, NULL);
	if (result != ASN1_SUCCESS) {
		gnutls_assert();
		result = _gnutls_asn2err(result);
		goto cleanup;
	}

	/* read the encapsulated content */
	len = sizeof(oid) - 1;
	result = asn1_read_value(c2, "encapContentInfo.eContentType", oid, &len);
	if (result != ASN1_SUCCESS) {
		gnutls_assert();
		result = _gnutls_asn2err(result);
		goto cleanup;
	}

	if (strcmp(oid, PLAIN_DATA_OID) != 0 && strcmp(oid, DIGESTED_DATA_OID) != 0) {
		gnutls_assert();
		_gnutls_debug_log("Unknown or unexpected PKCS7 Encapsulated Content OID '%s'\n", oid);
		result = GNUTLS_E_UNKNOWN_PKCS_CONTENT_TYPE;
		goto cleanup;
	}

	*sdata = c2;

	gnutls_free(tmp.data);
	return 0;

      cleanup:
	if (c2)
		asn1_delete_structure(&c2);
	gnutls_free(tmp.data);
	return result;
}

static int pkcs7_reinit(gnutls_pkcs7_t pkcs7)
{
	int result;

	asn1_delete_structure(&pkcs7->pkcs7);

	result = asn1_create_element(_gnutls_get_pkix(),
				     "PKIX1.pkcs-7-ContentInfo",
				     &pkcs7->pkcs7);
	if (result != ASN1_SUCCESS) {
		result = _gnutls_asn2err(result);
		gnutls_assert();
		return result;
	}

	return 0;
}

/**
 * gnutls_pkcs7_init:
 * @pkcs7: A pointer to the type to be initialized
 *
 * This function will initialize a PKCS7 structure. PKCS7 structures
 * usually contain lists of X.509 Certificates and X.509 Certificate
 * revocation lists.
 *
 * Returns: On success, %GNUTLS_E_SUCCESS (0) is returned, otherwise a
 *   negative error value.
 **/
int gnutls_pkcs7_init(gnutls_pkcs7_t * pkcs7)
{
	*pkcs7 = gnutls_calloc(1, sizeof(gnutls_pkcs7_int));

	if (*pkcs7) {
		int result = pkcs7_reinit(*pkcs7);
		if (result < 0) {
			gnutls_assert();
			gnutls_free(*pkcs7);
			return result;
		}
		return 0;	/* success */
	}
	return GNUTLS_E_MEMORY_ERROR;
}

/**
 * gnutls_pkcs7_deinit:
 * @pkcs7: the type to be deinitialized
 *
 * This function will deinitialize a PKCS7 type.
 **/
void gnutls_pkcs7_deinit(gnutls_pkcs7_t pkcs7)
{
	if (!pkcs7)
		return;

	if (pkcs7->pkcs7)
		asn1_delete_structure(&pkcs7->pkcs7);

	if (pkcs7->signed_data)
		asn1_delete_structure(&pkcs7->signed_data);

	gnutls_free(pkcs7);
}

/**
 * gnutls_pkcs7_import:
 * @pkcs7: The data to store the parsed PKCS7.
 * @data: The DER or PEM encoded PKCS7.
 * @format: One of DER or PEM
 *
 * This function will convert the given DER or PEM encoded PKCS7 to
 * the native #gnutls_pkcs7_t format.  The output will be stored in
 * @pkcs7.
 *
 * If the PKCS7 is PEM encoded it should have a header of "PKCS7".
 *
 * Returns: On success, %GNUTLS_E_SUCCESS (0) is returned, otherwise a
 *   negative error value.
 **/
int
gnutls_pkcs7_import(gnutls_pkcs7_t pkcs7, const gnutls_datum_t * data,
		    gnutls_x509_crt_fmt_t format)
{
	int result = 0, need_free = 0;
	gnutls_datum_t _data;

	if (pkcs7 == NULL)
		return GNUTLS_E_INVALID_REQUEST;

	_data.data = data->data;
	_data.size = data->size;

	/* If the PKCS7 is in PEM format then decode it
	 */
	if (format == GNUTLS_X509_FMT_PEM) {
		result =
		    _gnutls_fbase64_decode(PEM_PKCS7, data->data,
					   data->size, &_data);

		if (result <= 0) {
			gnutls_assert();
			return result;
		}

		need_free = 1;
	}

	if (pkcs7->expanded) {
		result = pkcs7_reinit(pkcs7);
		if (result < 0) {
			gnutls_assert();
			goto cleanup;
		}
	}
	pkcs7->expanded = 1;

	result =
	    asn1_der_decoding(&pkcs7->pkcs7, _data.data, _data.size, NULL);
	if (result != ASN1_SUCCESS) {
		result = _gnutls_asn2err(result);
		gnutls_assert();
		goto cleanup;
	}

	/* Decode the signed data.
	 */
	result = _decode_pkcs7_signed_data(pkcs7->pkcs7, &pkcs7->signed_data);
	if (result < 0) {
		gnutls_assert();
		goto cleanup;
	}

	result = 0;

      cleanup:
	if (need_free)
		_gnutls_free_datum(&_data);
	return result;
}

/**
 * gnutls_pkcs7_get_crt_raw2:
 * @pkcs7: should contain a gnutls_pkcs7_t type
 * @indx: contains the index of the certificate to extract
 * @cert: will hold the contents of the certificate; must be deallocated with gnutls_free()
 *
 * This function will return a certificate of the PKCS7 or RFC2630
 * certificate set.
 *
 * After the last certificate has been read
 * %GNUTLS_E_REQUESTED_DATA_NOT_AVAILABLE will be returned.
 *
 * Returns: On success, %GNUTLS_E_SUCCESS (0) is returned, otherwise a
 *   negative error value.  If the provided buffer is not long enough,
 *   then @certificate_size is updated and
 *   %GNUTLS_E_SHORT_MEMORY_BUFFER is returned.
 *
 * Since: 3.4.2
 **/
int
gnutls_pkcs7_get_crt_raw2(gnutls_pkcs7_t pkcs7,
			 int indx, gnutls_datum_t *cert)
{
	int result, len;
	char root2[ASN1_MAX_NAME_SIZE];
	char oid[MAX_OID_SIZE];
	gnutls_datum_t tmp = { NULL, 0 };

	if (pkcs7 == NULL)
		return GNUTLS_E_INVALID_REQUEST;

	/* Step 2. Parse the CertificateSet 
	 */
	snprintf(root2, sizeof(root2), "certificates.?%u", indx + 1);

	len = sizeof(oid) - 1;

	result = asn1_read_value(pkcs7->signed_data, root2, oid, &len);

	if (result == ASN1_VALUE_NOT_FOUND) {
		result = GNUTLS_E_REQUESTED_DATA_NOT_AVAILABLE;
		goto cleanup;
	}

	if (result != ASN1_SUCCESS) {
		gnutls_assert();
		result = _gnutls_asn2err(result);
		goto cleanup;
	}

	/* if 'Certificate' is the choice found: 
	 */
	if (strcmp(oid, "certificate") == 0) {
		int start, end;

		result = _gnutls_x509_read_value(pkcs7->pkcs7, "content", &tmp);
		if (result < 0) {
			gnutls_assert();
			goto cleanup;
		}

		result = asn1_der_decoding_startEnd(pkcs7->signed_data, tmp.data, tmp.size,
						    root2, &start, &end);

		if (result != ASN1_SUCCESS) {
			gnutls_assert();
			result = _gnutls_asn2err(result);
			goto cleanup;
		}

		end = end - start + 1;

		result = _gnutls_set_datum(cert, &tmp.data[start], end);
	} else {
		result = GNUTLS_E_UNSUPPORTED_CERTIFICATE_TYPE;
	}

      cleanup:
	_gnutls_free_datum(&tmp);
	return result;
}

/**
 * gnutls_pkcs7_get_crt_raw:
 * @pkcs7: should contain a gnutls_pkcs7_t type
 * @indx: contains the index of the certificate to extract
 * @certificate: the contents of the certificate will be copied
 *   there (may be null)
 * @certificate_size: should hold the size of the certificate
 *
 * This function will return a certificate of the PKCS7 or RFC2630
 * certificate set.
 *
 * After the last certificate has been read
 * %GNUTLS_E_REQUESTED_DATA_NOT_AVAILABLE will be returned.
 *
 * Returns: On success, %GNUTLS_E_SUCCESS (0) is returned, otherwise a
 *   negative error value.  If the provided buffer is not long enough,
 *   then @certificate_size is updated and
 *   %GNUTLS_E_SHORT_MEMORY_BUFFER is returned.
 **/
int
gnutls_pkcs7_get_crt_raw(gnutls_pkcs7_t pkcs7,
			 int indx, void *certificate,
			 size_t * certificate_size)
{
	int ret;
	gnutls_datum_t tmp = {NULL, 0};

	ret = gnutls_pkcs7_get_crt_raw2(pkcs7, indx, &tmp);
	if (ret < 0)
		return gnutls_assert_val(ret);

	if ((unsigned) tmp.size > *certificate_size) {
		*certificate_size = tmp.size;
		ret = GNUTLS_E_SHORT_MEMORY_BUFFER;
		goto cleanup;
	}

	*certificate_size = tmp.size;
	if (certificate)
		memcpy(certificate, tmp.data, tmp.size);

      cleanup:
	_gnutls_free_datum(&tmp);
	return ret;
}


/**
 * gnutls_pkcs7_get_crt_count:
 * @pkcs7: should contain a #gnutls_pkcs7_t type
 *
 * This function will return the number of certifcates in the PKCS7
 * or RFC2630 certificate set.
 *
 * Returns: On success, a positive number is returned, otherwise a
 *   negative error value.
 **/
int gnutls_pkcs7_get_crt_count(gnutls_pkcs7_t pkcs7)
{
	int result, count;

	if (pkcs7 == NULL)
		return GNUTLS_E_INVALID_REQUEST;

	/* Step 2. Count the CertificateSet */

	result = asn1_number_of_elements(pkcs7->signed_data, "certificates", &count);
	if (result != ASN1_SUCCESS) {
		gnutls_assert();
		return 0;	/* no certificates */
	}

	return count;
}

/**
 * gnutls_pkcs7_signature_info_deinit:
 * @info: should point to a #gnutls_pkcs7_signature_info_st structure
 *
 * This function will deinitialize any allocated value in the
 * provided #gnutls_pkcs7_signature_info_st.
 *
 * Since: 3.4.2
 **/
void gnutls_pkcs7_signature_info_deinit(gnutls_pkcs7_signature_info_st *info)
{
	gnutls_free(info->sig.data);
	gnutls_free(info->issuer_dn.data);
	gnutls_free(info->signer_serial.data);
	gnutls_free(info->issuer_keyid.data);
	gnutls_pkcs7_attrs_deinit(info->signed_attrs);
	gnutls_pkcs7_attrs_deinit(info->unsigned_attrs);
	memset(info, 0, sizeof(*info));
}

static time_t parse_time(gnutls_pkcs7_t pkcs7, const char *root)
{
	char tval[128];
	ASN1_TYPE c2 = ASN1_TYPE_EMPTY;
	time_t ret;
	int result, len;

	result = asn1_create_element(_gnutls_get_pkix(), "PKIX1.Time", &c2);
	if (result != ASN1_SUCCESS) {
		ret = -1;
		gnutls_assert();
		goto cleanup;
	}

	len = sizeof(tval);
	result = asn1_read_value(pkcs7->signed_data, root, tval, &len);
	if (result != ASN1_SUCCESS) {
		ret = -1;
		gnutls_assert();
		goto cleanup;
	}

	result = _asn1_strict_der_decode(&c2, tval, len, NULL);
	if (result != ASN1_SUCCESS) {
		ret = -1;
		gnutls_assert();
		goto cleanup;
	}

	ret = _gnutls_x509_get_time(c2, "", 0);

 cleanup:
 	asn1_delete_structure(&c2);
 	return ret;
}

/**
 * gnutls_pkcs7_get_signature_count:
 * @pkcs7: should contain a #gnutls_pkcs7_t type
 *
 * This function will return the number of signatures in the PKCS7
 * structure.
 *
 * Returns: On success, a positive number is returned, otherwise a
 *   negative error value.
 *
 * Since: 3.4.3
 **/
int gnutls_pkcs7_get_signature_count(gnutls_pkcs7_t pkcs7)
{
	int ret, count;

	if (pkcs7 == NULL)
		return GNUTLS_E_INVALID_REQUEST;

	ret = asn1_number_of_elements(pkcs7->signed_data, "signerInfos", &count);
	if (ret != ASN1_SUCCESS) {
		gnutls_assert();
		return 0;
	}

	return count;
}

/**
 * gnutls_pkcs7_get_signature_info:
 * @pkcs7: should contain a #gnutls_pkcs7_t type
 * @idx: the index of the signature info to check
 * @info: will contain the output signature
 *
 * This function will return information about the signature identified
 * by idx in the provided PKCS #7 structure. The information should be
 * deinitialized using gnutls_pkcs7_signature_info_deinit().
 *
 * Returns: On success, %GNUTLS_E_SUCCESS (0) is returned, otherwise a
 *   negative error value.
 *
 * Since: 3.4.2
 **/
int gnutls_pkcs7_get_signature_info(gnutls_pkcs7_t pkcs7, unsigned idx, gnutls_pkcs7_signature_info_st *info)
{
	int ret, count, len;
	char root[256];
	char oid[MAX_OID_SIZE];
	gnutls_pk_algorithm_t pk;
	gnutls_sign_algorithm_t sig;
	gnutls_datum_t tmp = {NULL, 0};
	unsigned i;

	if (pkcs7 == NULL)
		return GNUTLS_E_INVALID_REQUEST;

	memset(info, 0, sizeof(*info));
	info->signing_time = -1;

	ret = asn1_number_of_elements(pkcs7->signed_data, "signerInfos", &count);
	if (ret != ASN1_SUCCESS || idx+1 > (unsigned)count) {
		gnutls_assert();
		return GNUTLS_E_REQUESTED_DATA_NOT_AVAILABLE;
	}
	snprintf(root, sizeof(root), "signerInfos.?%u.signatureAlgorithm.algorithm", idx + 1);

	len = sizeof(oid)-1;
	ret = asn1_read_value(pkcs7->signed_data, root, oid, &len);
	if (ret != ASN1_SUCCESS) {
		gnutls_assert();
		goto unsupp_algo;
	}

	sig = gnutls_oid_to_sign(oid);
	if (sig == GNUTLS_SIGN_UNKNOWN) {
		/* great PKCS #7 allows to only specify a public key algo */
		pk = gnutls_oid_to_pk(oid);
		if (pk == GNUTLS_PK_UNKNOWN) {
			gnutls_assert();
			goto unsupp_algo;
		}

		/* use the digests algorithm */
		snprintf(root, sizeof(root), "signerInfos.?%u.digestAlgorithm.algorithm", idx + 1);

		len = sizeof(oid)-1;
		ret = asn1_read_value(pkcs7->signed_data, root, oid, &len);
		if (ret != ASN1_SUCCESS) {
			gnutls_assert();
			goto unsupp_algo;
		}

		ret = gnutls_oid_to_digest(oid);
		if (ret == GNUTLS_DIG_UNKNOWN) {
			gnutls_assert();
			goto unsupp_algo;
		}

		sig = gnutls_pk_to_sign(pk, ret);
		if (sig == GNUTLS_SIGN_UNKNOWN) {
			gnutls_assert();
			goto unsupp_algo;
		}
	}

	info->algo = sig;

	snprintf(root, sizeof(root), "signerInfos.?%u.signature", idx + 1);
	/* read the signature */
	ret = _gnutls_x509_read_value(pkcs7->signed_data, root, &info->sig);
	if (ret < 0) {
		gnutls_assert();
		goto fail;
	}

	/* read the issuer info */
	snprintf(root, sizeof(root), "signerInfos.?%u.sid.issuerAndSerialNumber.issuer.rdnSequence", idx + 1);
	/* read the signature */
	ret = _gnutls_x509_get_raw_field(pkcs7->signed_data, root, &info->issuer_dn);
	if (ret >= 0) {
		snprintf(root, sizeof(root), "signerInfos.?%u.sid.issuerAndSerialNumber.serialNumber", idx + 1);
		/* read the signature */
		ret = _gnutls_x509_read_value(pkcs7->signed_data, root, &info->signer_serial);
		if (ret < 0) {
			gnutls_assert();
			goto fail;
		}
	} else { /* keyid */
		snprintf(root, sizeof(root), "signerInfos.?%u.sid.subjectKeyIdentifier", idx + 1);
		/* read the signature */
		ret = _gnutls_x509_read_value(pkcs7->signed_data, root, &info->issuer_keyid);
		if (ret < 0) {
			gnutls_assert();
		}
	}

	if (info->issuer_keyid.data == NULL && info->issuer_dn.data == NULL) {
		ret = gnutls_assert_val(GNUTLS_E_PARSING_ERROR);
		goto fail;
	}

	/* read the signing time */
	for (i=0;;i++) {
		snprintf(root, sizeof(root), "signerInfos.?%u.signedAttrs.?%u.type", idx+1, i+1);
		len = sizeof(oid)-1;
		ret = asn1_read_value(pkcs7->signed_data, root, oid, &len);
		if (ret != ASN1_SUCCESS) {
			break;
		}

		snprintf(root, sizeof(root), "signerInfos.?%u.signedAttrs.?%u.values.?1", idx+1, i+1);
		ret = _gnutls_x509_read_value(pkcs7->signed_data, root, &tmp);
		if (ret == GNUTLS_E_ASN1_ELEMENT_NOT_FOUND) {
			tmp.data = NULL;
			tmp.size = 0;
		} else if (ret < 0) {
			gnutls_assert();
			goto fail;
		}

		ret = gnutls_pkcs7_add_attr(&info->signed_attrs, oid, &tmp, 0);
		gnutls_free(tmp.data);
		tmp.data = NULL;

		if (ret < 0) {
			gnutls_assert();
			goto fail;
		}

		if (strcmp(oid, ATTR_SIGNING_TIME) == 0) {
			info->signing_time = parse_time(pkcs7, root);
		}
	}

	/* read the unsigned attrs */
	for (i=0;;i++) {
		snprintf(root, sizeof(root), "signerInfos.?%u.unsignedAttrs.?%u.type", idx+1, i+1);
		len = sizeof(oid)-1;
		ret = asn1_read_value(pkcs7->signed_data, root, oid, &len);
		if (ret != ASN1_SUCCESS) {
			break;
		}

		snprintf(root, sizeof(root), "signerInfos.?%u.unsignedAttrs.?%u.values.?1", idx+1, i+1);
		ret = _gnutls_x509_read_value(pkcs7->signed_data, root, &tmp);
		if (ret == GNUTLS_E_ASN1_ELEMENT_NOT_FOUND) {
			tmp.data = NULL;
			tmp.size = 0;
		} else if (ret < 0) {
			gnutls_assert();
			goto fail;
		}

		ret = gnutls_pkcs7_add_attr(&info->unsigned_attrs, oid, &tmp, 0);
		gnutls_free(tmp.data);
		tmp.data = NULL;

		if (ret < 0) {
			gnutls_assert();
			goto fail;
		}
	}

 	return 0;
 fail:
	gnutls_free(tmp.data);
	gnutls_pkcs7_signature_info_deinit(info);
 	return ret;
 unsupp_algo:
	return GNUTLS_E_UNKNOWN_ALGORITHM;
}

/* Verifies that the hash attribute ATTR_MESSAGE_DIGEST is present
 * and matches our calculated hash */
static int verify_hash_attr(gnutls_pkcs7_t pkcs7, const char *root,
			    gnutls_sign_algorithm_t algo,
			    const gnutls_datum_t *data)
{
	unsigned hash;
	gnutls_datum_t tmp = {NULL, 0};
	gnutls_datum_t tmp2 = {NULL, 0};
	uint8_t hash_output[MAX_HASH_SIZE];
	unsigned hash_size, i;
	char oid[MAX_OID_SIZE];
	char name[256];
	unsigned msg_digest_ok = 0;
	unsigned num_cont_types = 0;
	int ret;

	hash = gnutls_sign_get_hash_algorithm(algo);

	/* hash the data */
	if (hash == GNUTLS_DIG_UNKNOWN)
		return gnutls_assert_val(GNUTLS_E_INTERNAL_ERROR);

	hash_size = gnutls_hash_get_len(hash);

	if (data == NULL || data->data == NULL) {
		ret = _gnutls_x509_read_value(pkcs7->signed_data, "encapContentInfo.eContent", &tmp);
		if (ret < 0) {
			if (ret == GNUTLS_E_ASN1_ELEMENT_NOT_FOUND)
				ret = GNUTLS_E_REQUESTED_DATA_NOT_AVAILABLE;
			gnutls_assert();
			return ret;
		}
		data = &tmp;
	}

	ret = gnutls_hash_fast(hash, data->data, data->size, hash_output);

	gnutls_free(tmp.data);
	tmp.data = NULL;

	if (ret < 0)
		return gnutls_assert_val(ret);

	/* now verify that hash matches */
	for (i=0;;i++) {
		snprintf(name, sizeof(name), "%s.signedAttrs.?%u", root, i+1);

		ret = _gnutls_x509_decode_and_read_attribute(pkcs7->signed_data,
				name, oid, sizeof(oid), &tmp, 1, 0);
		if (ret < 0) {
			if (ret == GNUTLS_E_ASN1_ELEMENT_NOT_FOUND)
				break;
			return gnutls_assert_val(ret);
		}

		if (strcmp(oid, ATTR_MESSAGE_DIGEST) == 0) {
			ret = _gnutls_x509_decode_string(ASN1_ETYPE_OCTET_STRING,
				tmp.data, tmp.size, &tmp2, 0);
			if (ret < 0) {
				gnutls_assert();
				goto cleanup;
			}

			if (tmp2.size == hash_size && memcmp(hash_output, tmp2.data, tmp2.size) == 0) {
				msg_digest_ok = 1;
			}
		} else if (strcmp(oid, ATTR_CONTENT_TYPE) == 0) {
			if (num_cont_types > 0) {
				gnutls_assert();
				ret = GNUTLS_E_PARSING_ERROR;
				goto cleanup;
			}

			num_cont_types++;

			/* check if it matches */
			ret = _gnutls_x509_get_raw_field(pkcs7->signed_data, "encapContentInfo.eContentType", &tmp2);
			if (ret < 0) {
				gnutls_assert();
				goto cleanup;
			}

			if (tmp2.size != tmp.size || memcmp(tmp.data, tmp2.data, tmp2.size) != 0) {
				gnutls_assert();
				ret = GNUTLS_E_PARSING_ERROR;
				goto cleanup;
			}
		}
	 	gnutls_free(tmp.data);
	 	tmp.data = NULL;
	 	gnutls_free(tmp2.data);
	 	tmp2.data = NULL;
	}

	if (msg_digest_ok)
		ret = 0;
	else
		ret = gnutls_assert_val(GNUTLS_E_PARSING_ERROR);

 cleanup:
 	gnutls_free(tmp.data);
 	gnutls_free(tmp2.data);
 	return ret;
}


/* Returns the data to be used for signature verification. PKCS #7
 * decided that this should not be an easy task.
 */
static int figure_pkcs7_sigdata(gnutls_pkcs7_t pkcs7, const char *root,
				const gnutls_datum_t *data,
				gnutls_sign_algorithm_t algo,
				gnutls_datum_t *sigdata)
{
	int ret;
	char name[256];

	snprintf(name, sizeof(name), "%s.signedAttrs", root);
	/* read the signature */
	ret = _gnutls_x509_get_raw_field(pkcs7->signed_data, name, sigdata);
	if (ret == 0) {
		/* verify that hash matches */
		ret = verify_hash_attr(pkcs7, root, algo, data);
		if (ret < 0)
			return gnutls_assert_val(ret);

		if (sigdata->size > 0)
			sigdata->data[0] = 0x31;

		return 0;
	}

	/* We have no signedAttrs. Use the provided data, or the encapsulated */
	if (data == NULL || data->data == NULL) {
		ret = _gnutls_x509_read_value(pkcs7->signed_data, "encapContentInfo.eContent", sigdata);
		if (ret < 0) {
			gnutls_assert();
			return gnutls_assert_val(ret);
		}
		return 0;
	}

	return _gnutls_set_datum(sigdata, data->data, data->size);
}

/**
 * gnutls_pkcs7_verify_direct:
 * @pkcs7: should contain a #gnutls_pkcs7_t type
 * @signer: the certificate believed to have signed the structure
 * @idx: the index of the signature info to check
 * @data: The data to be verified or %NULL
 * @flags: Zero or an OR list of #gnutls_certificate_verify_flags
 *
 * This function will verify the provided data against the signature
 * present in the SignedData of the PKCS #7 structure. If the data
 * provided are NULL then the data in the encapsulatedContent field
 * will be used instead.
 *
 * Returns: On success, %GNUTLS_E_SUCCESS (0) is returned, otherwise a
 *   negative error value. A verification error results to a
 *   %GNUTLS_E_PK_SIG_VERIFY_FAILED and the lack of encapsulated data
 *   to verify to a %GNUTLS_E_REQUESTED_DATA_NOT_AVAILABLE.
 *
 * Since: 3.4.2
 **/
int gnutls_pkcs7_verify_direct(gnutls_pkcs7_t pkcs7,
			gnutls_x509_crt_t signer,
			unsigned idx,
			const gnutls_datum_t *data,
			unsigned flags)
{
	int count, ret;
	gnutls_datum_t tmpdata = {NULL, 0};
	gnutls_pkcs7_signature_info_st info;
	gnutls_datum_t sigdata = {NULL, 0};
	char root[128];

	memset(&info, 0, sizeof(info));

	if (pkcs7 == NULL)
		return GNUTLS_E_INVALID_REQUEST;

	ret = asn1_number_of_elements(pkcs7->signed_data, "signerInfos", &count);
	if (ret != ASN1_SUCCESS || idx+1 > (unsigned)count) {
		gnutls_assert();
		return GNUTLS_E_REQUESTED_DATA_NOT_AVAILABLE;
	}

	ret = gnutls_pkcs7_get_signature_info(pkcs7, idx, &info);
	if (ret < 0) {
		gnutls_assert();
		goto cleanup;
	}

	snprintf(root, sizeof(root), "signerInfos.?%u", idx + 1);
	ret = figure_pkcs7_sigdata(pkcs7, root, data, info.algo, &sigdata);
	if (ret < 0) {
		gnutls_assert();
		goto cleanup;
	}

	ret = gnutls_x509_crt_verify_data2(signer, info.algo, flags, &sigdata, &info.sig);
	if (ret < 0) {
		gnutls_assert();
	}

 cleanup:
	gnutls_free(tmpdata.data);
	gnutls_free(sigdata.data);
	gnutls_pkcs7_signature_info_deinit(&info);

	return ret;
}

static
gnutls_x509_crt_t find_signer(gnutls_pkcs7_t pkcs7, gnutls_x509_trust_list_t tl,
			      gnutls_typed_vdata_st *vdata, unsigned vdata_size,
			      gnutls_pkcs7_signature_info_st *info)
{
	gnutls_x509_crt_t issuer = NULL, crt = NULL;
	int ret, count;
	uint8_t serial[128];
	size_t serial_size;
	gnutls_datum_t tmp = {NULL, 0};
	unsigned i, vtmp;

	if (info->issuer_dn.data) {
		ret = gnutls_x509_trust_list_get_issuer_by_dn(tl, &info->issuer_dn, &issuer, 0);
		if (ret < 0) {
			gnutls_assert();
			issuer = NULL;
		}
	}

	if (info->issuer_keyid.data && issuer == NULL) {
		ret = gnutls_x509_trust_list_get_issuer_by_subject_key_id(tl, NULL, &info->issuer_keyid, &issuer, 0);
		if (ret < 0) {
			gnutls_assert();
			issuer = NULL;
		}
	}

	if (issuer == NULL) {
		/* the issuer of the signer is not trusted. Too bad. */
		return NULL;
	}

	/* check issuer's key purpose */
	for (i=0;i<vdata_size;i++) {
		if (vdata[i].type == GNUTLS_DT_KEY_PURPOSE_OID) {
			ret = _gnutls_check_key_purpose(issuer, (char*)vdata[i].data, 0);
			if (ret == 0) {
				gnutls_assert();
				goto fail;
			} else {
				break;
			}
		}
	}

	/* if the serial number of the issuer matches the one in the cert,
	 * then the issuer is the signer */
	if (info->signer_serial.data) {
		serial_size = sizeof(serial);
		ret = gnutls_x509_crt_get_serial(issuer, serial, &serial_size);
		if (ret < 0) {
			gnutls_assert();
			goto fail;
		}

		if (serial_size == info->signer_serial.size && memcmp(info->signer_serial.data, serial, serial_size) == 0) {
			/* issuer == signer */
			return issuer;
		}
	}

	count = gnutls_pkcs7_get_crt_count(pkcs7);
	if (count < 0) {
		gnutls_assert();
		goto fail;
	}

	for (i=0;i<(unsigned)count;i++) {
		/* Try to find the signer in the appended list. */
		ret = gnutls_pkcs7_get_crt_raw2(pkcs7, 0, &tmp);
		if (ret < 0) {
			gnutls_assert();
			goto fail;
		}

		ret = gnutls_x509_crt_init(&crt);
		if (ret < 0) {
			gnutls_assert();
			goto fail;
		}

		ret = gnutls_x509_crt_import(crt, &tmp, GNUTLS_X509_FMT_DER);
		if (ret < 0) {
			gnutls_assert();
			goto fail;
		}

		serial_size = sizeof(serial);
		ret = gnutls_x509_crt_get_serial(crt, serial, &serial_size);
		if (ret < 0) {
			gnutls_assert();
			goto fail;
		}

		if (serial_size != info->signer_serial.size || memcmp(info->signer_serial.data, serial, serial_size) != 0) {
			gnutls_assert();
			goto skip;
		}

		ret = gnutls_x509_trust_list_verify_crt2(tl, &crt, 1, vdata, vdata_size, 0, &vtmp, NULL);
		if (ret < 0 || vtmp != 0) {
			gnutls_assert(); /* maybe next one is trusted */
 skip:
			gnutls_x509_crt_deinit(crt);
			crt = NULL;
			gnutls_free(tmp.data);
			tmp.data = NULL;
			continue;
		}

		/* we found a signer we trust. let's return it */
		break;
	}

	/* ok a trusted certificate was found. This is the signer */
	goto cleanup;

 fail:
	if (crt != NULL) {
		gnutls_x509_crt_deinit(crt);
		crt = NULL;
	}

 cleanup:
	gnutls_free(tmp.data);
	if (issuer)
		gnutls_x509_crt_deinit(issuer);
 
	return crt;
}

/**
 * gnutls_pkcs7_verify:
 * @pkcs7: should contain a #gnutls_pkcs7_t type
 * @tl: A list of trusted certificates
 * @vdata: an array of typed data
 * @vdata_size: the number of data elements
 * @idx: the index of the signature info to check
 * @data: The data to be verified or %NULL
 * @flags: Zero or an OR list of #gnutls_certificate_verify_flags
 *
 * This function will verify the provided data against the signature
 * present in the SignedData of the PKCS #7 structure. If the data
 * provided are NULL then the data in the encapsulatedContent field
 * will be used instead.
 *
 * Returns: On success, %GNUTLS_E_SUCCESS (0) is returned, otherwise a
 *   negative error value. A verification error results to a
 *   %GNUTLS_E_PK_SIG_VERIFY_FAILED and the lack of encapsulated data
 *   to verify to a %GNUTLS_E_REQUESTED_DATA_NOT_AVAILABLE.
 *
 * Since: 3.4.2
 **/
int gnutls_pkcs7_verify(gnutls_pkcs7_t pkcs7,
			gnutls_x509_trust_list_t tl,
			gnutls_typed_vdata_st * vdata,
			unsigned int vdata_size,
			unsigned idx,
			const gnutls_datum_t *data,
			unsigned flags)
{
	int count, ret;
	gnutls_datum_t tmpdata = {NULL, 0};
	gnutls_pkcs7_signature_info_st info;
	gnutls_x509_crt_t signer;
	gnutls_datum_t sigdata = {NULL, 0};
	char root[128];

	memset(&info, 0, sizeof(info));

	if (pkcs7 == NULL)
		return GNUTLS_E_INVALID_REQUEST;

	ret = asn1_number_of_elements(pkcs7->signed_data, "signerInfos", &count);
	if (ret != ASN1_SUCCESS || idx+1 > (unsigned)count) {
		gnutls_assert();
		return GNUTLS_E_REQUESTED_DATA_NOT_AVAILABLE;
	}

	/* read data */
	ret = gnutls_pkcs7_get_signature_info(pkcs7, idx, &info);
	if (ret < 0) {
		gnutls_assert();
		goto cleanup;
	}

	snprintf(root, sizeof(root), "signerInfos.?%u", idx + 1);
	ret = figure_pkcs7_sigdata(pkcs7, root, data, info.algo, &sigdata);
	if (ret < 0) {
		gnutls_assert();
		goto cleanup;
	}

	signer = find_signer(pkcs7, tl, vdata, vdata_size, &info);
	if (signer) {
		ret = gnutls_x509_crt_verify_data2(signer, info.algo, flags, &sigdata, &info.sig);
		if (ret < 0) {
			gnutls_assert();
		}
		gnutls_x509_crt_deinit(signer);
	} else {
		gnutls_assert();
		ret = GNUTLS_E_PK_SIG_VERIFY_FAILED;
	}


 cleanup:
	gnutls_free(tmpdata.data);
	gnutls_free(sigdata.data);
	gnutls_pkcs7_signature_info_deinit(&info);

	return ret;
}

static int reencode(gnutls_pkcs7_t pkcs7)
{
	int result;

	if (pkcs7->signed_data != ASN1_TYPE_EMPTY) {
		/* Replace the old content with the new
		 */
		result =
		    _gnutls_x509_der_encode_and_copy(pkcs7->signed_data, "", pkcs7->pkcs7,
						     "content", 0);
		if (result < 0) {
			return gnutls_assert_val(result);
		}

		/* Write the content type of the signed data
		 */
		result =
		    asn1_write_value(pkcs7->pkcs7, "contentType", SIGNED_DATA_OID, 1);
		if (result != ASN1_SUCCESS) {
			gnutls_assert();
			return _gnutls_asn2err(result);
		}
	}
	return 0;
}

/**
 * gnutls_pkcs7_export:
 * @pkcs7: The pkcs7 type
 * @format: the format of output params. One of PEM or DER.
 * @output_data: will contain a structure PEM or DER encoded
 * @output_data_size: holds the size of output_data (and will be
 *   replaced by the actual size of parameters)
 *
 * This function will export the pkcs7 structure to DER or PEM format.
 *
 * If the buffer provided is not long enough to hold the output, then
 * *@output_data_size is updated and %GNUTLS_E_SHORT_MEMORY_BUFFER
 * will be returned.
 *
 * If the structure is PEM encoded, it will have a header
 * of "BEGIN PKCS7".
 *
 * Returns: On success, %GNUTLS_E_SUCCESS (0) is returned, otherwise a
 *   negative error value.
 **/
int
gnutls_pkcs7_export(gnutls_pkcs7_t pkcs7,
		    gnutls_x509_crt_fmt_t format, void *output_data,
		    size_t * output_data_size)
{
	int ret;
	if (pkcs7 == NULL)
		return GNUTLS_E_INVALID_REQUEST;

	if ((ret = reencode(pkcs7)) < 0)
		return gnutls_assert_val(ret);

	return _gnutls_x509_export_int(pkcs7->pkcs7, format, PEM_PKCS7,
				       output_data, output_data_size);
}

/**
 * gnutls_pkcs7_export2:
 * @pkcs7: The pkcs7 type
 * @format: the format of output params. One of PEM or DER.
 * @out: will contain a structure PEM or DER encoded
 *
 * This function will export the pkcs7 structure to DER or PEM format.
 *
 * The output buffer is allocated using gnutls_malloc().
 *
 * If the structure is PEM encoded, it will have a header
 * of "BEGIN PKCS7".
 *
 * Returns: On success, %GNUTLS_E_SUCCESS (0) is returned, otherwise a
 *   negative error value.
 *
 * Since: 3.1.3
 **/
int
gnutls_pkcs7_export2(gnutls_pkcs7_t pkcs7,
		     gnutls_x509_crt_fmt_t format, gnutls_datum_t * out)
{
	int ret;
	if (pkcs7 == NULL)
		return GNUTLS_E_INVALID_REQUEST;

	if ((ret = reencode(pkcs7)) < 0)
		return gnutls_assert_val(ret);

	return _gnutls_x509_export_int2(pkcs7->pkcs7, format, PEM_PKCS7,
					out);
}

/* Creates an empty signed data structure in the pkcs7
 * structure and returns a handle to the signed data.
 */
static int create_empty_signed_data(ASN1_TYPE pkcs7, ASN1_TYPE * sdata)
{
	int result;

	*sdata = ASN1_TYPE_EMPTY;

	if ((result = asn1_create_element
	     (_gnutls_get_pkix(), "PKIX1.pkcs-7-SignedData",
	      sdata)) != ASN1_SUCCESS) {
		gnutls_assert();
		result = _gnutls_asn2err(result);
		goto cleanup;
	}

	/* Use version 1
	 */
	result = asn1_write_value(*sdata, "version", &one, 1);
	if (result != ASN1_SUCCESS) {
		gnutls_assert();
		result = _gnutls_asn2err(result);
		goto cleanup;
	}

	/* Use no digest algorithms
	 */

	/* id-data */
	result =
	    asn1_write_value(*sdata, "encapContentInfo.eContentType",
			     DIGESTED_DATA_OID, 1);
	if (result != ASN1_SUCCESS) {
		gnutls_assert();
		result = _gnutls_asn2err(result);
		goto cleanup;
	}

	result =
	    asn1_write_value(*sdata, "encapContentInfo.eContent", NULL, 0);
	if (result != ASN1_SUCCESS) {
		gnutls_assert();
		result = _gnutls_asn2err(result);
		goto cleanup;
	}

	/* Add no certificates.
	 */

	/* Add no crls.
	 */

	/* Add no signerInfos.
	 */


	return 0;

      cleanup:
	asn1_delete_structure(sdata);
	return result;

}

/**
 * gnutls_pkcs7_set_crt_raw:
 * @pkcs7: The pkcs7 type
 * @crt: the DER encoded certificate to be added
 *
 * This function will add a certificate to the PKCS7 or RFC2630
 * certificate set.
 *
 * Returns: On success, %GNUTLS_E_SUCCESS (0) is returned, otherwise a
 *   negative error value.
 **/
int
gnutls_pkcs7_set_crt_raw(gnutls_pkcs7_t pkcs7, const gnutls_datum_t * crt)
{
	int result;

	if (pkcs7 == NULL)
		return GNUTLS_E_INVALID_REQUEST;

	/* If the signed data are uninitialized
	 * then create them.
	 */
	if (pkcs7->signed_data == ASN1_TYPE_EMPTY) {
		/* The pkcs7 structure is new, so create the
		 * signedData.
		 */
		result = create_empty_signed_data(pkcs7->pkcs7, &pkcs7->signed_data);
		if (result < 0) {
			gnutls_assert();
			return result;
		}
	}

	/* Step 2. Append the new certificate.
	 */

	result = asn1_write_value(pkcs7->signed_data, "certificates", "NEW", 1);
	if (result != ASN1_SUCCESS) {
		gnutls_assert();
		result = _gnutls_asn2err(result);
		goto cleanup;
	}

	result =
	    asn1_write_value(pkcs7->signed_data, "certificates.?LAST", "certificate", 1);
	if (result != ASN1_SUCCESS) {
		gnutls_assert();
		result = _gnutls_asn2err(result);
		goto cleanup;
	}

	result =
	    asn1_write_value(pkcs7->signed_data, "certificates.?LAST.certificate",
			     crt->data, crt->size);
	if (result != ASN1_SUCCESS) {
		gnutls_assert();
		result = _gnutls_asn2err(result);
		goto cleanup;
	}


	result = 0;

      cleanup:
	return result;
}

/**
 * gnutls_pkcs7_set_crt:
 * @pkcs7: The pkcs7 type
 * @crt: the certificate to be copied.
 *
 * This function will add a parsed certificate to the PKCS7 or
 * RFC2630 certificate set.  This is a wrapper function over
 * gnutls_pkcs7_set_crt_raw() .
 *
 * Returns: On success, %GNUTLS_E_SUCCESS (0) is returned, otherwise a
 *   negative error value.
 **/
int gnutls_pkcs7_set_crt(gnutls_pkcs7_t pkcs7, gnutls_x509_crt_t crt)
{
	int ret;
	gnutls_datum_t data;

	if (pkcs7 == NULL)
		return GNUTLS_E_INVALID_REQUEST;

	ret = _gnutls_x509_der_encode(crt->cert, "", &data, 0);
	if (ret < 0) {
		gnutls_assert();
		return ret;
	}

	ret = gnutls_pkcs7_set_crt_raw(pkcs7, &data);

	_gnutls_free_datum(&data);

	if (ret < 0) {
		gnutls_assert();
		return ret;
	}

	return 0;
}


/**
 * gnutls_pkcs7_delete_crt:
 * @pkcs7: The pkcs7 type
 * @indx: the index of the certificate to delete
 *
 * This function will delete a certificate from a PKCS7 or RFC2630
 * certificate set.  Index starts from 0. Returns 0 on success.
 *
 * Returns: On success, %GNUTLS_E_SUCCESS (0) is returned, otherwise a
 *   negative error value.
 **/
int gnutls_pkcs7_delete_crt(gnutls_pkcs7_t pkcs7, int indx)
{
	int result;
	char root2[ASN1_MAX_NAME_SIZE];

	if (pkcs7 == NULL)
		return GNUTLS_E_INVALID_REQUEST;

	/* Step 2. Delete the certificate.
	 */

	snprintf(root2, sizeof(root2), "certificates.?%u", indx + 1);

	result = asn1_write_value(pkcs7->signed_data, root2, NULL, 0);
	if (result != ASN1_SUCCESS) {
		gnutls_assert();
		result = _gnutls_asn2err(result);
		goto cleanup;
	}

	return 0;

      cleanup:
	return result;
}

/* Read and write CRLs
 */

/**
 * gnutls_pkcs7_get_crl_raw2:
 * @pkcs7: The pkcs7 type
 * @indx: contains the index of the crl to extract
 * @crl: will contain the contents of the CRL in an allocated buffer
 *
 * This function will return a DER encoded CRL of the PKCS7 or RFC2630 crl set.
 *
 * Returns: On success, %GNUTLS_E_SUCCESS (0) is returned, otherwise a
 *   negative error value.  After the last crl has been read
 *   %GNUTLS_E_REQUESTED_DATA_NOT_AVAILABLE will be returned.
 *
 * Since: 3.4.2
 **/
int
gnutls_pkcs7_get_crl_raw2(gnutls_pkcs7_t pkcs7,
			  int indx, gnutls_datum_t *crl)
{
	int result;
	char root2[ASN1_MAX_NAME_SIZE];
	gnutls_datum_t tmp = { NULL, 0 };
	int start, end;

	if (pkcs7 == NULL || crl == NULL)
		return GNUTLS_E_INVALID_REQUEST;

	result = _gnutls_x509_read_value(pkcs7->pkcs7, "content", &tmp);
	if (result < 0) {
		gnutls_assert();
		goto cleanup;
	}

	/* Step 2. Parse the CertificateSet 
	 */

	snprintf(root2, sizeof(root2), "crls.?%u", indx + 1);

	/* Get the raw CRL 
	 */
	result = asn1_der_decoding_startEnd(pkcs7->signed_data, tmp.data, tmp.size,
					    root2, &start, &end);

	if (result != ASN1_SUCCESS) {
		gnutls_assert();
		result = _gnutls_asn2err(result);
		goto cleanup;
	}

	end = end - start + 1;

	result = _gnutls_set_datum(crl, &tmp.data[start], end);

      cleanup:
	_gnutls_free_datum(&tmp);
	return result;
}

/**
 * gnutls_pkcs7_get_crl_raw:
 * @pkcs7: The pkcs7 type
 * @indx: contains the index of the crl to extract
 * @crl: the contents of the crl will be copied there (may be null)
 * @crl_size: should hold the size of the crl
 *
 * This function will return a crl of the PKCS7 or RFC2630 crl set.
 *
 * Returns: On success, %GNUTLS_E_SUCCESS (0) is returned, otherwise a
 *   negative error value.  If the provided buffer is not long enough,
 *   then @crl_size is updated and %GNUTLS_E_SHORT_MEMORY_BUFFER is
 *   returned.  After the last crl has been read
 *   %GNUTLS_E_REQUESTED_DATA_NOT_AVAILABLE will be returned.
 **/
int
gnutls_pkcs7_get_crl_raw(gnutls_pkcs7_t pkcs7,
			 int indx, void *crl, size_t * crl_size)
{
	int ret;
	gnutls_datum_t tmp = {NULL, 0};

	ret = gnutls_pkcs7_get_crl_raw2(pkcs7, indx, &tmp);
	if (ret < 0)
		return gnutls_assert_val(ret);

	if ((unsigned) tmp.size > *crl_size) {
		*crl_size = tmp.size;
		ret = GNUTLS_E_SHORT_MEMORY_BUFFER;
		goto cleanup;
	}

	*crl_size = tmp.size;
	if (crl)
		memcpy(crl, tmp.data, tmp.size);

      cleanup:
	_gnutls_free_datum(&tmp);
	return ret;
}

/**
 * gnutls_pkcs7_get_crl_count:
 * @pkcs7: The pkcs7 type
 *
 * This function will return the number of certifcates in the PKCS7
 * or RFC2630 crl set.
 *
 * Returns: On success, %GNUTLS_E_SUCCESS (0) is returned, otherwise a
 *   negative error value.
 **/
int gnutls_pkcs7_get_crl_count(gnutls_pkcs7_t pkcs7)
{
	int result, count;

	if (pkcs7 == NULL)
		return GNUTLS_E_INVALID_REQUEST;

	/* Step 2. Count the CertificateSet */

	result = asn1_number_of_elements(pkcs7->signed_data, "crls", &count);
	if (result != ASN1_SUCCESS) {
		gnutls_assert();
		return 0;	/* no crls */
	}

	return count;

}

/**
 * gnutls_pkcs7_set_crl_raw:
 * @pkcs7: The pkcs7 type
 * @crl: the DER encoded crl to be added
 *
 * This function will add a crl to the PKCS7 or RFC2630 crl set.
 *
 * Returns: On success, %GNUTLS_E_SUCCESS (0) is returned, otherwise a
 *   negative error value.
 **/
int
gnutls_pkcs7_set_crl_raw(gnutls_pkcs7_t pkcs7, const gnutls_datum_t * crl)
{
	int result;

	if (pkcs7 == NULL)
		return GNUTLS_E_INVALID_REQUEST;

	/* If the signed data are uninitialized
	 * then create them.
	 */
	if (pkcs7->signed_data == ASN1_TYPE_EMPTY) {
		/* The pkcs7 structure is new, so create the
		 * signedData.
		 */
		result = create_empty_signed_data(pkcs7->pkcs7, &pkcs7->signed_data);
		if (result < 0) {
			gnutls_assert();
			return result;
		}
	}

	/* Step 2. Append the new crl.
	 */

	result = asn1_write_value(pkcs7->signed_data, "crls", "NEW", 1);
	if (result != ASN1_SUCCESS) {
		gnutls_assert();
		result = _gnutls_asn2err(result);
		goto cleanup;
	}

	result = asn1_write_value(pkcs7->signed_data, "crls.?LAST", crl->data, crl->size);
	if (result != ASN1_SUCCESS) {
		gnutls_assert();
		result = _gnutls_asn2err(result);
		goto cleanup;
	}

	result = 0;

      cleanup:
	return result;
}

/**
 * gnutls_pkcs7_set_crl:
 * @pkcs7: The pkcs7 type
 * @crl: the DER encoded crl to be added
 *
 * This function will add a parsed CRL to the PKCS7 or RFC2630 crl
 * set.
 *
 * Returns: On success, %GNUTLS_E_SUCCESS (0) is returned, otherwise a
 *   negative error value.
 **/
int gnutls_pkcs7_set_crl(gnutls_pkcs7_t pkcs7, gnutls_x509_crl_t crl)
{
	int ret;
	gnutls_datum_t data;

	if (pkcs7 == NULL)
		return GNUTLS_E_INVALID_REQUEST;

	ret = _gnutls_x509_der_encode(crl->crl, "", &data, 0);
	if (ret < 0) {
		gnutls_assert();
		return ret;
	}

	ret = gnutls_pkcs7_set_crl_raw(pkcs7, &data);

	_gnutls_free_datum(&data);

	if (ret < 0) {
		gnutls_assert();
		return ret;
	}

	return 0;
}

/**
 * gnutls_pkcs7_delete_crl:
 * @pkcs7: The pkcs7 type
 * @indx: the index of the crl to delete
 *
 * This function will delete a crl from a PKCS7 or RFC2630 crl set.
 * Index starts from 0. Returns 0 on success.
 *
 * Returns: On success, %GNUTLS_E_SUCCESS (0) is returned, otherwise a
 *   negative error value.
 **/
int gnutls_pkcs7_delete_crl(gnutls_pkcs7_t pkcs7, int indx)
{
	int result;
	char root2[ASN1_MAX_NAME_SIZE];

	if (pkcs7 == NULL)
		return GNUTLS_E_INVALID_REQUEST;

	/* Delete the crl.
	 */

	snprintf(root2, sizeof(root2), "crls.?%u", indx + 1);

	result = asn1_write_value(pkcs7->signed_data, root2, NULL, 0);
	if (result != ASN1_SUCCESS) {
		gnutls_assert();
		result = _gnutls_asn2err(result);
		goto cleanup;
	}

	return 0;

      cleanup:
	return result;
}

static int write_signer_id(ASN1_TYPE c2, const char *root, gnutls_x509_crt_t signer, unsigned flags)
{
	int result;
	size_t serial_size;
	uint8_t serial[128];
	char name[256];

	if (flags & GNUTLS_PKCS7_WRITE_SPKI) {
		const uint8_t ver = 3;

		snprintf(name, sizeof(name), "%s.version", root);
		result =
		    asn1_write_value(c2, name, &ver, 1);

		snprintf(name, sizeof(name), "%s.sid", root);
		result = asn1_write_value(c2, name, "subjectKeyIdentifier", 1);
		if (result != ASN1_SUCCESS) {
			gnutls_assert();
			return _gnutls_asn2err(result);
		}

		serial_size = sizeof(serial);
		result = gnutls_x509_crt_get_subject_key_id(signer, serial, &serial_size, NULL);
		if (result < 0)
			return gnutls_assert_val(result);

		snprintf(name, sizeof(name), "%s.subjectKeyIdentifier", root);
		result = asn1_write_value(c2, name, serial, serial_size);
		if (result != ASN1_SUCCESS) {
			gnutls_assert();
			return _gnutls_asn2err(result);
		}
	} else {
		serial_size = sizeof(serial);
		result = gnutls_x509_crt_get_serial(signer, serial, &serial_size);
		if (result < 0)
			return gnutls_assert_val(result);

		snprintf(name, sizeof(name), "%s.sid", root);
		result = asn1_write_value(c2, name, "issuerAndSerialNumber", 1);
		if (result != ASN1_SUCCESS) {
			gnutls_assert();
			return _gnutls_asn2err(result);
		}

		snprintf(name, sizeof(name), "%s.sid.issuerAndSerialNumber.serialNumber", root);
		result = asn1_write_value(c2, name, serial, serial_size);
		if (result != ASN1_SUCCESS) {
			gnutls_assert();
			return _gnutls_asn2err(result);
		}

		snprintf(name, sizeof(name), "%s.sid.issuerAndSerialNumber.issuer", root);
		result = asn1_copy_node(c2, name, signer->cert, "tbsCertificate.issuer");
		if (result != ASN1_SUCCESS) {
			gnutls_assert();
			return _gnutls_asn2err(result);
		}
	}

	return 0;
}

static int add_attrs(ASN1_TYPE c2, const char *root, gnutls_pkcs7_attrs_t attrs, unsigned already_set)
{
	char name[256];
	gnutls_pkcs7_attrs_st *p = attrs;
	int result;

	if (attrs == NULL) {
		/* if there are no other attributes delete that field */
		if (already_set == 0)
			asn1_write_value(c2, root, NULL, 0);
	} else {
		while(p != NULL) {
			result = asn1_write_value(c2, root, "NEW", 1);
			if (result != ASN1_SUCCESS) {
				gnutls_assert();
				return _gnutls_asn2err(result);
			}

			snprintf(name, sizeof(name), "%s.?LAST.type", root);
			result =
			    asn1_write_value(c2, name, p->oid, 1);
			if (result != ASN1_SUCCESS) {
				gnutls_assert();
				return _gnutls_asn2err(result);
			}

			snprintf(name, sizeof(name), "%s.?LAST.values", root);
			result = asn1_write_value(c2, name, "NEW", 1);
			if (result != ASN1_SUCCESS) {
				gnutls_assert();
				return _gnutls_asn2err(result);
			}

			snprintf(name, sizeof(name), "%s.?LAST.values.?1", root);
			result = asn1_write_value(c2, name, p->data.data, p->data.size);
			if (result != ASN1_SUCCESS) {
				gnutls_assert();
				return _gnutls_asn2err(result);
			}

			p = p->next;
		}
	}

	return 0;
}

static int write_attributes(ASN1_TYPE c2, const char *root, const gnutls_datum_t *data,
			    const mac_entry_st *me, gnutls_pkcs7_attrs_t other_attrs,
			    unsigned flags)
{
	char name[256];
	int result, ret;
	uint8_t digest[MAX_HASH_SIZE];
	unsigned digest_size;
	unsigned already_set = 0;

	if (flags & GNUTLS_PKCS7_INCLUDE_TIME) {
		if (data == NULL || data->data == NULL) {
			gnutls_assert();
			return GNUTLS_E_INVALID_REQUEST;
		}

		/* Add time */
		result = asn1_write_value(c2, root, "NEW", 1);
		if (result != ASN1_SUCCESS) {
			gnutls_assert();
			ret = _gnutls_asn2err(result);
			return ret;
		}

		snprintf(name, sizeof(name), "%s.?LAST.type", root);
		result =
		    asn1_write_value(c2, name, ATTR_SIGNING_TIME, 1);
		if (result != ASN1_SUCCESS) {
			gnutls_assert();
			ret = _gnutls_asn2err(result);
			return ret;
		}

		snprintf(name, sizeof(name), "%s.?LAST.values", root);
		result = asn1_write_value(c2, name, "NEW", 1);
		if (result != ASN1_SUCCESS) {
			gnutls_assert();
			ret = _gnutls_asn2err(result);
			return ret;
		}

		snprintf(name, sizeof(name), "%s.?LAST.values.?1", root);
		ret = _gnutls_x509_set_raw_time(c2, name, gnutls_time(0));
		if (result != ASN1_SUCCESS) {
			gnutls_assert();
			ret = _gnutls_asn2err(result);
			return ret;
		}

		already_set = 1;
	}

	ret = add_attrs(c2, root, other_attrs, already_set);
	if (ret < 0) {
		gnutls_assert();
		return ret;
	}

	if (already_set != 0 || other_attrs != NULL) {
		/* If we add any attribute we should add them all */
		/* Add hash */

		digest_size = _gnutls_hash_get_algo_len(me);
		ret = gnutls_hash_fast(me->id, data->data, data->size, digest);
		if (ret < 0) {
			gnutls_assert();
			return ret;
		}

		result = asn1_write_value(c2, root, "NEW", 1);
		if (result != ASN1_SUCCESS) {
			gnutls_assert();
			ret = _gnutls_asn2err(result);
			return ret;
		}

		snprintf(name, sizeof(name), "%s.?LAST", root);
		ret = _gnutls_x509_encode_and_write_attribute(ATTR_MESSAGE_DIGEST,
					c2, name,
					digest, digest_size, 1);
		if (ret < 0) {
			gnutls_assert();
			return ret;
		}
	}

	return 0;
}

/**
 * gnutls_pkcs7_sign:
 * @pkcs7: should contain a #gnutls_pkcs7_t type
 * @signer: the certificate to sign the structure
 * @signer_key: the key to sign the structure
 * @data: The data to be signed or %NULL if the data are already embedded
 * @signed_attrs: Any additional attributes to be included in the signed ones (or %NULL)
 * @unsigned_attrs: Any additional attributes to be included in the unsigned ones (or %NULL)
 * @dig: The digest algorithm to use for signing
 * @flags: Should be zero or one of %GNUTLS_PKCS7 flags
 *
 * This function will add a signature in the provided PKCS #7 structure
 * for the provided data. Multiple signatures can be made with different
 * signers.
 * 
 * The available flags are:
 *  %GNUTLS_PKCS7_EMBED_DATA, %GNUTLS_PKCS7_INCLUDE_TIME, %GNUTLS_PKCS7_INCLUDE_CERT,
 *  and %GNUTLS_PKCS7_WRITE_SPKI. They are explained in the #gnutls_pkcs7_sign_flags
 *  definition.
 *
 * Returns: On success, %GNUTLS_E_SUCCESS (0) is returned, otherwise a
 *   negative error value. 
 *
 * Since: 3.4.2
 **/
int gnutls_pkcs7_sign(gnutls_pkcs7_t pkcs7,
		      gnutls_x509_crt_t signer,
		      gnutls_privkey_t signer_key,
		      const gnutls_datum_t *data,
		      gnutls_pkcs7_attrs_t signed_attrs,
		      gnutls_pkcs7_attrs_t unsigned_attrs,
		      gnutls_digest_algorithm_t dig,
		      unsigned flags)
{
	int ret, result;
	gnutls_datum_t sigdata = {NULL, 0};
	gnutls_datum_t signature = {NULL, 0};
	const mac_entry_st *me = hash_to_entry(dig);
	unsigned pk, sigalgo;

	if (pkcs7 == NULL || me == NULL)
		return GNUTLS_E_INVALID_REQUEST;

	if (pkcs7->signed_data == ASN1_TYPE_EMPTY) {
		result = asn1_create_element(_gnutls_get_pkix(), "PKIX1.pkcs-7-SignedData", &pkcs7->signed_data);
		if (result != ASN1_SUCCESS) {
			gnutls_assert();
			ret = _gnutls_asn2err(result);
			goto cleanup;
		}

		if (!(flags & GNUTLS_PKCS7_EMBED_DATA)) {
			asn1_write_value(pkcs7->signed_data, "encapContentInfo.eContent", NULL, 0);
		}
	}

	asn1_write_value(pkcs7->signed_data, "version", &one, 1);

	result = asn1_write_value(pkcs7->signed_data, "encapContentInfo.eContentType", PLAIN_DATA_OID, 0);
	if (result != ASN1_SUCCESS) {
		ret = _gnutls_asn2err(result);
		goto cleanup;
	}

	if (flags & GNUTLS_PKCS7_EMBED_DATA && data->data) { /* embed data */
		result = asn1_write_value(pkcs7->signed_data, "encapContentInfo.eContent", data->data, data->size);
		if (result != ASN1_SUCCESS) {
			ret = _gnutls_asn2err(result);
			goto cleanup;
		}
	}

	if (flags & GNUTLS_PKCS7_INCLUDE_CERT) {
		ret = gnutls_pkcs7_set_crt(pkcs7, signer);
		if (ret < 0) {
			gnutls_assert();
			goto cleanup;
		}
	}

	/* append digest info algorithm */
	result = asn1_write_value(pkcs7->signed_data, "digestAlgorithms", "NEW", 1);
	if (result != ASN1_SUCCESS) {
		gnutls_assert();
		ret = _gnutls_asn2err(result);
		goto cleanup;
	}

	result =
	    asn1_write_value(pkcs7->signed_data, "digestAlgorithms.?LAST.algorithm", _gnutls_x509_digest_to_oid(me), 1);
	if (result != ASN1_SUCCESS) {
		gnutls_assert();
		ret = _gnutls_asn2err(result);
		goto cleanup;
	}
	asn1_write_value(pkcs7->signed_data, "digestAlgorithms.?LAST.parameters", NULL, 0);

	/* append signer's info */
	result = asn1_write_value(pkcs7->signed_data, "signerInfos", "NEW", 1);
	if (result != ASN1_SUCCESS) {
		gnutls_assert();
		ret = _gnutls_asn2err(result);
		goto cleanup;
	}

	result =
	    asn1_write_value(pkcs7->signed_data, "signerInfos.?LAST.version", &one, 1);
	if (result != ASN1_SUCCESS) {
		gnutls_assert();
		ret = _gnutls_asn2err(result);
		goto cleanup;
	}

	result =
	    asn1_write_value(pkcs7->signed_data, "signerInfos.?LAST.digestAlgorithm.algorithm", _gnutls_x509_digest_to_oid(me), 1);
	if (result != ASN1_SUCCESS) {
		gnutls_assert();
		ret = _gnutls_asn2err(result);
		goto cleanup;
	}
	asn1_write_value(pkcs7->signed_data, "signerInfos.?LAST.digestAlgorithm.parameters", NULL, 0);

	ret = write_signer_id(pkcs7->signed_data, "signerInfos.?LAST", signer, flags);
	if (ret < 0) {
		gnutls_assert();
		goto cleanup;
	}

	ret = add_attrs(pkcs7->signed_data, "signerInfos.?LAST.unsignedAttrs", unsigned_attrs, 0);
	if (ret < 0) {
		gnutls_assert();
		goto cleanup;
	}

	ret = write_attributes(pkcs7->signed_data, "signerInfos.?LAST.signedAttrs", data, me, signed_attrs, flags);
	if (ret < 0) {
		gnutls_assert();
		goto cleanup;
	}

	/* write the signature algorithm */
	pk = gnutls_x509_crt_get_pk_algorithm(signer, NULL);

	ret = _gnutls_x509_write_sig_params(pkcs7->signed_data, "signerInfos.?LAST.signatureAlgorithm", pk, dig);
	if (ret < 0) {
		gnutls_assert();
		goto cleanup;
	}

	sigalgo = gnutls_pk_to_sign(pk, dig);
	if (sigalgo == GNUTLS_SIGN_UNKNOWN) {
		gnutls_assert();
		ret = GNUTLS_E_INVALID_REQUEST;
		goto cleanup;
	}

	/* sign the data */
	ret = figure_pkcs7_sigdata(pkcs7, "signerInfos.?LAST", data, sigalgo, &sigdata);
	if (ret < 0) {
		gnutls_assert();
		goto cleanup;
	}

	ret = gnutls_privkey_sign_data(signer_key, dig, 0, &sigdata, &signature);
	if (ret < 0) {
		gnutls_assert();
		goto cleanup;
	}

	result =
	    asn1_write_value(pkcs7->signed_data, "signerInfos.?LAST.signature", signature.data, signature.size);
	if (result != ASN1_SUCCESS) {
		gnutls_assert();
		ret = _gnutls_asn2err(result);
		goto cleanup;
	}

	ret = 0;

 cleanup:
	gnutls_free(sigdata.data);
	gnutls_free(signature.data);
	return ret;
}

