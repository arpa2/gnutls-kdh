#if HAVE_CONFIG_H
# include "config.h"
#endif

#include <libtasn1.h>

const asn_static_node_t pkix_asn1_tab[] = {
  { "PKIX1", 536875024, NULL },
  { NULL, 1073741836, NULL },
  { "id-pkix", 1879048204, NULL },
  { "iso", 1073741825, "1"},
  { "identified-organization", 1073741825, "3"},
  { "dod", 1073741825, "6"},
  { "internet", 1073741825, "1"},
  { "security", 1073741825, "5"},
  { "mechanisms", 1073741825, "5"},
  { "pkix", 1, "7"},
  { "PrivateKeyUsagePeriod", 1610612741, NULL },
  { "notBefore", 1619025937, NULL },
  { NULL, 4104, "0"},
  { "notAfter", 545284113, NULL },
  { NULL, 4104, "1"},
  { "AuthorityKeyIdentifier", 1610612741, NULL },
  { "keyIdentifier", 1610637314, "KeyIdentifier"},
  { NULL, 4104, "0"},
  { "authorityCertIssuer", 1610637314, "GeneralNames"},
  { NULL, 4104, "1"},
  { "authorityCertSerialNumber", 536895490, "CertificateSerialNumber"},
  { NULL, 4104, "2"},
  { "KeyIdentifier", 1073741831, NULL },
  { "SubjectKeyIdentifier", 1073741826, "KeyIdentifier"},
  { "KeyUsage", 1073741830, NULL },
  { "DirectoryString", 1610612754, NULL },
  { "teletexString", 1612709890, "TeletexString"},
  { "MAX", 524298, "1"},
  { "printableString", 1612709890, "PrintableString"},
  { "MAX", 524298, "1"},
  { "universalString", 1612709890, "UniversalString"},
  { "MAX", 524298, "1"},
  { "utf8String", 1612709890, "UTF8String"},
  { "MAX", 524298, "1"},
  { "bmpString", 1612709890, "BMPString"},
  { "MAX", 524298, "1"},
  { "ia5String", 538968066, "IA5String"},
  { "MAX", 524298, "1"},
  { "SubjectAltName", 1073741826, "GeneralNames"},
  { "GeneralNames", 1612709899, NULL },
  { "MAX", 1074266122, "1"},
  { NULL, 2, "GeneralName"},
  { "GeneralName", 1610612754, NULL },
  { "otherName", 1610620930, "AnotherName"},
  { NULL, 4104, "0"},
  { "rfc822Name", 1610620930, "IA5String"},
  { NULL, 4104, "1"},
  { "dNSName", 1610620930, "IA5String"},
  { NULL, 4104, "2"},
  { "x400Address", 1610620941, NULL },
  { NULL, 4104, "3"},
  { "directoryName", 1610620930, "RDNSequence"},
  { NULL, 2056, "4"},
  { "ediPartyName", 1610620941, NULL },
  { NULL, 4104, "5"},
  { "uniformResourceIdentifier", 1610620930, "IA5String"},
  { NULL, 4104, "6"},
  { "iPAddress", 1610620935, NULL },
  { NULL, 4104, "7"},
  { "registeredID", 536879116, NULL },
  { NULL, 4104, "8"},
  { "AnotherName", 1610612741, NULL },
  { "type-id", 1073741836, NULL },
  { "value", 541073421, NULL },
  { NULL, 1073743880, "0"},
  { "type-id", 1, NULL },
  { "IssuerAltName", 1073741826, "GeneralNames"},
  { "BasicConstraints", 1610612741, NULL },
  { "cA", 1610645508, NULL },
  { NULL, 131081, NULL },
  { "pathLenConstraint", 537411587, NULL },
  { "0", 10, "MAX"},
  { "CRLDistributionPoints", 1612709899, NULL },
  { "MAX", 1074266122, "1"},
  { NULL, 2, "DistributionPoint"},
  { "DistributionPoint", 1610612741, NULL },
  { "distributionPoint", 1610637314, "DistributionPointName"},
  { NULL, 2056, "0"},
  { "reasons", 1610637314, "ReasonFlags"},
  { NULL, 4104, "1"},
  { "cRLIssuer", 536895490, "GeneralNames"},
  { NULL, 4104, "2"},
  { "DistributionPointName", 1610612754, NULL },
  { "fullName", 1610620930, "GeneralNames"},
  { NULL, 4104, "0"},
  { "nameRelativeToCRLIssuer", 536879106, "RelativeDistinguishedName"},
  { NULL, 4104, "1"},
  { "ReasonFlags", 1073741830, NULL },
  { "ExtKeyUsageSyntax", 1612709899, NULL },
  { "MAX", 1074266122, "1"},
  { NULL, 2, "KeyPurposeId"},
  { "KeyPurposeId", 1073741836, NULL },
  { "AuthorityInfoAccessSyntax", 1612709899, NULL },
  { "MAX", 1074266122, "1"},
  { NULL, 2, "AccessDescription"},
  { "AccessDescription", 1610612741, NULL },
  { "accessMethod", 1073741836, NULL },
  { "accessLocation", 2, "GeneralName"},
  { "NumericString", 1610620935, NULL },
  { NULL, 4360, "18"},
  { "IA5String", 1610620935, NULL },
  { NULL, 4360, "22"},
  { "TeletexString", 1610620935, NULL },
  { NULL, 4360, "20"},
  { "PrintableString", 1610620935, NULL },
  { NULL, 4360, "19"},
  { "UniversalString", 1610620935, NULL },
  { NULL, 4360, "28"},
  { "BMPString", 1610620935, NULL },
  { NULL, 4360, "30"},
  { "UTF8String", 1610620935, NULL },
  { NULL, 4360, "12"},
  { "Attribute", 1610612741, NULL },
  { "type", 1073741826, "AttributeType"},
  { "values", 536870927, NULL },
  { NULL, 2, "AttributeValue"},
  { "AttributeType", 1073741836, NULL },
  { "AttributeValue", 1614807053, NULL },
  { "type", 1, NULL },
  { "AttributeTypeAndValue", 1610612741, NULL },
  { "type", 1073741826, "AttributeType"},
  { "value", 2, "AttributeValue"},
  { "id-at", 1879048204, NULL },
  { "joint-iso-ccitt", 1073741825, "2"},
  { "ds", 1073741825, "5"},
  { NULL, 1, "4"},
  { "emailAddress", 1880096780, "AttributeType"},
  { "iso", 1073741825, "1"},
  { "member-body", 1073741825, "2"},
  { "us", 1073741825, "840"},
  { "rsadsi", 1073741825, "113549"},
  { "pkcs", 1073741825, "1"},
  { NULL, 1073741825, "9"},
  { NULL, 1, "1"},
  { "Name", 1610612754, NULL },
  { "rdnSequence", 2, "RDNSequence"},
  { "RDNSequence", 1610612747, NULL },
  { NULL, 2, "RelativeDistinguishedName"},
  { "DistinguishedName", 1073741826, "RDNSequence"},
  { "RelativeDistinguishedName", 1612709903, NULL },
  { "MAX", 1074266122, "1"},
  { NULL, 2, "AttributeTypeAndValue"},
  { "Certificate", 1610612741, NULL },
  { "tbsCertificate", 1073741826, "TBSCertificate"},
  { "signatureAlgorithm", 1073741826, "AlgorithmIdentifier"},
  { "signature", 6, NULL },
  { "TBSCertificate", 1610612741, NULL },
  { "version", 1610653699, NULL },
  { NULL, 1073741833, "0"},
  { NULL, 2056, "0"},
  { "serialNumber", 1073741826, "CertificateSerialNumber"},
  { "signature", 1073741826, "AlgorithmIdentifier"},
  { "issuer", 1073741826, "Name"},
  { "validity", 1073741826, "Validity"},
  { "subject", 1073741826, "Name"},
  { "subjectPublicKeyInfo", 1073741826, "SubjectPublicKeyInfo"},
  { "issuerUniqueID", 1610637314, "UniqueIdentifier"},
  { NULL, 4104, "1"},
  { "subjectUniqueID", 1610637314, "UniqueIdentifier"},
  { NULL, 4104, "2"},
  { "extensions", 536895490, "Extensions"},
  { NULL, 2056, "3"},
  { "CertificateSerialNumber", 1073741827, NULL },
  { "Validity", 1610612741, NULL },
  { "notBefore", 1073741826, "Time"},
  { "notAfter", 2, "Time"},
  { "Time", 1610612754, NULL },
  { "utcTime", 1090519057, NULL },
  { "generalTime", 8388625, NULL },
  { "UniqueIdentifier", 1073741830, NULL },
  { "SubjectPublicKeyInfo", 1610612741, NULL },
  { "algorithm", 1073741826, "AlgorithmIdentifier"},
  { "subjectPublicKey", 6, NULL },
  { "Extensions", 1612709899, NULL },
  { "MAX", 1074266122, "1"},
  { NULL, 2, "Extension"},
  { "Extension", 1610612741, NULL },
  { "extnID", 1073741836, NULL },
  { "critical", 1610645508, NULL },
  { NULL, 131081, NULL },
  { "extnValue", 7, NULL },
  { "CertificateList", 1610612741, NULL },
  { "tbsCertList", 1073741826, "TBSCertList"},
  { "signatureAlgorithm", 1073741826, "AlgorithmIdentifier"},
  { "signature", 6, NULL },
  { "TBSCertList", 1610612741, NULL },
  { "version", 1073758211, NULL },
  { "signature", 1073741826, "AlgorithmIdentifier"},
  { "issuer", 1073741826, "Name"},
  { "thisUpdate", 1073741826, "Time"},
  { "nextUpdate", 1073758210, "Time"},
  { "revokedCertificates", 1610629131, NULL },
  { NULL, 536870917, NULL },
  { "userCertificate", 1073741826, "CertificateSerialNumber"},
  { "revocationDate", 1073741826, "Time"},
  { "crlEntryExtensions", 16386, "Extensions"},
  { "crlExtensions", 536895490, "Extensions"},
  { NULL, 2056, "0"},
  { "AlgorithmIdentifier", 1610612741, NULL },
  { "algorithm", 1073741836, NULL },
  { "parameters", 541081613, NULL },
  { "algorithm", 1, NULL },
  { "Dss-Sig-Value", 1610612741, NULL },
  { "r", 1073741827, NULL },
  { "s", 3, NULL },
  { "DomainParameters", 1610612741, NULL },
  { "p", 1073741827, NULL },
  { "g", 1073741827, NULL },
  { "q", 1073741827, NULL },
  { "j", 1073758211, NULL },
  { "validationParms", 16386, "ValidationParms"},
  { "ValidationParms", 1610612741, NULL },
  { "seed", 1073741830, NULL },
  { "pgenCounter", 3, NULL },
  { "Dss-Parms", 1610612741, NULL },
  { "p", 1073741827, NULL },
  { "q", 1073741827, NULL },
  { "g", 3, NULL },
  { "CountryName", 1610620946, NULL },
  { NULL, 1073746952, "1"},
  { "x121-dcc-code", 1612709890, "NumericString"},
  { NULL, 1048586, "ub-country-name-numeric-length"},
  { "iso-3166-alpha2-code", 538968066, "PrintableString"},
  { NULL, 1048586, "ub-country-name-alpha-length"},
  { "OrganizationName", 1612709890, "PrintableString"},
  { "ub-organization-name-length", 524298, "1"},
  { "NumericUserIdentifier", 1612709890, "NumericString"},
  { "ub-numeric-user-id-length", 524298, "1"},
  { "OrganizationalUnitNames", 1612709899, NULL },
  { "ub-organizational-units", 1074266122, "1"},
  { NULL, 2, "OrganizationalUnitName"},
  { "OrganizationalUnitName", 1612709890, "PrintableString"},
  { "ub-organizational-unit-name-length", 524298, "1"},
  { "CommonName", 1073741826, "PrintableString"},
  { "pkcs-7-ContentInfo", 1610612741, NULL },
  { "contentType", 1073741826, "pkcs-7-ContentType"},
  { "content", 541073421, NULL },
  { NULL, 1073743880, "0"},
  { "contentType", 1, NULL },
  { "pkcs-7-DigestInfo", 1610612741, NULL },
  { "digestAlgorithm", 1073741826, "AlgorithmIdentifier"},
  { "digest", 7, NULL },
  { "pkcs-7-ContentType", 1073741836, NULL },
  { "pkcs-7-SignedData", 1610612741, NULL },
  { "version", 1073741827, NULL },
  { "digestAlgorithms", 1073741826, "pkcs-7-DigestAlgorithmIdentifiers"},
  { "encapContentInfo", 1073741826, "pkcs-7-EncapsulatedContentInfo"},
  { "certificates", 1610637314, "pkcs-7-CertificateSet"},
  { NULL, 4104, "0"},
  { "crls", 1610637314, "pkcs-7-CertificateRevocationLists"},
  { NULL, 4104, "1"},
  { "signerInfos", 2, "pkcs-7-SignerInfos"},
  { "pkcs-7-DigestAlgorithmIdentifiers", 1610612751, NULL },
  { NULL, 2, "AlgorithmIdentifier"},
  { "pkcs-7-EncapsulatedContentInfo", 1610612741, NULL },
  { "eContentType", 1073741826, "pkcs-7-ContentType"},
  { "eContent", 536895495, NULL },
  { NULL, 2056, "0"},
  { "pkcs-7-CertificateRevocationLists", 1610612751, NULL },
  { NULL, 13, NULL },
  { "pkcs-7-CertificateChoices", 1610612754, NULL },
  { "certificate", 13, NULL },
  { "pkcs-7-CertificateSet", 1610612751, NULL },
  { NULL, 2, "pkcs-7-CertificateChoices"},
  { "pkcs-7-SignerInfos", 1610612751, NULL },
  { NULL, 13, NULL },
  { "pkcs-10-CertificationRequestInfo", 1610612741, NULL },
  { "version", 1073741827, NULL },
  { "subject", 1073741826, "Name"},
  { "subjectPKInfo", 1073741826, "SubjectPublicKeyInfo"},
  { "attributes", 536879106, "Attributes"},
  { NULL, 4104, "0"},
  { "Attributes", 1610612751, NULL },
  { NULL, 2, "Attribute"},
  { "pkcs-10-CertificationRequest", 1610612741, NULL },
  { "certificationRequestInfo", 1073741826, "pkcs-10-CertificationRequestInfo"},
  { "signatureAlgorithm", 1073741826, "AlgorithmIdentifier"},
  { "signature", 6, NULL },
  { "pkcs-9-at-challengePassword", 1879048204, NULL },
  { "iso", 1073741825, "1"},
  { "member-body", 1073741825, "2"},
  { "us", 1073741825, "840"},
  { "rsadsi", 1073741825, "113549"},
  { "pkcs", 1073741825, "1"},
  { NULL, 1073741825, "9"},
  { NULL, 1, "7"},
  { "pkcs-9-challengePassword", 1610612754, NULL },
  { "printableString", 1073741826, "PrintableString"},
  { "utf8String", 2, "UTF8String"},
  { "pkcs-9-localKeyId", 1073741831, NULL },
  { "pkcs-8-PrivateKeyInfo", 1610612741, NULL },
  { "version", 1073741827, NULL },
  { "privateKeyAlgorithm", 1073741826, "AlgorithmIdentifier"},
  { "privateKey", 1073741831, NULL },
  { "attributes", 536895490, "Attributes"},
  { NULL, 4104, "0"},
  { "pkcs-8-Attributes", 1610612751, NULL },
  { NULL, 2, "Attribute"},
  { "pkcs-8-EncryptedPrivateKeyInfo", 1610612741, NULL },
  { "encryptionAlgorithm", 1073741826, "AlgorithmIdentifier"},
  { "encryptedData", 2, "pkcs-8-EncryptedData"},
  { "pkcs-8-EncryptedData", 1073741831, NULL },
  { "pkcs-5-des-EDE3-CBC-params", 1612709895, NULL },
  { NULL, 1048586, "8"},
  { "pkcs-5-aes128-CBC-params", 1612709895, NULL },
  { NULL, 1048586, "16"},
  { "pkcs-5-aes192-CBC-params", 1612709895, NULL },
  { NULL, 1048586, "16"},
  { "pkcs-5-aes256-CBC-params", 1612709895, NULL },
  { NULL, 1048586, "16"},
  { "pkcs-5-PBES2-params", 1610612741, NULL },
  { "keyDerivationFunc", 1073741826, "AlgorithmIdentifier"},
  { "encryptionScheme", 2, "AlgorithmIdentifier"},
  { "pkcs-5-PBKDF2-params", 1610612741, NULL },
  { "salt", 1610612754, NULL },
  { "specified", 1073741831, NULL },
  { "otherSource", 2, "AlgorithmIdentifier"},
  { "iterationCount", 1611137027, NULL },
  { "1", 10, "MAX"},
  { "keyLength", 1611153411, NULL },
  { "1", 10, "MAX"},
  { "prf", 16386, "AlgorithmIdentifier"},
  { "pkcs-12-PFX", 1610612741, NULL },
  { "version", 1610874883, NULL },
  { "v3", 1, "3"},
  { "authSafe", 1073741826, "pkcs-7-ContentInfo"},
  { "macData", 16386, "pkcs-12-MacData"},
  { "pkcs-12-PbeParams", 1610612741, NULL },
  { "salt", 1073741831, NULL },
  { "iterations", 3, NULL },
  { "pkcs-12-MacData", 1610612741, NULL },
  { "mac", 1073741826, "pkcs-7-DigestInfo"},
  { "macSalt", 1073741831, NULL },
  { "iterations", 536903683, NULL },
  { NULL, 9, "1"},
  { "pkcs-12-AuthenticatedSafe", 1610612747, NULL },
  { NULL, 2, "pkcs-7-ContentInfo"},
  { "pkcs-12-SafeContents", 1610612747, NULL },
  { NULL, 2, "pkcs-12-SafeBag"},
  { "pkcs-12-SafeBag", 1610612741, NULL },
  { "bagId", 1073741836, NULL },
  { "bagValue", 1614815245, NULL },
  { NULL, 1073743880, "0"},
  { "badId", 1, NULL },
  { "bagAttributes", 536887311, NULL },
  { NULL, 2, "Attribute"},
  { "pkcs-12-CertBag", 1610612741, NULL },
  { "certId", 1073741836, NULL },
  { "certValue", 541073421, NULL },
  { NULL, 1073743880, "0"},
  { "certId", 1, NULL },
  { "pkcs-12-CRLBag", 1610612741, NULL },
  { "crlId", 1073741836, NULL },
  { "crlValue", 541073421, NULL },
  { NULL, 1073743880, "0"},
  { "crlId", 1, NULL },
  { "pkcs-12-SecretBag", 1610612741, NULL },
  { "secretTypeId", 1073741836, NULL },
  { "secretValue", 541073421, NULL },
  { NULL, 1073743880, "0"},
  { "secretTypeId", 1, NULL },
  { "pkcs-7-Data", 1073741831, NULL },
  { "pkcs-7-EncryptedData", 1610612741, NULL },
  { "version", 1073741827, NULL },
  { "encryptedContentInfo", 1073741826, "pkcs-7-EncryptedContentInfo"},
  { "unprotectedAttrs", 536895490, "pkcs-7-UnprotectedAttributes"},
  { NULL, 4104, "1"},
  { "pkcs-7-EncryptedContentInfo", 1610612741, NULL },
  { "contentType", 1073741826, "pkcs-7-ContentType"},
  { "contentEncryptionAlgorithm", 1073741826, "pkcs-7-ContentEncryptionAlgorithmIdentifier"},
  { "encryptedContent", 536895495, NULL },
  { NULL, 4104, "0"},
  { "pkcs-7-ContentEncryptionAlgorithmIdentifier", 1073741826, "AlgorithmIdentifier"},
  { "pkcs-7-UnprotectedAttributes", 1612709903, NULL },
  { "MAX", 1074266122, "1"},
  { NULL, 2, "Attribute"},
  { "ProxyCertInfo", 1610612741, NULL },
  { "pCPathLenConstraint", 1611153411, NULL },
  { "0", 10, "MAX"},
  { "proxyPolicy", 2, "ProxyPolicy"},
  { "ProxyPolicy", 1610612741, NULL },
  { "policyLanguage", 1073741836, NULL },
  { "policy", 16391, NULL },
  { "OCSPRequest", 1610612741, NULL },
  { "tbsRequest", 1073741826, "TBSRequest"},
  { "optionalSignature", 536895490, "Signature"},
  { NULL, 2056, "0"},
  { "TBSRequest", 1610612741, NULL },
  { "version", 1610653699, NULL },
  { NULL, 1073741833, "0"},
  { NULL, 2056, "0"},
  { "requestorName", 1610637314, "GeneralName"},
  { NULL, 2056, "1"},
  { "requestList", 1610612747, NULL },
  { NULL, 2, "Request"},
  { "requestExtensions", 536895490, "Extensions"},
  { NULL, 2056, "2"},
  { "Signature", 1610612741, NULL },
  { "signatureAlgorithm", 1073741826, "AlgorithmIdentifier"},
  { "signature", 1073741830, NULL },
  { "certs", 536895499, NULL },
  { NULL, 1073743880, "0"},
  { NULL, 2, "Certificate"},
  { "Request", 1610612741, NULL },
  { "reqCert", 1073741826, "CertID"},
  { "singleRequestExtensions", 536895490, "Extensions"},
  { NULL, 2056, "0"},
  { "CertID", 1610612741, NULL },
  { "hashAlgorithm", 1073741826, "AlgorithmIdentifier"},
  { "issuerNameHash", 1073741831, NULL },
  { "issuerKeyHash", 1073741831, NULL },
  { "serialNumber", 2, "CertificateSerialNumber"},
  { "OCSPResponse", 1610612741, NULL },
  { "responseStatus", 1073741826, "OCSPResponseStatus"},
  { "responseBytes", 536895490, "ResponseBytes"},
  { NULL, 2056, "0"},
  { "OCSPResponseStatus", 1610874901, NULL },
  { "successful", 1073741825, "0"},
  { "malformedRequest", 1073741825, "1"},
  { "internalError", 1073741825, "2"},
  { "tryLater", 1073741825, "3"},
  { "sigRequired", 1073741825, "5"},
  { "unauthorized", 1, "6"},
  { "ResponseBytes", 1610612741, NULL },
  { "responseType", 1073741836, NULL },
  { "response", 7, NULL },
  { "BasicOCSPResponse", 1610612741, NULL },
  { "tbsResponseData", 1073741826, "ResponseData"},
  { "signatureAlgorithm", 1073741826, "AlgorithmIdentifier"},
  { "signature", 1073741830, NULL },
  { "certs", 536895499, NULL },
  { NULL, 1073743880, "0"},
  { NULL, 2, "Certificate"},
  { "ResponseData", 1610612741, NULL },
  { "version", 1610653699, NULL },
  { NULL, 1073741833, "0"},
  { NULL, 2056, "0"},
  { "responderID", 1073741826, "ResponderID"},
  { "producedAt", 1082130449, NULL },
  { "responses", 1610612747, NULL },
  { NULL, 2, "SingleResponse"},
  { "responseExtensions", 536895490, "Extensions"},
  { NULL, 2056, "1"},
  { "ResponderID", 1610612754, NULL },
  { "byName", 1610620930, "RDNSequence"},
  { NULL, 2056, "1"},
  { "byKey", 536879111, NULL },
  { NULL, 4104, "2"},
  { "SingleResponse", 1610612741, NULL },
  { "certID", 1073741826, "CertID"},
  { "certStatus", 1073741826, "CertStatus"},
  { "thisUpdate", 1082130449, NULL },
  { "nextUpdate", 1619025937, NULL },
  { NULL, 2056, "0"},
  { "singleExtensions", 536895490, "Extensions"},
  { NULL, 2056, "1"},
  { "CertStatus", 1610612754, NULL },
  { "good", 1610620948, NULL },
  { NULL, 4104, "0"},
  { "revoked", 1610620930, "RevokedInfo"},
  { NULL, 4104, "1"},
  { "unknown", 536879106, "UnknownInfo"},
  { NULL, 4104, "2"},
  { "RevokedInfo", 1610612741, NULL },
  { "revocationTime", 1082130449, NULL },
  { "revocationReason", 536895490, "CRLReason"},
  { NULL, 2056, "0"},
  { "UnknownInfo", 1073741844, NULL },
  { "CRLReason", 537133077, NULL },
  { "unspecified", 1073741825, "0"},
  { "keyCompromise", 1073741825, "1"},
  { "cACompromise", 1073741825, "2"},
  { "affiliationChanged", 1073741825, "3"},
  { "superseded", 1073741825, "4"},
  { "cessationOfOperation", 1073741825, "5"},
  { "certificateHold", 1073741825, "6"},
  { "removeFromCRL", 1073741825, "8"},
  { "privilegeWithdrawn", 1073741825, "9"},
  { "aACompromise", 1, "10"},
  { NULL, 0, NULL }
};
