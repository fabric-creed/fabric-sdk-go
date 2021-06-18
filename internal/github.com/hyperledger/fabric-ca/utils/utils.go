package utils

import (
	otls "crypto/tls"
	ox509 "crypto/x509"
	"github.com/fabric-creed/cryptogm/tls"
	"github.com/fabric-creed/cryptogm/x509"
)

func CopyX509ToGMx509(cert *ox509.Certificate) *x509.Certificate {
	var extKeyUsages []x509.ExtKeyUsage
	for _, k := range cert.ExtKeyUsage {
		extKeyUsages = append(extKeyUsages, x509.ExtKeyUsage(k))
	}
	return &x509.Certificate{
		Raw:                         cert.Raw,
		RawTBSCertificate:           cert.RawTBSCertificate,
		RawSubjectPublicKeyInfo:     cert.RawSubjectPublicKeyInfo,
		RawSubject:                  cert.RawSubject,
		RawIssuer:                   cert.RawIssuer,
		Signature:                   cert.Signature,
		SignatureAlgorithm:          x509.SignatureAlgorithm(cert.SignatureAlgorithm),
		PublicKeyAlgorithm:          x509.PublicKeyAlgorithm(cert.PublicKeyAlgorithm),
		PublicKey:                   cert.PublicKey,
		Version:                     cert.Version,
		SerialNumber:                cert.SerialNumber,
		Issuer:                      cert.Issuer,
		Subject:                     cert.Subject,
		NotBefore:                   cert.NotBefore,
		NotAfter:                    cert.NotAfter,
		KeyUsage:                    x509.KeyUsage(cert.KeyUsage),
		Extensions:                  cert.Extensions,
		ExtraExtensions:             cert.ExtraExtensions,
		UnhandledCriticalExtensions: cert.UnhandledCriticalExtensions,
		ExtKeyUsage:                 extKeyUsages,
		UnknownExtKeyUsage:          cert.UnknownExtKeyUsage,
		BasicConstraintsValid:       cert.BasicConstraintsValid,
		IsCA:                        cert.IsCA,
		MaxPathLen:                  cert.MaxPathLen,
		MaxPathLenZero:              cert.MaxPathLenZero,
		SubjectKeyId:                cert.SubjectKeyId,
		AuthorityKeyId:              cert.AuthorityKeyId,
		OCSPServer:                  cert.OCSPServer,
		IssuingCertificateURL:       cert.IssuingCertificateURL,
		DNSNames:                    cert.DNSNames,
		EmailAddresses:              cert.EmailAddresses,
		IPAddresses:                 cert.IPAddresses,
		PermittedDNSDomainsCritical: cert.PermittedDNSDomainsCritical,
		PermittedDNSDomains:         cert.PermittedDNSDomains,
		ExcludedDNSDomains:          cert.ExcludedDNSDomains,
		CRLDistributionPoints:       cert.CRLDistributionPoints,
		PolicyIdentifiers:           cert.PolicyIdentifiers,
	}
}

func CopyGMX509ToX509(cert *x509.Certificate) *ox509.Certificate {
	var extKeyUsages []ox509.ExtKeyUsage
	for _, k := range cert.ExtKeyUsage {
		extKeyUsages = append(extKeyUsages, ox509.ExtKeyUsage(k))
	}
	return &ox509.Certificate{
		Raw:                         cert.Raw,
		RawTBSCertificate:           cert.RawTBSCertificate,
		RawSubjectPublicKeyInfo:     cert.RawSubjectPublicKeyInfo,
		RawSubject:                  cert.RawSubject,
		RawIssuer:                   cert.RawIssuer,
		Signature:                   cert.Signature,
		SignatureAlgorithm:          ox509.SignatureAlgorithm(cert.SignatureAlgorithm),
		PublicKeyAlgorithm:          ox509.PublicKeyAlgorithm(cert.PublicKeyAlgorithm),
		PublicKey:                   cert.PublicKey,
		Version:                     cert.Version,
		SerialNumber:                cert.SerialNumber,
		Issuer:                      cert.Issuer,
		Subject:                     cert.Subject,
		NotBefore:                   cert.NotBefore,
		NotAfter:                    cert.NotAfter,
		KeyUsage:                    ox509.KeyUsage(cert.KeyUsage),
		Extensions:                  cert.Extensions,
		ExtraExtensions:             cert.ExtraExtensions,
		UnhandledCriticalExtensions: cert.UnhandledCriticalExtensions,
		ExtKeyUsage:                 extKeyUsages,
		UnknownExtKeyUsage:          cert.UnknownExtKeyUsage,
		BasicConstraintsValid:       cert.BasicConstraintsValid,
		IsCA:                        cert.IsCA,
		MaxPathLen:                  cert.MaxPathLen,
		MaxPathLenZero:              cert.MaxPathLenZero,
		SubjectKeyId:                cert.SubjectKeyId,
		AuthorityKeyId:              cert.AuthorityKeyId,
		OCSPServer:                  cert.OCSPServer,
		IssuingCertificateURL:       cert.IssuingCertificateURL,
		DNSNames:                    cert.DNSNames,
		EmailAddresses:              cert.EmailAddresses,
		IPAddresses:                 cert.IPAddresses,
		PermittedDNSDomainsCritical: cert.PermittedDNSDomainsCritical,
		PermittedDNSDomains:         cert.PermittedDNSDomains,
		ExcludedDNSDomains:          cert.ExcludedDNSDomains,
		CRLDistributionPoints:       cert.CRLDistributionPoints,
		PolicyIdentifiers:           cert.PolicyIdentifiers,
	}
}

func CopyX509ToGMx509s(certs []*ox509.Certificate) []*x509.Certificate {
	var gmCerts []*x509.Certificate
	for _, cert := range certs {
		var extKeyUsages []x509.ExtKeyUsage
		for _, k := range cert.ExtKeyUsage {
			extKeyUsages = append(extKeyUsages, x509.ExtKeyUsage(k))
		}
		gmCerts = append(gmCerts, &x509.Certificate{
			Raw:                         cert.Raw,
			RawTBSCertificate:           cert.RawTBSCertificate,
			RawSubjectPublicKeyInfo:     cert.RawSubjectPublicKeyInfo,
			RawSubject:                  cert.RawSubject,
			RawIssuer:                   cert.RawIssuer,
			Signature:                   cert.Signature,
			SignatureAlgorithm:          x509.SignatureAlgorithm(cert.SignatureAlgorithm),
			PublicKeyAlgorithm:          x509.PublicKeyAlgorithm(cert.PublicKeyAlgorithm),
			PublicKey:                   cert.PublicKey,
			Version:                     cert.Version,
			SerialNumber:                cert.SerialNumber,
			Issuer:                      cert.Issuer,
			Subject:                     cert.Subject,
			NotBefore:                   cert.NotBefore,
			NotAfter:                    cert.NotAfter,
			KeyUsage:                    x509.KeyUsage(cert.KeyUsage),
			Extensions:                  cert.Extensions,
			ExtraExtensions:             cert.ExtraExtensions,
			UnhandledCriticalExtensions: cert.UnhandledCriticalExtensions,
			ExtKeyUsage:                 extKeyUsages,
			UnknownExtKeyUsage:          cert.UnknownExtKeyUsage,
			BasicConstraintsValid:       cert.BasicConstraintsValid,
			IsCA:                        cert.IsCA,
			MaxPathLen:                  cert.MaxPathLen,
			MaxPathLenZero:              cert.MaxPathLenZero,
			SubjectKeyId:                cert.SubjectKeyId,
			AuthorityKeyId:              cert.AuthorityKeyId,
			OCSPServer:                  cert.OCSPServer,
			IssuingCertificateURL:       cert.IssuingCertificateURL,
			DNSNames:                    cert.DNSNames,
			EmailAddresses:              cert.EmailAddresses,
			IPAddresses:                 cert.IPAddresses,
			PermittedDNSDomainsCritical: cert.PermittedDNSDomainsCritical,
			PermittedDNSDomains:         cert.PermittedDNSDomains,
			ExcludedDNSDomains:          cert.ExcludedDNSDomains,
			CRLDistributionPoints:       cert.CRLDistributionPoints,
			PolicyIdentifiers:           cert.PolicyIdentifiers,
		})
	}

	return gmCerts
}

func CopyGMX509ToX509s(certs []*x509.Certificate) []*ox509.Certificate {
	var ocerts []*ox509.Certificate
	for _, cert := range certs {
		var extKeyUsages []ox509.ExtKeyUsage
		for _, k := range cert.ExtKeyUsage {
			extKeyUsages = append(extKeyUsages, ox509.ExtKeyUsage(k))
		}
		ocerts = append(ocerts, &ox509.Certificate{
			Raw:                         cert.Raw,
			RawTBSCertificate:           cert.RawTBSCertificate,
			RawSubjectPublicKeyInfo:     cert.RawSubjectPublicKeyInfo,
			RawSubject:                  cert.RawSubject,
			RawIssuer:                   cert.RawIssuer,
			Signature:                   cert.Signature,
			SignatureAlgorithm:          ox509.SignatureAlgorithm(cert.SignatureAlgorithm),
			PublicKeyAlgorithm:          ox509.PublicKeyAlgorithm(cert.PublicKeyAlgorithm),
			PublicKey:                   cert.PublicKey,
			Version:                     cert.Version,
			SerialNumber:                cert.SerialNumber,
			Issuer:                      cert.Issuer,
			Subject:                     cert.Subject,
			NotBefore:                   cert.NotBefore,
			NotAfter:                    cert.NotAfter,
			KeyUsage:                    ox509.KeyUsage(cert.KeyUsage),
			Extensions:                  cert.Extensions,
			ExtraExtensions:             cert.ExtraExtensions,
			UnhandledCriticalExtensions: cert.UnhandledCriticalExtensions,
			ExtKeyUsage:                 extKeyUsages,
			UnknownExtKeyUsage:          cert.UnknownExtKeyUsage,
			BasicConstraintsValid:       cert.BasicConstraintsValid,
			IsCA:                        cert.IsCA,
			MaxPathLen:                  cert.MaxPathLen,
			MaxPathLenZero:              cert.MaxPathLenZero,
			SubjectKeyId:                cert.SubjectKeyId,
			AuthorityKeyId:              cert.AuthorityKeyId,
			OCSPServer:                  cert.OCSPServer,
			IssuingCertificateURL:       cert.IssuingCertificateURL,
			DNSNames:                    cert.DNSNames,
			EmailAddresses:              cert.EmailAddresses,
			IPAddresses:                 cert.IPAddresses,
			PermittedDNSDomainsCritical: cert.PermittedDNSDomainsCritical,
			PermittedDNSDomains:         cert.PermittedDNSDomains,
			ExcludedDNSDomains:          cert.ExcludedDNSDomains,
			CRLDistributionPoints:       cert.CRLDistributionPoints,
			PolicyIdentifiers:           cert.PolicyIdentifiers,
		})
	}

	return ocerts
}

func CopyGMTLSCertificateToTLSCertificates(certs []tls.Certificate) []otls.Certificate {
	var ocerts []otls.Certificate
	for _, cert := range certs {
		ocerts = append(ocerts, otls.Certificate{
			Certificate:                 cert.Certificate,
			PrivateKey:                  cert.PrivateKey,
			OCSPStaple:                  cert.OCSPStaple,
			SignedCertificateTimestamps: cert.SignedCertificateTimestamps,
			Leaf:                        CopyGMX509ToX509(cert.Leaf),
		})
	}

	return ocerts
}

func CopyGMTLSCertificateToTLSCertificate(cert tls.Certificate) otls.Certificate {
	return otls.Certificate{
		Certificate:                 cert.Certificate,
		PrivateKey:                  cert.PrivateKey,
		OCSPStaple:                  cert.OCSPStaple,
		SignedCertificateTimestamps: cert.SignedCertificateTimestamps,
		Leaf:                        CopyGMX509ToX509(cert.Leaf),
	}
}
