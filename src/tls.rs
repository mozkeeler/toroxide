//use base64;
use openssl::ssl::{Ssl, SslContext, SslStream, SslMethod, SslVerifyMode};
use openssl::x509::X509Ref;
use openssl::sign::Verifier;
use openssl::pkey::PKey;
use openssl::rsa::Rsa;
use openssl::hash::MessageDigest;
use std::net::TcpStream;

use dir::TorPeer;
use util;

pub struct TlsConnection {
    stream: SslStream<TcpStream>,
}

impl TlsConnection {
    pub fn new(tor_peer: &TorPeer) -> TlsConnection {
        let mut stream = TcpStream::connect(tor_peer).unwrap();
        let mut ssl_context_builder = SslContext::builder(SslMethod::tls()).unwrap();
        let issuer_public_key = tor_peer.rsa_public_key.clone();
        ssl_context_builder.set_verify_callback(SslVerifyMode::PEER, move |_, x509_store_ctx| {
            // bruh.
            if let Some(chain) = x509_store_ctx.chain() {
                if let Some(cert) = chain.iter().nth(0) {
                    return check_signature(cert, &issuer_public_key);
                }
            }
            false
        });
        let mut ssl_context = ssl_context_builder.build();
        let ssl = Ssl::new(&ssl_context).unwrap();
        TlsConnection {
            stream: ssl.connect(stream).unwrap(),
        }
    }
}

const SEQUENCE: u8 = 0x30;

/// Given an X509 certificate and the bytes of an issuer subject public key info (RSA only at the
/// moment), checks that the issuer key signed the certificate.
fn check_signature(cert: &X509Ref, issuer_spki: &[u8]) -> bool {
    let signature = cert.signature().as_slice();
    let cert_der = cert.to_der().unwrap();
    // Unfortunately the current API doesn't expose a way to get just the TBSCertificate bytes,
    // which is what we need to validate the signature. Sooooo, let's write an ASN.1 parser.
    // Certificate  ::=  SEQUENCE  {
    //      tbsCertificate       TBSCertificate,
    //      signatureAlgorithm   AlgorithmIdentifier,
    //      signature            BIT STRING  }
    // TBSCertificate  ::=  SEQUENCE { ... don't care about the contents ... }
    // Practically speaking, this means we'll have:
    // 30 <LENGTH FIELD A>
    //    30 <LENGTH FIELD B> <BYTES OF LENGTH B> <- this TLV is what we need
    //    <SIGNATURE ALGORITHM>
    //    <SIGNATURE>
    let length_field_a_length = match get_der_lengths(&cert_der, SEQUENCE) {
        Err(()) => return false,
        Ok((length, _)) => length,
    };
    if cert_der.len() < 1 + length_field_a_length {
        return false;
    }
    let cert_der_contents = &cert_der[1 + length_field_a_length..];
    let (length_field_b_length, length_b) = match get_der_lengths(cert_der_contents, SEQUENCE) {
        Err(()) => return false,
        Ok((length_length, length)) => (length_length, length),
    };
    if cert_der_contents.len() < 1 + length_field_b_length + length_b {
        return false;
    }
    let tbs_certificate = &cert_der_contents[..1 + length_field_b_length + length_b];
    // TODO: is sha256 specified? or do we have to parse it out?
    let key = Rsa::public_key_from_der_pkcs1(issuer_spki).unwrap();
    let key = PKey::from_rsa(key).unwrap();
    let mut verifier = Verifier::new(MessageDigest::sha256(), &key).unwrap();
    verifier.update(tbs_certificate);
    verifier.verify(signature).unwrap()
}

/// Given some bytes of DER and an expected tag, returns a pair consisting of the length of the
/// length field of the next TLV as well as the length of the value.
/// Informed by:
/// https://hg.mozilla.org/mozilla-central/file/35edab8d84db/security/pkix/lib/pkixder.cpp#l33
fn get_der_lengths(der: &[u8], expected_tag: u8) -> Result<(usize, usize), ()> {
    if der.len() < 1 {
        return Err(());
    }
    if der[0] != expected_tag {
        return Err(());
    }
    if der.len() < 2 {
        return Err(());
    }
    let length1 = der[1];
    // If the highest bit isn't set, the first byte is just the length of the value.
    if length1 & 0x80 == 0 {
        return Ok((1, length1 as usize));
    }
    if der.len() < 3 {
        return Err(());
    }
    if length1 == 0x81 {
        let length2 = der[2];
        // This would be invalid because it's not the shortest possible encoding.
        if length2 < 0x80 {
            return Err(());
        }
        return Ok((2, length2 as usize));
    }
    if der.len() < 4 {
        return Err(());
    }
    if length1 == 0x82 {
        let length = ((der[2] as usize) << 8) + der[3] as usize;
        // This would be invalid because it's not the shortest possible encoding.
        if length < 256 {
            return Err(());
        }
        return Ok((3, length));
    }
    // Certificates larger than 16k aren't supported.
    Err(())
}
