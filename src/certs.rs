use byteorder::{ByteOrder, NetworkEndian, WriteBytesExt};
use openssl::x509::X509;
use openssl::sign::Verifier;
use openssl::hash::MessageDigest;
use std::io::{Read, Write};

use keys;

// errg so having this and types::CertType seems a bit unnecessary?
#[derive(Debug)]
pub enum Cert {
    RsaLink(X509Cert),
    RsaIdentity(X509Cert),
    RsaAuthenticate(X509Cert),
    Ed25519Signing(Ed25519Cert),
    Ed25519Link(Ed25519Cert),
    Ed25519Authenticate(Ed25519Cert),
    Ed25519Identity(Ed25519Identity),
}

pub type HoursSinceEpoch = u32;

#[derive(Debug)]
pub struct Ed25519Cert {
    cert_type: Ed25519CertType,
    expiration_date: HoursSinceEpoch,
    certified_key_type: Ed25519CertifiedKeyType,
    certified_key: [u8; 32],
    extensions: Vec<Ed25519CertExtension>,
    // if this is a [u8; 64] I get that it can't be formatted with debug?
    signature: Vec<u8>,
}

impl Ed25519Cert {
    pub fn read_new<R: Read>(reader: &mut R) -> Result<Ed25519Cert, &'static str> {
        let mut one_byte_buf = [0; 1];
        if let Err(_) = reader.read_exact(&mut one_byte_buf) {
            return Err("failed to read certificate version");
        }
        if one_byte_buf[0] != 1 {
            return Err("unsupported certificate version");
        }
        if let Err(_) = reader.read_exact(&mut one_byte_buf) {
            return Err("failed to read certificate type");
        }
        let cert_type = Ed25519CertType::from_u8(one_byte_buf[0]);
        let mut four_byte_buf = [0; 4];
        if let Err(_) = reader.read_exact(&mut four_byte_buf) {
            return Err("failed to read expiration time");
        }
        let expiration_date = NetworkEndian::read_u32(&four_byte_buf);
        if let Err(_) = reader.read_exact(&mut one_byte_buf) {
            return Err("failed to read certified key type");
        }
        let certified_key_type = Ed25519CertifiedKeyType::from_u8(one_byte_buf[0]);
        let mut certified_key: [u8; 32] = [0; 32];
        if let Err(_) = reader.read_exact(&mut certified_key) {
            return Err("failed to read certified key");
        }
        if let Err(_) = reader.read_exact(&mut one_byte_buf) {
            return Err("failed to read number of extensions");
        }
        let mut extensions: Vec<Ed25519CertExtension> = Vec::new();
        for _ in 0..one_byte_buf[0] {
            match Ed25519CertExtension::read_new(reader) {
                Ok(extension) => extensions.push(extension),
                Err(e) => return Err(e),
            }
        }
        let mut signature: Vec<u8> = Vec::with_capacity(64);
        signature.resize(64, 0);
        if let Err(_) = reader.read_exact(signature.as_mut_slice()) {
            return Err("failed to read signature");
        }
        Ok(Ed25519Cert {
            cert_type: cert_type,
            expiration_date: expiration_date,
            certified_key_type: certified_key_type,
            certified_key: certified_key,
            extensions: extensions,
            signature: signature,
        })
    }

    pub fn new_unsigned(
        cert_type: Ed25519CertType,
        certified_key: [u8; 32],
        signing_key_bytes: &[u8; 32],
    ) -> Ed25519Cert {
        Ed25519Cert {
            cert_type: cert_type,
            // I think this is 2050-01-01, but maybe this should be dynamic
            expiration_date: 701288,
            certified_key_type: Ed25519CertifiedKeyType::Ed25519Key,
            certified_key: certified_key,
            extensions: vec![Ed25519CertExtension::new(signing_key_bytes)],
            signature: Vec::new(),
        }
    }

    pub fn write_to<W: Write>(&self, writer: &mut W) {
        writer.write_u8(1).unwrap();
        writer.write_u8(self.cert_type.as_u8()).unwrap();
        writer
            .write_u32::<NetworkEndian>(self.expiration_date)
            .unwrap();
        writer.write_u8(self.certified_key_type.as_u8()).unwrap();
        writer.write_all(&self.certified_key).unwrap();
        assert!(self.extensions.len() < 256);
        writer.write_u8(self.extensions.len() as u8).unwrap();
        for extension in &self.extensions {
            extension.write_to(writer);
        }
        writer.write_all(&self.signature).unwrap();
    }

    pub fn get_tbs_bytes(&self) -> Vec<u8> {
        let mut tbs_bytes: Vec<u8> = Vec::new();
        tbs_bytes.push(1);
        tbs_bytes.push(self.cert_type.as_u8());
        tbs_bytes
            .write_u32::<NetworkEndian>(self.expiration_date)
            .unwrap();
        tbs_bytes.push(self.certified_key_type.as_u8());
        tbs_bytes.extend(self.certified_key.iter());
        assert!(self.extensions.len() < 256);
        tbs_bytes.push(self.extensions.len() as u8);
        for extension in &self.extensions {
            tbs_bytes.extend(extension.as_bytes());
        }
        tbs_bytes
    }

    pub fn set_signature(&mut self, signature: [u8; 64]) {
        self.signature.clear();
        self.signature.extend(signature.iter());
    }

    pub fn get_signature(&self) -> &[u8] {
        &self.signature
    }

    // TODO: this doesn't make sense for non-Ed25519 keys (which brings up the question of why this
    // is called an Ed25519 Certificate, but ok), so maybe return a Result or something?
    // (Although see below - apparently we can't be sure that something marked as an Ed25519 key
    // actually is an Ed25519 key anyway.)
    pub fn get_key(&self) -> keys::Ed25519PublicKey {
        keys::Ed25519PublicKey::new_from_bytes(self.certified_key)
    }

    /// Check that the certified key is an X509 certificate hash and that the given hash matches.
    pub fn check_x509_certificate_hash(&self, hash: &[u8]) -> bool {
        // It would make sense to do something like this, but the official implementation is giving
        // us a Ed25519 link certificate where the certified key type is not marked as the hash of
        // an x509 certificate, so I guess we just can't check this?
        /*
        if self.certified_key_type != Ed25519CertifiedKeyType::X509CertificateSha256Hash {
            return false;
        }
        */
        hash == self.certified_key
    }

    pub fn get_extensions(&self) -> &[Ed25519CertExtension] {
        &self.extensions
    }
}

#[derive(Debug)]
pub enum Ed25519CertType {
    // Ed25519 signing key signed by an identity key
    SigningKey,
    // TLS link certificate signed by Ed25519 signing key
    TlsLinkCertificate,
    // Ed25519 authentication key signed by Ed25519 signing key
    AuthenticationKey,
    // I think this is the cross-signed Ed25519 ID key (signed by RSA ID key)
    IdentityKey,
    Unknown(u8),
}

impl Ed25519CertType {
    fn from_u8(cert_type: u8) -> Ed25519CertType {
        match cert_type {
            0x04 => Ed25519CertType::SigningKey,
            0x05 => Ed25519CertType::TlsLinkCertificate,
            0x06 => Ed25519CertType::AuthenticationKey,
            0x0A => Ed25519CertType::IdentityKey,
            _ => Ed25519CertType::Unknown(cert_type),
        }
    }

    fn as_u8(&self) -> u8 {
        match self {
            &Ed25519CertType::SigningKey => 0x04,
            &Ed25519CertType::TlsLinkCertificate => 0x05,
            &Ed25519CertType::AuthenticationKey => 0x06,
            &Ed25519CertType::IdentityKey => 0x0A,
            &Ed25519CertType::Unknown(val) => val,
        }
    }
}

#[derive(Debug, PartialEq)]
pub enum Ed25519CertifiedKeyType {
    Ed25519Key,
    RsaKeySha256Hash,
    X509CertificateSha256Hash,
    Unknown(u8),
}

impl Ed25519CertifiedKeyType {
    fn from_u8(key_type: u8) -> Ed25519CertifiedKeyType {
        match key_type {
            1 => Ed25519CertifiedKeyType::Ed25519Key,
            2 => Ed25519CertifiedKeyType::RsaKeySha256Hash,
            3 => Ed25519CertifiedKeyType::X509CertificateSha256Hash,
            _ => Ed25519CertifiedKeyType::Unknown(key_type),
        }
    }

    fn as_u8(&self) -> u8 {
        match self {
            &Ed25519CertifiedKeyType::Ed25519Key => 1,
            &Ed25519CertifiedKeyType::RsaKeySha256Hash => 2,
            &Ed25519CertifiedKeyType::X509CertificateSha256Hash => 3,
            &Ed25519CertifiedKeyType::Unknown(val) => val,
        }
    }
}

#[derive(Debug)]
pub struct Ed25519CertExtension {
    pub ext_type: Ed25519CertExtensionType,
    pub ext_flags: Ed25519CertExtensionFlags,
    pub ext_data: Vec<u8>,
}

impl Ed25519CertExtension {
    pub fn read_new<R: Read>(reader: &mut R) -> Result<Ed25519CertExtension, &'static str> {
        let mut two_byte_buf = [0; 2];
        if let Err(_) = reader.read_exact(&mut two_byte_buf) {
            return Err("failed to read extension length");
        }
        let length: usize = NetworkEndian::read_u16(&two_byte_buf) as usize;
        let mut one_byte_buf = [0; 1];
        if let Err(_) = reader.read_exact(&mut one_byte_buf) {
            return Err("failed to read extension type");
        }
        let ext_type = Ed25519CertExtensionType::from_u8(one_byte_buf[0]);
        if let Err(_) = reader.read_exact(&mut one_byte_buf) {
            return Err("failed to read extension flags");
        }
        let ext_flags = Ed25519CertExtensionFlags::from_u8(one_byte_buf[0]);
        let mut ext_data: Vec<u8> = Vec::with_capacity(length);
        ext_data.resize(length, 0);
        if let Err(_) = reader.read_exact(ext_data.as_mut_slice()) {
            return Err("failed to read extension data");
        }
        Ok(Ed25519CertExtension {
            ext_type: ext_type,
            ext_flags: ext_flags,
            ext_data: ext_data,
        })
    }

    pub fn write_to<W: Write>(&self, writer: &mut W) {
        writer.write_all(&self.as_bytes()).unwrap();
    }

    pub fn as_bytes(&self) -> Vec<u8> {
        let mut bytes: Vec<u8> = Vec::new();
        assert!(self.ext_data.len() < 65536);
        bytes
            .write_u16::<NetworkEndian>(self.ext_data.len() as u16)
            .unwrap();
        bytes.push(self.ext_type.as_u8());
        bytes.push(self.ext_flags.as_u8());
        bytes.extend(self.ext_data.iter());
        bytes
    }

    pub fn new(ed25519_key_bytes: &[u8; 32]) -> Ed25519CertExtension {
        let mut ext_data: Vec<u8> = Vec::with_capacity(32);
        ext_data.extend(ed25519_key_bytes);
        Ed25519CertExtension {
            ext_type: Ed25519CertExtensionType::SignedWithEd25519Key,
            ext_flags: Ed25519CertExtensionFlags::None,
            ext_data: ext_data,
        }
    }
}

#[derive(Debug)]
pub enum Ed25519CertExtensionType {
    SignedWithEd25519Key,
    Unknown(u8),
}

impl Ed25519CertExtensionType {
    fn from_u8(ext_type: u8) -> Ed25519CertExtensionType {
        match ext_type {
            4 => Ed25519CertExtensionType::SignedWithEd25519Key,
            _ => Ed25519CertExtensionType::Unknown(ext_type),
        }
    }

    fn as_u8(&self) -> u8 {
        match self {
            &Ed25519CertExtensionType::SignedWithEd25519Key => 4,
            &Ed25519CertExtensionType::Unknown(val) => val,
        }
    }
}

// So I suppose technically Critical should be true if the 0th bit is set, maybe?
#[derive(Debug)]
pub enum Ed25519CertExtensionFlags {
    /// No bits are set (i.e. 0).
    None,
    /// The 0th bit is set, and some others may be set (represented by the value held in the enum).
    Critical(u8),
    /// The 0th bit is not set, and some others may be set.
    Unknown(u8),
}

impl Ed25519CertExtensionFlags {
    fn from_u8(ext_flags: u8) -> Ed25519CertExtensionFlags {
        if ext_flags == 0 {
            Ed25519CertExtensionFlags::None
        } else if ext_flags & 1 == 1 {
            Ed25519CertExtensionFlags::Critical(ext_flags | 0b1111_1110)
        } else {
            Ed25519CertExtensionFlags::Unknown(ext_flags)
        }
    }

    fn as_u8(&self) -> u8 {
        match self {
            &Ed25519CertExtensionFlags::None => 0,
            &Ed25519CertExtensionFlags::Critical(rest) => rest | 1,
            &Ed25519CertExtensionFlags::Unknown(val) => val,
        }
    }
}

#[derive(Debug)]
pub struct Ed25519Identity {
    ed25519_key: [u8; 32],
    expiration_date: HoursSinceEpoch,
    signature: Vec<u8>,
}

impl Ed25519Identity {
    pub fn read_new<R: Read>(reader: &mut R) -> Result<Ed25519Identity, &'static str> {
        let mut ed25519_key = [0; 32];
        if let Err(_) = reader.read_exact(&mut ed25519_key) {
            return Err("failed to read ed25519 key");
        }
        let mut four_byte_buf = [0; 4];
        if let Err(_) = reader.read_exact(&mut four_byte_buf) {
            return Err("failed to read expiration time");
        }
        let expiration_date = NetworkEndian::read_u32(&four_byte_buf);
        let mut one_byte_buf = [0; 1];
        if let Err(_) = reader.read_exact(&mut one_byte_buf) {
            return Err("failed to read signature length");
        }
        let mut signature: Vec<u8> = Vec::with_capacity(one_byte_buf[0] as usize);
        signature.resize(one_byte_buf[0] as usize, 0);
        if let Err(_) = reader.read_exact(signature.as_mut_slice()) {
            return Err("failed to read signature");
        }
        Ok(Ed25519Identity {
            ed25519_key: ed25519_key,
            expiration_date: expiration_date,
            signature: signature,
        })
    }

    pub fn write_to<W: Write>(&self, writer: &mut W) {
        writer.write_all(&self.ed25519_key).unwrap();
        writer
            .write_u32::<NetworkEndian>(self.expiration_date)
            .unwrap();
        assert!(self.signature.len() < 256);
        writer.write_u8(self.signature.len() as u8).unwrap();
        writer.write_all(&self.signature).unwrap();
    }

    pub fn new(
        ed25519_key: [u8; 32],
        expiration_date: HoursSinceEpoch,
        signature: Vec<u8>,
    ) -> Ed25519Identity {
        Ed25519Identity {
            ed25519_key: ed25519_key,
            expiration_date: expiration_date,
            signature: signature,
        }
    }

    pub fn get_key_bytes(&self) -> &[u8] {
        &self.ed25519_key[..]
    }

    pub fn get_expiration_date(&self) -> HoursSinceEpoch {
        self.expiration_date
    }

    pub fn get_signature(&self) -> &[u8] {
        &self.signature
    }

    pub fn get_key(&self) -> keys::Ed25519PublicKey {
        keys::Ed25519PublicKey::new_from_bytes(self.ed25519_key)
    }
}

const SEQUENCE: u8 = 0x30;

#[derive(Debug)]
pub struct X509Cert {
    der: Vec<u8>,
}

impl X509Cert {
    pub fn read_new<R: Read>(reader: &mut R) -> Result<X509Cert, &'static str> {
        let mut x509cert = X509Cert { der: Vec::new() };
        if let Err(_) = reader.read_to_end(&mut x509cert.der) {
            return Err("failed to read x509 cert");
        }
        // make sure we can decode the certificate (for whatever reason I don't want to keep a
        // handle on the openssl::x509::X509...)
        if let Err(_) = X509::from_der(&x509cert.der) {
            return Err("failed to decode x509 cert");
        }
        Ok(x509cert)
    }

    pub fn write_to<W: Write>(&self, writer: &mut W) {
        writer.write_all(&self.der).unwrap();
    }

    pub fn is_self_signed(&self) -> bool {
        let openssl_cert = match X509::from_der(&self.der) {
            Err(_) => return false,
            Ok(cert) => cert,
        };
        let signature = openssl_cert.signature().as_slice();
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
        let length_field_a_length = match get_der_lengths(&self.der, SEQUENCE) {
            Err(()) => return false,
            Ok((length, _)) => length,
        };
        if self.der.len() < 1 + length_field_a_length {
            return false;
        }
        let cert_der_contents = &self.der[1 + length_field_a_length..];
        let (length_field_b_length, length_b) = match get_der_lengths(cert_der_contents, SEQUENCE) {
            Err(()) => return false,
            Ok((length_length, length)) => (length_length, length),
        };
        if cert_der_contents.len() < 1 + length_field_b_length + length_b {
            return false;
        }
        let tbs_certificate = &cert_der_contents[..1 + length_field_b_length + length_b];
        // TODO: is sha256 specified? or do we have to parse it out?
        let key = openssl_cert.public_key().unwrap();
        let mut verifier = Verifier::new(MessageDigest::sha256(), &key).unwrap();
        verifier.update(tbs_certificate).unwrap();
        verifier.verify(signature).unwrap()
    }

    pub fn get_key(&self) -> keys::RsaPublicKey {
        // I'm having a hard time deciding when to propagate errors...
        // (particularly in cases like this, where we've already decoded the certificate, so things
        // here probably shouldn't fail?)
        let openssl_cert = X509::from_der(&self.der).unwrap();
        let key = openssl_cert.public_key().unwrap();
        // It may seem weird to go from an openssl type to bytes to (ultimately) another openssl
        // type, but I'd like to create an external API that doesn't depend on the backing
        // implementation, given that we might not always want to use openssl.
        let spki = key.public_key_to_der().unwrap();
        keys::RsaPublicKey::from_spki(&spki).unwrap()
    }
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
