//use openssl::x509::X509;
use std::io::Read;

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
        let mut one_byte_buf = [0; 2];
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
        let expiration_date = ((four_byte_buf[0] as u32) << 24) + ((four_byte_buf[1] as u32) << 16)
            + ((four_byte_buf[2] as u32) << 16)
            + (four_byte_buf[3] as u32);
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
}

#[derive(Debug)]
pub enum Ed25519CertType {
    // Ed25519 signing key signed by an identity key
    SigningKey,
    // TLS link certificate signed by Ed25519 signing key
    TlsLinkCertificate,
    // Ed25519 authentication key signed by Ed25519 signing key
    AuthenticationKey,
    Unknown(u8),
}

impl Ed25519CertType {
    fn from_u8(cert_type: u8) -> Ed25519CertType {
        match cert_type {
            4 => Ed25519CertType::SigningKey,
            5 => Ed25519CertType::TlsLinkCertificate,
            6 => Ed25519CertType::AuthenticationKey,
            _ => Ed25519CertType::Unknown(cert_type),
        }
    }
}

#[derive(Debug)]
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
}

#[derive(Debug)]
pub struct Ed25519CertExtension {
    ext_type: Ed25519CertExtensionType,
    ext_flags: Ed25519CertExtensionFlags,
    ext_data: Vec<u8>,
}

impl Ed25519CertExtension {
    pub fn read_new<R: Read>(reader: &mut R) -> Result<Ed25519CertExtension, &'static str> {
        let mut two_byte_buf = [0; 2];
        if let Err(_) = reader.read_exact(&mut two_byte_buf) {
            return Err("failed to read extension length");
        }
        let length: usize = ((two_byte_buf[0] as usize) << 8) + (two_byte_buf[1] as usize);
        let mut one_byte_buf = [0; 1];
        if let Err(_) = reader.read_exact(&mut one_byte_buf) {
            return Err("failed to read extension type");
        }
        let ext_type = Ed25519CertExtensionType::from_u8(one_byte_buf[0]);
        if let Err(_) = reader.read_exact(&mut one_byte_buf) {
            return Err("failed to read extension flags");
        }
        let ext_flags = Ed25519CertExtensionFlags::from_u8(one_byte_buf[0]);
        let mut ext_data: Vec<u8> = Vec::new();
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
}

// So I suppose technically Critical should be true if the 0th bit is set, maybe?
#[derive(Debug)]
pub enum Ed25519CertExtensionFlags {
    None,
    Critical,
    Unknown(u8),
}

impl Ed25519CertExtensionFlags {
    fn from_u8(ext_flags: u8) -> Ed25519CertExtensionFlags {
        match ext_flags {
            0 => Ed25519CertExtensionFlags::None,
            1 => Ed25519CertExtensionFlags::Critical,
            _ => Ed25519CertExtensionFlags::Unknown(ext_flags),
        }
    }
}
