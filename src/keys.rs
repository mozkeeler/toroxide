use byteorder::{NetworkEndian, WriteBytesExt};
use ed25519_dalek::{Keypair, PublicKey, Signature};
use openssl::asn1::Asn1Time;
use openssl::bn::BigNum;
use openssl::hash::{Hasher, MessageDigest};
use openssl::pkey::{PKey, Private, Public};
use openssl::rand::rand_bytes;
use openssl::rsa::{Padding, Rsa};
use openssl::x509::{X509Builder, X509NameBuilder};
use rand::OsRng;
use sha2::Sha512;

use certs;

pub const MAX_RSA_KEY_BITS: usize = 16384;

const CROSS_SIGN_PREFIX: &'static [u8; 37] = b"Tor TLS RSA/Ed25519 cross-certificate";

pub struct RsaPrivateKey {
    key: PKey<Private>,
}

impl RsaPrivateKey {
    pub fn new(bit_len: usize) -> Result<RsaPrivateKey, &'static str> {
        if bit_len > MAX_RSA_KEY_BITS {
            return Err("specified RSA key size too large");
        }
        let key = match Rsa::generate(bit_len as u32) {
            Ok(key) => key,
            Err(_) => return Err("error generating RSA key"),
        };
        Ok(RsaPrivateKey {
            key: PKey::from_rsa(key).unwrap(),
        })
    }

    pub fn generate_self_signed_cert(&self) -> Result<certs::X509Cert, &'static str> {
        let mut builder = X509Builder::new().unwrap();
        builder.set_version(2).unwrap();
        let mut random_bytes = [0; 20];
        rand_bytes(&mut random_bytes).unwrap();
        // this might be unnecessary, depending on how BigNum/ASN.1 impl works.
        random_bytes[0] &= 0x7f; // make sure the higest bit isn't set
        random_bytes[0] |= 0x01; // make sure at least one bit is set in the first ocetet
        let serial_number = BigNum::from_slice(&random_bytes).unwrap();
        let serial_number = serial_number.to_asn1_integer().unwrap();
        builder.set_serial_number(&serial_number).unwrap();
        let mut name_builder = X509NameBuilder::new().unwrap();
        name_builder
            .append_entry_by_text("CN", "www.randomizeme.test")
            .unwrap();
        let name = name_builder.build();
        builder.set_subject_name(&name).unwrap();
        builder.set_issuer_name(&name).unwrap();
        // So unfortunately if there's a lot of clock skew this might not work. TODO: improve the
        // ASN1Time api (docs reference setting the value with a string, but I can't find any actual
        // implementation evidence to support this).
        let not_before = Asn1Time::days_from_now(0).unwrap();
        builder.set_not_before(&not_before).unwrap();
        let not_after = Asn1Time::days_from_now(1000).unwrap();
        builder.set_not_after(&not_after).unwrap();
        builder.set_pubkey(&self.key).unwrap();
        builder.sign(&self.key, MessageDigest::sha256()).unwrap();
        let x509 = builder.build();
        let der = x509.to_der().unwrap();
        certs::X509Cert::read_new(&mut &der[..])
    }

    pub fn sign_ed25519_key(
        &self,
        ed25519key: &Ed25519Key,
    ) -> Result<certs::Ed25519Identity, &'static str> {
        // The payload to be signed is:
        // "Tor TLS RSA/Ed25519 cross-certificate" || Ed25519 public key (32 bytes) ||
        // expiration date (hours since epoch, 4 bytes)
        let mut buf: Vec<u8> = Vec::new();
        // I think this represents 2050-01-01
        let expiration_date = 701288;
        buf.extend(CROSS_SIGN_PREFIX.iter());
        buf.extend(ed25519key.key.public.as_bytes());
        buf.write_u32::<NetworkEndian>(expiration_date).unwrap();
        let mut hasher = Hasher::new(MessageDigest::sha256()).unwrap();
        hasher.update(&buf).unwrap();
        let hashed = hasher.finish().unwrap();
        let rsa_key = &self.key.rsa().unwrap();
        let mut signature: Vec<u8> = Vec::with_capacity(rsa_key.size() as usize);
        signature.resize(rsa_key.size() as usize, 0);
        rsa_key
            .private_encrypt(&hashed, &mut signature, Padding::PKCS1)
            .unwrap();
        Ok(certs::Ed25519Identity::new(
            *ed25519key.key.public.as_bytes(),
            expiration_date,
            signature,
        ))
    }
}

pub struct RsaPublicKey {
    key: PKey<Public>,
}

impl RsaPublicKey {
    pub fn from_spki(spki: &[u8]) -> Result<RsaPublicKey, &'static str> {
        let key = match PKey::public_key_from_der(spki) {
            Ok(key) => key,
            Err(_) => return Err("error decoding SPKI"),
        };
        Ok(RsaPublicKey { key: key })
    }

    pub fn check_ed25519_identity_signature(
        &self,
        ed25519_identity_cert: &certs::Ed25519Identity,
    ) -> bool {
        let mut buf: Vec<u8> = Vec::new();
        buf.extend(CROSS_SIGN_PREFIX.iter());
        buf.extend(ed25519_identity_cert.get_key_bytes());
        let expiration_date = ed25519_identity_cert.get_expiration_date();
        buf.write_u32::<NetworkEndian>(expiration_date).unwrap();
        let mut hasher = Hasher::new(MessageDigest::sha256()).unwrap();
        hasher.update(&buf).unwrap();
        let hashed = hasher.finish().unwrap();
        let rsa_key = &self.key.rsa().unwrap();
        let mut buf: Vec<u8> = Vec::with_capacity(rsa_key.size() as usize);
        buf.resize(rsa_key.size() as usize, 0);
        let len_decrypted_bytes = match rsa_key.public_decrypt(
            ed25519_identity_cert.get_signature(),
            &mut buf,
            Padding::PKCS1,
        ) {
            Err(_) => return false,
            Ok(len) => len,
        };
        // So since this is public data, we don't have to be concerned about
        // constant-time-comparison, right?
        if len_decrypted_bytes < hashed.len() {
            return false;
        }
        for i in 0..len_decrypted_bytes {
            if hashed[i] != buf[i] {
                return false;
            }
        }
        true
    }

    pub fn get_size_in_bits(&self) -> usize {
        self.key.rsa().unwrap().size() as usize * 8
    }

    /// Returns the sha-256 hash of the DER encoding of this key as an ASN.1 RSA public key as
    /// specified in PKCS #1.
    pub fn get_sha256_hash(&self) -> Vec<u8> {
        let bytes = self.key.rsa().unwrap().public_key_to_pem_pkcs1().unwrap();
        let mut hasher = Hasher::new(MessageDigest::sha256()).unwrap();
        hasher.update(&bytes).unwrap();
        (*hasher.finish().unwrap()).to_vec()
    }
}

pub struct Ed25519Key {
    key: Keypair,
}

impl Ed25519Key {
    pub fn new() -> Ed25519Key {
        let mut csprng: OsRng = OsRng::new().unwrap();
        Ed25519Key {
            key: Keypair::generate::<Sha512>(&mut csprng),
        }
    }

    pub fn sign_ed25519_key(
        &self,
        other: &Ed25519Key,
        cert_type: certs::Ed25519CertType,
    ) -> certs::Ed25519Cert {
        let mut to_be_signed: Vec<u8> = Vec::new();
        // Yeah so cert-spec.txt section 2.1 is just flat out wrong - there is no prefix and the
        // string "Tor node signing key certificate v1" appears nowhere in the tor codebase.
        //to_be_signed.extend(b"Tor node signing key certificate v1".iter().cloned());
        let mut new_cert = certs::Ed25519Cert::new_unsigned(cert_type, other.key.public.to_bytes());
        to_be_signed.extend(new_cert.get_tbs_bytes());
        let signature = self.sign_data(&to_be_signed);
        new_cert.set_signature(signature);
        new_cert
    }

    pub fn get_public_key_bytes(&self) -> [u8; 32] {
        self.key.public.to_bytes()
    }

    pub fn sign_data(&self, data: &[u8]) -> [u8; 64] {
        self.key.sign::<Sha512>(data).to_bytes()
    }
}

pub struct Ed25519PublicKey {
    key: PublicKey,
}

impl Ed25519PublicKey {
    pub fn new_from_bytes(key_bytes: [u8; 32]) -> Ed25519PublicKey {
        Ed25519PublicKey {
            key: PublicKey::from_bytes(&key_bytes).unwrap(),
        }
    }

    pub fn check_ed25519_signature(&self, ed25519_cert: &certs::Ed25519Cert) -> bool {
        // TODO: check that self.key is what's in ed25519_cert's key-identifying-extension, if
        // present
        let mut to_verify: Vec<u8> = Vec::new();
        // Yeah so cert-spec.txt section 2.1 is just flat out wrong - there is no prefix and the
        // string "Tor node signing key certificate v1" appears nowhere in the tor codebase.
        //to_verify.extend(b"Tor node signing key certificate v1".iter().cloned());
        to_verify.extend(ed25519_cert.get_tbs_bytes());
        let signature = Signature::from_bytes(ed25519_cert.get_signature()).unwrap();
        self.key.verify::<Sha512>(&to_verify, &signature)
    }
}
