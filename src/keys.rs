use curve25519_dalek::scalar::Scalar;
use curve25519_dalek::constants::BASE_COMPRESSED_MONTGOMERY;
use ed25519_dalek::{Keypair, PublicKey, Signature};
use rand::{OsRng, Rng};
use sha2::Sha512;
use std::ops::Mul;

use certs;

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
        let mut new_cert = certs::Ed25519Cert::new_unsigned(
            cert_type,
            other.key.public.to_bytes(),
            &self.get_public_key_bytes(),
        );
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
        let mut to_verify: Vec<u8> = Vec::new();
        // Yeah so cert-spec.txt section 2.1 is just flat out wrong - there is no prefix and the
        // string "Tor node signing key certificate v1" appears nowhere in the tor codebase.
        //to_verify.extend(b"Tor node signing key certificate v1".iter().cloned());
        to_verify.extend(ed25519_cert.get_tbs_bytes());
        let signature = Signature::from_bytes(ed25519_cert.get_signature()).unwrap();
        if !self.key.verify::<Sha512>(&to_verify, &signature) {
            return false;
        }
        for extension in ed25519_cert.get_extensions() {
            match extension.ext_type {
                certs::Ed25519CertExtensionType::SignedWithEd25519Key => {
                    if extension.ext_data != self.key.as_bytes() {
                        return false;
                    }
                }
                _ => {
                    if let certs::Ed25519CertExtensionFlags::Critical(_) = extension.ext_flags {
                        return false;
                    }
                }
            }
        }
        true
    }

    pub fn matches_expected_key(&self, expected_bytes: &[u8; 32]) -> bool {
        self.key.as_bytes() == expected_bytes
    }
}

pub struct Curve25519Keypair {
    secret_bytes: [u8; 32],
    public_bytes: [u8; 32],
}

impl Curve25519Keypair {
    pub fn new() -> Curve25519Keypair {
        let mut csprng: OsRng = OsRng::new().unwrap();
        let mut secret_bytes: [u8; 32] = [0; 32];
        csprng.fill_bytes(&mut secret_bytes);
        // Magical clamping - apparently prevents some attacks and bugs.
        secret_bytes[0] &= 248;
        secret_bytes[31] &= 127;
        secret_bytes[31] |= 64;
        let nine = BASE_COMPRESSED_MONTGOMERY.decompress();
        let secret_bytes_as_scalar = Scalar::from_bits(secret_bytes.clone());
        let result = nine.mul(&secret_bytes_as_scalar);
        let public_bytes = result.compress().to_bytes();
        Curve25519Keypair {
            secret_bytes: secret_bytes,
            public_bytes: public_bytes,
        }
    }

    pub fn get_public_key_bytes(&self) -> [u8; 32] {
        self.public_bytes.clone()
    }

    pub fn get_secret_key_bytes(&self) -> [u8; 32] {
        self.secret_bytes.clone()
    }
}
