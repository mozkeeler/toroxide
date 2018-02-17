use ed25519_dalek::Keypair;
use openssl::asn1::Asn1Time;
use openssl::bn::BigNum;
use openssl::hash::MessageDigest;
use openssl::pkey::{PKey, Private};
use openssl::rand::rand_bytes;
use openssl::rsa::Rsa;
use openssl::sign::Signer;
use openssl::x509::{X509Builder, X509NameBuilder};
use rand::OsRng;
use sha2::Sha512;

use certs;

pub const MAX_RSA_KEY_BITS: usize = 16384;

pub struct RsaKey {
    key: PKey<Private>,
}

impl RsaKey {
    pub fn new(bit_len: usize) -> Result<RsaKey, &'static str> {
        if bit_len > MAX_RSA_KEY_BITS {
            return Err("specified RSA key size too large");
        }
        let key = match Rsa::generate(bit_len as u32) {
            Ok(key) => key,
            Err(_) => return Err("error generating RSA key"),
        };
        Ok(RsaKey {
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
        // expiration date (hours since epoch - 4 bytes)
        let mut signer = Signer::new(MessageDigest::sha256(), &self.key).unwrap();
        signer
            .update(b"Tor TLS RSA/Ed25519 cross-certificate")
            .unwrap();
        signer.update(ed25519key.key.public.as_bytes()).unwrap();
        signer.update(&[1, 0, 0, 0]).unwrap(); // This is sometime in the year 3883.
        let signature = signer.sign_to_vec().unwrap();
        Ok(certs::Ed25519Identity::new(
            *ed25519key.key.public.as_bytes(),
            0x0100_0000,
            signature,
        ))
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
        to_be_signed.extend(b"Tor node signing key certificate v1".iter().cloned());
        let mut new_cert = certs::Ed25519Cert::new_unsigned(cert_type, other.key.public.to_bytes());
        to_be_signed.extend(new_cert.get_tbs_bytes());
        let signature = self.key.sign::<Sha512>(&to_be_signed).to_bytes();
        new_cert.set_signature(signature);
        new_cert
    }
}
