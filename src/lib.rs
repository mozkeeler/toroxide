extern crate base64;
extern crate byteorder;
extern crate constant_time_eq;
extern crate crypto;
extern crate curve25519_dalek;
extern crate ed25519_dalek;
extern crate hmac;
extern crate num;
extern crate rand;
extern crate sha1;
extern crate sha2;

mod certs;
pub mod dir;
mod keys;
pub mod types;
mod util;

use constant_time_eq::constant_time_eq;
use crypto::{aessafe, blockmodes};
use crypto::symmetriccipher::SynchronousStreamCipher;
use curve25519_dalek::montgomery;
use curve25519_dalek::scalar;
use hmac::{Hmac, Mac};
use num::PrimInt;
use rand::{OsRng, Rand, Rng};
use sha1::Sha1;
use sha2::{Digest, Sha256};
use std::collections::HashSet;
use std::hash::Hash;
use std::io::prelude::*;
use std::ops::Mul;
use std::time::{SystemTime, UNIX_EPOCH};

pub trait TlsImpl {
    fn get_peer_cert_hash(&self) -> Result<[u8; 32], ()>;
    fn get_tls_secrets(&self, label: &str, context: &[u8]) -> Result<Vec<u8>, ()>;
}

pub trait RsaVerifierImpl {
    fn verify_signature(&self, cert: &[u8], data: &[u8], signature: &[u8]) -> bool;
    fn get_key_hash(&self, cert: &[u8]) -> [u8; 32];
}

pub trait RsaSignerImpl {
    fn sign_data(&self, data: &[u8]) -> Vec<u8>;
    fn get_cert_bytes(&self) -> &[u8];
}

/// Generates unique IDs.
pub struct IdTracker<T>
where
    T: PrimInt + Hash + Rand,
{
    /// A set indicating the IDs that have been used.
    used_ids: HashSet<T>,
}

impl<T> IdTracker<T>
where
    T: PrimInt + Hash + Rand,
{
    pub fn new() -> IdTracker<T> {
        IdTracker {
            used_ids: HashSet::new(),
        }
    }

    /// Generates a new, nonzero, random id with the highest bit set that hasn't been used before or
    /// panics.
    pub fn get_new_id(&mut self) -> T {
        const RETRY_LIMIT: usize = 1024;
        let mut csprng: OsRng = OsRng::new().unwrap();
        let mut retries = RETRY_LIMIT;
        while retries > 0 {
            // We need to set the highest bit because we're initiating the connection.
            // Technically we only need to do this for circuit IDs, but having this implementation
            // be generic is nice and it doesn't mean anything for stream IDs.
            let new_id = csprng.gen::<T>() | (!T::zero() & !(!T::zero() >> 1));
            // HashSet.insert returns true if the value was not already present and false otherwise.
            if self.used_ids.insert(new_id) {
                return new_id;
            }
            retries -= 1;
        }
        panic!("couldn't generate new circuit id. (maybe implement gc?)");
    }
}

pub struct Circuit<T, V, S>
where
    T: TlsImpl + Read + Write,
    V: RsaVerifierImpl,
    S: RsaSignerImpl,
{
    /// TLS connection with the first hop in the circuit.
    tls_connection: TlsHashWrapper<T>,
    /// Implementation of RSA signature verification.
    rsa_verifier: V,
    /// Implementation of RSA signature creation.
    rsa_signer: S,
    /// The circuit ID for this connection.
    circ_id: u32,
    /// Maybe the certs parsed and validated from a peer's CERTS cell
    responder_certs: Option<ResponderCerts>,
    /// Sequence of CircuitKeys for each hop in this circuit.
    circuit_keys: Vec<CircuitKeys>,
    /// Stream IDs that have been used
    used_stream_ids: IdTracker<u16>,
    /// How many times we've used RELAY_EARLY.
    relay_early_count: usize,
}

impl<T, V, S> Circuit<T, V, S>
where
    T: TlsImpl + Read + Write,
    V: RsaVerifierImpl,
    S: RsaSignerImpl,
{
    pub fn new(tls_impl: T, rsa_verifier: V, rsa_signer: S, circ_id: u32) -> Circuit<T, V, S> {
        Circuit {
            tls_connection: TlsHashWrapper::new(tls_impl),
            rsa_verifier: rsa_verifier,
            rsa_signer: rsa_signer,
            circ_id: circ_id,
            responder_certs: None,
            circuit_keys: Vec::new(),
            used_stream_ids: IdTracker::new(),
            relay_early_count: 0,
        }
    }

    pub fn negotiate_versions(&mut self) -> Result<(), ()> {
        let versions = types::VersionsCell::new(vec![4]);
        let mut buf: Vec<u8> = Vec::new();
        if versions.write_to(&mut buf).is_err() {
            return Err(());
        }
        match self.tls_connection.write(&buf) {
            Ok(_) => {}
            Err(_) => return Err(()),
        };
        let peer_versions = match types::VersionsCell::read_new(&mut self.tls_connection) {
            Ok(peer_versions) => peer_versions,
            Err(_) => return Err(()),
        };
        let version = match versions.negotiate(&peer_versions) {
            Ok(version) => version,
            Err(_) => return Err(()),
        };
        println!("negotiated version {}", version);
        Ok(())
    }

    pub fn read_certs(&mut self, expected_ed25519_id_key: &[u8; 32]) -> Result<(), ()> {
        let cell = match types::Cell::read_new(&mut self.tls_connection) {
            Ok(cell) => cell,
            Err(_) => return Err(()),
        };
        if cell.command != types::Command::Certs {
            return Err(());
        }
        let certs_cell = match types::CertsCell::read_new(&mut &cell.payload[..]) {
            Ok(certs_cell) => certs_cell,
            Err(_) => return Err(()),
        };
        let responder_certs = match ResponderCerts::new(certs_cell.decode_certs()) {
            Ok(responder_certs) => responder_certs,
            Err(_) => return Err(()),
        };
        let peer_cert_hash = self.tls_connection.get_peer_cert_hash()?;
        if responder_certs
            .validate(expected_ed25519_id_key, &peer_cert_hash, &self.rsa_verifier)
            .is_err()
        {
            return Err(());
        }
        self.responder_certs = Some(responder_certs);
        Ok(())
    }

    pub fn read_auth_challenge(&mut self) -> Result<(), ()> {
        let cell = match types::Cell::read_new(&mut self.tls_connection) {
            Ok(cell) => cell,
            Err(_) => return Err(()),
        };
        if cell.command != types::Command::AuthChallenge {
            return Err(());
        }
        let auth_challenge = match types::AuthChallengeCell::read_new(&mut &cell.payload[..]) {
            Ok(auth_challenge_cell) => auth_challenge_cell,
            Err(_) => return Err(()),
        };
        println!("{:?}", auth_challenge);
        if !auth_challenge.has_auth_type(types::AuthType::Ed25519Sha256Rfc5705) {
            return Err(());
        }
        // It seems we don't actually have to do anything else here, since the only thing we would
        // need is actually in our connection's read digest.
        Ok(())
    }

    pub fn send_certs_and_authenticate_cells(&mut self) -> Result<(), ()> {
        let initiator_certs = InitiatorCerts::new(&self.rsa_signer);
        let certs_cell = initiator_certs.to_certs_cell();
        let mut buf: Vec<u8> = Vec::new();
        if certs_cell.write_to(&mut buf).is_err() {
            return Err(());
        }
        let cell = types::Cell::new(0, types::Command::Certs, buf);
        if cell.write_to(&mut self.tls_connection).is_err() {
            return Err(());
        };

        // tor-spec.txt section 4.4.2: With Ed25519-SHA256-RFC5705 link authentication, the
        // authentication field of the AUTHENTICATE cell is as follows:
        // "AUTH0003" [8 bytes]
        // (TODO: these next two are a bit underspecified. Combining section 0.3 with this, I
        // suppose this means "sha-256 hash of DER encoding of an ASN.1 RSA public key (PKCS #1).)
        // CID: sha-256 hash of initiator's RSA identity key [32 bytes]
        // SID: sha-256 hash of responder's RSA identity key [32 bytes]
        // CID_ED: initiator's Ed25519 identity public key [32 bytes]
        // SID_ED: responder's Ed25519 identity public key [32 bytes]
        // SLOG: sha-256 hash of all bytes received from responder by initiator (should be VERSIONS
        //       cell, CERTS cell, AUTH_CHALLENGE cell, and any padding cells (currently not
        //       handled...)) [32 bytes]
        // CLOG: sha-256 hash of all bytes sent to responder by initiator (should be VERSIONS cell,
        //       CERTS cell, and any padding cells (currently not sent...)) [32 bytes]
        // SCERT: sha-256 hash of the responder's TLS link certificate [32 bytes]
        // TLSSECRETS: output from an RFC5705 exporter on the TLS session, using:
        //             - the label "EXPORTER FOR TOR TLS CLIENT BINDING AUTH0003"
        //             - the context of the initiator's Ed25519 identity public key
        //             - output length of 32 bytes
        //             [32 bytes]
        // RAND: a 24-byte random value chosen by the initiator [24 bytes]
        // SIG: a signature over this data using the initiator's Ed25519 authenticate key
        //      [variable length? (shouldn't it just be 64 bytes?)]

        // "AUTH0003"
        let mut buf: Vec<u8> = b"AUTH0003".to_vec();
        // CID
        let cid = self.rsa_verifier
            .get_key_hash(&initiator_certs.rsa_identity_cert.get_bytes());
        buf.extend(&cid);
        // SID
        let responder_certs = match self.responder_certs {
            Some(ref responder_certs) => responder_certs,
            None => return Err(()),
        };
        let sid = self.rsa_verifier
            .get_key_hash(&responder_certs.rsa_identity_cert.get_bytes());
        buf.extend(&sid);
        // CID_ED
        let cid_ed = initiator_certs.ed25519_identity_cert.get_key_bytes();
        buf.extend(cid_ed);
        // SID_ED
        let sid_ed = responder_certs.ed25519_identity_cert.get_key_bytes();
        buf.extend(sid_ed);
        // SLOG (yes, the responder is first this time. don't know why)
        let slog = self.tls_connection.get_read_digest();
        buf.extend(slog);
        // CLOG
        let clog = self.tls_connection.get_write_digest();
        buf.extend(clog);
        // SCERT
        let scert = self.tls_connection.get_peer_cert_hash()?;
        buf.extend(&scert);
        // TLSSECRETS
        // tor-spec.txt section 4.4.1 is wrong here - the context is the sha-256 hash of the
        // initiator's RSA identity cert (in other words, CID)
        // Get the TLSSECRETS bytes ala tor-spec.txt, section 4.4.2. (RFC5705 exporter using the
        // label "EXPORTER FOR TOR TLS CLIENT BINDING AUTH0003", and the given context.
        const TLS_SECRET_LABEL: &'static str = "EXPORTER FOR TOR TLS CLIENT BINDING AUTH0003";
        let tlssecrets = self.tls_connection.get_tls_secrets(TLS_SECRET_LABEL, &cid)?;
        buf.extend(tlssecrets);
        // RAND
        let mut rand = [0; 24];
        let mut csprng: OsRng = match OsRng::new() {
            Ok(csprng) => csprng,
            Err(_) => return Err(()),
        };
        csprng.fill_bytes(&mut rand);
        buf.extend(rand.iter());
        // SIG
        let ed25519_authenticate_key = initiator_certs.get_ed25519_authenticate_key();
        let signature = ed25519_authenticate_key.sign_data(&buf);
        buf.extend(signature.iter());

        let authenticate_cell =
            types::AuthenticateCell::new(types::AuthType::Ed25519Sha256Rfc5705, buf);
        let mut buf: Vec<u8> = Vec::new();
        if authenticate_cell.write_to(&mut buf).is_err() {
            return Err(());
        }
        let cell = types::Cell::new(0, types::Command::Authenticate, buf);
        if cell.write_to(&mut self.tls_connection).is_err() {
            return Err(());
        }
        Ok(())
    }

    pub fn read_netinfo(&mut self) -> Result<(), ()> {
        let cell = match types::Cell::read_new(&mut self.tls_connection) {
            Ok(cell) => cell,
            Err(_) => return Err(()),
        };
        println!("{:?}", cell);
        if cell.command != types::Command::Netinfo {
            return Err(());
        }
        let netinfo = match types::NetinfoCell::read_new(&mut &cell.payload[..]) {
            Ok(netinfo_cell) => netinfo_cell,
            Err(_) => return Err(()),
        };
        println!("{:?}", netinfo);

        let timestamp: types::EpochSeconds = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs() as u32;
        let other_or_address = netinfo.get_other_or_address();
        let localhost = types::OrAddress::IPv4Address([127, 0, 0, 1]);
        let netinfo = types::NetinfoCell::new(timestamp, other_or_address, localhost);
        let mut buf: Vec<u8> = Vec::new();
        if netinfo.write_to(&mut buf).is_err() {
            return Err(());
        }
        let cell = types::Cell::new(0, types::Command::Netinfo, buf);
        if cell.write_to(&mut self.tls_connection).is_err() {
            return Err(());
        }
        Ok(())
    }

    pub fn create_fast(&mut self) -> Result<(), ()> {
        let mut x = [0; 20];
        let mut csprng: OsRng = match OsRng::new() {
            Ok(csprng) => csprng,
            Err(_) => return Err(()),
        };
        csprng.fill_bytes(&mut x);
        let create_fast_cell = types::CreateFastCell::new(x);
        let mut buf: Vec<u8> = Vec::new();
        if create_fast_cell.write_to(&mut buf).is_err() {
            return Err(());
        }
        let cell = types::Cell::new(self.circ_id, types::Command::CreateFast, buf);

        if cell.write_to(&mut self.tls_connection).is_err() {
            return Err(());
        }
        let cell = match types::Cell::read_new(&mut self.tls_connection) {
            Ok(cell) => cell,
            Err(_) => return Err(()),
        };
        println!("{:?}", cell);
        // TODO: handle DESTROY differently here?
        if cell.command != types::Command::CreatedFast {
            return Err(());
        }
        let created_fast = match types::CreatedFastCell::read_new(&mut &cell.payload[..]) {
            Ok(created_fast) => created_fast,
            Err(_) => return Err(()),
        };
        println!("{:?}", created_fast);
        let circuit_keys = match tor_kdf(&x, created_fast.get_y(), created_fast.get_kh()) {
            Ok(circuit_keys) => circuit_keys,
            Err(_) => return Err(()),
        };
        self.circuit_keys.push(circuit_keys);
        Ok(())
    }

    // TODO: stream_id == 0 for control commands - how do we make this easy/automatic?
    // (maybe tie it into the "get me a new stream id" function?)
    fn encrypt_cell_bytes(
        &mut self,
        relay_command: types::RelayCommand,
        in_bytes: &[u8],
        stream_id: u16,
    ) -> Vec<u8> {
        let mut bytes = Vec::new();
        bytes.extend_from_slice(in_bytes);
        let mut first = true;
        for circuit_keys in self.circuit_keys.iter_mut().rev() {
            // TODO: this 0 may need to be something else in the future?
            // (for non-command cells)
            if first {
                let mut relay_cell = types::RelayCell::new(relay_command.clone(), stream_id, bytes);
                relay_cell.set_digest(&mut circuit_keys.forward_digest);
                bytes = Vec::new();
                relay_cell.write_to(&mut bytes).unwrap();
                first = false;
            }
            let mut encrypted_bytes = Vec::with_capacity(bytes.len());
            encrypted_bytes.resize(bytes.len(), 0);
            circuit_keys
                .forward_key
                .aes
                .process(&bytes, &mut encrypted_bytes);
            bytes = encrypted_bytes;
        }
        bytes
    }

    fn decrypt_cell_bytes(&mut self, in_bytes: &[u8]) -> Result<types::RelayCell, ()> {
        let mut bytes = Vec::new();
        bytes.extend_from_slice(in_bytes);
        for circuit_keys in self.circuit_keys.iter_mut() {
            let mut decrypted_cell_bytes: Vec<u8> = Vec::with_capacity(bytes.len());
            decrypted_cell_bytes.resize(bytes.len(), 0);
            // So we have to have some way to roll back things that weren't actually for us (or
            // attacks that would attempt to modify our counter...)
            // It seems the canonical implementation just kills the connection if this ever happens.
            circuit_keys
                .backward_key
                .aes
                .process(&bytes, &mut decrypted_cell_bytes);
            // TODO: handle digest, things not for us, etc.
            bytes = decrypted_cell_bytes;
        }
        match types::RelayCell::read_new(&mut &bytes[..]) {
            Ok(decrypted_cell) => Ok(decrypted_cell),
            Err(_) => Err(()),
        }
    }

    fn send_cell_bytes(&mut self, bytes: Vec<u8>) -> Result<(), ()> {
        let command = if self.relay_early_count < 8 {
            self.relay_early_count += 1;
            types::Command::RelayEarly
        } else {
            types::Command::Relay
        };
        let cell = types::Cell::new(self.circ_id, command, bytes);
        match cell.write_to(&mut self.tls_connection) {
            Ok(_) => Ok(()),
            Err(_) => Err(()),
        }
    }

    fn read_cell(&mut self) -> Result<types::Cell, ()> {
        match types::Cell::read_new(&mut self.tls_connection) {
            Ok(cell) => Ok(cell),
            Err(_) => Err(()),
        }
    }

    pub fn extend(&mut self, node: &dir::TorPeer) -> Result<(), ()> {
        println!("attempting to extend to {:?}", node);
        let client_keypair = keys::Curve25519Keypair::new();
        let ntor_client_handshake = types::NtorClientHandshake::new(node, &client_keypair);
        let mut ntor_client_handshake_bytes = Vec::new();
        if ntor_client_handshake
            .write_to(&mut ntor_client_handshake_bytes)
            .is_err()
        {
            return Err(());
        }
        let extend2 = types::Extend2Cell::new(node, ntor_client_handshake_bytes);
        let mut extend2_bytes = Vec::new();
        if extend2.write_to(&mut extend2_bytes).is_err() {
            return Err(());
        }
        let bytes = self.encrypt_cell_bytes(types::RelayCommand::Extend2, &extend2_bytes, 0);
        self.send_cell_bytes(bytes)?;
        let cell = self.read_cell()?;
        println!("{:?}", cell);
        if cell.command != types::Command::Relay {
            return Err(());
        }
        let relay_cell = self.decrypt_cell_bytes(&cell.payload)?;
        println!("{}", relay_cell);
        if relay_cell.relay_command != types::RelayCommand::Extended2 {
            return Err(());
        }
        // The contents of an EXTENDED2 relay cell is the same as a CREATED2 cell
        let extended2 = match types::Created2Cell::read_new(&mut &relay_cell.data[..]) {
            Ok(extended2) => extended2,
            Err(_) => return Err(()),
        };
        let circuit_keys = match ntor_handshake(
            &extended2,
            node.get_node_id(),
            node.get_ntor_key(),
            client_keypair.get_public_key_bytes(),
            client_keypair.get_secret_key_bytes(),
        ) {
            Ok(circuit_keys) => circuit_keys,
            Err(_) => return Err(()),
        };
        self.circuit_keys.push(circuit_keys);
        Ok(())
    }

    // returns what stream id we picked
    /// begin_command must be types::RelayCommand::RELAY_BEGIN or
    /// types::RelayCommand::RELAY_BEGIN_DIR for this to be useful
    fn begin_common(
        &mut self,
        begin_command: types::RelayCommand,
        begin_bytes: &[u8],
    ) -> Result<u16, ()> {
        let stream_id = self.used_stream_ids.get_new_id();
        let bytes = self.encrypt_cell_bytes(begin_command, begin_bytes, stream_id);
        self.send_cell_bytes(bytes)?;
        let cell = self.read_cell()?;
        println!("{:?}", cell);
        if cell.command != types::Command::Relay {
            return Err(());
        }
        let relay_cell = self.decrypt_cell_bytes(&cell.payload)?;
        println!("{}", relay_cell);
        if relay_cell.relay_command != types::RelayCommand::Connected {
            return Err(());
        }
        Ok(stream_id)
    }

    pub fn begin(&mut self, addrport: &str) -> Result<u16, ()> {
        let begin = types::BeginCell::new(addrport);
        println!("{:?}", begin);
        // Hmmm maybe I wouldn't have to do all this "make a cell then make a vec then write_to it"
        // if I defined a trait...?
        let mut begin_bytes: Vec<u8> = Vec::new();
        if begin.write_to(&mut begin_bytes).is_err() {
            return Err(());
        }
        self.begin_common(types::RelayCommand::Begin, &begin_bytes)
    }

    pub fn begin_dir(&mut self) -> Result<u16, ()> {
        let begin = types::BeginDirCell::new();
        let mut begin_bytes: Vec<u8> = Vec::new();
        if begin.write_to(&mut begin_bytes).is_err() {
            return Err(());
        }
        self.begin_common(types::RelayCommand::BeginDir, &begin_bytes)
    }

    pub fn send(&mut self, stream_id: u16, data: &[u8]) -> Result<(), ()> {
        let bytes = self.encrypt_cell_bytes(types::RelayCommand::Data, data, stream_id);
        self.send_cell_bytes(bytes)
    }

    // I think this will return an Err if there's nothing to read... (but also it'll return an Err
    // if we get invalid data, so... I need some sort of "would block" indication?
    pub fn recv(&mut self) -> Result<Vec<u8>, ()> {
        //self.tls_connection.set_nonblocking();
        let mut buf = Vec::new();
        let cell = self.read_cell()?;
        println!("{:?}", cell);
        if cell.command != types::Command::Relay {
            return Err(());
        }
        let relay_cell = self.decrypt_cell_bytes(&cell.payload)?;
        println!("{}", relay_cell);
        match relay_cell.relay_command {
            types::RelayCommand::Data => buf.extend(relay_cell.get_data()),
            types::RelayCommand::End => {}
            _ => return Err(()),
        }
        Ok(buf)
    }

    pub fn recv_to_end(&mut self) -> Result<Vec<u8>, ()> {
        let mut buf = Vec::new();
        loop {
            let cell = self.read_cell()?;
            println!("{:?}", cell);
            if cell.command != types::Command::Relay {
                return Err(());
            }
            let relay_cell = self.decrypt_cell_bytes(&cell.payload)?;
            println!("{}", relay_cell);
            match relay_cell.relay_command {
                types::RelayCommand::Data => buf.extend(relay_cell.get_data()),
                types::RelayCommand::End => break,
                _ => return Err(()),
            }
        }
        Ok(buf)
    }
}

struct TlsHashWrapper<T: TlsImpl + Read + Write> {
    tls_impl: T,
    /// A running sha256 digest of all data read from the stream
    read_log: Sha256,
    /// A running sha256 digest of all data written to the stream
    write_log: Sha256,
}

impl<T: TlsImpl + Read + Write> TlsHashWrapper<T> {
    pub fn new(tls_impl: T) -> TlsHashWrapper<T> {
        TlsHashWrapper {
            tls_impl: tls_impl,
            read_log: Sha256::new(),
            write_log: Sha256::new(),
        }
    }

    /// Get the sha-256 hash of all data read from the stream.
    pub fn get_read_digest(&self) -> Vec<u8> {
        // Clone self.read_log so calling .result() doesn't modify its state.
        let read_log = self.read_log.clone();
        let mut bytes: Vec<u8> = Vec::new();
        bytes.extend(read_log.result().into_iter());
        bytes
    }

    /// Get the sha-256 hash of all data written to the stream.
    pub fn get_write_digest(&self) -> Vec<u8> {
        // Clone self.write_log so calling .result() doesn't modify its state.
        let write_log = self.write_log.clone();
        let mut bytes: Vec<u8> = Vec::new();
        bytes.extend(write_log.result().into_iter());
        bytes
    }
}

impl<T: TlsImpl + Read + Write> TlsImpl for TlsHashWrapper<T> {
    fn get_peer_cert_hash(&self) -> Result<[u8; 32], ()> {
        self.tls_impl.get_peer_cert_hash()
    }

    fn get_tls_secrets(&self, label: &str, context_key: &[u8]) -> Result<Vec<u8>, ()> {
        self.tls_impl.get_tls_secrets(label, context_key)
    }
}

impl<T: TlsImpl + Read + Write> Read for TlsHashWrapper<T> {
    fn read(&mut self, buf: &mut [u8]) -> Result<usize, std::io::Error> {
        let result = self.tls_impl.read(buf);
        if let &Ok(len) = &result {
            self.read_log.input(&buf[..len]);
        }
        result
    }
}

impl<T: TlsImpl + Read + Write> Write for TlsHashWrapper<T> {
    fn write(&mut self, data: &[u8]) -> Result<usize, std::io::Error> {
        let result = self.tls_impl.write(data);
        if let &Ok(len) = &result {
            self.write_log.input(&data[..len]);
        }
        result
    }

    fn flush(&mut self) -> Result<(), std::io::Error> {
        self.tls_impl.flush()
    }
}

struct AesContext {
    aes: blockmodes::CtrMode<aessafe::AesSafe128Encryptor>,
}

impl AesContext {
    fn new(key: &[u8]) -> AesContext {
        let mut iv: Vec<u8> = Vec::with_capacity(16);
        iv.resize(16, 0);
        let key: [u8; 16] = slice_to_16_byte_array(key);
        let aes_dec = aessafe::AesSafe128Encryptor::new(&key);
        AesContext {
            aes: blockmodes::CtrMode::new(aes_dec, iv),
        }
    }
}

struct CircuitKeys {
    forward_digest: Sha1,
    // backward_digest: Sha1, TODO: use this
    forward_key: AesContext,
    backward_key: AesContext,
}

impl CircuitKeys {
    fn new(k: &[u8]) -> CircuitKeys {
        CircuitKeys {
            forward_digest: Sha1::from(&k[0..20]),
            // backward_digest: Sha1::from(&k[20..40]),
            forward_key: AesContext::new(&k[40..56]),
            backward_key: AesContext::new(&k[56..72]),
        }
    }
}

/// Represents the certs that are supposed to be present in a responder's CERTS cell.
/// If any of these are None, the cell is invalid (see tor-spec.txt section 4.2).
#[derive(Debug)]
struct ResponderCerts {
    rsa_identity_cert: certs::X509Cert,
    ed25519_signing_cert: certs::Ed25519Cert,
    ed25519_link_cert: certs::Ed25519Cert,
    ed25519_identity_cert: certs::Ed25519Identity,
}

impl ResponderCerts {
    fn new(certs: Vec<certs::Cert>) -> Result<ResponderCerts, &'static str> {
        let mut rsa_identity_cert: Option<certs::X509Cert> = None;
        let mut ed25519_signing_cert: Option<certs::Ed25519Cert> = None;
        let mut ed25519_link_cert: Option<certs::Ed25519Cert> = None;
        let mut ed25519_identity_cert: Option<certs::Ed25519Identity> = None;

        // Technically we're supposed to ensure all X509 certificates have valid dates and that all
        // certificate are correctly signed, but...
        for cert in certs {
            match cert {
                certs::Cert::RsaIdentity(cert) => {
                    if let Some(_) = rsa_identity_cert {
                        return Err("more than one RSA identity cert -> invalid CERTS cell");
                    }
                    rsa_identity_cert = Some(cert);
                }
                certs::Cert::Ed25519Signing(cert) => {
                    if let Some(_) = ed25519_signing_cert {
                        return Err("more than one RSA identity cert -> invalid CERTS cell");
                    }
                    ed25519_signing_cert = Some(cert);
                }
                certs::Cert::Ed25519Link(cert) => {
                    if let Some(_) = ed25519_link_cert {
                        return Err("more than one RSA identity cert -> invalid CERTS cell");
                    }
                    ed25519_link_cert = Some(cert);
                }
                certs::Cert::Ed25519Identity(cert) => {
                    if let Some(_) = ed25519_identity_cert {
                        return Err("more than one RSA identity cert -> invalid CERTS cell");
                    }
                    ed25519_identity_cert = Some(cert);
                }
                _ => {}
            }
        }
        if rsa_identity_cert.is_none() {
            return Err("no RSA identity cert");
        }
        if ed25519_signing_cert.is_none() {
            return Err("no ed25519 signing cert");
        }
        if ed25519_link_cert.is_none() {
            return Err("no ed25519 link cert");
        }
        if ed25519_identity_cert.is_none() {
            return Err("no ed25519 identity cert");
        }
        Ok(ResponderCerts {
            rsa_identity_cert: rsa_identity_cert.take().unwrap(),
            ed25519_signing_cert: ed25519_signing_cert.take().unwrap(),
            ed25519_link_cert: ed25519_link_cert.take().unwrap(),
            ed25519_identity_cert: ed25519_identity_cert.take().unwrap(),
        })
    }

    fn validate(
        &self,
        expected_ed25519_id_key: &[u8; 32],
        peer_cert_hash: &[u8; 32],
        rsa_verifier: &RsaVerifierImpl,
    ) -> Result<(), &'static str> {
        // Need to check:
        // rsa_identity_cert is self-signed
        /* honestly, not sure what this protects against
        if !self.rsa_identity_cert.is_self_signed() {
            return Err("RSA identity cert is not self-signed");
        }
        */
        // rsa identity key (in rsa_identity_cert) signed ed25519_identity_cert, is 1024 bits
        if !self.rsa_identity_cert
            .check_ed25519_identity_signature(&self.ed25519_identity_cert, rsa_verifier)
        {
            return Err("RSA identity cert did not sign Ed25519 identity cert");
        }
        /*
        if identity_key.get_size_in_bits() != 1024 {
            return Err("RSA identity key wrong size");
        }
        */
        // ed25519 identity key (in ed25519_identity_cert) signed ed25519_signing_cert
        let ed25519_identity_key = self.ed25519_identity_cert.get_key();
        if !ed25519_identity_key.matches_expected_key(expected_ed25519_id_key) {
            return Err("Ed25519 identity key does not match the expected key");
        }
        if !ed25519_identity_key.check_ed25519_signature(&self.ed25519_signing_cert) {
            return Err("Ed25519 identity key did not sign Ed25519 signing cert");
        }
        // ed25519 signing key (in ed25519_signing_cert) signed ed25519_link_cert
        let ed25519_signing_key = self.ed25519_signing_cert.get_key();
        if !ed25519_signing_key.check_ed25519_signature(&self.ed25519_link_cert) {
            return Err("Ed25519 signing key did not sign Ed25519 link cert");
        }
        // certified "key" in ed25519_link_cert matches sha-256 hash of TLS peer certificate
        if !self.ed25519_link_cert
            .check_x509_certificate_hash(peer_cert_hash)
        {
            return Err("Ed25519 link key does not match peer certificate");
        }
        Ok(())
    }
}

/// The certificates and keys needed by an initiator (`Circuit`) to perform a link authentication
/// with a responder.
struct InitiatorCerts {
    rsa_identity_cert: certs::X509Cert,
    ed25519_identity_cert: certs::Ed25519Identity,
    ed25519_signing_cert: certs::Ed25519Cert,
    ed25519_authenticate_key: keys::Ed25519Key,
    ed25519_authenticate_cert: certs::Ed25519Cert,
}

impl InitiatorCerts {
    fn new(rsa_signer: &RsaSignerImpl) -> InitiatorCerts {
        // Apparently we don't need to keep this around for now.
        let rsa_identity_cert = certs::X509Cert::new(rsa_signer.get_cert_bytes());
        // Apparently we don't need to keep this around for now.
        let ed25519_identity_key = keys::Ed25519Key::new();
        let ed25519_identity_cert =
            rsa_identity_cert.sign_ed25519_key(&ed25519_identity_key, rsa_signer);
        // Apparently we don't need to keep this around for now.
        let ed25519_signing_key = keys::Ed25519Key::new();
        let ed25519_signing_cert = ed25519_identity_key
            .sign_ed25519_key(&ed25519_signing_key, certs::Ed25519CertType::SigningKey);
        let ed25519_authenticate_key = keys::Ed25519Key::new();
        let ed25519_authenticate_cert = ed25519_signing_key.sign_ed25519_key(
            &ed25519_authenticate_key,
            certs::Ed25519CertType::AuthenticationKey,
        );
        InitiatorCerts {
            rsa_identity_cert: rsa_identity_cert,
            ed25519_identity_cert: ed25519_identity_cert,
            ed25519_signing_cert: ed25519_signing_cert,
            ed25519_authenticate_key: ed25519_authenticate_key,
            ed25519_authenticate_cert: ed25519_authenticate_cert,
        }
    }

    fn to_certs_cell(&self) -> types::CertsCell {
        let mut certs: Vec<types::RawCert> = Vec::new();
        let mut bytes: Vec<u8> = Vec::new();
        self.rsa_identity_cert.write_to(&mut bytes);
        certs.push(types::RawCert::new(types::CertType::RsaIdentity, bytes));

        let mut bytes: Vec<u8> = Vec::new();
        self.ed25519_identity_cert.write_to(&mut bytes);
        certs.push(types::RawCert::new(types::CertType::Ed25519Identity, bytes));

        let mut bytes: Vec<u8> = Vec::new();
        self.ed25519_signing_cert.write_to(&mut bytes);
        certs.push(types::RawCert::new(types::CertType::Ed25519Signing, bytes));

        let mut bytes: Vec<u8> = Vec::new();
        self.ed25519_authenticate_cert.write_to(&mut bytes);
        certs.push(types::RawCert::new(
            types::CertType::Ed25519Authenticate,
            bytes,
        ));

        types::CertsCell::new_from_raw_certs(certs)
    }

    fn get_ed25519_authenticate_key(&self) -> &keys::Ed25519Key {
        &self.ed25519_authenticate_key
    }
}

/// Implements KDF-TOR as specified by tor-spec.txt section 5.2.1 in the context of a CREATE FAST
/// handshake. The TAP handshake is not implemented.
/// Given K0 as `x` and `y` concatenated together, computes
/// K = H(K0 | [00]) | H(K0 | [01]) | H(K0 | [02]) | ...
/// where H is SHA-1 (?), '|' indicated concatenation, and [XX] is a byte of the indicated value.
/// The first 20 bytes should equal the given `kh` (this demonstrates that the server knows `x`).
/// The next 20 bytes are the forward digest. The next 20 bytes are the backward digest. The next
/// 16 bytes are the forward encryption key. The next 16 bytes are the backward encryption key.
/// In total, 92 bytes of K need to be generated, which means 5 blocks in total (the last 8 bytes
/// are discarded).
fn tor_kdf(x: &[u8; 20], y: &[u8; 20], kh: &[u8; 20]) -> Result<CircuitKeys, ()> {
    let mut k0: Vec<u8> = Vec::with_capacity(40);
    k0.extend(x.iter());
    k0.extend(y.iter());

    let mut hash = Sha1::new();
    hash.update(&k0);
    hash.update(&[0]);
    let kh_calculated = hash.digest().bytes();
    if !constant_time_eq(&kh_calculated, kh) {
        return Err(());
    }

    let mut buffer: Vec<u8> = Vec::new();
    for i in 1..5 {
        let mut hash = Sha1::new();
        hash.update(&k0);
        hash.update(&[i]);
        buffer.extend(hash.digest().bytes().iter());
    }
    Ok(CircuitKeys::new(&buffer))
}

#[allow(non_snake_case)]
fn ntor_handshake(
    created2_cell: &types::Created2Cell,
    router_id: [u8; 20],
    server_B: [u8; 32],
    client_X: [u8; 32],
    mut client_x: [u8; 32],
) -> Result<CircuitKeys, ()> {
    println!("{:?}", created2_cell);
    // technically we should check the corresponding create2_cell type here
    let server_handshake =
        types::NtorServerHandshake::read_new(&mut &created2_cell.h_data[..]).unwrap();
    println!("{:?}", server_handshake);
    client_x[0] &= 248;
    client_x[31] &= 127;
    client_x[31] |= 64;
    let Y = montgomery::CompressedMontgomeryU(server_handshake.server_pk);
    let x = scalar::Scalar::from_bits(client_x);
    let exp_Y_x = curve25519_multiply(&Y, &x);
    let B = montgomery::CompressedMontgomeryU(server_B);
    let exp_B_x = curve25519_multiply(&B, &x);
    let mut secret_input: Vec<u8> = Vec::new();
    secret_input.extend(exp_Y_x.iter());
    secret_input.extend(exp_B_x.iter());
    secret_input.extend(router_id.iter());
    secret_input.extend(server_B.iter());
    secret_input.extend(client_X.iter());
    secret_input.extend(server_handshake.server_pk.iter());
    secret_input.extend("ntor-curve25519-sha256-1".as_bytes());
    let verify = ntor_hmac(&secret_input, b"ntor-curve25519-sha256-1:verify");
    let mut auth_input: Vec<u8> = Vec::new();
    auth_input.extend(verify.iter());
    auth_input.extend(router_id.iter());
    auth_input.extend(server_B.iter());
    auth_input.extend(server_handshake.server_pk.iter());
    auth_input.extend(client_X.iter());
    auth_input.extend("ntor-curve25519-sha256-1".as_bytes());
    auth_input.extend("Server".as_bytes());
    let calculated_auth = ntor_hmac(&auth_input, b"ntor-curve25519-sha256-1:mac");
    if constant_time_eq(&calculated_auth, &server_handshake.auth) {
        // so this is actually the prk in the kdf... (confusing documentation)
        let key_seed = ntor_hmac(&secret_input, b"ntor-curve25519-sha256-1:key_extract");
        Ok(compute_ntor_keys(&key_seed))
    } else {
        Err(())
    }
}

fn slice_to_16_byte_array(bytes: &[u8]) -> [u8; 16] {
    let mut fixed_size: [u8; 16] = [0; 16];
    fixed_size.copy_from_slice(&bytes);
    fixed_size
}

fn curve25519_multiply(x: &montgomery::CompressedMontgomeryU, s: &scalar::Scalar) -> [u8; 32] {
    x.decompress().mul(s).compress().to_bytes()
}

fn ntor_hmac(input: &[u8], context: &[u8]) -> Vec<u8> {
    // We seem to be using a public value for a private key here - am I misunderstanding?
    let mut mac = Hmac::<Sha256>::new(context).unwrap();
    mac.input(input);
    let mut bytes: Vec<u8> = Vec::new();
    bytes.extend(mac.result().code().as_slice().iter());
    bytes
}

// TODO: maybe rename this function (tor-spec.txt section 5.2.2. KDF-RFC5869)
fn compute_ntor_keys(key_seed: &[u8]) -> CircuitKeys {
    // We need to generate:
    // HASH_LEN bytes (forward digest)
    // HASH_LEN bytes (backward digest)
    // KEY_LEN bytes (forward key)
    // KEY_LEN bytes (backward key)
    // HASH_LEN bytes (KH in hidden service protocol (?))
    // where HASH_LEN is 20 bytes and KEY_LEN is 16 bytes.
    // We're using HMAC-SHA256, so each out block is 32 bytes.
    // We'll need 3 total blocks.
    // m_expand = b"ntor-curve25519-sha256-1:key_expand"
    // HMAC-SHA256(x, t): input is x, key is t
    // K(1) = HMAC-SHA256(m_expand | 0x01 as u8, key_seed)
    // K(2) = HMAC-SHA256(K(1) | m_expand | 0x02 as u8, key_seed)
    // K(2) = HMAC-SHA256(K(2) | m_expand | 0x03 as u8, key_seed)
    let mut m_expand_1: Vec<u8> = Vec::new();
    m_expand_1
        .write_all(b"ntor-curve25519-sha256-1:key_expand")
        .unwrap();
    m_expand_1.push(1);
    let k_1 = ntor_hmac(&m_expand_1, key_seed);
    let mut m_expand_2: Vec<u8> = Vec::new();
    m_expand_2.write_all(&k_1).unwrap();
    m_expand_2
        .write_all(b"ntor-curve25519-sha256-1:key_expand")
        .unwrap();
    m_expand_2.push(2);
    let k_2 = ntor_hmac(&m_expand_2, key_seed);
    let mut m_expand_3: Vec<u8> = Vec::new();
    m_expand_3.write_all(&k_2).unwrap();
    m_expand_3
        .write_all(b"ntor-curve25519-sha256-1:key_expand")
        .unwrap();
    m_expand_3.push(3);
    let k_3 = ntor_hmac(&m_expand_3, key_seed);
    let mut k: Vec<u8> = Vec::new();
    k.write_all(&k_1).unwrap();
    k.write_all(&k_2).unwrap();
    k.write_all(&k_3).unwrap();
    CircuitKeys::new(&k)
}
