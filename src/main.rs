extern crate base64;
extern crate byteorder;
extern crate constant_time_eq;
extern crate crypto;
extern crate curl;
extern crate curve25519_dalek;
extern crate ed25519_dalek;
extern crate getopts;
extern crate hex;
extern crate hmac;
extern crate num;
extern crate openssl;
extern crate rand;
extern crate sha1;
extern crate sha2;

mod certs;
mod dir;
mod keys;
mod tls;
mod types;
mod util;

use constant_time_eq::constant_time_eq;
use crypto::{aes, symmetriccipher};
use curve25519_dalek::montgomery;
use curve25519_dalek::scalar;
use hmac::{Hmac, Mac};
use num::PrimInt;
use rand::{OsRng, Rand, Rng};
use sha1::Sha1;
use sha2::Sha256;
use std::collections::HashSet;
use std::env;
use std::hash::Hash;
use std::io::prelude::*;
use std::ops::Mul;
use std::time::{SystemTime, UNIX_EPOCH};

struct Circuit {
    /// TLS connection with the first hop in the circuit.
    tls_connection: tls::TlsConnection,
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

/// Generates unique IDs.
struct IdTracker<T>
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
    fn new() -> IdTracker<T> {
        IdTracker {
            used_ids: HashSet::new(),
        }
    }

    /// Generates a new, nonzero, random id with the highest bit set that hasn't been used before or
    /// panics.
    fn get_new_id(&mut self) -> T {
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

struct AesContext {
    aes: Box<symmetriccipher::SynchronousStreamCipher + 'static>,
}

impl AesContext {
    fn new(key: &[u8]) -> AesContext {
        let iv: [u8; 16] = [0; 16];
        let key: [u8; 16] = slice_to_16_byte_array(key);
        AesContext {
            aes: aes::ctr(aes::KeySize::KeySize128, &key, &iv),
        }
    }
}

struct CircuitKeys {
    forward_digest: Sha1,
    backward_digest: Sha1,
    forward_key: AesContext,
    backward_key: AesContext,
    // KH in hidden service protocol? (doesn't appear to be implemented...?)
}

impl CircuitKeys {
    fn new(k: &[u8]) -> CircuitKeys {
        CircuitKeys {
            forward_digest: Sha1::from(&k[0..20]),
            backward_digest: Sha1::from(&k[20..40]),
            forward_key: AesContext::new(&k[40..56]),
            backward_key: AesContext::new(&k[56..72]),
        }
    }
}

fn usage(program: &str) {
    println!("Usage: {} <directory server>:<port>", program);
}

fn main() {
    let args: Vec<String> = env::args().collect();
    if args.len() != 2 {
        usage(&args[0]);
        return;
    }
    let peers = dir::get_tor_peers(&args[1]);
    println!("{:?}", peers);
    let mut circ_id_tracker: IdTracker<u32> = IdTracker::new();
    let circ_id = circ_id_tracker.get_new_id();
    let mut circuit = Circuit::new(&peers[0], circ_id);
    circuit.negotiate_versions();
    circuit.read_certs(&peers[0].get_ed25519_id_key());
    circuit.read_auth_challenge();
    circuit.send_certs_and_authenticate_cells();
    circuit.read_netinfo();
    circuit.create_fast();
    circuit.extend(&peers[1]);
    circuit.extend(&peers[3]);
    let stream_id = circuit.begin("example.com:80");
    let request = r#"GET / HTTP/1.1
Host: example.com
User-Agent: toroxide/0.1.0
Accept: text/html
Accept-Language: en-US,en;q=0.5
Connection: close

"#;
    circuit.send(stream_id, request.as_bytes());
    let response = circuit.recv_to_end();
    print!("{}", String::from_utf8(response).unwrap());

    let stream_id = circuit.begin("ip.seeip.org:80");
    let request = r#"GET / HTTP/1.1
Host: ip.seeip.org
User-Agent: toroxide/0.1.0
Connection: close

"#;
    circuit.send(stream_id, request.as_bytes());
    let response = circuit.recv_to_end();
    print!("{}", String::from_utf8(response).unwrap());
}

impl Circuit {
    fn new(peer: &dir::TorPeer, circ_id: u32) -> Circuit {
        println!("attempting to connect to {:?}", peer);
        Circuit {
            tls_connection: tls::TlsConnection::new(peer),
            circ_id: circ_id,
            responder_certs: None,
            circuit_keys: Vec::new(),
            used_stream_ids: IdTracker::new(),
            relay_early_count: 0,
        }
    }

    fn negotiate_versions(&mut self) {
        let versions = types::VersionsCell::new(vec![4]);
        let mut buf: Vec<u8> = Vec::new();
        versions.write_to(&mut buf).unwrap();
        match self.tls_connection.write(&buf) {
            Ok(len) => println!("sent {}", len),
            Err(e) => panic!(e),
        };
        let peer_versions = types::VersionsCell::read_new(&mut self.tls_connection).unwrap();
        let version = versions.negotiate(&peer_versions).unwrap();
        println!("negotiated version {}", version);
    }

    fn read_certs(&mut self, expected_ed25519_id_key: &[u8; 32]) {
        // Also assert versions negotiated?
        let cell = types::Cell::read_new(&mut self.tls_connection).unwrap();
        match cell.command {
            types::Command::Certs => match types::CertsCell::read_new(&mut &cell.payload[..]) {
                Ok(certs_cell) => {
                    let responder_certs = ResponderCerts::new(certs_cell.decode_certs()).unwrap();
                    if responder_certs
                        .validate(
                            expected_ed25519_id_key,
                            self.tls_connection.get_peer_cert_hash(),
                        )
                        .is_ok()
                    {
                        self.responder_certs = Some(responder_certs);
                    } // TODO: else indicate that we need to close the connection?
                }
                Err(msg) => println!("{}", msg),
            },
            _ => panic!("Expected CERTS, got {:?}", cell.command),
        };
    }

    fn read_auth_challenge(&mut self) {
        // Also assert everything beforehand...?
        let cell = types::Cell::read_new(&mut self.tls_connection).unwrap();
        let auth_challenge = match cell.command {
            types::Command::AuthChallenge => {
                match types::AuthChallengeCell::read_new(&mut &cell.payload[..]) {
                    Ok(auth_challenge_cell) => auth_challenge_cell,
                    Err(msg) => panic!("error decoding AUTH_CHALLENGE cell: {}", msg),
                }
            }
            _ => panic!("Expected AUTH_CHALLENGE, got {:?}", cell.command),
        };
        println!("{:?}", auth_challenge);
        if !auth_challenge.has_auth_type(types::AuthType::Ed25519Sha256Rfc5705) {
            println!("peer doesn't support the auth type we require");
            // TODO: error out here somehow
        }
        // It seems we don't actually have to do anything else here, since the only thing we would
        // need is actually in our connection's read digest.
    }

    fn send_certs_and_authenticate_cells(&mut self) {
        let initiator_certs = InitiatorCerts::new();
        let certs_cell = initiator_certs.to_certs_cell();
        let mut buf: Vec<u8> = Vec::new();
        certs_cell.write_to(&mut buf).unwrap();
        let cell = types::Cell::new(0, types::Command::Certs, buf);
        cell.write_to(&mut self.tls_connection).unwrap();

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
        let cid = initiator_certs
            .rsa_identity_cert
            .get_key()
            .get_sha256_hash();
        buf.extend(&cid);
        // SID
        let responder_certs = match self.responder_certs {
            Some(ref responder_certs) => responder_certs,
            None => panic!("invalid state - call read_certs first"),
        };
        let sid = responder_certs
            .rsa_identity_cert
            .get_key()
            .get_sha256_hash();
        buf.extend(sid);
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
        let scert = self.tls_connection.get_peer_cert_hash();
        buf.extend(scert);
        // TLSSECRETS
        // tor-spec.txt section 4.4.1 is wrong here - the context is the sha-256 hash of the
        // initiator's RSA identity cert (in other words, CID)
        let tlssecrets = self.tls_connection.get_tls_secrets(&cid);
        buf.extend(tlssecrets);
        // RAND
        let mut rand = [0; 24];
        let mut csprng: OsRng = OsRng::new().unwrap();
        csprng.fill_bytes(&mut rand);
        buf.extend(rand.iter());
        // SIG
        let ed25519_authenticate_key = initiator_certs.get_ed25519_authenticate_key();
        let signature = ed25519_authenticate_key.sign_data(&buf);
        buf.extend(signature.iter());

        let authenticate_cell =
            types::AuthenticateCell::new(types::AuthType::Ed25519Sha256Rfc5705, buf);
        let mut buf: Vec<u8> = Vec::new();
        authenticate_cell.write_to(&mut buf).unwrap();
        let cell = types::Cell::new(0, types::Command::Authenticate, buf);
        cell.write_to(&mut self.tls_connection).unwrap();
    }

    fn read_netinfo(&mut self) {
        let cell = types::Cell::read_new(&mut self.tls_connection).unwrap();
        println!("{:?}", cell);
        let netinfo = match cell.command {
            types::Command::Netinfo => match types::NetinfoCell::read_new(&mut &cell.payload[..]) {
                Ok(netinfo_cell) => netinfo_cell,
                Err(msg) => panic!("error decoding NETINFO cell: {}", msg),
            },
            _ => panic!("Expected NETINFO, got {:?}", cell.command),
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
        netinfo.write_to(&mut buf).unwrap();
        let cell = types::Cell::new(0, types::Command::Netinfo, buf);
        cell.write_to(&mut self.tls_connection).unwrap();
    }

    fn create_fast(&mut self) {
        let mut x = [0; 20];
        let mut csprng: OsRng = OsRng::new().unwrap();
        csprng.fill_bytes(&mut x);
        let create_fast_cell = types::CreateFastCell::new(x);
        let mut buf: Vec<u8> = Vec::new();
        create_fast_cell.write_to(&mut buf).unwrap();
        let cell = types::Cell::new(self.circ_id, types::Command::CreateFast, buf);

        cell.write_to(&mut self.tls_connection).unwrap();
        let cell = types::Cell::read_new(&mut self.tls_connection).unwrap();
        println!("{:?}", cell);
        let circuit_keys = match cell.command {
            types::Command::CreatedFast => {
                let created_fast =
                    types::CreatedFastCell::read_new(&mut &cell.payload[..]).unwrap();
                println!("{:?}", created_fast);
                tor_kdf(&x, created_fast.get_y(), created_fast.get_kh())
            }
            types::Command::Destroy => panic!("got DESTROY cell"),
            _ => panic!("Expected CREATED_FAST or DESTROY, got {:?}", cell.command),
        };
        self.circuit_keys.push(circuit_keys);
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

    fn decrypt_cell_bytes(&mut self, in_bytes: &[u8]) -> types::RelayCell {
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
        types::RelayCell::read_new(&mut &bytes[..]).unwrap()
    }

    fn send_cell_bytes(&mut self, bytes: Vec<u8>) {
        let command = if self.relay_early_count < 8 {
            self.relay_early_count += 1;
            types::Command::RelayEarly
        } else {
            types::Command::Relay
        };
        let cell = types::Cell::new(self.circ_id, command, bytes);
        cell.write_to(&mut self.tls_connection).unwrap();
    }

    fn read_cell(&mut self) -> types::Cell {
        types::Cell::read_new(&mut self.tls_connection).unwrap()
    }

    fn extend(&mut self, node: &dir::TorPeer) {
        println!("attempting to extend to {:?}", node);
        let client_keypair = keys::Curve25519Keypair::new();
        let ntor_client_handshake = types::NtorClientHandshake::new(node, &client_keypair);
        let mut ntor_client_handshake_bytes = Vec::new();
        ntor_client_handshake
            .write_to(&mut ntor_client_handshake_bytes)
            .unwrap();
        let extend2 = types::Extend2Cell::new(
            node,
            types::ClientHandshakeType::Ntor,
            ntor_client_handshake_bytes,
        );
        let mut extend2_bytes = Vec::new();
        extend2.write_to(&mut extend2_bytes).unwrap();
        let bytes = self.encrypt_cell_bytes(types::RelayCommand::Extend2, &extend2_bytes, 0);
        self.send_cell_bytes(bytes);
        let cell = self.read_cell();
        println!("{:?}", cell);
        let relay_cell = match cell.command {
            types::Command::Relay => self.decrypt_cell_bytes(&cell.payload),
            _ => panic!("expected RELAY, got {:?}", cell.command),
        };
        println!("{}", relay_cell);
        let extended2 = match relay_cell.relay_command {
            types::RelayCommand::Extended2 =>
                // The contents of an EXTENDED2 relay cell is the same as a CREATED2 cell
                types::Created2Cell::read_new(&mut &relay_cell.data[..]).unwrap(),
            _ => panic!("expected EXTENDED2, got {:?}", relay_cell.relay_command),
        };
        if let Ok(circuit_keys) = ntor_handshake(
            &extended2,
            node.get_node_id(),
            node.get_ntor_key(),
            client_keypair.get_public_key_bytes(),
            client_keypair.get_secret_key_bytes(),
        ) {
            self.circuit_keys.push(circuit_keys);
        }
    }

    // returns what stream id we picked
    fn begin(&mut self, addrport: &str) -> u16 {
        let begin = types::BeginCell::new(addrport);
        println!("{:?}", begin);
        // Hmmm maybe I wouldn't have to do all this "make a cell then make a vec then write_to it"
        // if I defined a trait...?
        let mut begin_bytes: Vec<u8> = Vec::new();
        begin.write_to(&mut begin_bytes).unwrap();
        let stream_id = self.used_stream_ids.get_new_id();
        let bytes = self.encrypt_cell_bytes(types::RelayCommand::Begin, &begin_bytes, stream_id);
        self.send_cell_bytes(bytes);
        let cell = self.read_cell();
        println!("{:?}", cell);
        let relay_cell = match cell.command {
            types::Command::Relay => self.decrypt_cell_bytes(&cell.payload),
            _ => panic!("expected RELAY, got {:?}", cell.command),
        };
        println!("{}", relay_cell);
        // TODO: verify that this is a RELAY_CONNECTED cell...
        stream_id
    }

    fn send(&mut self, stream_id: u16, data: &[u8]) {
        let bytes = self.encrypt_cell_bytes(types::RelayCommand::Data, data, stream_id);
        self.send_cell_bytes(bytes);
    }

    fn recv_to_end(&mut self) -> Vec<u8> {
        let mut buf = Vec::new();
        loop {
            let cell = self.read_cell();
            println!("{:?}", cell);
            let relay_cell = match cell.command {
                types::Command::Relay => self.decrypt_cell_bytes(&cell.payload),
                _ => panic!("expected RELAY, got {:?}", cell.command),
            };
            println!("{}", relay_cell);
            match relay_cell.relay_command {
                types::RelayCommand::Data => buf.extend(relay_cell.data),
                types::RelayCommand::End => break,
                _ => panic!("expected DATA or END, got {:?}", relay_cell.relay_command),
            }
        }
        buf
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
        peer_cert_hash: Vec<u8>,
    ) -> Result<(), &'static str> {
        // Need to check:
        // rsa_identity_cert is self-signed
        if !self.rsa_identity_cert.is_self_signed() {
            return Err("RSA identity cert is not self-signed");
        }
        // rsa identity key (in rsa_identity_cert) signed ed25519_identity_cert, is 1024 bits
        let identity_key = self.rsa_identity_cert.get_key();
        if !identity_key.check_ed25519_identity_signature(&self.ed25519_identity_cert) {
            return Err("RSA identity cert did not sign Ed25519 identity cert");
        }
        if identity_key.get_size_in_bits() != 1024 {
            return Err("RSA identity key wrong size");
        }
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
            .check_x509_certificate_hash(&peer_cert_hash)
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
    fn new() -> InitiatorCerts {
        // Apparently we don't need to keep this around for now.
        let rsa_identity_key = keys::RsaPrivateKey::new(1024).unwrap();
        let rsa_identity_cert = rsa_identity_key.generate_self_signed_cert().unwrap();
        // Apparently we don't need to keep this around for now.
        let ed25519_identity_key = keys::Ed25519Key::new();
        let ed25519_identity_cert = rsa_identity_key
            .sign_ed25519_key(&ed25519_identity_key)
            .unwrap();
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
fn tor_kdf(x: &[u8; 20], y: &[u8; 20], kh: &[u8; 20]) -> CircuitKeys {
    let mut k0: Vec<u8> = Vec::with_capacity(40);
    k0.extend(x.iter());
    k0.extend(y.iter());

    let mut hash = Sha1::new();
    hash.update(&k0);
    hash.update(&[0]);
    let kh_calculated = hash.digest().bytes();
    if !constant_time_eq(&kh_calculated, kh) {
        println!("didn't get the same kh?");
    }

    let mut buffer: Vec<u8> = Vec::new();
    for i in 1..5 {
        let mut hash = Sha1::new();
        hash.update(&k0);
        hash.update(&[i]);
        buffer.extend(hash.digest().bytes().iter());
    }
    CircuitKeys::new(&buffer)
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
