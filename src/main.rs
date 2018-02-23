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
extern crate openssl;
extern crate rand;
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
use getopts::Options;
use hmac::{Hmac, Mac};
use rand::{OsRng, Rng};
use sha2::Sha256;
use std::collections::HashMap;
use std::env;
use std::io::prelude::*;
use std::io;
use std::ops::Mul;
use std::time::{SystemTime, UNIX_EPOCH};

struct TorClient {
    /// Maybe a TLS connection with a peer.
    tls_connection: Option<tls::TlsConnection>,
    /// Map of circuit id to NtorContext
    ntor_contexts: HashMap<u32, NtorContext>,
    /// Created NtorContext that we don't know what circuit id it's for yet
    pending_ntor_context: Option<NtorContext>,
    /// Map of circuit id to NtorKeys
    ntor_keys: HashMap<u32, NtorKeys>,
    /// Maybe the certs parsed and validated from a peer's CERTS cell
    responder_certs: Option<ResponderCerts>,
}

#[allow(non_snake_case)]
struct NtorContext {
    /// The SHA-1 hash of the router's RSA key
    router_id: [u8; 20],
    /// The client's ntor onion key "B" (public)
    client_B: [u8; 32],
    /// The ntor handshake public key "X"
    client_X: [u8; 32],
    /// The ntor handshake private key "x"
    client_x: [u8; 32],
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

struct NtorKeys {
    forward_digest: [u8; 20],
    backward_digest: [u8; 20],
    forward_key: AesContext,
    backward_key: AesContext,
    // KH in hidden service protocol? (doesn't appear to be implemented...?)
}

impl NtorKeys {
    fn new(k: &[u8]) -> NtorKeys {
        NtorKeys {
            forward_digest: slice_to_20_byte_array(&k[0..20]),
            backward_digest: slice_to_20_byte_array(&k[20..40]),
            forward_key: AesContext::new(&k[40..56]),
            backward_key: AesContext::new(&k[56..72]),
        }
    }
}

fn print_usage(program: &str, opts: Options) {
    let brief = format!("Usage: {} [options]", program);
    print!("{}", opts.usage(&brief));
}

fn main() {
    let args: Vec<String> = env::args().collect();
    let program = &args[0];
    let mut opts = Options::new();
    opts.optflag("d", "dump", "dump debug output from another Tor client");
    opts.optflag("h", "help", "display this help message");
    let matches = match opts.parse(&args[1..]) {
        Ok(m) => m,
        Err(e) => panic!(e),
    };
    if matches.opt_present("h") {
        print_usage(program, opts);
        return;
    }
    if matches.opt_present("d") {
        debug_dump_from_stdin();
        return;
    }

    let peer = &dir::get_tor_peers()[0];
    println!("{:?}", peer);
    let mut tor_client = TorClient::new();
    tor_client.connect_to(&peer);
    tor_client.negotiate_versions();
    tor_client.read_certs();
    tor_client.read_auth_challenge();
    tor_client.send_certs_and_authenticate_cells();
    tor_client.read_netinfo();
    tor_client.create_fast(1);
}

fn debug_dump_from_stdin() {
    let mut tor_client = TorClient::new();
    let stdin = io::stdin();
    for line in stdin.lock().lines() {
        let line = line.unwrap();
        if line.len() == 0 {
            break;
        }
        tor_client.handle_event(&line);
    }
}

#[derive(Debug)]
enum Direction {
    Incoming,
    Outgoing,
}

impl TorClient {
    fn new() -> TorClient {
        TorClient {
            tls_connection: None,
            ntor_contexts: HashMap::new(),
            pending_ntor_context: None,
            ntor_keys: HashMap::new(),
            responder_certs: None,
        }
    }

    fn connect_to(&mut self, peer: &dir::TorPeer) {
        self.tls_connection = Some(tls::TlsConnection::new(peer));
    }

    fn negotiate_versions(&mut self) {
        let versions = types::VersionsCell::new(vec![4]);
        let data = versions.to_bytes();
        let mut connection = match self.tls_connection {
            Some(ref mut connection) => connection,
            None => panic!("invalid state - call connect_to first"),
        };
        match connection.write(&data) {
            Ok(len) => println!("sent {}", len),
            Err(e) => panic!(e),
        };
        let peer_versions = types::VersionsCell::read_new(&mut connection).unwrap();
        let version = versions.negotiate(&peer_versions).unwrap();
        println!("negotiated version {}", version);
    }

    fn read_certs(&mut self) {
        let mut connection = match self.tls_connection {
            Some(ref mut connection) => connection,
            None => panic!("invalid state - call connect_to first"),
        };
        // Also assert versions negotiated?
        let cell = types::Cell::read_new(&mut connection).unwrap();
        match cell.command {
            types::Command::Certs => match types::CertsCell::read_new(&mut &cell.payload[..]) {
                Ok(certs_cell) => {
                    let responder_certs = ResponderCerts::new(certs_cell.decode_certs()).unwrap();
                    if responder_certs
                        .validate(connection.get_peer_cert_hash())
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
        let mut connection = match self.tls_connection {
            Some(ref mut connection) => connection,
            None => panic!("invalid state - call connect_to first"),
        };
        // Also assert everything beforehand...?
        let cell = types::Cell::read_new(&mut connection).unwrap();
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
        let mut connection = match self.tls_connection {
            Some(ref mut connection) => connection,
            None => panic!("invalid state - call connect_to first"),
        };
        let initiator_certs = InitiatorCerts::new();
        let certs_cell = initiator_certs.to_certs_cell();
        let mut buf: Vec<u8> = Vec::new();
        certs_cell.write_to(&mut buf);
        let cell = types::Cell::new(0, types::Command::Certs, buf);
        cell.write_to(&mut connection);

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
        buf.extend(cid);
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
        let slog = connection.get_read_digest();
        buf.extend(slog);
        // CLOG
        let clog = connection.get_write_digest();
        buf.extend(clog);
        // SCERT
        let scert = connection.get_peer_cert_hash();
        buf.extend(scert);
        // TLSSECRETS
        let ed25519_identity_key = initiator_certs.get_ed25519_identity_key();
        let tlssecrets = connection.get_tls_secrets(&ed25519_identity_key.get_public_key_bytes());
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
        authenticate_cell.write_to(&mut buf);
        let cell = types::Cell::new(0, types::Command::Authenticate, buf);
        cell.write_to(&mut connection);
    }

    fn read_netinfo(&mut self) {
        let mut connection = match self.tls_connection {
            Some(ref mut connection) => connection,
            None => panic!("invalid state - call connect_to first"),
        };
        let cell = types::Cell::read_new(&mut connection).unwrap();
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
        netinfo.write_to(&mut buf);
        let cell = types::Cell::new(0, types::Command::Netinfo, buf);
        cell.write_to(&mut connection);
    }

    fn create_fast(&mut self, circ_id: u32) {
        let mut x = [0; 20];
        let mut csprng: OsRng = OsRng::new().unwrap();
        csprng.fill_bytes(&mut x);
        let create_fast_cell = types::CreateFastCell::new(x);
        let mut buf: Vec<u8> = Vec::new();
        create_fast_cell.write_to(&mut buf);
        let cell = types::Cell::new(circ_id, types::Command::CreateFast, buf);

        {
            let mut connection = match self.tls_connection {
                Some(ref mut connection) => connection,
                None => panic!("invalid state - call connect_to first"),
            };
            cell.write_to(&mut connection);
        }
        self.read_cell();
    }

    fn read_cell(&mut self) {
        let mut connection = match self.tls_connection {
            Some(ref mut connection) => connection,
            None => panic!("invalid state - call connect_to first"),
        };
        let cell = types::Cell::read_new(&mut connection).unwrap();
        println!("{:?}", cell);
    }

    fn handle_event(&mut self, event: &String) {
        let parts: Vec<_> = event.split(":").collect();
        match parts[0] {
            "keygen" => self.decode_keygen(&parts[1..]),
            "read" => self.decode_cell_hex(Direction::Incoming, parts[1]),
            "write" => self.decode_cell_hex(Direction::Outgoing, parts[1]),
            _ => println!("unknown operation {}", parts[0]),
        }
    }

    fn decode_keygen(&mut self, keys_hex: &[&str]) {
        self.pending_ntor_context = Some(NtorContext {
            router_id: slice_to_20_byte_array(&hex::decode(keys_hex[0]).unwrap()),
            client_B: util::slice_to_32_byte_array(&hex::decode(keys_hex[1]).unwrap()),
            client_X: util::slice_to_32_byte_array(&hex::decode(keys_hex[2]).unwrap()),
            client_x: util::slice_to_32_byte_array(&hex::decode(keys_hex[3]).unwrap()),
        });
    }

    fn decode_cell_hex(&mut self, direction: Direction, cell_hex: &str) {
        let mut bytes = &hex::decode(cell_hex).unwrap()[..];
        self.decode_input(direction, &mut bytes);
    }

    fn decode_input<R: Read>(&mut self, direction: Direction, input: &mut R) {
        let tor_cell = types::Cell::read_new(input).unwrap();
        println!("{:?}", tor_cell);
        match tor_cell.command {
            types::Command::Relay => {
                self.handle_encrypted_relay_cell(tor_cell.circ_id, direction, &tor_cell.payload);
            }
            types::Command::Netinfo => {
                match types::NetinfoCell::read_new(&mut &tor_cell.payload[..]) {
                    Ok(netinfo_cell) => {
                        println!("{:?}", netinfo_cell);
                    }
                    Err(msg) => println!("{}", msg),
                }
            }
            types::Command::Create2 => {
                match types::Create2Cell::from_slice(&tor_cell.payload) {
                    Ok(create2_cell) => {
                        println!("{:?}", create2_cell);
                        // technically we should check create2_cell.h_type here
                        let client_handshake =
                            types::NtorClientHandshake::from_slice(create2_cell.h_data).unwrap();
                        println!("{:?}", client_handshake);
                        if let Some(pending_ntor_context) = self.pending_ntor_context.take() {
                            self.ntor_contexts
                                .insert(tor_cell.circ_id, pending_ntor_context);
                        }
                    }
                    Err(msg) => println!("{}", msg),
                }
            }
            types::Command::Created2 => match types::Created2Cell::from_slice(&tor_cell.payload) {
                Ok(created2_cell) => self.do_ntor_handshake(tor_cell.circ_id, &created2_cell),
                Err(msg) => println!("{}", msg),
            },
            types::Command::Certs => match types::CertsCell::read_new(&mut &tor_cell.payload[..]) {
                Ok(certs_cell) => println!("{:?}", certs_cell),
                Err(msg) => println!("{}", msg),
            },
            types::Command::AuthChallenge => {
                match types::AuthChallengeCell::read_new(&mut &tor_cell.payload[..]) {
                    Ok(auth_challenge_cell) => println!("{:?}", auth_challenge_cell),
                    Err(msg) => println!("{}", msg),
                }
            }
            _ => {}
        }
    }

    #[allow(non_snake_case)]
    fn do_ntor_handshake(&mut self, circ_id: u32, created2_cell: &types::Created2Cell) {
        if let Some(ref ntor_context) = self.ntor_contexts.get(&circ_id) {
            println!("{:?}", created2_cell);
            // technically we should check the corresponding create2_cell type here
            let server_handshake =
                types::NtorServerHandshake::from_slice(created2_cell.h_data).unwrap();
            println!("{:?}", server_handshake);
            let Y = montgomery::CompressedMontgomeryU(server_handshake.server_pk);
            let x = scalar::Scalar::from_bits(ntor_context.client_x);
            let exp_Y_x = curve25519_multiply(&Y, &x);
            let B = montgomery::CompressedMontgomeryU(ntor_context.client_B);
            let exp_B_x = curve25519_multiply(&B, &x);
            let mut secret_input: Vec<u8> = Vec::new();
            secret_input.extend(exp_Y_x.iter());
            secret_input.extend(exp_B_x.iter());
            secret_input.extend(ntor_context.router_id.iter());
            secret_input.extend(ntor_context.client_B.iter());
            secret_input.extend(ntor_context.client_X.iter());
            secret_input.extend(server_handshake.server_pk.iter());
            secret_input.extend("ntor-curve25519-sha256-1".as_bytes());
            let verify = ntor_hmac(&secret_input, b"ntor-curve25519-sha256-1:verify");
            let mut auth_input: Vec<u8> = Vec::new();
            auth_input.extend(verify.iter());
            auth_input.extend(ntor_context.router_id.iter());
            auth_input.extend(ntor_context.client_B.iter());
            auth_input.extend(server_handshake.server_pk.iter());
            auth_input.extend(ntor_context.client_X.iter());
            auth_input.extend("ntor-curve25519-sha256-1".as_bytes());
            auth_input.extend("Server".as_bytes());
            let calculated_auth = ntor_hmac(&auth_input, b"ntor-curve25519-sha256-1:mac");
            if constant_time_eq(&calculated_auth, &server_handshake.auth) {
                // so this is actually the prk in the kdf... (confusing documentation)
                let key_seed = ntor_hmac(&secret_input, b"ntor-curve25519-sha256-1:key_extract");
                let ntor_keys = compute_ntor_keys(&key_seed);
                self.ntor_keys.insert(circ_id, ntor_keys);
            }
        }
    }

    fn handle_encrypted_relay_cell(
        &mut self,
        circ_id: u32,
        direction: Direction,
        encrypted_relay_cell: &[u8],
    ) {
        let bytes = if let Some(ref mut ntor_keys) = self.ntor_keys.get_mut(&circ_id) {
            let mut decrypted_relay_cell: Vec<u8> = Vec::with_capacity(encrypted_relay_cell.len());
            decrypted_relay_cell.resize(encrypted_relay_cell.len(), 0);
            // So we have to have some way to roll back things that weren't actually for us (or
            // attacks that would attempt to modify our counter...)
            // It seems the canonical implementation just kills the connection if this ever happens.
            let aes_context = match direction {
                Direction::Incoming => &mut ntor_keys.backward_key,
                Direction::Outgoing => &mut ntor_keys.forward_key,
            };
            aes_context
                .aes
                .process(encrypted_relay_cell, &mut decrypted_relay_cell);
            decrypted_relay_cell
        } else {
            return;
        };
        match types::RelayCell::from_slice(&bytes) {
            Ok(relay_cell) => self.handle_relay_cell(circ_id, direction, relay_cell),
            Err(err) => match err {
                types::RelayCellError::Unrecognized => {
                    println!("that cell wasn't for us? (need to decrypt again?)")
                }
                types::RelayCellError::InsufficientLength => {
                    println!("didn't even have PAYLOAD_LEN bytes? (shouldn't happen)")
                }
                types::RelayCellError::InsufficientPayloadLength => {
                    println!("cell not long internally (error?)")
                }
            },
        };
    }

    fn handle_relay_cell(&self, circ_id: u32, direction: Direction, relay_cell: types::RelayCell) {
        println!(
            "handle_relay_cell({}, {:?}, {}",
            circ_id, direction, relay_cell
        );
    }
}

// Ok there has to be a way to do this more generically.
fn slice_to_16_byte_array(bytes: &[u8]) -> [u8; 16] {
    let mut fixed_size: [u8; 16] = [0; 16];
    fixed_size.copy_from_slice(&bytes);
    fixed_size
}

fn slice_to_20_byte_array(bytes: &[u8]) -> [u8; 20] {
    let mut fixed_size: [u8; 20] = [0; 20];
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

fn compute_ntor_keys(key_seed: &[u8]) -> NtorKeys {
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
    NtorKeys::new(&k)
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

    fn validate(&self, peer_cert_hash: Vec<u8>) -> Result<(), &'static str> {
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

/// The certificates and keys needed by an initiator (`TorClient`) to perform a link authentication
/// with a responder.
struct InitiatorCerts {
    rsa_identity_key: keys::RsaPrivateKey,
    rsa_identity_cert: certs::X509Cert,
    ed25519_identity_key: keys::Ed25519Key,
    ed25519_identity_cert: certs::Ed25519Identity,
    ed25519_signing_key: keys::Ed25519Key,
    ed25519_signing_cert: certs::Ed25519Cert,
    ed25519_authenticate_key: keys::Ed25519Key,
    ed25519_authenticate_cert: certs::Ed25519Cert,
}

impl InitiatorCerts {
    fn new() -> InitiatorCerts {
        let rsa_identity_key = keys::RsaPrivateKey::new(1024).unwrap();
        let rsa_identity_cert = rsa_identity_key.generate_self_signed_cert().unwrap();
        let ed25519_identity_key = keys::Ed25519Key::new();
        let ed25519_identity_cert = rsa_identity_key
            .sign_ed25519_key(&ed25519_identity_key)
            .unwrap();
        let ed25519_signing_key = keys::Ed25519Key::new();
        let ed25519_signing_cert = ed25519_identity_key
            .sign_ed25519_key(&ed25519_signing_key, certs::Ed25519CertType::SigningKey);
        let ed25519_authenticate_key = keys::Ed25519Key::new();
        let ed25519_authenticate_cert = ed25519_signing_key.sign_ed25519_key(
            &ed25519_authenticate_key,
            certs::Ed25519CertType::AuthenticationKey,
        );
        InitiatorCerts {
            rsa_identity_key: rsa_identity_key,
            rsa_identity_cert: rsa_identity_cert,
            ed25519_identity_key: ed25519_identity_key,
            ed25519_identity_cert: ed25519_identity_cert,
            ed25519_signing_key: ed25519_signing_key,
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

    fn get_ed25519_identity_key(&self) -> &keys::Ed25519Key {
        &self.ed25519_identity_key
    }

    fn get_ed25519_authenticate_key(&self) -> &keys::Ed25519Key {
        &self.ed25519_authenticate_key
    }
}
