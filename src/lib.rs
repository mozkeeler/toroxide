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
use std::collections::{HashMap, HashSet};
use std::hash::Hash;
use std::io::{Cursor, Error, ErrorKind, Seek, SeekFrom};
use std::io::prelude::*;
use std::ops::Mul;
use std::time::{SystemTime, UNIX_EPOCH};

pub trait TlsImpl {
    fn get_peer_cert_hash(&self) -> Result<[u8; 32], Error>;
    fn get_tls_secrets(&self, label: &str, context: &[u8]) -> Result<Vec<u8>, Error>;
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

#[derive(Debug, PartialEq)]
enum CircuitState {
    NegotiateWriting,
    NegotiateReading,
    CertsReading,
    AuthChallengeReading,
    CertsWriting,
    AuthenticateWriting,
    NetinfoReading,
    NetinfoWriting,
    CreateFastWriting,
    CreateFastReading,
    Ready,
    Extend2Writing,
    Extended2Reading,
    Error,
}

#[derive(Debug)]
pub enum Async<T> {
    Ready(T),
    NotReady,
}

pub struct Circuit<T, V>
where
    T: TlsImpl + Read + Write,
    V: RsaVerifierImpl,
{
    /// Current state of the curcuit.
    state: CircuitState,
    /// TLS connection with the first hop in the circuit.
    tls_connection: TlsHashWrapper<T>,
    /// Implementation of RSA signature verification.
    rsa_verifier: V,
    /// Initiator keys for this circuit (TODO: should these be re-used across circuits?)
    initiator_certs: InitiatorCerts,
    /// The circuit ID for this connection.
    circ_id: u32,
    /// The expected Ed25519 identity key from the peer.
    expected_ed25519_id_key: [u8; 32],
    /// Maybe the certs parsed and validated from a peer's CERTS cell
    responder_certs: Option<ResponderCerts>,
    /// Maybe the peer's OR address
    other_or_address: Option<types::OrAddress>,
    /// 20 byte random value for Tor KDF
    x: [u8; 20],
    /// Maybe Ntor client keypair for an in-progress extend.
    ntor_keypair: Option<keys::Curve25519Keypair>,
    /// Sequence of CircuitKeys for each hop in this circuit.
    circuit_keys: Vec<CircuitKeys>,
    /// Stream IDs that have been used
    used_stream_ids: IdTracker<u16>,
    /// How many times we've used RELAY_EARLY.
    relay_early_count: usize,
    /// Internal read buffer for when some data is available from the peer but not enough to
    /// complete the operation we're doing.
    buffer: Cursor<Vec<u8>>,
    write_buffer: Vec<u8>,
    /// Map of ids to currently-open `Stream`s.
    streams: HashMap<u16, Stream>,
}

impl<T, V> Circuit<T, V>
where
    T: TlsImpl + Read + Write,
    V: RsaVerifierImpl,
{
    pub fn new(
        tls_impl: T,
        rsa_verifier: V,
        rsa_signer: &RsaSignerImpl,
        circ_id: u32,
        expected_ed25519_id_key: [u8; 32],
    ) -> Circuit<T, V> {
        Circuit {
            state: CircuitState::NegotiateWriting,
            tls_connection: TlsHashWrapper::new(tls_impl),
            rsa_verifier,
            initiator_certs: InitiatorCerts::new(rsa_signer),
            circ_id,
            expected_ed25519_id_key,
            responder_certs: None,
            other_or_address: None,
            // This gets filled in in `do_create_fast_write`.
            x: [0; 20],
            ntor_keypair: None,
            circuit_keys: Vec::new(),
            used_stream_ids: IdTracker::new(),
            relay_early_count: 0,
            buffer: Cursor::new(Vec::new()),
            write_buffer: Vec::new(),
            streams: HashMap::new(),
        }
    }

    pub fn poll(&mut self) -> Result<Async<()>, Error> {
        let result = match self.state {
            CircuitState::NegotiateWriting => self.do_negotiate_write(),
            CircuitState::NegotiateReading => self.do_negotiate_read(),
            CircuitState::CertsReading => self.do_certs_read(),
            CircuitState::AuthChallengeReading => self.do_auth_challenge_read(),
            CircuitState::CertsWriting => self.do_certs_write(),
            CircuitState::AuthenticateWriting => self.do_authenticate_write(),
            CircuitState::NetinfoReading => self.do_netinfo_read(),
            CircuitState::NetinfoWriting => self.do_netinfo_write(),
            CircuitState::CreateFastWriting => self.do_create_fast_write(),
            CircuitState::CreateFastReading => self.do_create_fast_read(),
            CircuitState::Ready => return Ok(Async::Ready(())),
            _ => Err(Error::new(ErrorKind::Other, "library error: invalid state")),
        };
        if result.is_err() {
            self.state = CircuitState::Error;
            return result;
        }
        Ok(Async::NotReady)
    }

    /// Attempt to read as much as possible from `self.tls_connection`, appending to the local
    /// buffer. After doing so, if there is no data available in the read buffer, returns
    /// `Ok(Async::NotReady)`.
    fn read_to_buffer(&mut self) -> Result<Async<()>, Error> {
        // Most packets we're reading will be ~514 bytes, but the CERTS cell can be much larger, so
        // we read as much as we can in 514-byte chunks.
        loop {
            let mut tmp = Vec::with_capacity(514);
            tmp.resize(514, 0);
            let bytes_read = match self.tls_connection.read(&mut tmp) {
                Ok(n) => {
                    if n == 0 {
                        return Err(Error::new(
                            ErrorKind::UnexpectedEof,
                            "peer closed connection?",
                        ));
                    }
                    n
                }
                Err(ref e) if e.kind() == ErrorKind::WouldBlock => break,
                Err(e) => {
                    return Err(e);
                }
            };
            // We read and write from/to different parts of the `Cursor`, so we have to save the
            // read position here.
            let read_position = self.buffer.position();
            self.buffer.seek(SeekFrom::End(0))?;
            self.buffer.write_all(&tmp[..bytes_read])?;
            self.buffer.set_position(read_position);
        }
        // Find out if there's any data past the read position.
        let read_position = self.buffer.position();
        self.buffer.seek(SeekFrom::End(0))?;
        let has_data = read_position != self.buffer.position();
        self.buffer.set_position(read_position);
        if has_data {
            Ok(Async::Ready(()))
        } else {
            Ok(Async::NotReady)
        }
    }

    fn do_negotiate_write(&mut self) -> Result<Async<()>, Error> {
        let versions = types::VersionsCell::new(vec![4]);
        let mut buf: Vec<u8> = Vec::new();
        if let Err(e) = versions.write_to(&mut buf) {
            return Err(e);
        }
        match self.tls_connection.write_all(&buf) {
            Ok(_) => {
                self.state = CircuitState::NegotiateReading;
                Ok(Async::Ready(()))
            }
            Err(ref e) if e.kind() == ErrorKind::WouldBlock => Ok(Async::NotReady),
            Err(e) => Err(e),
        }
    }

    fn do_negotiate_read(&mut self) -> Result<Async<()>, Error> {
        match self.read_to_buffer()? {
            Async::Ready(()) => {}
            Async::NotReady => return Ok(Async::NotReady),
        }
        // Save the read position in case we don't have enough data to decode the cell we want to
        // read (in which case we'll re-set the position to the saved value and return
        // `Ok(Async::NotReady)`).
        let saved_position = self.buffer.position();
        let peer_versions = match types::VersionsCell::read_new(&mut self.buffer) {
            Ok(peer_versions) => peer_versions,
            // TODO: differentiate between EOF (i.e. need to read more) and error decoding due to
            // bad data.
            Err(_) => {
                self.buffer.set_position(saved_position);
                return Ok(Async::NotReady);
            }
        };
        // TODO: a not-great thing is we have to re-create the `versions` we created in
        // `do_negotiate_write` - maybe make it essentially a constant?
        let versions = types::VersionsCell::new(vec![4]);
        let version = match versions.negotiate(&peer_versions) {
            Ok(version) => version,
            Err(_) => {
                return Err(Error::new(
                    ErrorKind::InvalidInput,
                    "couldn't negotiate version",
                ))
            }
        };
        println!("negotiated version {}", version);
        self.state = CircuitState::CertsReading;
        Ok(Async::Ready(()))
    }

    fn do_certs_read(&mut self) -> Result<Async<()>, Error> {
        match self.read_to_buffer()? {
            Async::Ready(()) => {}
            Async::NotReady => return Ok(Async::NotReady),
        }
        let saved_position = self.buffer.position();
        let cell = match types::Cell::read_new(&mut self.buffer) {
            Ok(cell) => cell,
            Err(_) => {
                self.buffer.set_position(saved_position);
                return Ok(Async::NotReady);
            }
        };
        if cell.command != types::Command::Certs {
            return Err(Error::new(ErrorKind::InvalidInput, "unexpected cell type"));
        }
        let certs_cell = match types::CertsCell::read_new(&mut &cell.payload[..]) {
            Ok(certs_cell) => certs_cell,
            Err(_) => {
                return Err(Error::new(
                    ErrorKind::InvalidInput,
                    "error decoding CERTS cell",
                ))
            }
        };
        let responder_certs = match ResponderCerts::new(certs_cell.decode_certs()) {
            Ok(responder_certs) => responder_certs,
            Err(_) => {
                return Err(Error::new(
                    ErrorKind::InvalidInput,
                    "error decoding certs in CERTS cell",
                ))
            }
        };
        let peer_cert_hash = match self.tls_connection.get_peer_cert_hash() {
            Ok(peer_cert_hash) => peer_cert_hash,
            Err(e) => return Err(e),
        };
        // TODO map_err I think
        if let Err(e) = responder_certs.validate(
            &self.expected_ed25519_id_key,
            &peer_cert_hash,
            &self.rsa_verifier,
        ) {
            return Err(Error::new(ErrorKind::Other, e));
        }
        self.responder_certs = Some(responder_certs);
        self.state = CircuitState::AuthChallengeReading;
        Ok(Async::Ready(()))
    }

    fn do_auth_challenge_read(&mut self) -> Result<Async<()>, Error> {
        match self.read_to_buffer()? {
            Async::Ready(()) => {}
            Async::NotReady => return Ok(Async::NotReady),
        }
        let saved_position = self.buffer.position();
        let cell = match types::Cell::read_new(&mut self.buffer) {
            Ok(cell) => cell,
            Err(_) => {
                self.buffer.set_position(saved_position);
                return Ok(Async::NotReady);
            }
        };
        if cell.command != types::Command::AuthChallenge {
            return Err(Error::new(ErrorKind::InvalidInput, "unexpected cell type"));
        }
        let auth_challenge = match types::AuthChallengeCell::read_new(&mut &cell.payload[..]) {
            Ok(auth_challenge_cell) => auth_challenge_cell,
            Err(_) => {
                return Err(Error::new(
                    ErrorKind::InvalidInput,
                    "error decoding AUTH CHALLENGE cell",
                ))
            }
        };
        println!("{:?}", auth_challenge);
        if !auth_challenge.has_auth_type(types::AuthType::Ed25519Sha256Rfc5705) {
            return Err(Error::new(ErrorKind::InvalidInput, "unsupported auth type"));
        }
        // It seems we don't actually have to do anything else here, since the only thing we would
        // need is actually in our connection's read digest.
        self.state = CircuitState::CertsWriting;
        Ok(Async::Ready(()))
    }

    fn do_certs_write(&mut self) -> Result<Async<()>, Error> {
        let certs_cell = self.initiator_certs.to_certs_cell();
        let mut buf: Vec<u8> = Vec::new();
        if certs_cell.write_to(&mut buf).is_err() {
            return Err(Error::new(
                ErrorKind::InvalidInput,
                "couldn't serialize CERTS cell",
            ));
        }
        let cell = types::Cell::new(0, types::Command::Certs, buf);
        let mut buf: Vec<u8> = Vec::new();
        if cell.write_to(&mut buf).is_err() {
            return Err(Error::new(
                ErrorKind::InvalidInput,
                "couldn't serialize cell",
            ));
        }
        match self.tls_connection.write_all(&buf) {
            Ok(_) => {
                self.state = CircuitState::AuthenticateWriting;
                Ok(Async::Ready(()))
            }
            Err(ref e) if e.kind() == ErrorKind::WouldBlock => Ok(Async::NotReady),
            Err(e) => Err(e),
        }
    }

    fn do_authenticate_write(&mut self) -> Result<Async<()>, Error> {
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
            .get_key_hash(&self.initiator_certs.rsa_identity_cert.get_bytes());
        buf.extend(&cid);
        // SID
        let responder_certs = match self.responder_certs {
            Some(ref responder_certs) => responder_certs,
            None => return Err(Error::new(ErrorKind::Other, "`responder_certs` not set?")),
        };
        let sid = self.rsa_verifier
            .get_key_hash(&responder_certs.rsa_identity_cert.get_bytes());
        buf.extend(&sid);
        // CID_ED
        let cid_ed = self.initiator_certs.ed25519_identity_cert.get_key_bytes();
        buf.extend(cid_ed);
        // SID_ED
        let sid_ed = responder_certs.ed25519_identity_cert.get_key_bytes();
        buf.extend(sid_ed);
        // SLOG (yes, the responder is first this time. don't know why)
        // For CLOG, our `TlsHashWrapper` intercepts all written bytes and keeps track of the
        // running hash. This doesn't work with SLOG, because we read as much as we can until the
        // stream blocks, which means the hash covers more data than we've actually processed, and
        // we'll get the wrong result here.
        let mut hash = Sha256::new();
        let read_position = self.buffer.position();
        let mut hash_buf = Vec::with_capacity(read_position as usize);
        hash_buf.resize(read_position as usize, 0);
        self.buffer.seek(SeekFrom::Start(0))?;
        self.buffer.read(&mut hash_buf)?;
        hash.input(&hash_buf);
        let mut slog = Vec::new();
        slog.extend(hash.result().into_iter());
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
            Err(e) => return Err(Error::new(ErrorKind::Other, e)),
        };
        csprng.fill_bytes(&mut rand);
        buf.extend(rand.iter());
        // SIG
        let ed25519_authenticate_key = self.initiator_certs.get_ed25519_authenticate_key();
        let signature = ed25519_authenticate_key.sign_data(&buf);
        buf.extend(signature.iter());

        let authenticate_cell =
            types::AuthenticateCell::new(types::AuthType::Ed25519Sha256Rfc5705, buf);
        let mut buf: Vec<u8> = Vec::new();
        if authenticate_cell.write_to(&mut buf).is_err() {
            return Err(Error::new(
                ErrorKind::Other,
                "couldn't serialize AUTHENTICATE cell",
            ));
        }
        let cell = types::Cell::new(0, types::Command::Authenticate, buf);
        let mut buf: Vec<u8> = Vec::new();
        if cell.write_to(&mut buf).is_err() {
            return Err(Error::new(ErrorKind::Other, "couldn't serialize cell"));
        }
        match self.tls_connection.write_all(&buf) {
            Ok(_) => {
                self.state = CircuitState::NetinfoReading;
                Ok(Async::Ready(()))
            }
            Err(ref e) if e.kind() == ErrorKind::WouldBlock => Ok(Async::NotReady),
            Err(e) => Err(e),
        }
    }

    fn do_netinfo_read(&mut self) -> Result<Async<()>, Error> {
        match self.read_to_buffer()? {
            Async::Ready(()) => {}
            Async::NotReady => return Ok(Async::NotReady),
        }
        let saved_position = self.buffer.position();
        let cell = match types::Cell::read_new(&mut self.buffer) {
            Ok(cell) => cell,
            Err(_) => {
                self.buffer.set_position(saved_position);
                return Ok(Async::NotReady);
            }
        };
        println!("{:?}", cell);
        if cell.command != types::Command::Netinfo {
            return Err(Error::new(ErrorKind::Other, "unexpected cell type"));
        }
        let netinfo = match types::NetinfoCell::read_new(&mut &cell.payload[..]) {
            Ok(netinfo_cell) => netinfo_cell,
            Err(_) => return Err(Error::new(ErrorKind::Other, "couldn't decode NETINFO cell")),
        };
        println!("{:?}", netinfo);
        self.other_or_address = Some(netinfo.get_other_or_address());
        self.state = CircuitState::NetinfoWriting;
        Ok(Async::Ready(()))
    }

    fn do_netinfo_write(&mut self) -> Result<Async<()>, Error> {
        let timestamp: types::EpochSeconds = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs() as u32;
        let other_or_address = match self.other_or_address {
            Some(ref other_or_address) => other_or_address.clone(),
            None => return Err(Error::new(ErrorKind::Other, "other_or_address not set?")),
        };
        let localhost = types::OrAddress::IPv4Address([127, 0, 0, 1]);
        let netinfo = types::NetinfoCell::new(timestamp, other_or_address, localhost);
        let mut buf: Vec<u8> = Vec::new();
        if netinfo.write_to(&mut buf).is_err() {
            return Err(Error::new(
                ErrorKind::Other,
                "error serializing NETINFO cell",
            ));
        }
        let cell = types::Cell::new(0, types::Command::Netinfo, buf);
        let mut buf: Vec<u8> = Vec::new();
        if cell.write_to(&mut buf).is_err() {
            return Err(Error::new(ErrorKind::Other, "error serializing cell"));
        }
        match self.tls_connection.write_all(&buf) {
            Ok(_) => {
                self.state = CircuitState::CreateFastWriting;
                Ok(Async::Ready(()))
            }
            Err(ref e) if e.kind() == ErrorKind::WouldBlock => Ok(Async::NotReady),
            Err(e) => Err(e),
        }
    }

    fn do_create_fast_write(&mut self) -> Result<Async<()>, Error> {
        let mut csprng: OsRng = match OsRng::new() {
            Ok(csprng) => csprng,
            Err(e) => return Err(Error::new(ErrorKind::Other, e)),
        };
        csprng.fill_bytes(&mut self.x);
        let create_fast_cell = types::CreateFastCell::new(self.x);
        let mut buf: Vec<u8> = Vec::new();
        if create_fast_cell.write_to(&mut buf).is_err() {
            return Err(Error::new(
                ErrorKind::Other,
                "couldn't serialize CREATE FAST cell",
            ));
        }
        let cell = types::Cell::new(self.circ_id, types::Command::CreateFast, buf);
        let mut buf: Vec<u8> = Vec::new();
        if cell.write_to(&mut buf).is_err() {
            return Err(Error::new(ErrorKind::Other, "couldn't serialize cell"));
        }
        match self.tls_connection.write_all(&buf) {
            Ok(_) => {
                self.state = CircuitState::CreateFastReading;
                Ok(Async::Ready(()))
            }
            Err(ref e) if e.kind() == ErrorKind::WouldBlock => Ok(Async::NotReady),
            Err(e) => Err(e),
        }
    }

    fn do_create_fast_read(&mut self) -> Result<Async<()>, Error> {
        match self.read_to_buffer()? {
            Async::Ready(()) => {}
            Async::NotReady => return Ok(Async::NotReady),
        }
        let saved_position = self.buffer.position();
        let cell = match types::Cell::read_new(&mut self.buffer) {
            Ok(cell) => cell,
            Err(_) => {
                self.buffer.set_position(saved_position);
                return Ok(Async::NotReady);
            }
        };
        println!("{:?}", cell);
        // TODO: handle DESTROY differently here?
        if cell.command != types::Command::CreatedFast {
            return Err(Error::new(ErrorKind::InvalidInput, "unexpected cell type"));
        }
        let created_fast = match types::CreatedFastCell::read_new(&mut &cell.payload[..]) {
            Ok(created_fast) => created_fast,
            Err(_) => {
                return Err(Error::new(
                    ErrorKind::InvalidInput,
                    "error decoding CREATED FAST cell",
                ))
            }
        };
        println!("{:?}", created_fast);
        let circuit_keys = match tor_kdf(&self.x, created_fast.get_y(), created_fast.get_kh()) {
            Ok(circuit_keys) => circuit_keys,
            Err(_) => return Err(Error::new(ErrorKind::Other, "Tor KDF failed")),
        };
        self.circuit_keys.push(circuit_keys);
        self.state = CircuitState::Ready;
        Ok(Async::Ready(()))
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

    fn decrypt_cell_bytes(&mut self, in_bytes: &[u8]) -> Result<types::RelayCell, Error> {
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
            Err(_) => Err(Error::new(ErrorKind::Other, "could not decrypt RELAY cell")),
        }
    }

    /*
    fn read_cell(&mut self) -> Result<types::Cell, ()> {
        match types::Cell::read_new(&mut self.tls_connection) {
            Ok(cell) => Ok(cell),
            Err(_) => Err(()),
        }
    }
    */

    // TODO: validate that there are no open streams when this happens.
    pub fn poll_extend(&mut self, node: &dir::TorPeer) -> Result<Async<()>, Error> {
        match self.state {
            CircuitState::Ready => {
                let client_keypair = keys::Curve25519Keypair::new();
                let ntor_client_handshake = types::NtorClientHandshake::new(node, &client_keypair);
                let mut ntor_client_handshake_bytes = Vec::new();
                if ntor_client_handshake
                    .write_to(&mut ntor_client_handshake_bytes)
                    .is_err()
                {
                    return Err(Error::new(ErrorKind::Other,
                                          "couldn't serialize NtorClientHandshake"));
                }
                let extend2 = types::Extend2Cell::new(node, ntor_client_handshake_bytes);
                let mut extend2_bytes = Vec::new();
                if extend2.write_to(&mut extend2_bytes).is_err() {
                    return Err(Error::new(ErrorKind::Other, "couldn't serialize EXTEND2 cell"));
                }
                let bytes = self.encrypt_cell_bytes(types::RelayCommand::Extend2, &extend2_bytes,
                                                    0);
                self.write_buffer.clear();
                self.write_buffer.extend(bytes);
                self.ntor_keypair = Some(client_keypair);
                self.state = CircuitState::Extend2Writing;
                Ok(Async::NotReady)
            }
            CircuitState::Extend2Writing => {
                let bytes = self.write_buffer.clone();
                match self.send_cell_bytes(bytes)? {
                    Async::Ready(()) => {
                        self.state = CircuitState::Extended2Reading;
                        Ok(Async::NotReady)
                    }
                    Async::NotReady => {
                        Ok(Async::NotReady)
                    }
                }
            }
            CircuitState::Extended2Reading => {
                let cell = match self.poll_read_cell()? {
                    Async::Ready(cell) => cell,
                    Async::NotReady => return Ok(Async::NotReady),
                };
                println!("{:?}", cell);
                if cell.command != types::Command::Relay {
                    return Err(Error::new(ErrorKind::Other, "expected Command::Relay"));
                }
                let relay_cell = self.decrypt_cell_bytes(&cell.payload)?;
                println!("{}", relay_cell);
                if relay_cell.relay_command != types::RelayCommand::Extended2 {
                    return Err(Error::new(ErrorKind::Other, "expected RelayCommand::Extended2"));
                }
                // The contents of an EXTENDED2 relay cell is the same as a CREATED2 cell
                let extended2 = match types::Created2Cell::read_new(&mut relay_cell.get_data()) {
                    Ok(extended2) => extended2,
                    Err(_) => return Err(Error::new(ErrorKind::Other,
                                                    "couldn't decode EXTENDED2 cell")),
                };
                let client_keypair = match self.ntor_keypair.take() {
                    Some(client_keypair) => client_keypair,
                    None => return Err(Error::new(ErrorKind::Other,
                                                  "library error: ntor_keypair should be Some")),
                };
                let circuit_keys = match ntor_handshake(
                    &extended2,
                    node.get_node_id(),
                    node.get_ntor_key(),
                    client_keypair.get_public_key_bytes(),
                    client_keypair.get_secret_key_bytes(),
                ) {
                    Ok(circuit_keys) => circuit_keys,
                    Err(_) => return Err(Error::new(ErrorKind::Other, "Ntor handshake failed")),
                };
                self.circuit_keys.push(circuit_keys);
                self.state = CircuitState::Ready;
                Ok(Async::Ready(()))
            }
            _ => {
                self.state = CircuitState::Error;
                Err(Error::new(ErrorKind::Other, "invalid state in poll_extend"))
            }
        }
    }

    /*
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
    */

    /*
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
    */

    pub fn open_dir_stream(&mut self) -> u16 {
        let stream_id = self.used_stream_ids.get_new_id();
        let stream = Stream {
            state: StreamState::New,
            flavor: StreamFlavor::Dir,
            destination: String::new(),
            buffer: Vec::new(),
        };
        self.streams.insert(stream_id, stream);
        stream_id
    }

    pub fn poll_stream_setup(&mut self, stream_id: u16) -> Result<Async<()>, Error> {
        let mut stream = match self.streams.remove(&stream_id) {
            Some(stream) => stream,
            None => return Err(Error::new(ErrorKind::Other, "invalid stream_id")),
        };
        let result = match stream.state {
            StreamState::New => {
                stream.state = StreamState::WritingBegin;
                let command = match stream.flavor {
                    StreamFlavor::Dir => {
                        let begin = types::BeginDirCell::new();
                        if begin.write_to(&mut stream.buffer).is_err() {
                            return Err(Error::new(ErrorKind::Other,
                                                  "couldn't serialize BEGIN DIR cell"));
                        }
                        types::RelayCommand::BeginDir
                    }
                    StreamFlavor::Data => {
                        let begin = types::BeginCell::new(&stream.destination);
                        if begin.write_to(&mut stream.buffer).is_err() {
                            return Err(Error::new(ErrorKind::Other,
                                                  "couldn't serialize BEGIN cell"));
                        }
                        types::RelayCommand::Begin
                    }
                };
                let mut bytes = self.encrypt_cell_bytes(command, &stream.buffer, stream_id);
                stream.buffer.clear();
                stream.buffer.append(&mut bytes);
                Ok(Async::NotReady)
            }
            StreamState::WritingBegin => {
                match self.send_cell_bytes(stream.buffer.clone())? {
                    Async::Ready(()) => {
                        stream.state = StreamState::ReadingBegan;
                        Ok(Async::NotReady)
                    }
                    Async::NotReady => {
                        Ok(Async::NotReady)
                    }
                }
            }
            StreamState::ReadingBegan => {
                if let Async::Ready(cell) = self.poll_read_cell()? {
                    println!("{:?}", cell);
                    if cell.command != types::Command::Relay {
                        return Err(Error::new(ErrorKind::Other, "unexpected cell type"));
                    }
                    let relay_cell = self.decrypt_cell_bytes(&cell.payload)?;
                    println!("{}", relay_cell);
                    if relay_cell.relay_command != types::RelayCommand::Connected {
                        return Err(Error::new(ErrorKind::Other, "expected RelayCommand::Connected"));
                    }
                    stream.state = StreamState::Ready;
                    stream.buffer.clear();
                    Ok(Async::Ready(()))
                } else {
                    Ok(Async::NotReady)
                }
            }
            _ => Err(Error::new(ErrorKind::Other, "poll_stream_setup: invalid state"))
        };
        self.streams.insert(stream_id, stream);
        result
    }

    pub fn poll_stream_write(&mut self, stream_id: u16, data: &[u8]) -> Result<Async<()>, Error> {
        let stream = match self.streams.remove(&stream_id) {
            Some(stream) => stream,
            None => return Err(Error::new(ErrorKind::Other, "invalid stream_id")),
        };
        if stream.state != StreamState::Ready {
            return Err(Error::new(ErrorKind::Other, "poll_stream_write: invalid stream state"));
        }
        // It's unclear how to do this correctly. If we actually do have to poll here, we don't want
        // to re-encrypt the same bytes and try to send them...
        // Also this doesn't handle data.len() > 509, so that's another thing...
        let bytes = self.encrypt_cell_bytes(types::RelayCommand::Data, data, stream_id);
        let async = self.send_cell_bytes(bytes)?;
        self.streams.insert(stream_id, stream);
        Ok(async)
    }

    pub fn poll_stream_read(&mut self, stream_id: u16) -> Result<Async<Vec<u8>>, Error> {
        let mut stream = match self.streams.remove(&stream_id) {
            Some(stream) => stream,
            None => return Err(Error::new(ErrorKind::Other, "invalid stream_id")),
        };
        if stream.state != StreamState::Ready {
            return Err(Error::new(ErrorKind::Other, "poll_stream_write: invalid stream state"));
        }
        let result = if let Async::Ready(cell) = self.poll_read_cell()? {
            println!("{:?}", cell);
            if cell.command != types::Command::Relay {
                return Err(Error::new(ErrorKind::Other, "poll_stream_read: expected RELAY cell"));
            }
            let relay_cell = self.decrypt_cell_bytes(&cell.payload)?;
            println!("{}", relay_cell);
            match relay_cell.relay_command {
                types::RelayCommand::Data => {
                    Ok(Async::Ready(relay_cell.get_data().to_owned()))
                }
                types::RelayCommand::End => {
                    stream.state = StreamState::Dead;
                    Ok(Async::Ready(Vec::new()))
                }
                _ => return Err(Error::new(ErrorKind::Other,
                                           "expected RelayCommand::Data or End")),
            }
        } else {
            Ok(Async::NotReady)
        };
        self.streams.insert(stream_id, stream);
        result
    }

    pub fn open_stream(&mut self, destination: &str) -> u16 {
        let stream_id = self.used_stream_ids.get_new_id();
        let stream = Stream {
            state: StreamState::New,
            flavor: StreamFlavor::Data,
            destination: destination.to_owned(),
            buffer: Vec::new(),
        };
        self.streams.insert(stream_id, stream);
        stream_id
    }

    fn send_cell_bytes(
        &mut self,
        bytes: Vec<u8>,
    ) -> Result<Async<()>, Error> {
        let command = if self.relay_early_count < 8 {
            self.relay_early_count += 1;
            types::Command::RelayEarly
        } else {
            types::Command::Relay
        };
        let cell = types::Cell::new(self.circ_id, command, bytes);
        let mut buf: Vec<u8> = Vec::new();
        if let Err(e) = cell.write_to(&mut buf) {
            return Err(e);
        }
        match self.tls_connection.write_all(&buf) {
            Ok(_) => {
                Ok(Async::Ready(()))
            }
            Err(ref e) if e.kind() == ErrorKind::WouldBlock => {
                println!("this is probably a bug - we need to buffer a write");
                Ok(Async::NotReady)
            }
            Err(e) => Err(e),
        }
    }

    fn poll_read_cell(&mut self) -> Result<Async<types::Cell>, Error> {
        match self.read_to_buffer()? {
            Async::Ready(()) => {}
            Async::NotReady => return Ok(Async::NotReady),
        }
        let saved_position = self.buffer.position();
        match types::Cell::read_new(&mut self.buffer) {
            Ok(cell) => Ok(Async::Ready(cell)),
            Err(_) => {
                self.buffer.set_position(saved_position);
                Ok(Async::NotReady)
            }
        }
    }

    /*
    pub fn recv(&mut self) -> Result<Vec<u8>, ()> {
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
    */

    /*
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
    */
}

#[derive(Debug, PartialEq)]
enum StreamState {
    New,
    WritingBegin,
    ReadingBegan,
    Ready,
    Dead,
}

#[derive(PartialEq)]
enum StreamFlavor {
    Dir,
    Data,
}

struct Stream {
    state: StreamState,
    flavor: StreamFlavor,
    destination: String,
    buffer: Vec<u8>,
}

struct TlsHashWrapper<T: TlsImpl + Read + Write> {
    tls_impl: T,
    /// A running sha256 digest of all data written to the stream (we can't do the same thing with
    /// data read because we read as much as we can and then buffer it in the `Circuit` that owns
    /// this `TlsHashWrapper`, which means the read hash ends up covering more data than has
    /// actually been processed).
    write_log: Sha256,
}

impl<T: TlsImpl + Read + Write> TlsHashWrapper<T> {
    pub fn new(tls_impl: T) -> TlsHashWrapper<T> {
        TlsHashWrapper {
            tls_impl: tls_impl,
            write_log: Sha256::new(),
        }
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
    fn get_peer_cert_hash(&self) -> Result<[u8; 32], Error> {
        self.tls_impl.get_peer_cert_hash()
    }

    fn get_tls_secrets(&self, label: &str, context_key: &[u8]) -> Result<Vec<u8>, Error> {
        self.tls_impl.get_tls_secrets(label, context_key)
    }
}

impl<T: TlsImpl + Read + Write> Read for TlsHashWrapper<T> {
    fn read(&mut self, buf: &mut [u8]) -> Result<usize, Error> {
        self.tls_impl.read(buf)
    }
}

impl<T: TlsImpl + Read + Write> Write for TlsHashWrapper<T> {
    fn write(&mut self, data: &[u8]) -> Result<usize, Error> {
        let result = self.tls_impl.write(data);
        if let &Ok(len) = &result {
            self.write_log.input(&data[..len]);
        }
        result
    }

    fn flush(&mut self) -> Result<(), Error> {
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
