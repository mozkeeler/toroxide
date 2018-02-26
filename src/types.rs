use byteorder::{NetworkEndian, ReadBytesExt, WriteBytesExt};
use std::fmt;
use std::str;
use std::io::{Read, Write};

use certs;

const PAYLOAD_LEN: usize = 509;
const CELL_LEN: usize = 514; // link protocol v4 is the only one supported at the moment

#[derive(Debug)]
pub struct Cell {
    pub circ_id: u32,
    pub command: Command,
    pub payload: Vec<u8>,
}

#[derive(Debug, PartialEq)]
pub enum Command {
    Padding,
    Create,
    Created,
    Relay,
    Destroy,
    CreateFast,
    CreatedFast,
    Netinfo,
    RelayEarly,
    Create2,
    Created2,
    PaddingNegotiate,
    // Versions is handled separately
    VPadding,
    Certs,
    AuthChallenge,
    Authenticate,
    Authorize,
    Unknown(u8),
}

impl Command {
    pub fn from_u8(command: u8) -> Command {
        match command {
            0 => Command::Padding,
            1 => Command::Create,
            2 => Command::Created,
            3 => Command::Relay,
            4 => Command::Destroy,
            5 => Command::CreateFast,
            6 => Command::CreatedFast,
            8 => Command::Netinfo,
            9 => Command::RelayEarly,
            10 => Command::Create2,
            11 => Command::Created2,
            12 => Command::PaddingNegotiate,
            // variable-length commands:
            // 7 => Command::Versions is handled separately
            128 => Command::VPadding,
            129 => Command::Certs,
            130 => Command::AuthChallenge,
            131 => Command::Authenticate,
            132 => Command::Authorize,
            _ => Command::Unknown(command),
        }
    }

    fn is_variable_length(&self) -> bool {
        match *self {
            Command::VPadding
            | Command::Certs
            | Command::AuthChallenge
            | Command::Authenticate
            | Command::Authorize => true,
            _ => false,
        }
    }

    fn as_u8(&self) -> u8 {
        match self {
            &Command::Padding => 0,
            &Command::Create => 1,
            &Command::Created => 2,
            &Command::Relay => 3,
            &Command::Destroy => 4,
            &Command::CreateFast => 5,
            &Command::CreatedFast => 6,
            &Command::Netinfo => 8,
            &Command::RelayEarly => 9,
            &Command::Create2 => 10,
            &Command::Created2 => 11,
            &Command::PaddingNegotiate => 12,
            &Command::VPadding => 128,
            &Command::Certs => 129,
            &Command::AuthChallenge => 130,
            &Command::Authenticate => 131,
            &Command::Authorize => 132,
            &Command::Unknown(value) => value,
        }
    }
}

impl Cell {
    pub fn read_new<R: Read>(reader: &mut R) -> Result<Cell, &'static str> {
        let circ_id = match reader.read_u32::<NetworkEndian>() {
            Ok(circ_id) => circ_id,
            Err(_) => return Err("failed to read circ_id"),
        };
        let mut one_byte_buf = [0; 1];
        if let Err(_) = reader.read_exact(&mut one_byte_buf) {
            return Err("failed to read command");
        }
        let command = Command::from_u8(one_byte_buf[0]);
        let length = if command.is_variable_length() {
            let mut two_byte_buf = [0; 2];
            if let Err(_) = reader.read_exact(&mut two_byte_buf) {
                return Err("failed to read variable cell length");
            }
            ((two_byte_buf[0] as usize) << 8) + two_byte_buf[1] as usize
        } else {
            PAYLOAD_LEN
        };
        let mut payload: Vec<u8> = Vec::with_capacity(length);
        payload.resize(length, 0);
        if let Err(_) = reader.read_exact(payload.as_mut_slice()) {
            return Err("failed to read payload");
        }
        Ok(Cell {
            circ_id: circ_id,
            command: command,
            payload: payload,
        })
    }

    pub fn new(circ_id: u32, command: Command, payload: Vec<u8>) -> Cell {
        Cell {
            circ_id: circ_id,
            command: command,
            payload: payload,
        }
    }

    pub fn write_to<W: Write>(&self, writer: &mut W) {
        writer.write_u32::<NetworkEndian>(self.circ_id).unwrap();
        writer.write_u8(self.command.as_u8()).unwrap();
        if self.command.is_variable_length() {
            assert!(self.payload.len() < 65536);
            writer
                .write_u16::<NetworkEndian>(self.payload.len() as u16)
                .unwrap();
        }
        writer.write_all(&self.payload).unwrap();
        if !self.command.is_variable_length() {
            assert!(self.payload.len() <= PAYLOAD_LEN);
            let padding_length = PAYLOAD_LEN - self.payload.len();
            let mut zeroes: Vec<u8> = Vec::with_capacity(padding_length);
            zeroes.resize(padding_length, 0);
            writer.write_all(&zeroes).unwrap();
        }
    }
}

#[derive(Debug)]
pub enum CertType {
    RsaLink,
    RsaIdentity,
    RsaAuthenticate,
    Ed25519Signing,
    Ed25519Link,
    Ed25519Authenticate,
    Ed25519Identity,
    Unknown(u8),
}

impl CertType {
    fn from_u8(cert_type: u8) -> CertType {
        match cert_type {
            1 => CertType::RsaLink,
            2 => CertType::RsaIdentity,
            3 => CertType::RsaAuthenticate,
            4 => CertType::Ed25519Signing,
            5 => CertType::Ed25519Link,
            6 => CertType::Ed25519Authenticate,
            7 => CertType::Ed25519Identity,
            _ => CertType::Unknown(cert_type),
        }
    }

    fn as_u8(&self) -> u8 {
        match self {
            &CertType::RsaLink => 1,
            &CertType::RsaIdentity => 2,
            &CertType::RsaAuthenticate => 3,
            &CertType::Ed25519Signing => 4,
            &CertType::Ed25519Link => 5,
            &CertType::Ed25519Authenticate => 6,
            &CertType::Ed25519Identity => 7,
            &CertType::Unknown(value) => value,
        }
    }
}

#[derive(Debug)]
pub struct RawCert {
    cert_type: CertType,
    bytes: Vec<u8>,
}

impl RawCert {
    pub fn read_new<R: Read>(reader: &mut R) -> Result<RawCert, &'static str> {
        let mut one_byte_buf = [0; 1];
        if let Err(_) = reader.read_exact(&mut one_byte_buf) {
            return Err("failed to read cert type");
        }
        let mut two_byte_buf = [0; 2];
        if let Err(_) = reader.read_exact(&mut two_byte_buf) {
            return Err("failed to read cert length");
        }
        let length = ((two_byte_buf[0] as usize) << 8) + two_byte_buf[1] as usize;
        let mut cert = RawCert {
            cert_type: CertType::from_u8(one_byte_buf[0]),
            bytes: Vec::with_capacity(length),
        };
        cert.bytes.resize(length, 0);
        if let Err(_) = reader.read_exact(cert.bytes.as_mut_slice()) {
            return Err("failed to read cert bytes");
        }
        Ok(cert)
    }

    pub fn new(cert_type: CertType, bytes: Vec<u8>) -> RawCert {
        RawCert {
            cert_type: cert_type,
            bytes: bytes,
        }
    }

    pub fn write_to<W: Write>(&self, writer: &mut W) {
        writer.write_u8(self.cert_type.as_u8()).unwrap();
        assert!(self.bytes.len() < 65536);
        writer
            .write_u16::<NetworkEndian>(self.bytes.len() as u16)
            .unwrap();
        writer.write_all(&self.bytes).unwrap();
    }
}

#[derive(Debug)]
pub struct CertsCell {
    certs: Vec<RawCert>,
}

impl CertsCell {
    pub fn read_new<R: Read>(reader: &mut R) -> Result<CertsCell, &'static str> {
        let mut one_byte_buf = [0; 1];
        if let Err(_) = reader.read_exact(&mut one_byte_buf) {
            return Err("failed to read number of certs");
        }
        let mut certs: Vec<RawCert> = Vec::with_capacity(one_byte_buf[0] as usize);
        for _ in 0..one_byte_buf[0] {
            let cert = RawCert::read_new(reader)?;
            certs.push(cert);
        }
        Ok(CertsCell { certs: certs })
    }

    // also should probably return a result if something fails to decode?
    pub fn decode_certs(&self) -> Vec<certs::Cert> {
        let mut certs: Vec<certs::Cert> = Vec::new();
        for cert in &self.certs {
            // Obviously this should be refactored into certs::read_new...
            match cert.cert_type {
                CertType::RsaLink => match certs::X509Cert::read_new(&mut &cert.bytes[..]) {
                    Ok(cert) => certs.push(certs::Cert::RsaLink(cert)),
                    Err(e) => println!("{}", e),
                },
                CertType::RsaIdentity => match certs::X509Cert::read_new(&mut &cert.bytes[..]) {
                    Ok(cert) => certs.push(certs::Cert::RsaIdentity(cert)),
                    Err(e) => println!("{}", e),
                },
                CertType::RsaAuthenticate => {
                    match certs::X509Cert::read_new(&mut &cert.bytes[..]) {
                        Ok(cert) => certs.push(certs::Cert::RsaAuthenticate(cert)),
                        Err(e) => println!("{}", e),
                    }
                }
                CertType::Ed25519Signing => {
                    match certs::Ed25519Cert::read_new(&mut &cert.bytes[..]) {
                        Ok(cert) => certs.push(certs::Cert::Ed25519Signing(cert)),
                        Err(e) => println!("{}", e),
                    };
                }
                CertType::Ed25519Link => {
                    match certs::Ed25519Cert::read_new(&mut &cert.bytes[..]) {
                        Ok(cert) => certs.push(certs::Cert::Ed25519Link(cert)),
                        Err(e) => println!("{}", e),
                    };
                }
                CertType::Ed25519Authenticate => {
                    match certs::Ed25519Cert::read_new(&mut &cert.bytes[..]) {
                        Ok(cert) => certs.push(certs::Cert::Ed25519Authenticate(cert)),
                        Err(e) => println!("{}", e),
                    };
                }
                CertType::Ed25519Identity => {
                    match certs::Ed25519Identity::read_new(&mut &cert.bytes[..]) {
                        Ok(cert) => certs.push(certs::Cert::Ed25519Identity(cert)),
                        Err(e) => println!("{}", e),
                    }
                }
                _ => {}
            }
        }
        certs
    }

    pub fn new_from_raw_certs(certs: Vec<RawCert>) -> CertsCell {
        CertsCell { certs: certs }
    }

    pub fn write_to<W: Write>(&self, writer: &mut W) {
        assert!(self.certs.len() < 256);
        writer.write_u8(self.certs.len() as u8).unwrap();
        for cert in &self.certs {
            cert.write_to(writer);
        }
    }
}

pub struct AuthenticateCell {
    auth_type: AuthType,
    authentication: Vec<u8>,
}

impl AuthenticateCell {
    pub fn new(auth_type: AuthType, authentication: Vec<u8>) -> AuthenticateCell {
        AuthenticateCell {
            auth_type: auth_type,
            authentication: authentication,
        }
    }

    pub fn write_to<W: Write>(&self, writer: &mut W) {
        writer
            .write_u16::<NetworkEndian>(self.auth_type.as_u16())
            .unwrap();
        assert!(self.authentication.len() < 65536);
        writer
            .write_u16::<NetworkEndian>(self.authentication.len() as u16)
            .unwrap();
        writer.write_all(&self.authentication).unwrap();
    }
}

#[derive(Debug, PartialEq)]
pub enum AuthType {
    RsaSha256TlsSecret,
    Ed25519Sha256Rfc5705,
    Unknown(u16),
}

impl AuthType {
    fn from_u16(auth_type: u16) -> AuthType {
        match auth_type {
            1 => AuthType::RsaSha256TlsSecret,
            3 => AuthType::Ed25519Sha256Rfc5705,
            _ => AuthType::Unknown(auth_type),
        }
    }

    fn as_u16(&self) -> u16 {
        match self {
            &AuthType::RsaSha256TlsSecret => 1,
            &AuthType::Ed25519Sha256Rfc5705 => 3,
            &AuthType::Unknown(value) => value,
        }
    }
}

#[derive(Debug)]
pub struct AuthChallengeCell {
    challenge: [u8; 32],
    methods: Vec<AuthType>,
}

impl AuthChallengeCell {
    pub fn read_new<R: Read>(reader: &mut R) -> Result<AuthChallengeCell, &'static str> {
        let mut auth_challenge_cell = AuthChallengeCell {
            challenge: [0; 32],
            methods: Vec::new(),
        };
        if let Err(_) = reader.read_exact(&mut auth_challenge_cell.challenge) {
            return Err("failed to read challenge bytes");
        }
        let mut two_byte_buf = [0; 2];
        if let Err(_) = reader.read_exact(&mut two_byte_buf) {
            return Err("failed to read number of methods");
        }
        // There's only two methods possible.
        if two_byte_buf[0] != 0 || two_byte_buf[1] > 2 || two_byte_buf[1] == 0 {
            return Err("invalid number of methods");
        }
        for _ in 0..two_byte_buf[1] {
            if let Err(_) = reader.read_exact(&mut two_byte_buf) {
                return Err("failed to read method");
            }
            let method: u16 = ((two_byte_buf[0] as u16) << 8) + two_byte_buf[1] as u16;
            auth_challenge_cell.methods.push(AuthType::from_u16(method));
        }
        Ok(auth_challenge_cell)
    }

    pub fn has_auth_type(&self, auth_type: AuthType) -> bool {
        self.methods.contains(&auth_type)
    }
}

#[derive(Clone, Debug)]
pub enum OrAddress {
    Hostname(String),
    IPv4Address([u8; 4]),
    IPv6Address([u8; 16]),
    TransientError,
    NontransientError,
    Unknown(u8),
}

impl OrAddress {
    pub fn read_new<R: Read>(reader: &mut R) -> Result<OrAddress, &'static str> {
        // These are TLV encoded, with one byte each for type and length.
        let address_type = reader.read_u8().unwrap();
        let address_length = reader.read_u8().unwrap();
        Ok(match address_type {
            0 => {
                let mut buf: Vec<u8> = Vec::with_capacity(address_length as usize);
                buf.resize(address_length as usize, 0);
                reader.read_exact(&mut buf).unwrap();
                let result = String::from_utf8(buf);
                match result {
                    // TODO vaildate the hostname?
                    Ok(string) => OrAddress::Hostname(string.to_owned()),
                    Err(_) => return Err("invalid hostname"),
                }
            }
            4 => {
                if address_length != 4 {
                    return Err("malformed ipv4 in OrAddress");
                }
                let mut dest = [0; 4];
                reader.read_exact(&mut dest).unwrap();
                OrAddress::IPv4Address(dest)
            }
            6 => {
                if address_length != 16 {
                    return Err("malformed ipv6 in OrAddress");
                }
                let mut dest = [0; 16];
                reader.read_exact(&mut dest).unwrap();
                OrAddress::IPv6Address(dest)
            }
            0xf0 => {
                // We have to drop these bytes.
                let mut buf: Vec<u8> = Vec::with_capacity(address_length as usize);
                buf.resize(address_length as usize, 0);
                reader.read_exact(&mut buf).unwrap();
                OrAddress::TransientError
            }
            0xf1 => {
                // We have to drop these bytes.
                let mut buf: Vec<u8> = Vec::with_capacity(address_length as usize);
                buf.resize(address_length as usize, 0);
                reader.read_exact(&mut buf).unwrap();
                OrAddress::NontransientError
            }
            _ => OrAddress::Unknown(address_type), // TODO: still read the length and value?
        })
    }

    pub fn write_to<W: Write>(&self, writer: &mut W) {
        match self {
            &OrAddress::Hostname(ref string) => {
                writer.write_u8(0).unwrap();
                let bytes = string.as_bytes();
                assert!(bytes.len() < 256);
                writer.write_u8(bytes.len() as u8).unwrap();
                writer.write_all(bytes).unwrap();
            }
            &OrAddress::IPv4Address(bytes) => {
                writer.write_u8(4).unwrap();
                writer.write_all(&bytes).unwrap();
            }
            &OrAddress::IPv6Address(bytes) => {
                writer.write_u8(6).unwrap();
                writer.write_all(&bytes).unwrap();
            }
            _ => panic!("unimplemented"),
        }
    }
}

pub type EpochSeconds = u32;

#[derive(Debug)]
pub struct NetinfoCell {
    timestamp: u32,
    other_or_address: OrAddress,
    this_or_addresses: Vec<OrAddress>,
}

impl NetinfoCell {
    pub fn read_new<R: Read>(reader: &mut R) -> Result<NetinfoCell, &'static str> {
        let timestamp = match reader.read_u32::<NetworkEndian>() {
            Err(_) => return Err("failed to read timestamp"),
            Ok(timestamp) => timestamp,
        };
        let other_or_address = OrAddress::read_new(reader)?;
        let num_addresses = reader.read_u8().unwrap();
        let mut this_or_addresses = Vec::new();
        for _ in 0..num_addresses {
            this_or_addresses.push(OrAddress::read_new(reader)?);
        }
        Ok(NetinfoCell {
            timestamp: timestamp,
            other_or_address: other_or_address,
            this_or_addresses: this_or_addresses,
        })
    }

    pub fn write_to<W: Write>(&self, writer: &mut W) {
        writer.write_u32::<NetworkEndian>(self.timestamp).unwrap();
        self.other_or_address.write_to(writer);
        assert!(self.this_or_addresses.len() < 256);
        writer.write_u8(self.this_or_addresses.len() as u8).unwrap();
        for address in &self.this_or_addresses {
            address.write_to(writer);
        }
    }

    pub fn new(
        timestamp: EpochSeconds,
        other_or_address: OrAddress,
        this_or_address: OrAddress,
    ) -> NetinfoCell {
        NetinfoCell {
            timestamp: timestamp,
            other_or_address: other_or_address,
            this_or_addresses: vec![this_or_address],
        }
    }

    /// Returns some `OrAddress` in `this_or_addresses` or panics.
    /// TODO: make this robust against adversarial input.
    pub fn get_other_or_address(&self) -> OrAddress {
        self.this_or_addresses[0].clone()
    }
}

pub struct RelayCell<'a> {
    relay_command: RelayCommand,
    recognized: u16,
    stream_id: u16,
    digest: u32,
    length: u16,
    data: &'a [u8],
}

#[derive(Debug)]
pub enum RelayCommand {
    Begin,
    Data,
    End,
    Connected,
    SendMe,
    Extend,
    Extended,
    Truncate,
    Truncated,
    Drop,
    Resolve,
    Resolved,
    BeginDir,
    Extend2,
    Extended2,
    Unknown(u8),
}

impl RelayCommand {
    pub fn from_u8(relay_command: u8) -> RelayCommand {
        match relay_command {
            1 => RelayCommand::Begin,
            2 => RelayCommand::Data,
            3 => RelayCommand::End,
            4 => RelayCommand::Connected,
            5 => RelayCommand::SendMe,
            6 => RelayCommand::Extend,
            7 => RelayCommand::Extended,
            8 => RelayCommand::Truncate,
            9 => RelayCommand::Truncated,
            10 => RelayCommand::Drop,
            11 => RelayCommand::Resolve,
            12 => RelayCommand::Resolved,
            13 => RelayCommand::BeginDir,
            14 => RelayCommand::Extend2,
            15 => RelayCommand::Extended2,
            _ => RelayCommand::Unknown(relay_command),
        }
    }
}

pub enum RelayCellError {
    Unrecognized,
    InsufficientLength,
    InsufficientPayloadLength,
}

impl<'a> RelayCell<'a> {
    // Maybe pass expected digest here so we can validate that too?
    // (as is this can erroneously be "recognized" 1/256^2 of the time)
    pub fn from_slice(bytes: &[u8]) -> Result<RelayCell, RelayCellError> {
        if bytes.len() < PAYLOAD_LEN {
            return Err(RelayCellError::InsufficientLength);
        }
        let relay_command = RelayCommand::from_u8(bytes[0]);
        // TODO: not this
        let recognized = ((bytes[1] as u16) << 8) + (bytes[2] as u16);
        if recognized != 0 as u16 {
            return Err(RelayCellError::Unrecognized);
        }
        let stream_id = ((bytes[3] as u16) << 8) + (bytes[4] as u16);
        // endian-ness?
        let digest = ((bytes[6] as u32) << 24) + ((bytes[7] as u32) << 16)
            + ((bytes[8] as u32) << 8) + (bytes[9] as u32);
        // This isn't making much sense to me. For DATA cells, the length field doesn't seem to
        // correspond to... anything?
        let length = ((bytes[10] as u16) << 8) + (bytes[11] as u16);
        let data_length = if length < (PAYLOAD_LEN - 11) as u16 {
            length
        } else {
            (PAYLOAD_LEN - 11) as u16
        };
        let data = &bytes[11..11 + data_length as usize];
        Ok(RelayCell {
            relay_command: relay_command,
            recognized: recognized,
            stream_id: stream_id,
            digest: digest,
            length: length,
            data: data,
        })
    }
}

impl<'a> fmt::Display for RelayCell<'a> {
    fn fmt(&self, dest: &mut fmt::Formatter) -> fmt::Result {
        write!(
            dest,
            "RelayCell {{ {:?} {} {} {} {} ",
            self.relay_command, self.recognized, self.stream_id, self.digest, self.length
        )?;
        for b in self.data {
            write!(dest, "{:02x}", b)?;
        }
        write!(dest, " }}")
    }
}

#[derive(Debug)]
pub enum ClientHandshakeType {
    Tap,
    Reserved,
    Ntor,
    Unknown(u16),
}

impl ClientHandshakeType {
    pub fn from_u16(h_type: u16) -> ClientHandshakeType {
        match h_type {
            0 => ClientHandshakeType::Tap,
            1 => ClientHandshakeType::Reserved,
            2 => ClientHandshakeType::Ntor,
            _ => ClientHandshakeType::Unknown(h_type),
        }
    }
}

#[derive(Debug)]
pub struct Create2Cell<'a> {
    h_type: ClientHandshakeType,
    h_len: u16,
    pub h_data: &'a [u8],
}

impl<'a> Create2Cell<'a> {
    pub fn from_slice(bytes: &[u8]) -> Result<Create2Cell, &'static str> {
        if bytes.len() < 4 {
            return Err("input not long enough for Create2Cell");
        }
        let h_type_raw = ((bytes[0] as u16) << 8) + (bytes[1] as u16);
        let h_len = ((bytes[2] as u16) << 8) + (bytes[3] as u16);
        if bytes.len() < 4 + h_len as usize {
            return Err("input not long enough for specified length in Create2Cell");
        }
        Ok(Create2Cell {
            h_type: ClientHandshakeType::from_u16(h_type_raw),
            h_len: h_len,
            h_data: &bytes[4..4 + h_len as usize],
        })
    }
}

const NTOR_CLIENT_HANDSHAKE_SIZE: usize = 84;

#[derive(Debug)]
pub struct NtorClientHandshake {
    node_id: [u8; 20],
    key_id: [u8; 32],
    client_pk: [u8; 32],
}

impl NtorClientHandshake {
    pub fn from_slice(bytes: &[u8]) -> Result<NtorClientHandshake, &'static str> {
        if bytes.len() != NTOR_CLIENT_HANDSHAKE_SIZE {
            return Err("incorrect input size for ntor client handshake");
        }
        let mut handshake = NtorClientHandshake {
            node_id: [0; 20],
            key_id: [0; 32],
            client_pk: [0; 32],
        };
        // ugh there has to be a better way to do this...
        for i in 0..20 {
            handshake.node_id[i] = bytes[i];
        }
        for i in 0..32 {
            handshake.key_id[i] = bytes[20 + i];
            handshake.client_pk[i] = bytes[52 + i];
        }
        Ok(handshake)
    }
}

#[derive(Debug)]
pub struct Created2Cell<'a> {
    h_len: u16,
    pub h_data: &'a [u8],
}

impl<'a> Created2Cell<'a> {
    pub fn from_slice(bytes: &[u8]) -> Result<Created2Cell, &'static str> {
        if bytes.len() < 2 {
            return Err("input not long enough for Created2Cell");
        }
        let h_len = ((bytes[0] as u16) << 8) + (bytes[1] as u16);
        if bytes.len() < 2 + h_len as usize {
            return Err("input not long enough for specified length in Created2Cell");
        }
        Ok(Created2Cell {
            h_len: h_len,
            h_data: &bytes[2..2 + h_len as usize],
        })
    }
}

const NTOR_SERVER_HANDSHAKE_SIZE: usize = 64;

#[derive(Debug)]
pub struct NtorServerHandshake {
    pub server_pk: [u8; 32],
    pub auth: [u8; 32],
}

impl NtorServerHandshake {
    pub fn from_slice(bytes: &[u8]) -> Result<NtorServerHandshake, &'static str> {
        if bytes.len() != NTOR_SERVER_HANDSHAKE_SIZE {
            return Err("incorrect input size for ntor client handshake");
        }
        let mut handshake = NtorServerHandshake {
            server_pk: [0; 32],
            auth: [0; 32],
        };
        // ugh there has to be a better way to do this...
        for i in 0..32 {
            handshake.server_pk[i] = bytes[i];
            handshake.auth[i] = bytes[32 + i];
        }
        Ok(handshake)
    }
}

#[derive(Debug)]
pub struct VersionsCell {
    // Technically they're 2 bytes on the wire, but since only versions 1-5 are defined, u8 works.
    versions: Vec<u8>,
}

impl VersionsCell {
    pub fn new(versions: Vec<u8>) -> VersionsCell {
        // we really only support v3, 4, 5 (and we really don't do much validation...)
        assert!(versions.len() < 3);
        VersionsCell { versions: versions }
    }

    pub fn to_bytes(&self) -> Vec<u8> {
        // a VERSIONS cell is variable-length and has CIRCID_LEN equal to 2.
        // Thus:
        // CircID     [2 bytes]
        // Command(7) [1 bytes]
        // Length     [2 bytes]
        // Payload    [Length bytes]
        // (where the payload is a sequence of 2-byte big-endian version numbers)
        let mut bytes: Vec<u8> = Vec::new();
        // I think CircID is supposed to be 0, but it's unclear if that's specified.
        bytes.push(0);
        bytes.push(0);
        // 7 is VERSIONS
        bytes.push(7);
        // Payload is 2 bytes.
        bytes.push(0);
        assert!(self.versions.len() < 128);
        bytes.push((self.versions.len() * 2) as u8);
        for version in &self.versions {
            bytes.push(0);
            bytes.push(*version);
        }
        bytes
    }

    pub fn read_new<R: Read>(reader: &mut R) -> Result<VersionsCell, &'static str> {
        let mut two_byte_buf = [0; 2];
        if let Err(_) = reader.read_exact(&mut two_byte_buf) {
            return Err("failed to read CircID");
        }
        // validate CircID == 0?
        let mut one_byte_buf = [0; 1];
        if let Err(_) = reader.read_exact(&mut one_byte_buf) {
            return Err("failed to read command");
        }
        if one_byte_buf[0] != 7 {
            return Err("expected VERSIONS");
        }
        if let Err(_) = reader.read_exact(&mut two_byte_buf) {
            return Err("failed to read payload length");
        }
        if two_byte_buf[0] != 0 || two_byte_buf[1] > 6 {
            return Err("unsupported number of versions");
        }
        if two_byte_buf[1] % 2 != 0 {
            return Err("odd length VERSIONS payload");
        }
        let mut versions: Vec<u8> = Vec::new();
        for _ in 0..two_byte_buf[1] / 2 {
            if let Err(_) = reader.read_exact(&mut two_byte_buf) {
                return Err("couldn't read version");
            }
            // check highest byte is 0
            versions.push(two_byte_buf[1]);
        }
        Ok(VersionsCell { versions: versions })
    }

    /// tor-spec.txt, section 4:
    /// Both parties MUST select as the link protocol version the highest number contained both in
    /// the VERSIONS cell they sent and in the versions cell they received. If they have no such
    /// version in common, they cannot communicate and MUST close the connection.
    pub fn negotiate(&self, other: &VersionsCell) -> Result<u8, &'static str> {
        let mut highest: u8 = 0;
        for self_version in &self.versions {
            if *self_version > highest && other.versions.contains(self_version) {
                highest = *self_version;
            }
        }
        // In reality we only support version 4 right now.
        if highest == 4 {
            Ok(highest)
        } else {
            Err("no shared versions")
        }
    }
}

pub struct CreateFastCell {
    x: [u8; 20],
}

impl CreateFastCell {
    pub fn new(x: [u8; 20]) -> CreateFastCell {
        CreateFastCell { x: x }
    }

    pub fn write_to<W: Write>(&self, writer: &mut W) {
        writer.write_all(&self.x).unwrap();
    }
}

#[derive(Debug)]
pub struct CreatedFastCell {
    y: [u8; 20],
    kh: [u8; 20],
}

impl CreatedFastCell {
    pub fn read_new<R: Read>(reader: &mut R) -> CreatedFastCell {
        let mut created_fast_cell = CreatedFastCell {
            y: [0; 20],
            kh: [0; 20],
        };
        reader.read_exact(&mut created_fast_cell.y).unwrap();
        reader.read_exact(&mut created_fast_cell.kh).unwrap();
        created_fast_cell
    }

    pub fn get_y(&self) -> &[u8; 20] {
        &self.y
    }

    pub fn get_kh(&self) -> &[u8; 20] {
        &self.kh
    }
}
