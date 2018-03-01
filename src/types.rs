use byteorder::{NetworkEndian, ReadBytesExt, WriteBytesExt};
use sha1::Sha1;
use std::fmt;
use std::io::{Error, ErrorKind, Read, Result, Write};

use certs;
use dir;
use keys;

const PAYLOAD_LEN: usize = 509;

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
    pub fn read_new<R: Read>(reader: &mut R) -> Result<Cell> {
        let circ_id = reader.read_u32::<NetworkEndian>()?;
        let mut one_byte_buf = [0; 1];
        reader.read_exact(&mut one_byte_buf)?;
        let command = Command::from_u8(one_byte_buf[0]);
        let length = if command.is_variable_length() {
            reader.read_u16::<NetworkEndian>()? as usize
        } else {
            PAYLOAD_LEN
        };
        let mut payload: Vec<u8> = Vec::with_capacity(length);
        payload.resize(length, 0);
        reader.read_exact(payload.as_mut_slice())?;
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

    pub fn write_to<W: Write>(&self, writer: &mut W) -> Result<()> {
        writer.write_u32::<NetworkEndian>(self.circ_id)?;
        writer.write_u8(self.command.as_u8())?;
        if self.command.is_variable_length() {
            assert!(self.payload.len() < 65536);
            writer.write_u16::<NetworkEndian>(self.payload.len() as u16)?;
        }
        writer.write_all(&self.payload)?;
        if !self.command.is_variable_length() {
            assert!(self.payload.len() <= PAYLOAD_LEN);
            let padding_length = PAYLOAD_LEN - self.payload.len();
            let mut zeroes: Vec<u8> = Vec::with_capacity(padding_length);
            zeroes.resize(padding_length, 0);
            writer.write_all(&zeroes)?;
        }
        Ok(())
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
    pub fn read_new<R: Read>(reader: &mut R) -> Result<RawCert> {
        let cert_type_byte = reader.read_u8()?;
        let length = reader.read_u16::<NetworkEndian>()? as usize;
        let mut cert = RawCert {
            cert_type: CertType::from_u8(cert_type_byte),
            bytes: Vec::with_capacity(length),
        };
        cert.bytes.resize(length, 0);
        reader.read_exact(cert.bytes.as_mut_slice())?;
        Ok(cert)
    }

    pub fn new(cert_type: CertType, bytes: Vec<u8>) -> RawCert {
        RawCert {
            cert_type: cert_type,
            bytes: bytes,
        }
    }

    pub fn write_to<W: Write>(&self, writer: &mut W) -> Result<()> {
        writer.write_u8(self.cert_type.as_u8())?;
        assert!(self.bytes.len() < 65536);
        writer.write_u16::<NetworkEndian>(self.bytes.len() as u16)?;
        writer.write_all(&self.bytes)
    }
}

#[derive(Debug)]
pub struct CertsCell {
    certs: Vec<RawCert>,
}

impl CertsCell {
    pub fn read_new<R: Read>(reader: &mut R) -> Result<CertsCell> {
        let num_certs = reader.read_u8()?;
        let mut certs: Vec<RawCert> = Vec::with_capacity(num_certs as usize);
        for _ in 0..num_certs {
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
            // Hmmm. This seems less obvious to me now.
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

    pub fn write_to<W: Write>(&self, writer: &mut W) -> Result<()> {
        assert!(self.certs.len() < 256);
        writer.write_u8(self.certs.len() as u8)?;
        for cert in &self.certs {
            cert.write_to(writer)?;
        }
        Ok(())
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

    pub fn write_to<W: Write>(&self, writer: &mut W) -> Result<()> {
        writer.write_u16::<NetworkEndian>(self.auth_type.as_u16())?;
        assert!(self.authentication.len() < 65536);
        writer.write_u16::<NetworkEndian>(self.authentication.len() as u16)?;
        writer.write_all(&self.authentication)
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
    pub fn read_new<R: Read>(reader: &mut R) -> Result<AuthChallengeCell> {
        let mut auth_challenge_cell = AuthChallengeCell {
            challenge: [0; 32],
            methods: Vec::new(),
        };
        reader.read_exact(&mut auth_challenge_cell.challenge)?;
        let num_methods = reader.read_u16::<NetworkEndian>()?;
        // There are only two methods possible. Should we validate this?
        for _ in 0..num_methods {
            let method = reader.read_u16::<NetworkEndian>()?;
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
    pub fn read_new<R: Read>(reader: &mut R) -> Result<OrAddress> {
        // These are TLV encoded, with one byte each for type and length.
        let address_type = reader.read_u8()?;
        let address_length = reader.read_u8()?;
        Ok(match address_type {
            0 => {
                let mut buf: Vec<u8> = Vec::with_capacity(address_length as usize);
                buf.resize(address_length as usize, 0);
                reader.read_exact(&mut buf)?;
                let result = match String::from_utf8(buf) {
                    Ok(string) => string,
                    Err(e) => return Err(Error::new(ErrorKind::InvalidData, e)),
                };
                OrAddress::Hostname(result.to_owned())
            }
            4 => {
                let mut dest = [0; 4];
                reader.read_exact(&mut dest)?;
                OrAddress::IPv4Address(dest)
            }
            6 => {
                let mut dest = [0; 16];
                reader.read_exact(&mut dest)?;
                OrAddress::IPv6Address(dest)
            }
            0xf0 => {
                // We have to drop these bytes.
                let mut buf: Vec<u8> = Vec::with_capacity(address_length as usize);
                buf.resize(address_length as usize, 0);
                reader.read_exact(&mut buf)?;
                OrAddress::TransientError
            }
            0xf1 => {
                // We have to drop these bytes.
                let mut buf: Vec<u8> = Vec::with_capacity(address_length as usize);
                buf.resize(address_length as usize, 0);
                reader.read_exact(&mut buf)?;
                OrAddress::NontransientError
            }
            _ => OrAddress::Unknown(address_type), // TODO: still read the length and value?
        })
    }

    pub fn write_to<W: Write>(&self, writer: &mut W) -> Result<()> {
        match self {
            &OrAddress::Hostname(ref string) => {
                writer.write_u8(0)?;
                let bytes = string.as_bytes();
                assert!(bytes.len() < 256);
                writer.write_u8(bytes.len() as u8)?;
                writer.write_all(bytes)
            }
            &OrAddress::IPv4Address(bytes) => {
                writer.write_u8(4)?;
                writer.write_all(&bytes)
            }
            &OrAddress::IPv6Address(bytes) => {
                writer.write_u8(6)?;
                writer.write_all(&bytes)
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
    pub fn read_new<R: Read>(reader: &mut R) -> Result<NetinfoCell> {
        let timestamp = reader.read_u32::<NetworkEndian>()?;
        let other_or_address = OrAddress::read_new(reader)?;
        let num_addresses = reader.read_u8()?;
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

    pub fn write_to<W: Write>(&self, writer: &mut W) -> Result<()> {
        writer.write_u32::<NetworkEndian>(self.timestamp)?;
        self.other_or_address.write_to(writer)?;
        assert!(self.this_or_addresses.len() < 256);
        writer.write_u8(self.this_or_addresses.len() as u8)?;
        for address in &self.this_or_addresses {
            address.write_to(writer)?;
        }
        Ok(())
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

pub struct RelayCell {
    pub relay_command: RelayCommand,
    recognized: u16,
    stream_id: u16,
    digest: u32,
    length: u16,
    pub data: Vec<u8>,
}

#[derive(Clone, Debug)]
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

    pub fn as_u8(&self) -> u8 {
        match self {
            &RelayCommand::Begin => 1,
            &RelayCommand::Data => 2,
            &RelayCommand::End => 3,
            &RelayCommand::Connected => 4,
            &RelayCommand::SendMe => 5,
            &RelayCommand::Extend => 6,
            &RelayCommand::Extended => 7,
            &RelayCommand::Truncate => 8,
            &RelayCommand::Truncated => 9,
            &RelayCommand::Drop => 10,
            &RelayCommand::Resolve => 11,
            &RelayCommand::Resolved => 12,
            &RelayCommand::BeginDir => 13,
            &RelayCommand::Extend2 => 14,
            &RelayCommand::Extended2 => 15,
            &RelayCommand::Unknown(value) => value,
        }
    }
}

impl RelayCell {
    // Maybe pass expected digest here so we can validate that too?
    // (as is this can erroneously be "recognized" 1/256^2 of the time)
    pub fn read_new<R: Read>(reader: &mut R) -> Result<RelayCell> {
        let relay_command_byte = reader.read_u8()?;
        let relay_command = RelayCommand::from_u8(relay_command_byte);
        let recognized = reader.read_u16::<NetworkEndian>()?;
        let stream_id = reader.read_u16::<NetworkEndian>()?;
        let digest = reader.read_u32::<NetworkEndian>()?;
        // This isn't making much sense to me. For DATA cells, the length field doesn't seem to
        // correspond to... anything?
        let length = reader.read_u16::<NetworkEndian>()?;
        // So, we have an indication of the length of the data in the relay cell, but there's
        // actually always supposed to be PAYLOAD_LEN - 11 bytes (the rest padded 0 I suppose).
        let mut data: Vec<u8> = Vec::with_capacity(PAYLOAD_LEN - 11);
        data.resize(PAYLOAD_LEN - 11, 0);
        reader.read_exact(&mut data)?;
        Ok(RelayCell {
            relay_command: relay_command,
            recognized: recognized,
            stream_id: stream_id,
            digest: digest,
            length: length,
            data: data,
        })
    }

    /// Creates a new `RelayCell` with the digest set to 0. Call `set_digest` with the appropriate
    /// running digest to set its value (which is calculated in part based on the rest of the bytes
    /// of the `RelayCell`, with the digest set to 0).
    pub fn new(relay_command: RelayCommand, stream_id: u16, data: Vec<u8>) -> RelayCell {
        assert!(data.len() <= PAYLOAD_LEN - 11);
        RelayCell {
            relay_command: relay_command,
            recognized: 0,
            stream_id: stream_id,
            digest: 0,
            length: data.len() as u16,
            data: data,
        }
    }

    pub fn set_digest(&mut self, digest: &mut Sha1) {
        // This should only be called if the digest hasn't been set or read from the wire.
        assert!(self.digest == 0);
        // It would be neat if Sha1 implemented Write, so we could just self.write_to(digest), but
        // we can fake it here.
        let mut buf = Vec::new();
        self.write_to(&mut buf).unwrap();
        digest.update(&buf);
        let result = digest.digest().bytes();
        self.digest = (&mut &result[..]).read_u32::<NetworkEndian>().unwrap();
    }

    pub fn write_to<W: Write>(&self, writer: &mut W) -> Result<()> {
        writer.write_u8(self.relay_command.as_u8())?;
        writer.write_u16::<NetworkEndian>(self.recognized)?;
        writer.write_u16::<NetworkEndian>(self.stream_id)?;
        writer.write_u32::<NetworkEndian>(self.digest)?;
        writer.write_u16::<NetworkEndian>(self.length)?;
        // This always gets padded with 0 bytes to PAYLOAD_LEN - 11 bytes
        writer.write_all(&self.data)?;
        // TODO: this should be a const
        if self.data.len() < PAYLOAD_LEN - 11 {
            let padding_size = PAYLOAD_LEN - 11 - self.data.len();
            let mut zeroes = Vec::with_capacity(padding_size);
            zeroes.resize(padding_size, 0);
            writer.write_all(&zeroes)?;
        }
        Ok(())
    }
}

impl fmt::Display for RelayCell {
    fn fmt(&self, dest: &mut fmt::Formatter) -> fmt::Result {
        write!(
            dest,
            "RelayCell {{ {:?} {} {} {} {} ",
            self.relay_command, self.recognized, self.stream_id, self.digest, self.length
        )?;
        for b in &self.data {
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

    pub fn as_u16(&self) -> u16 {
        match self {
            &ClientHandshakeType::Tap => 0,
            &ClientHandshakeType::Reserved => 1,
            &ClientHandshakeType::Ntor => 2,
            &ClientHandshakeType::Unknown(value) => value,
        }
    }
}

#[derive(Debug)]
pub struct Create2Cell {
    h_type: ClientHandshakeType,
    h_len: u16,
    h_data: Vec<u8>,
}

impl Create2Cell {
    pub fn read_new<R: Read>(reader: &mut R) -> Result<Create2Cell> {
        let h_type_raw = reader.read_u16::<NetworkEndian>()?;
        let h_len = reader.read_u16::<NetworkEndian>()?;
        let mut h_data: Vec<u8> = Vec::with_capacity(h_len as usize);
        h_data.resize(h_len as usize, 0);
        reader.read_exact(&mut h_data)?;
        Ok(Create2Cell {
            h_type: ClientHandshakeType::from_u16(h_type_raw),
            h_len: h_len,
            h_data: h_data,
        })
    }

    pub fn new(h_type: ClientHandshakeType, h_data: Vec<u8>) -> Create2Cell {
        assert!(h_data.len() < 65536);
        Create2Cell {
            h_type: h_type,
            h_len: h_data.len() as u16,
            h_data: h_data,
        }
    }

    pub fn write_to<W: Write>(&self, writer: &mut W) -> Result<()> {
        writer.write_u16::<NetworkEndian>(self.h_type.as_u16())?;
        assert!(self.h_data.len() < 65536);
        writer.write_u16::<NetworkEndian>(self.h_data.len() as u16)?;
        writer.write_all(&self.h_data)
    }

    pub fn get_h_data(&self) -> &[u8] {
        &self.h_data
    }
}

#[derive(Debug)]
pub struct NtorClientHandshake {
    node_id: [u8; 20],
    key_id: [u8; 32],
    client_pk: [u8; 32],
}

impl NtorClientHandshake {
    pub fn read_new<R: Read>(reader: &mut R) -> Result<NtorClientHandshake> {
        let mut handshake = NtorClientHandshake {
            node_id: [0; 20],
            key_id: [0; 32],
            client_pk: [0; 32],
        };
        reader.read_exact(&mut handshake.node_id)?;
        reader.read_exact(&mut handshake.key_id)?;
        reader.read_exact(&mut handshake.client_pk)?;
        Ok(handshake)
    }

    pub fn new(peer: &dir::TorPeer, client_key: &keys::Curve25519Keypair) -> NtorClientHandshake {
        NtorClientHandshake {
            node_id: peer.get_node_id(),
            key_id: peer.get_ntor_key(),
            client_pk: client_key.get_public_key_bytes(),
        }
    }

    pub fn write_to<W: Write>(&self, writer: &mut W) -> Result<()> {
        writer.write_all(&self.node_id)?;
        writer.write_all(&self.key_id)?;
        writer.write_all(&self.client_pk)
    }
}

#[derive(Debug)]
pub struct Created2Cell {
    h_len: u16,
    pub h_data: Vec<u8>,
}

impl Created2Cell {
    pub fn read_new<R: Read>(reader: &mut R) -> Result<Created2Cell> {
        let h_len = reader.read_u16::<NetworkEndian>()?;
        let mut h_data: Vec<u8> = Vec::with_capacity(h_len as usize);
        h_data.resize(h_len as usize, 0);
        reader.read_exact(&mut h_data)?;
        Ok(Created2Cell {
            h_len: h_len,
            h_data: h_data,
        })
    }
}

#[derive(Debug)]
pub struct NtorServerHandshake {
    pub server_pk: [u8; 32],
    pub auth: [u8; 32],
}

impl NtorServerHandshake {
    pub fn read_new<R: Read>(reader: &mut R) -> Result<NtorServerHandshake> {
        let mut handshake = NtorServerHandshake {
            server_pk: [0; 32],
            auth: [0; 32],
        };
        reader.read_exact(&mut handshake.server_pk)?;
        reader.read_exact(&mut handshake.auth)?;
        Ok(handshake)
    }
}

#[derive(Debug)]
pub struct VersionsCell {
    versions: Vec<u16>,
}

impl VersionsCell {
    pub fn new(versions: Vec<u16>) -> VersionsCell {
        // we really only support v3, 4, 5 (and we really don't do much validation...)
        assert!(versions.len() < 3);
        VersionsCell { versions: versions }
    }

    pub fn write_to<W: Write>(&self, writer: &mut W) -> Result<()> {
        // a VERSIONS cell is variable-length and has CIRCID_LEN equal to 2.
        // Thus:
        // CircID     [2 bytes]
        // Command(7) [1 bytes]
        // Length     [2 bytes]
        // Payload    [Length bytes]
        // (where the payload is a sequence of 2-byte big-endian version numbers)
        // I think CircID is supposed to be 0, but it's unclear if that's specified.
        writer.write_u16::<NetworkEndian>(0)?;
        // 7 is VERSIONS
        writer.write_u8(7)?;
        // Payload length is 2 bytes.
        assert!(self.versions.len() < 65536 / 2);
        writer.write_u16::<NetworkEndian>(2 * self.versions.len() as u16)?;
        for version in &self.versions {
            writer.write_u16::<NetworkEndian>(*version)?;
        }
        Ok(())
    }

    pub fn read_new<R: Read>(reader: &mut R) -> Result<VersionsCell> {
        // TODO
        let circ_id = reader.read_u16::<NetworkEndian>()?;
        assert!(circ_id == 0);
        let command = reader.read_u8()?;
        // TODO
        assert!(command == 7);
        let length = reader.read_u16::<NetworkEndian>()?;
        // TODO
        assert!(length <= 6);
        // TODO
        assert!(length % 2 == 0);
        let mut versions = Vec::new();
        for _ in 0..length / 2 {
            let version = reader.read_u16::<NetworkEndian>()?;
            // check highest byte is 0
            versions.push(version);
        }
        Ok(VersionsCell { versions: versions })
    }

    /// tor-spec.txt, section 4:
    /// Both parties MUST select as the link protocol version the highest number contained both in
    /// the VERSIONS cell they sent and in the versions cell they received. If they have no such
    /// version in common, they cannot communicate and MUST close the connection.
    pub fn negotiate(&self, other: &VersionsCell) -> Result<u16> {
        let mut highest: u16 = 0;
        for self_version in &self.versions {
            if *self_version > highest && other.versions.contains(self_version) {
                highest = *self_version;
            }
        }
        // In reality we only support version 4 right now.
        // TODO
        assert!(highest == 4);
        Ok(highest)
    }
}

pub struct CreateFastCell {
    x: [u8; 20],
}

impl CreateFastCell {
    pub fn new(x: [u8; 20]) -> CreateFastCell {
        CreateFastCell { x: x }
    }

    pub fn write_to<W: Write>(&self, writer: &mut W) -> Result<()> {
        writer.write_all(&self.x)
    }
}

#[derive(Debug)]
pub struct CreatedFastCell {
    y: [u8; 20],
    kh: [u8; 20],
}

impl CreatedFastCell {
    pub fn read_new<R: Read>(reader: &mut R) -> Result<CreatedFastCell> {
        let mut created_fast_cell = CreatedFastCell {
            y: [0; 20],
            kh: [0; 20],
        };
        reader.read_exact(&mut created_fast_cell.y)?;
        reader.read_exact(&mut created_fast_cell.kh)?;
        Ok(created_fast_cell)
    }

    pub fn get_y(&self) -> &[u8; 20] {
        &self.y
    }

    pub fn get_kh(&self) -> &[u8; 20] {
        &self.kh
    }
}

#[derive(Debug)]
pub struct Extend2Cell {
    /// The Ed25519 identity key of the node being extended to.
    ed25519_identity: [u8; 32],
    /// SHA-1 hash of RSA identity key. Mandatory for some reason (but not specified?)
    rsa_id: [u8; 20],
    /// IPv4 address of node being extended to (again mandatory but not specified?)
    /// (do we have to worry about endianness here?)
    ipv4: [u8; 4],
    /// (port for the above)
    port: u16,
    /// In reality, always ClientHandshakeType::Ntor
    h_type: ClientHandshakeType,
    h_data: Vec<u8>,
}

impl Extend2Cell {
    pub fn new(node: &dir::TorPeer, h_type: ClientHandshakeType, h_data: Vec<u8>) -> Extend2Cell {
        Extend2Cell {
            ed25519_identity: node.get_ed25519_id_key(),
            rsa_id: node.get_node_id(),
            ipv4: node.get_ipv4_as_bytes(),
            port: node.get_port(),
            h_type: h_type,
            h_data: h_data,
        }
    }

    pub fn write_to<W: Write>(&self, writer: &mut W) -> Result<()> {
        // 3 link specifiers
        writer.write_u8(3)?;
        // IPv4 address
        writer.write_u8(0)?;
        writer.write_u8(6)?; // 4 bytes for IPv4 plus 2 bytes for port
        writer.write_all(&self.ipv4)?;
        writer.write_u16::<NetworkEndian>(self.port)?;
        // RSA ID hash
        writer.write_u8(2)?;
        writer.write_u8(20)?;
        writer.write_all(&self.rsa_id)?;
        // Ed25519 public key (docs say fingerprint but that's wrong)
        writer.write_u8(3)?;
        writer.write_u8(32)?; // Ed25519 public key is 32 bytes
        writer.write_all(&self.ed25519_identity)?;

        writer.write_u16::<NetworkEndian>(self.h_type.as_u16())?;
        assert!(self.h_data.len() < 65536);
        writer.write_u16::<NetworkEndian>(self.h_data.len() as u16)?;
        writer.write_all(&self.h_data)
    }
}

// This is really just a placeholder.
#[derive(Debug)]
pub enum BeginFlags {
    None,
}

impl BeginFlags {
    fn as_u32(&self) -> u32 {
        match self {
            &BeginFlags::None => 0,
        }
    }
}

#[derive(Debug)]
pub struct BeginCell {
    addrport: String,  // eh... make this less opaque in the future?
    flags: BeginFlags, // TODO
}

impl BeginCell {
    pub fn new(addrport: &str) -> BeginCell {
        BeginCell {
            addrport: addrport.to_string(),
            flags: BeginFlags::None,
        }
    }

    pub fn write_to<W: Write>(&self, writer: &mut W) -> Result<()> {
        writer.write_all(self.addrport.as_bytes())?;
        writer.write_u8(0)?; // null-terminate the string
        writer.write_u32::<NetworkEndian>(self.flags.as_u32())
    }
}

// TODO...
/*
pub struct ConnectedCell {

}

pub enum RelayEndReason {
}
*/
