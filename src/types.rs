use std::fmt;
use std::str;
use std::io::Read;

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
            _ => Command::Unknown(command),
        }
    }
}

impl Cell {
    pub fn read_new<R: Read>(reader: &mut R) -> Result<Cell, &'static str> {
        let mut four_byte_buf: [u8; 4] = [0; 4];
        if let Err(_) = reader.read_exact(&mut four_byte_buf) {
            return Err("failed to read CircID");
        }
        let circ_id = ((four_byte_buf[0] as u32) << 24) + ((four_byte_buf[1] as u32) << 16)
            + ((four_byte_buf[2] as u32) << 8) + (four_byte_buf[3] as u32); // endian-ness?
        let mut one_byte_buf = [0; 1];
        if let Err(_) = reader.read_exact(&mut one_byte_buf) {
            return Err("failed to read command");
        }
        let command = Command::from_u8(one_byte_buf[0]);
        let mut payload: Vec<u8> = Vec::with_capacity(PAYLOAD_LEN);
        payload.resize(PAYLOAD_LEN, 0);
        if let Err(_) = reader.read_exact(payload.as_mut_slice()) {
            return Err("failed to read payload");
        }
        Ok(Cell {
            circ_id: circ_id,
            command: command,
            payload: payload,
        })
    }
}

// Useful for reading something of an unknown size from a slice of bytes and then continuing to read
// the bytes after that something (where it internally knows how large it is).
pub struct Cursor<'a> {
    position: usize,
    bytes: &'a [u8],
}

impl<'a> Cursor<'a> {
    pub fn new(bytes: &'a [u8]) -> Cursor<'a> {
        Cursor {
            position: 0,
            bytes: bytes,
        }
    }

    pub fn remaining(&self) -> usize {
        assert!(self.position <= self.bytes.len());
        self.bytes.len() - self.position
    }

    pub fn read_byte(&mut self) -> Result<u8, &'static str> {
        if self.remaining() < 1 {
            return Err("input not long enough");
        }
        self.position += 1;
        Ok(self.bytes[self.position - 1])
    }

    pub fn read_slice(&mut self, length: usize) -> Result<&'a [u8], &'static str> {
        if self.remaining() < length {
            return Err("input not long enough");
        }
        self.position += length;
        Ok(&self.bytes[self.position - length..self.position])
    }

    pub fn advance(&mut self, length: usize) -> Result<(), &'static str> {
        if self.remaining() < length {
            return Err("input not long enough");
        }
        self.position += length;
        Ok(())
    }
}

#[derive(Debug)]
pub enum OrAddress {
    Hostname(String),
    IPv4Address([u8; 4]),
    IPv6Address([u8; 16]),
    TransientError,
    NontransientError,
    Unknown(u8),
}

impl OrAddress {
    pub fn from_cursor(cursor: &mut Cursor) -> Result<OrAddress, &'static str> {
        // These are TLV encoded, with one byte each for type and length.
        let address_type = cursor.read_byte()?;
        let address_length = cursor.read_byte()?;
        Ok(match address_type {
            0 => {
                let result = str::from_utf8(cursor.read_slice(address_length as usize)?);
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
                // there has to be a better way of doing this
                let mut dest = [0; 4];
                dest[0] = cursor.read_byte()?;
                dest[1] = cursor.read_byte()?;
                dest[2] = cursor.read_byte()?;
                dest[3] = cursor.read_byte()?;
                OrAddress::IPv4Address(dest)
            }
            6 => {
                if address_length != 16 {
                    return Err("malformed ipv6 in OrAddress");
                }
                // there has to be a better way of doing this
                let mut dest = [0; 16];
                for i in 0..16 {
                    dest[i] = cursor.read_byte()?;
                }
                OrAddress::IPv6Address(dest)
            }
            0xf0 => {
                cursor.advance(address_length as usize)?;
                OrAddress::TransientError
            }
            0xf1 => {
                cursor.advance(address_length as usize)?;
                OrAddress::NontransientError
            }
            _ => OrAddress::Unknown(address_type),
        })
    }
}

#[derive(Debug)]
pub struct NetinfoCell {
    timestamp: u32,
    other_or_address: OrAddress,
    num_addresses: u8,
    this_or_addresses: Vec<OrAddress>,
}

impl NetinfoCell {
    pub fn from_slice(bytes: &[u8]) -> Result<NetinfoCell, &'static str> {
        if bytes.len() < 4 {
            return Err("input not long enough for NetinfoCell");
        }
        // refactor me, etc.
        let timestamp = ((bytes[0] as u32) << 24) + ((bytes[1] as u32) << 16)
            + ((bytes[2] as u32) << 8) + (bytes[3] as u32); // big-endian
        let mut cursor = Cursor::new(&bytes[4..]);
        let other_or_address = OrAddress::from_cursor(&mut cursor)?;
        let num_addresses = cursor.read_byte()?;
        let mut this_or_addresses = Vec::new();
        for _ in 0..num_addresses {
            this_or_addresses.push(OrAddress::from_cursor(&mut cursor)?);
        }
        Ok(NetinfoCell {
            timestamp: timestamp,
            other_or_address: other_or_address,
            num_addresses: num_addresses,
            this_or_addresses: this_or_addresses,
        })
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
        let mut one_byte_buf = [0; 1];
        if let Err(_) = reader.read_exact(&mut two_byte_buf) {
            return Err("failed to read CircID");
        }
        // validate CircID == 0?
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
