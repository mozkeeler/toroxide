use openssl::ssl::{Ssl, SslContext, SslMethod, SslStream, SslVerifyMode};
use sha2::{Digest, Sha256};
use std::net::TcpStream;
use std::io::{Read, Result, Write};

use dir::TorPeer;

pub struct TlsConnection {
    stream: SslStream<TcpStream>,
    /// A running sha256 digest of all data read from the stream
    readlog: Sha256,
    /// A running sha256 digest of all data written to the stream
    writelog: Sha256,
}

impl TlsConnection {
    pub fn new(tor_peer: &TorPeer) -> TlsConnection {
        let stream = TcpStream::connect(tor_peer).unwrap();
        let mut ssl_context_builder = SslContext::builder(SslMethod::tls()).unwrap();
        ssl_context_builder.set_verify_callback(SslVerifyMode::PEER, |_, _| {
            // if we're doing a "in-protocol" handshake, we don't verify the peer's TLS certificate
            true
        });
        let ssl_context = ssl_context_builder.build();
        let ssl = Ssl::new(&ssl_context).unwrap();
        TlsConnection {
            stream: ssl.connect(stream).unwrap(),
            readlog: Sha256::new(),
            writelog: Sha256::new(),
        }
    }

    /// Get the sha-256 hash of all data read from the stream.
    pub fn get_read_digest(&self) -> Vec<u8> {
        // Clone self.readlog so calling .result() doesn't modify its state.
        let readlog = self.readlog.clone();
        let mut bytes: Vec<u8> = Vec::new();
        bytes.extend(readlog.result().into_iter());
        bytes
    }

    /// Get the sha-256 hash of all data written to the stream.
    pub fn get_write_digest(&self) -> Vec<u8> {
        // Clone self.writelog so calling .result() doesn't modify its state.
        let writelog = self.writelog.clone();
        let mut bytes: Vec<u8> = Vec::new();
        bytes.extend(writelog.result().into_iter());
        bytes
    }
}

impl Read for TlsConnection {
    fn read(&mut self, buf: &mut [u8]) -> Result<usize> {
        let result = self.stream.read(buf);
        if let &Ok(len) = &result {
            self.readlog.input(&buf[..len]);
        }
        result
    }
}

impl Write for TlsConnection {
    fn write(&mut self, data: &[u8]) -> Result<usize> {
        let result = self.stream.write(data);
        if let &Ok(len) = &result {
            self.writelog.input(&data[..len]);
        }
        result
    }

    fn flush(&mut self) -> Result<()> {
        self.stream.flush()
    }
}
