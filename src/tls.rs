use openssl::hash::MessageDigest;
use openssl::ssl::{Ssl, SslContext, SslMethod, SslStream, SslVerifyMode};
use sha2::{Digest, Sha256};
use std::io::{Read, Result, Write};
use std::net::TcpStream;
use std::time::Duration;

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

    /// Get the sha-256 hash of the peer's certificate.
    pub fn get_peer_cert_hash(&self) -> Vec<u8> {
        let peer_cert = self.stream.ssl().peer_certificate().unwrap();
        peer_cert.fingerprint(MessageDigest::sha256()).unwrap()
    }

    /// Get the TLSSECRETS bytes ala tor-spec.txt, section 4.4.2.
    /// (RFC5705 exporter using the label "EXPORTER FOR TOR TLS CLIENT BINDING AUTH0003", and the
    /// given context.
    pub fn get_tls_secrets(&mut self, context_key: &[u8]) -> Vec<u8> {
        let mut buf: Vec<u8> = Vec::with_capacity(32);
        buf.resize(32, 0);
        self.stream
            .ssl()
            .export_keying_material(
                &mut buf,
                "EXPORTER FOR TOR TLS CLIENT BINDING AUTH0003",
                Some(context_key),
            )
            .unwrap();
        buf
    }

    // "nonblocking" is a bit of a lie - it just means the read timeout is 16ms
    pub fn set_nonblocking(&mut self) {
        self.stream
            .get_mut()
            .set_read_timeout(Some(Duration::from_millis(16)))
            .unwrap();
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
