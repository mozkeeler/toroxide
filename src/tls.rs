//use base64;
use openssl::ssl::{Ssl, SslContext, SslMethod, SslStream, SslVerifyMode};
use std::net::TcpStream;
use std::io::{Read, Result, Write};

use dir::TorPeer;

pub struct TlsConnection {
    stream: SslStream<TcpStream>,
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
        }
    }
}

impl Read for TlsConnection {
    fn read(&mut self, buf: &mut [u8]) -> Result<usize> {
        self.stream.read(buf)
    }
}

impl Write for TlsConnection {
    fn write(&mut self, data: &[u8]) -> Result<usize> {
        self.stream.write(data)
    }

    fn flush(&mut self) -> Result<()> {
        self.stream.flush()
    }
}
