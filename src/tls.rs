use base64;
use openssl::ssl::{Ssl, SslContext, SslStream, SslMethod, SslVerifyMode};
use std::net::TcpStream;

use dir::TorPeer;

pub struct TlsConnection {
    stream: SslStream<TcpStream>,
}

impl TlsConnection {
    pub fn new(tor_peer: &TorPeer) -> TlsConnection {
        let mut stream = TcpStream::connect(tor_peer).unwrap();
        let mut ssl_context_builder = SslContext::builder(SslMethod::tls()).unwrap();
        let expected_public_key = tor_peer.rsa_public_key.clone();
        ssl_context_builder.set_verify_callback(SslVerifyMode::PEER, move |_, x509_store_ctx| {
            // bruh.
            if let Some(chain) = x509_store_ctx.chain() {
                if let Some(cert) = chain.iter().nth(0) {
                    if let Ok(key) = cert.public_key() {
                        if let Ok(der) = key.public_key_to_der() {
                            // So, what's going on is the server certificate doesn't have the key
                            // that's in the microdescriptor. Presumably it's been *signed* by that
                            // key, though, so we have to validate the certificate's signature using
                            // it :(
                            println!("{:?}", der);
                            println!("{:?}", expected_public_key);
                            return der == expected_public_key;
                        }
                    }
                }
            }
            false
        });
        let mut ssl_context = ssl_context_builder.build();
        let ssl = Ssl::new(&ssl_context).unwrap();
        TlsConnection {
            stream: ssl.connect(stream).unwrap(),
        }
    }
}
