use curl::easy::Easy;
use std::net::{SocketAddr, IpAddr, Ipv4Addr, ToSocketAddrs};
use std::str::FromStr;
use std::option;
use std::io;
use base64;

use util;

// eventually we'll want to know *where* to get the peers from
// also async? also we're not even going to do this in the long run (we'll need some sort of
// get-this-using-your-own-http-client API or whatever)
fn do_get(uri: &str) -> String {
    let mut data = Vec::new();
    let mut handle = Easy::new();
    handle.url(uri).unwrap();
    {
        // Ok this is for sure poor API design, though.
        let mut transfer = handle.transfer();
        transfer.write_function(|new_data| {
            data.extend_from_slice(new_data);
            Ok(new_data.len())
        }).unwrap();
        transfer.perform().unwrap();
    }
    String::from_utf8(data).unwrap()
}

pub fn get_tor_peers() -> Vec<TorPeer> {
    let uri = "http://localhost:7000/tor/status-vote/current/consensus-microdesc/";
    TorPeer::parse_all(do_get(uri))
}

#[derive(Debug)]
pub struct TorPeer {
    ip_address: Ipv4Addr,
    port: u16,
    pub rsa_public_key: Vec<u8>,
    ntor_onion_key: [u8; 32],
}

impl TorPeer {
    fn parse_all(response_string: String) -> Vec<TorPeer> {
        let mut microdescs: Vec<TorPeer> = Vec::new();
        let (routers, m_hashes): (Vec<&str>, Vec<&str>) = response_string
            .lines()
            .filter(|&line| line.starts_with("r ") || line.starts_with("m "))
            .partition(|&line| line.starts_with("r "));
        // TODO: check that routers.len() == m_hashes.len()
        for (router_line, m_hash_line) in routers.iter().zip(m_hashes) {
            microdescs.push(TorPeer::new(router_line, m_hash_line));
        }
        microdescs
    }

    fn new(router_line: &str, m_hash_line: &str) -> TorPeer {
        let keys_uri = format!("http://localhost:7000/tor/micro/d/{}",
                               m_hash_line.split(" ").nth(1).unwrap());
        let keys_data = do_get(&keys_uri);
        let mut ntor_onion_key: [u8; 32] = [0; 32];
        let mut in_rsa_key = false;
        let mut rsa_public_key: Vec<u8> = Vec::new();
        for line in keys_data.lines() {
            if line == "-----END RSA PUBLIC KEY-----" {
                in_rsa_key = false;
            }
            if in_rsa_key {
                rsa_public_key.extend(base64::decode(line).unwrap());
            }
            if line == "-----BEGIN RSA PUBLIC KEY-----" {
                in_rsa_key = true;
            }
            if line.starts_with("ntor-onion-key") {
                ntor_onion_key = util::slice_to_32_byte_array(
                    &base64::decode(line.split(" ").nth(1).unwrap()).unwrap());
            }
        }
        let router_parts: Vec<&str> = router_line.split(" ").collect();
        TorPeer {
            ip_address: router_parts[5].parse().unwrap(),
            port: u16::from_str(router_parts[6]).unwrap(),
            rsa_public_key: rsa_public_key,
            ntor_onion_key: ntor_onion_key,
        }
    }
}

impl ToSocketAddrs for TorPeer {
    type Iter = option::IntoIter<SocketAddr>;
    fn to_socket_addrs(&self) -> io::Result<option::IntoIter<SocketAddr>> {
        let addr = SocketAddr::new(IpAddr::V4(self.ip_address), self.port);
        addr.to_socket_addrs()
    }
}
