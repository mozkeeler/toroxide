use curl::easy::Easy;
use std::net::{IpAddr, Ipv4Addr, SocketAddr, ToSocketAddrs};
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
        transfer
            .write_function(|new_data| {
                data.extend_from_slice(new_data);
                Ok(new_data.len())
            })
            .unwrap();
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
    /// I don't know what this is for.
    rsa_public_key: Vec<u8>,
    /// Ntor handshake key, right?
    ntor_onion_key: [u8; 32],
    /// sha-1 hash of the peer's RSA ID key (not the above rsa_public_key)
    node_id: [u8; 20],
    /// Ed25519 identity public key
    ed25519_id_key: [u8; 32],
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
        let keys_uri = format!(
            "http://localhost:7000/tor/micro/d/{}",
            m_hash_line.split(" ").nth(1).unwrap()
        );
        let keys_data = do_get(&keys_uri);
        let mut ntor_onion_key: [u8; 32] = [0; 32];
        let mut ed25519_id_key: [u8; 32] = [0; 32];
        let mut in_rsa_key = false;
        let mut rsa_public_key_base64 = String::new();
        for line in keys_data.lines() {
            if line == "-----END RSA PUBLIC KEY-----" {
                in_rsa_key = false;
            }
            if in_rsa_key {
                rsa_public_key_base64.push_str(line);
            }
            if line == "-----BEGIN RSA PUBLIC KEY-----" {
                in_rsa_key = true;
            }
            if line.starts_with("ntor-onion-key") {
                ntor_onion_key = util::slice_to_32_byte_array(&base64::decode(
                    line.split(" ").nth(1).unwrap(),
                ).unwrap());
            }
            if line.starts_with("id ed25519") {
                ed25519_id_key = util::slice_to_32_byte_array(&base64::decode(
                    line.split(" ").nth(2).unwrap(),
                ).unwrap());
            }
        }
        let router_parts: Vec<&str> = router_line.split(" ").collect();
        let node_id: [u8; 20] =
            util::slice_to_20_byte_array(&base64::decode(router_parts[2]).unwrap());
        TorPeer {
            ip_address: router_parts[5].parse().unwrap(),
            port: u16::from_str(router_parts[6]).unwrap(),
            rsa_public_key: base64::decode(&rsa_public_key_base64).unwrap(),
            ntor_onion_key: ntor_onion_key,
            node_id: node_id,
            ed25519_id_key: ed25519_id_key,
        }
    }

    /// Get the sha-1 hash of the node's RSA identity key. For use in the Ntor handshake.
    pub fn get_node_id(&self) -> [u8; 20] {
        self.node_id
    }

    /// Get the node's public Ntor key. For use in the Ntor handshake.
    pub fn get_ed25519_id_key(&self) -> [u8; 32] {
        self.ed25519_id_key
    }

    pub fn get_ipv4_as_bytes(&self) -> [u8; 4] {
        self.ip_address.octets()
    }

    pub fn get_port(&self) -> u16 {
        self.port
    }
}

impl ToSocketAddrs for TorPeer {
    type Iter = option::IntoIter<SocketAddr>;
    fn to_socket_addrs(&self) -> io::Result<option::IntoIter<SocketAddr>> {
        let addr = SocketAddr::new(IpAddr::V4(self.ip_address), self.port);
        addr.to_socket_addrs()
    }
}
