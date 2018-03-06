use curl::easy::Easy;
use std::iter::FromIterator;
use std::collections::HashSet;
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

pub fn get_tor_peers(hostport: &str) -> TorPeerList {
    let uri = format!(
        "http://{}/tor/status-vote/current/consensus-microdesc/",
        hostport
    );
    TorPeerList::new(hostport, PreTorPeer::parse_all(do_get(&uri)))
}

#[derive(Debug)]
pub struct TorPeerList {
    hostport: String,
    peers: HashSet<PreTorPeer>,
}

impl TorPeerList {
    fn new(hostport: &str, peer_list: Vec<PreTorPeer>) -> TorPeerList {
        TorPeerList {
            hostport: hostport.to_owned(),
            peers: HashSet::from_iter(peer_list),
        }
    }

    pub fn get_guard_node(&mut self) -> Option<TorPeer> {
        let node = match self.peers
            .iter()
            .find(|node| node.is_usable && node.is_guard)
        {
            Some(node) => node.clone(),
            None => return None,
        };
        if let Some(taken) = self.peers.take(&node) {
            Some(taken.to_tor_peer(&self.hostport))
        } else {
            None // this shouldn't happen but still
        }
    }

    pub fn get_interior_node(&mut self) -> Option<TorPeer> {
        let node = match self.peers.iter().find(|node| node.is_usable) {
            Some(node) => node.clone(),
            None => return None,
        };
        if let Some(taken) = self.peers.take(&node) {
            Some(taken.to_tor_peer(&self.hostport))
        } else {
            None // this shouldn't happen but still
        }
    }

    pub fn get_exit_node(&mut self) -> Option<TorPeer> {
        let node = match self.peers
            .iter()
            .find(|node| node.is_usable && node.is_exit)
        {
            Some(node) => node.clone(),
            None => return None,
        };
        if let Some(taken) = self.peers.take(&node) {
            Some(taken.to_tor_peer(&self.hostport))
        } else {
            None // this shouldn't happen but still
        }
    }
}

#[derive(Debug, PartialEq, Eq, Hash, Clone)]
struct PreTorPeer {
    /// The microdescriptor hash string as parsed out of the "m somebase64..." line.
    mdesc_hash: String,
    ip_address: Ipv4Addr,
    node_id: [u8; 20],
    port: u16,
    /// Is this an exit node?
    is_exit: bool,
    /// Is this a guard node?
    is_guard: bool,
    /// Is this node running and valid?
    is_usable: bool,
}

impl PreTorPeer {
    fn parse_all(response_string: String) -> Vec<PreTorPeer> {
        let mut microdescs = Vec::new();
        let mut router_line: Option<&str> = None;
        let mut mdesc_line: Option<&str> = None;
        let mut flags_line: Option<&str> = None;
        // TODO: so this doesn't protect against misordered lines... (maybe verify signature first?)
        // (probably still want to validate the structure of the data too...)
        for line in response_string.lines() {
            if line.starts_with("r ") && router_line.is_none() {
                router_line = Some(line);
            }
            if line.starts_with("m ") && mdesc_line.is_none() {
                mdesc_line = Some(line);
            }
            if line.starts_with("s ") && flags_line.is_none() {
                flags_line = Some(line);
            }
            if router_line.is_some() && mdesc_line.is_some() && flags_line.is_some() {
                microdescs.push(PreTorPeer::new(
                    router_line.take().unwrap(),
                    mdesc_line.take().unwrap(),
                    flags_line.take().unwrap(),
                ));
            }
        }
        microdescs
    }

    fn new(router_line: &str, m_hash_line: &str, flags_line: &str) -> PreTorPeer {
        let mut flags = flags_line.split(" ");
        let router_parts: Vec<&str> = router_line.split(" ").collect();
        let node_id: [u8; 20] =
            util::slice_to_20_byte_array(&base64::decode(router_parts[2]).unwrap());
        PreTorPeer {
            mdesc_hash: m_hash_line.split(" ").nth(1).unwrap().to_owned(),
            ip_address: router_parts[5].parse().unwrap(),
            port: u16::from_str(router_parts[6]).unwrap(),
            node_id: node_id,
            is_exit: flags.find(|s| s == &"Exit").is_some(),
            is_guard: flags.find(|s| s == &"Guard").is_some(),
            is_usable: flags.find(|s| s == &"Running").is_some()
                && flags.find(|s| s == &"Valid").is_some(),
        }
    }

    fn to_tor_peer(&self, hostport: &str) -> TorPeer {
        let keys_uri = format!("http://{}/tor/micro/d/{}", hostport, self.mdesc_hash);
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
        TorPeer {
            ip_address: self.ip_address,
            port: self.port,
            rsa_public_key: base64::decode(&rsa_public_key_base64).unwrap(),
            ntor_onion_key: ntor_onion_key,
            ed25519_id_key: ed25519_id_key,
            node_id: self.node_id,
        }
    }
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
    /// Get the sha-1 hash of the node's RSA identity key. For use in the Ntor handshake.
    pub fn get_node_id(&self) -> [u8; 20] {
        self.node_id
    }

    /// Get the node's public Ntor key. For use in the Ntor handshake.
    pub fn get_ntor_key(&self) -> [u8; 32] {
        self.ntor_onion_key
    }

    /// Get the node's public Ed25519 identity key. For use in the link handshake.
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
