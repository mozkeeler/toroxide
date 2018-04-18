use base64;
use rand::{thread_rng, Rng};
use sha2::{Digest, Sha256};
use std::collections::HashSet;
use std::net::Ipv4Addr;
use std::str::FromStr;
use std::io::{Error, ErrorKind};

use util;

#[derive(Debug)]
pub struct TorPeerList {
    peers: HashSet<PreTorPeer>,
}

impl TorPeerList {
    pub fn new(consensus: &str) -> TorPeerList {
        let mut peers = HashSet::new();
        let mut router_line: Option<&str> = None;
        let mut mdesc_line: Option<&str> = None;
        let mut flags_line: Option<&str> = None;
        // TODO: so this doesn't protect against misordered lines... (maybe verify signature first?)
        // (probably still want to validate the structure of the data too...)
        for line in consensus.lines() {
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
                peers.insert(PreTorPeer::new(
                    router_line.take().unwrap(),
                    mdesc_line.take().unwrap(),
                    flags_line.take().unwrap(),
                ));
            }
        }
        TorPeerList {
            peers,
        }
    }

    pub fn get_guard_node(&self) -> Option<&PreTorPeer> {
        let candidates = self.peers
            .iter()
            .filter(|node| node.is_usable && node.is_guard);
        let mut collected: Vec<&PreTorPeer> = candidates.collect();
        thread_rng().shuffle(&mut collected);
        if collected.len() > 0 {
            Some(collected[0])
        } else {
            None
        }
    }

    pub fn get_interior_node(&self, blacklist: &[&PreTorPeer]) -> Option<&PreTorPeer> {
        self.peers.iter().find(|node| node.is_usable && node.not_in(blacklist))
    }

    pub fn get_exit_node(&self, blacklist: &[&PreTorPeer]) -> Option<&PreTorPeer> {
        self.peers.iter().find(|node| node.is_usable && node.is_exit && node.not_in(blacklist))
    }
}

#[derive(Debug, PartialEq, Eq, Hash, Clone)]
pub struct PreTorPeer {
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
                && flags.find(|s| s == &"Valid").is_some()
                && flags.find(|s| s== &"Authority").is_none(),
        }
    }

    pub fn get_microdescriptor_uri(&self, hostport: &str) -> String {
        format!("http://{}/tor/micro/d/{}", hostport, self.mdesc_hash)
    }

    pub fn get_microdescriptor_path(&self) -> String {
        format!("/tor/micro/d/{}", self.mdesc_hash)
    }

    // TODO: make an error type for this Result (or just use Error)
    pub fn to_tor_peer(&self, microdescriptor: &str) -> Result<TorPeer, Error> {
        // This is how we authenticate the returned data. The microdescriptor hash was part of the
        // signed consensus document, so if the hash of the data we get back matches that hash, then
        // the data is what went into the consensus, in theory.
        let hashed = Sha256::digest(microdescriptor.as_bytes());
        let hashed_encoded = base64::encode_config(&hashed, base64::STANDARD_NO_PAD);
        if hashed_encoded != self.mdesc_hash {
            return Err(Error::new(ErrorKind::Other, "microdescriptor hash mismatch"));
        }

        let mut ntor_onion_key: [u8; 32] = [0; 32];
        let mut ed25519_id_key: [u8; 32] = [0; 32];
        let mut in_rsa_key = false;
        let mut rsa_public_key_base64 = String::new();
        for line in microdescriptor.lines() {
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
        Ok(TorPeer {
            ip_address: self.ip_address,
            port: self.port,
            rsa_public_key: base64::decode(&rsa_public_key_base64).unwrap(),
            ntor_onion_key: ntor_onion_key,
            ed25519_id_key: ed25519_id_key,
            node_id: self.node_id,
        })
    }

    fn not_in(&self, blacklist: &[&PreTorPeer]) -> bool {
        for peer in blacklist {
            // TODO: something stronger than node_id?
            if self.node_id == peer.node_id {
                return false;
            }
        }
        true
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

    pub fn get_ip_addr(&self) -> Ipv4Addr {
        self.ip_address.clone()
    }

    pub fn get_port(&self) -> u16 {
        self.port
    }
}
