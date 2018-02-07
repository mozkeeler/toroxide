extern crate curve25519_dalek;
extern crate hex;
extern crate hmac;
extern crate sha2;

mod types;

use curve25519_dalek::montgomery;
use curve25519_dalek::scalar;
use hmac::{Hmac, Mac};
use sha2::Sha256;
use std::io::prelude::*;
use std::io;
use std::ops::Mul;

#[allow(non_snake_case)]
struct NtorHandshakeContext {
    /// The SHA-1 hash of the router's RSA key
    router_id: [u8; 20],
    /// The client's ntor onion key "B" (public)
    client_B: [u8; 32],
    /// The ntor handshake public key "X"
    client_X: [u8; 32],
    /// The ntor handshake private key "x"
    client_x: [u8; 32],
}

fn main() {
    let mut ntor_context: Option<NtorHandshakeContext> = None;
    let stdin = io::stdin();
    for line in stdin.lock().lines() {
        let line = line.unwrap();
        if line.len() == 0 {
            break;
        }
        let parts: Vec<_> = line.split(":").collect();
        match parts[0] {
            "read" => decode_cell(parts[1], &ntor_context),
            "write" => decode_cell(parts[1], &ntor_context),
            "keygen" => ntor_context = Some(decode_keygen(&parts[1..])),
            _ => println!("unknown operation {}", parts[0]),
        }
    }
}

fn slice_to_20_byte_array(bytes: &[u8]) -> [u8; 20] {
    let mut fixed_size: [u8; 20] = [0; 20];
    fixed_size.copy_from_slice(&bytes);
    fixed_size
}

fn slice_to_32_byte_array(bytes: &[u8]) -> [u8; 32] {
    let mut fixed_size: [u8; 32] = [0; 32];
    fixed_size.copy_from_slice(&bytes);
    fixed_size
}

fn decode_keygen(keys_hex: &[&str]) -> NtorHandshakeContext {
    NtorHandshakeContext {
        router_id: slice_to_20_byte_array(&hex::decode(keys_hex[0]).unwrap()),
        client_B: slice_to_32_byte_array(&hex::decode(keys_hex[1]).unwrap()),
        client_X: slice_to_32_byte_array(&hex::decode(keys_hex[2]).unwrap()),
        client_x: slice_to_32_byte_array(&hex::decode(keys_hex[3]).unwrap()),
    }
}

fn curve25519_multiply(x: &montgomery::CompressedMontgomeryU, s: &scalar::Scalar) -> [u8; 32] {
    x.decompress().mul(s).compress().to_bytes()
}

fn hexdump(bytes: &[u8]) {
    for b in bytes {
        print!("{:02x}", b);
    }
    println!();
}

fn ntor_hmac(input: &[u8], context: &'static [u8]) -> Vec<u8> {
    let mut mac = Hmac::<Sha256>::new(context).unwrap(); // this can't possibly be right
    mac.input(input);
    let mut bytes: Vec<u8> = Vec::new();
    bytes.extend(mac.result().code().as_slice().iter());
    bytes
}

#[allow(non_snake_case)]
fn do_ntor_handshake(
    created2_cell: &types::Created2Cell,
    ntor_context: &Option<NtorHandshakeContext>)
{
    if let &Some(ref ntor_context) = ntor_context {
        println!("{:?}", created2_cell);
        // technically we should check the corresponding create2_cell type here
        let server_handshake =
            types::NtorServerHandshake::from_slice(created2_cell.h_data).unwrap();
        println!("{:?}", server_handshake);
        let Y = montgomery::CompressedMontgomeryU(server_handshake.server_pk);
        let x = scalar::Scalar::from_bits(ntor_context.client_x);
        let exp_Y_x = curve25519_multiply(&Y, &x);
        let B = montgomery::CompressedMontgomeryU(ntor_context.client_B);
        let exp_B_x = curve25519_multiply(&B, &x);
        let mut secret_input: Vec<u8> = Vec::new();
        secret_input.extend(exp_Y_x.iter());
        secret_input.extend(exp_B_x.iter());
        secret_input.extend(ntor_context.router_id.iter());
        secret_input.extend(ntor_context.client_B.iter());
        secret_input.extend(ntor_context.client_X.iter());
        secret_input.extend(server_handshake.server_pk.iter());
        secret_input.extend("ntor-curve25519-sha256-1".as_bytes());
        println!("secret input");
        hexdump(&secret_input);
        let verify = ntor_hmac(&secret_input, b"ntor-curve25519-sha256-1:verify");
        println!("verify");
        hexdump(&verify);
        let mut auth_input: Vec<u8> = Vec::new();
        auth_input.extend(verify.iter());
        auth_input.extend(ntor_context.router_id.iter());
        auth_input.extend(ntor_context.client_B.iter());
        auth_input.extend(server_handshake.server_pk.iter());
        auth_input.extend(ntor_context.client_X.iter());
        auth_input.extend("ntor-curve25519-sha256-1".as_bytes());
        auth_input.extend("Server".as_bytes());
        println!("auth input");
        hexdump(&auth_input);
        let calculated_auth = ntor_hmac(&auth_input, b"ntor-curve25519-sha256-1:mac");
        println!("calculated auth");
        hexdump(&calculated_auth);
        println!("server's auath");
        hexdump(&server_handshake.auth);
        println!("key seed");
        let key_seed = ntor_hmac(&secret_input, b"ntor-curve25519-sha256-1:key_extract");
        hexdump(&key_seed);
    }
}

fn decode_cell(cell_hex: &str, ntor_context: &Option<NtorHandshakeContext>) {
    let bytes = hex::decode(cell_hex).unwrap();
    let tor_cell = types::Cell::from_slice(&bytes).unwrap();
    println!("{:?}", tor_cell);
    match tor_cell.command {
        // We actually have to (try to) decrypt the relay cell for it to mean anything
        /*
        types::Command::Relay => {
            match types::RelayCell::from_slice(tor_cell.payload) {
                Ok(relay_cell) => println!("{:?}", relay_cell),
                Err(msg) => println!("{}", msg),
            }
        },
        */
        types::Command::Netinfo => match types::NetinfoCell::from_slice(tor_cell.payload) {
            Ok(netinfo_cell) => {
                println!("{:?}", netinfo_cell);
            }
            Err(msg) => println!("{}", msg),
        },
        types::Command::Create2 => {
            match types::Create2Cell::from_slice(tor_cell.payload) {
                Ok(create2_cell) => {
                    println!("{:?}", create2_cell);
                    // technically we should check create2_cell.h_type here
                    let client_handshake =
                        types::NtorClientHandshake::from_slice(create2_cell.h_data).unwrap();
                    println!("{:?}", client_handshake);
                }
                Err(msg) => println!("{}", msg),
            }
        }
        types::Command::Created2 => {
            match types::Created2Cell::from_slice(tor_cell.payload) {
                Ok(created2_cell) => do_ntor_handshake(&created2_cell, ntor_context),
                Err(msg) => println!("{}", msg),
            }
        }
        _ => {}
    }
}
