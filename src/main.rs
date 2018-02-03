extern crate hex;

mod types;
use std::io;
use std::io::prelude::*;

fn main() {
    let stdin = io::stdin();
    for line in stdin.lock().lines() {
        let line = line.unwrap();
        if line.len() == 0 {
            break;
        }
        let bytes = hex::decode(line.replace(" ", "")).unwrap();
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
                    Ok(created2_cell) => {
                        println!("{:?}", created2_cell);
                        // technically we should check the corresponding create2_cell type here
                        let server_handshake =
                            types::NtorServerHandshake::from_slice(created2_cell.h_data).unwrap();
                        println!("{:?}", server_handshake);
                    }
                    Err(msg) => println!("{}", msg),
                }
            }
            _ => {}
        }
    }
}
