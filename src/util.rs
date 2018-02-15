pub fn slice_to_32_byte_array(bytes: &[u8]) -> [u8; 32] {
    let mut fixed_size: [u8; 32] = [0; 32];
    fixed_size.copy_from_slice(&bytes);
    fixed_size
}

pub fn hexdump(bytes: &[u8]) {
    for b in bytes {
        print!("{:02x}", b);
    }
    println!();
}
