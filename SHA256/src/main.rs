use std::io;
use hex::ToHex;

fn main() {
    // Get input from user
    println!("Enter password to be hashed: ");
    let mut input_str = String::new();

    io::stdin().read_line(&mut input_str).expect("Error");

    //convert to i8 slice of assic values
    let mut input_slice: &[u8] = input_str.as_bytes();

    // remove last element as it is not part of password
    input_slice = &input_slice[0..input_slice.len() - 1];

    println!("Size of input message in bytes: {}", input_slice.len());

    let hash_bytes = digest(input_slice);

    let output: String = hash_bytes.encode_hex_upper();
    println!("The SHA-256 hash is: {}", output);

    println!("The length of string hash is: {}", output.len());


}

fn digest(input: &[u8]) -> [u8; 32] {

    // Padding message to multiple of 16 words
    let length: i32 = input.len() as i32;
    let length_in_bits: u64 = length as u64 * 8;
    let k_zero_bytes: i32;

    if length % 64 >= 56 { // message too big to pad into a single block
        // Add new block
        k_zero_bytes = 128 - ((length % 64) + 9);
    } else {
        k_zero_bytes = 64 - ((length % 64) + 9);
    }
    println!("Number of k_zero_bytes: {}", k_zero_bytes);

    
    let pad_byte: u8 = 128; // byte as "10000000"

    // Copy input into padded_message
    let mut padded_message: Vec<u8> = Vec::new();
    padded_message.extend_from_slice(input);

    // Add in the pad byte
    padded_message.push(pad_byte);

    // Add in the zero bytes
    for _ in 0 .. k_zero_bytes {
        padded_message.push(0u8);
    }

    // Add in length bytes
    let mut size_bytes = length_in_bits.to_be_bytes().to_vec();
    padded_message.append(&mut size_bytes);

    println!("Size of Padded Message: {}", padded_message.len());

    /*
    for i in 0..padded_message.len() {
        println!("{}", padded_message[i]);
    } */


    // Setup initial hash values
    let mut hash_values: [u32; 8] = [ // values specified in FIPS-180-2
        0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a,
        0x510e527f, 0x9b05688c, 0x1f83d9ab, 0x5be0cd19];
    
    let mut message_schedule: [u32; 64] = [0;64];

    let blocks:u32 = padded_message.len() as u32 / 64;

    println!("Blocks: {}", blocks);

    for block_i in 0..blocks { // for each block
        // Copy part of message into block array
        let mut block_array: [u32;16] = [0;16];
        let mut int_bytes: [u8;4] = [0;4];
        for x in 0..16 {
            let offset: usize = ((block_i * 64) + (x * 4)) as usize;
        
            int_bytes[0] = padded_message[offset];
            int_bytes[1] = padded_message[offset + 1];
            int_bytes[2] = padded_message[offset + 2];
            int_bytes[3] = padded_message[offset + 3];
            let value: u32 = u32::from_be_bytes(int_bytes);
            block_array[x as usize] = value;
        }

        //Prepare the message schedule
        for t in 0..64 {
            if t <= 15 {
                message_schedule[t] = block_array[t];
            } else {
                message_schedule[t] = add_mod2_32(add_mod2_32(add_mod2_32(std_dev1(message_schedule[t - 2]), message_schedule[t - 7]), std_dev0(message_schedule[t-15])), message_schedule[t-16]);
            }
        }

        // Initialize 8 working variables with the previous hash values
        let mut a:u32 = hash_values[0];
        let mut b:u32 = hash_values[1];
        let mut c:u32 = hash_values[2];
        let mut d:u32 = hash_values[3];
        let mut e:u32 = hash_values[4];
        let mut f:u32 = hash_values[5];
        let mut g:u32 = hash_values[6];
        let mut h:u32 = hash_values[7];

        for t in 0..64 {
            let t1: u32 = add_mod2_32(add_mod2_32(add_mod2_32(add_mod2_32(h,sigma1(e)), ch(e,f,g)), K256CONSTANTS[t]), message_schedule[t]);
            let t2: u32 = add_mod2_32(sigma0(a), maj(a,b,c));
            h = g;
            g = f;
            f = e;
            e = add_mod2_32(d, t1);
            d = c;
            c = b;
            b = a;
            a = add_mod2_32(t1, t2);
        }

        // Set new hash values
        hash_values[0] = add_mod2_32(a, hash_values[0]);
        hash_values[1] = add_mod2_32(b, hash_values[1]);
        hash_values[2] = add_mod2_32(c, hash_values[2]);
        hash_values[3] = add_mod2_32(d, hash_values[3]);
        hash_values[4] = add_mod2_32(e, hash_values[4]);
        hash_values[5] = add_mod2_32(f, hash_values[5]);
        hash_values[6] = add_mod2_32(g, hash_values[6]);
        hash_values[7] = add_mod2_32(h, hash_values[7]);
    }
    let mut index:usize = 0;
    let mut final_hash:[u8;32] = [0;32];
    for i in 0..8 {
        let bytes = hash_values[i].to_be_bytes();
        final_hash[index] = bytes[0];
        final_hash[index + 1] = bytes[1];
        final_hash[index + 2] = bytes[2];
        final_hash[index + 3] = bytes[3];
        index += 4;
    }
    return final_hash;
}

// SHA-256 Funtions
fn rotr(x:u32, n:u32) -> u32 {
    return (x >> n) | (x << 32 - n); // Note Arithmetic right shift on signed integer types, logical right shift on unsigned integer types.
}
fn shr(x:u32, n:u32) -> u32 {
    return x >> n;
}

fn ch(x:u32, y:u32, z:u32) -> u32 {
    return (x & y) ^ (!x & z);
}
fn maj(x:u32, y:u32, z:u32) -> u32 {
    return (x & y) ^ (x & z) ^ (y & z);
}
fn sigma0(x:u32) -> u32 {
    return rotr(x, 2) ^ rotr(x, 13) ^ rotr(x, 22);
}
fn sigma1(x:u32) -> u32 {
    return rotr(x, 6) ^ rotr(x, 11) ^ rotr(x, 25);
}
fn std_dev0(x:u32) -> u32 {
    return rotr(x, 7) ^ rotr(x, 18) ^ shr(x, 3);
}
fn std_dev1(x:u32) -> u32 {
    return rotr(x, 17) ^ rotr(x, 19) ^ shr(x, 10);
}
fn add_mod2_32(x:u32, y:u32) -> u32 {
    let x_64: u64 = x as u64;
    let y_64: u64 = y as u64;
    return ((x_64 + y_64) % 4294967296u64) as u32;
}
const K256CONSTANTS: [u32; 64] = [
        0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5,
        0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
        0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3,
        0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
        0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc,
        0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
        0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7,
        0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
        0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13,
        0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
        0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3,
        0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
        0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5,
        0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
        0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208,
        0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2];