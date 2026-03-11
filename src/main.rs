extern crate aes_gcm;
extern crate sha2;

use std::env;
use aes_gcm::{Aes256Gcm, Key, Nonce};
use aes_gcm::aead::{Aead, KeyInit};
use sha2::{Sha256, Digest};

fn main() {
    let mut args: Vec<String> = env::args().collect();
    if args.len() < 4 {
        println!("Please provide: <encrypt/decrypt> <key> <content>");
        std::process::exit(1);
    }
    args.remove(0);

    match args[0].as_str() {
        "encrypt" => {
            let encrypted_string = encrypt(args[1].to_string(), args[2].to_string());
            println!("{:?}", encrypted_string);
            return;
        },
        "decrypt" => {
            let decrypted_string = decrypt(args[1].to_string(), args[2].to_string());
             println!("{:?}", decrypted_string);
            return;
        },
        _ => {
            println!("First argument has to be encrypt or decrypt");
            std::process::exit(1);
        }
    }
}

fn encrypt(key: String, content: String) -> String {
    let content_bytes = content.as_bytes().to_vec();
    let key_bytes = key.as_bytes();

    let mut result = vigenere_shift(content_bytes, key_bytes);
    result = bit_spin(result, key_bytes);
    result = rail_fence(result, key_bytes);
    result = aes_encrypt(result, &key);
    let hex: String = result.iter().map(|b| format!("{:02x}", b)).collect();

    hex
}

fn decrypt(key: String, content: String) -> String {
    let content_bytes: Vec<u8> = (0..content.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&content[i..i+2], 16).unwrap())
        .collect();
    let key_bytes = key.as_bytes();

    let mut result = aes_decrypt(content_bytes, &key);
    result = rail_fence_decrypt(result, key_bytes);
    result = bit_spin_decrypt(result, key_bytes);
    result = vigenere_shift_decrypt(result, key_bytes);

    String::from_utf8(result).unwrap()
}

fn vigenere_shift(mut content_bytes: Vec<u8>, key_bytes: &[u8]) -> Vec<u8> {
    for (count, byte) in content_bytes.iter_mut().enumerate() {
         *byte = byte.wrapping_add(key_bytes[count % key_bytes.len()]);
    }

    content_bytes
}

fn bit_spin(mut content_bytes: Vec<u8>, key_bytes: &[u8]) -> Vec<u8> {
    for (count, byte) in content_bytes.iter_mut().enumerate() {
        let spin = (key_bytes[count % key_bytes.len()] as usize ^ count * 31) % 8;
        *byte = byte.rotate_left(spin as u32);
    }

    content_bytes
}

fn rail_fence(content_bytes: Vec<u8>, key_bytes: &[u8]) -> Vec<u8> {
    let rails = (key_bytes.iter().map(|b| *b as usize).sum::<usize>() % 5) + 2;

    let mut pattern = vec![0usize; content_bytes.len()];
    let mut rail = 0i32;
    let mut direction = 1i32;

    for i in 0..content_bytes.len() {
        pattern[i] = rail as usize;
        if rail == 0 {
            direction = 1;
        } else if rail == rails as i32 - 1 {
            direction = -1;
        }
        rail += direction;
    }

    let mut output = Vec::new();
    for r in 0..rails {
      for (i, &rail_num) in pattern.iter().enumerate() {
         if rail_num == r {
            output.push(content_bytes[i]);
         }
       }
    }
   output
}

fn aes_encrypt(data: Vec<u8>, key: &str) -> Vec<u8> {
    let mut hasher = Sha256::new();
    hasher.update(key.as_bytes());
    let key_bytes = hasher.finalize();

    let key = Key::<Aes256Gcm>::from_slice(&key_bytes);
    let cipher = Aes256Gcm::new(key);

    let nonce = Nonce::from_slice(b"unique nonce");

    cipher.encrypt(nonce, data.as_ref()).unwrap()
}




fn vigenere_shift_decrypt(mut content_bytes: Vec<u8>, key_bytes: &[u8]) -> Vec<u8> {
    for (count, byte) in content_bytes.iter_mut().enumerate() {
        *byte = byte.wrapping_sub(key_bytes[count % key_bytes.len()]);
    }
    content_bytes
}

fn bit_spin_decrypt(mut content_bytes: Vec<u8>, key_bytes: &[u8]) -> Vec<u8> {
    for (count, byte) in content_bytes.iter_mut().enumerate() {
        let spin = (key_bytes[count % key_bytes.len()] as usize ^ count * 31) % 8;
        *byte = byte.rotate_right(spin as u32);
    }

    content_bytes
}

fn rail_fence_decrypt(content_bytes: Vec<u8>, key_bytes: &[u8]) -> Vec<u8> {
    let rails = (key_bytes.iter().map(|b| *b as usize).sum::<usize>() % 5) + 2;

    let mut pattern = vec![0usize; content_bytes.len()];
    let mut rail = 0i32;
    let mut direction = 1i32;
    for i in 0..content_bytes.len() {
        pattern[i] = rail as usize;
        if rail == 0 {
            direction = 1;
        } else if rail == rails as i32 - 1 {
            direction = -1;
        }
        rail += direction;
    }

    let mut rail_lengths = vec![0usize; rails];
    for &r in &pattern {
        rail_lengths[r] += 1;
    }

    let mut rails_data: Vec<Vec<u8>> = Vec::new();
    let mut pos = 0;
    for &len in &rail_lengths {
       rails_data.push(content_bytes[pos..pos + len].to_vec());
       pos += len;
    }

    let mut rail_indices = vec![0usize; rails];
    let mut output = vec![0u8; content_bytes.len()];
    for (i, &r) in pattern.iter().enumerate() {
       output[i] = rails_data[r][rail_indices[r]];
       rail_indices[r] += 1;
    }
    output
}

fn aes_decrypt(data: Vec<u8>, key: &str) -> Vec<u8> {
    let mut hasher = Sha256::new();
    hasher.update(key.as_bytes());
    let key_bytes = hasher.finalize();

    let key = Key::<Aes256Gcm>::from_slice(&key_bytes);
    let cipher = Aes256Gcm::new(key);

    let nonce = Nonce::from_slice(b"unique nonce");

    cipher.decrypt(nonce, data.as_ref()).unwrap()

}
