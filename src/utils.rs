use bytes::{ BufMut, Bytes, BytesMut};
use hex::ToHex;
use std::iter::Iterator;
use openssl::{
    symm::{encrypt, Cipher,Crypter,Mode, decrypt},
};
use std::{fmt::Write, num::ParseIntError};

use crate::error::Error;
pub trait IterSequenceSearch {
    type Item;
    fn sequence_search(self,searched_sequence: &[Self::Item]) -> Option<usize>;
}

impl<'a,T,U: 'a> IterSequenceSearch for T
    where T: Iterator<Item = &'a U>,
    U: std::cmp::PartialEq {
    type Item = U;
    fn sequence_search(self, searched_sequence: &[Self::Item]) -> Option<usize> {
        let mut seq_iter = searched_sequence.iter();
        let mut self_enumerated = self.enumerate();
        let mut initial_idx = None;
        loop {
            if let Some((idx,it)) = self_enumerated.next() {
                if let Some(sit) = seq_iter.next() {
                    if *it == *sit {
                        if initial_idx.is_none() {
                            initial_idx = Some(idx);
                        }
                        // the sequence matches
                    } else {
                        // the sequence doesn't match
                        initial_idx = None;
                        seq_iter = searched_sequence.iter();
                    }
                } else { // the searched sequence just ended
                    return initial_idx;
                }
            } else { // the sequence in which we're searching has just ended
                break;
            }
        }
        None
    }
}


pub fn pad_data(data: &mut BytesMut) {
    data.put_u8(128);
    while data.len() % 16 > 0 {
        data.put_u8(0);
    }
}

pub fn set_bit(value: u8, bit: u8) -> u8{
    return value | (1 << bit);
}

pub fn clear_bit(value: u8, bit: u8) -> u8{
    return value & !(1 << bit);
}

pub fn remove_padding(data: &BytesMut) -> Option<Bytes> {
    data.iter()
        .enumerate()
        .rev()
        .find(|(_, b)| **b != 0)
        .and_then(|(idx, val)| match *val {
            128 => Some(Bytes::copy_from_slice(data.split_at(idx).0)),
            _ => None,
        })
}

pub fn path_to_bytes(path_str: String) -> Bytes{
    fn read_path_unit(path: &str) -> Vec<u8>{
        let  out ;
        if path.chars().last().unwrap() == '\''{
            let path = &path[..path.len()-1];
            out = path.parse::<u32>().unwrap() + 2147483648;
        }else{
            out = path.parse::<u32>().unwrap();
        }
        return out.to_be_bytes().to_vec();
    }
    assert!(&path_str[..2] == "m/");

    let mut path: Vec<&str> = path_str.split("/").collect();
    path.remove(0);

    let x: Vec<Vec<u8>> = path.iter().map(|x| read_path_unit(x)).collect();

    let mut y : Vec<u8> = vec![];

    for mut each in x{
        y.append(&mut each);
    }

    return Bytes::from(y);
}

pub fn list_to_hexadecimal(data: &[u8]) -> String{
    return (data.iter().map(|x| format!("{:02x}",x)).collect::<Vec<String>>()).join("");
}

pub fn hexadecimal_to_list(s: &str) -> Option<Vec<u8>> {
    if s.len() % 2 == 0 {
        (0..s.len())
            .step_by(2)
            .map(|i| s.get(i..i + 2)
                      .and_then(|sub| u8::from_str_radix(sub, 16).ok()))
            .collect()
    } else {
        None
    }
}

pub fn binary_to_list(data: Vec<u8>) -> Vec<u8>{
    return hexadecimal_to_list(&data.encode_hex::<String>()).unwrap()
}

pub fn aes_encrypt(key: Bytes, initialization_vector: Bytes, data: Bytes) -> Result<Bytes,Error> {
        let encrypted_result = {
            let cipher = Cipher::aes_256_cbc();
            encrypt(
                cipher,
                key.as_ref(),
                Some(initialization_vector.as_ref()),
                &data,
            )
            .unwrap()
        };
        let encrypted_result_len = encrypted_result.len();
        Ok(encrypted_result
            .into_iter()
            .skip(encrypted_result_len - 16)
            .collect())
}

pub fn aes_encrypt_unpadded(key:Bytes, initialization_vector: Bytes, data: Bytes,unpad: usize) -> Result<Bytes,Error>{
    let encrypted_result = {
        let cipher = Cipher::aes_256_cbc();
        encrypt(
            cipher,
            key.as_ref(),
            Some(initialization_vector.as_ref()),
            &data,
        )
        .unwrap()
    };
    let res_v = encrypted_result[..unpad].to_vec();
    Ok(Bytes::from(res_v))
}

pub fn aes_decrypt(key: Bytes, initialization_vector: Bytes, data: Bytes) -> Result<Bytes,Error> {
    let decrypted_result = {
        let cipher = Cipher::aes_256_cbc();
        decrypt(
            cipher,
            key.as_ref(),
            Some(initialization_vector.as_ref()),
            &data,
        )
        .unwrap()
    };
    Ok(Bytes::from(decrypted_result))
}

pub fn aes_decrypt_unpadded(key: &[u8], initialization_vector: Option<&[u8]>, data: &[u8]) -> Result<Bytes,Error> {
    let cipher = Cipher::aes_256_cbc();

    let mut decrypted = Crypter::new(cipher, Mode::Decrypt, &key, initialization_vector).unwrap();
    decrypted.pad(false);
    let mut output = vec![0 as u8; data.len() + Cipher::aes_256_cbc().block_size()];

    let decrypted_result = decrypted.update(&data, &mut output);

    match decrypted_result {
        Ok(_) => Ok(Bytes::from(output)),
        Err(e) => panic!("Error decrypting text: {}", e),
    }
}


pub fn decode_hex(s: &str) -> Result<Vec<u8>, ParseIntError> {
    (0..s.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&s[i..i + 2], 16))
        .collect()
}

pub fn encode_hex(bytes: &[u8]) -> String {
    let mut s = String::with_capacity(bytes.len() * 2);
    for &b in bytes {
        write!(&mut s, "{:02x}", b).unwrap();
    }
    s
}
