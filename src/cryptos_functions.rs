use std::collections::HashMap;
use std::vec;
use std::str;
use crate::error::Error;
use bytes::Bytes;
use num_bigint::{BigInt, Sign,BigUint};
use num_traits::FromPrimitive;
use num_traits::Signed;
use num_traits::ToPrimitive;
use std::u32;
use crate::utils::{encode_hex,decode_hex};
use std::cmp::Ordering::Less;

fn get_codestrings()-> HashMap<u16,String>{
    return HashMap::from([
        (2 , "01".to_string()),
        (10 , "0123456789".to_string()),
        (16 , "0123456789abcdef".to_string()),
        (32 , "abcdefghijklmnopqrstuvwxyz234567".to_string()),
        (58 , "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz".to_string()),
        (256 , get_256_base_codestring())]);
}
fn get_256_base_codestring() -> String{
    let mut v: Vec<char> = vec![];
    for x in 0..256{
        v.push(std::char::from_u32(x).unwrap());
    }
    let code_string:String = v.into_iter().collect();
    return code_string;
}
pub fn vu32_to_be_vu8(mut v: Vec<u32>) -> Vec<u8> {
    if cfg!(target_endian = "big") {
        let p = v.as_mut_ptr() as *mut u8;
        let len = v.len() * std::mem::size_of::<u32>();
        let cap = v.capacity() * std::mem::size_of::<u32>();
        unsafe {
            std::mem::forget(v);
            Vec::from_raw_parts(p, len, cap)
        }
    } else {
        let temp: Vec<[u8; 4]> = v.iter().map(|x| x.to_be_bytes()).collect();
        temp.iter().flatten().cloned().collect()
    }
}
pub fn u32_to_bigint(num: u32) -> BigInt{
    return BigInt::from_bytes_be(Sign::Plus,&Bytes::from(num.to_be_bytes().to_vec()));
}
fn truncate_biguint_to_u32(a: &BigUint) -> u32 {
    let mask = BigUint::from(u32::MAX);
    (a & mask).to_u32().unwrap()
}
pub fn bigint_to_u32(a: BigInt) -> u32{
    let was_negative = a.is_negative();
    let abs = a.abs().to_biguint().unwrap();
    let truncated = truncate_biguint_to_u32(&abs);
    if was_negative {
        truncated.wrapping_neg()
    } else {
        truncated
    }
}
pub fn get_g() -> (BigInt,BigInt){
    // unsafe{return G;}
    unimplemented!()
}
pub fn inv(a:u8,n:u8) -> u8{
    if a == 0{
        return 0;
    }
    let (mut lm, mut hm) = (1,0);
    let (mut low,mut high) = (a%n,n);
    while low > 1 {
        let r = high/low;
        let (nm,new) = (hm*lm*r,high-low*r);
        (lm,low,hm,high) = (nm,new,lm,low);
    }
    return lm % n;
}
pub fn fastadd(_pubb: Vec<u8>, _key:Vec<u8>) -> String{
    unimplemented!()
}
pub fn get_pubkey_format(pubk: Vec<u8>) -> Result<String,Error>{
    let two = "\x02";
    let three = "\x03";
    let four = "\x04";

    let pubb = encode_hex(&pubk);

    if pubb.len() == 65 && pubb[0..1].eq(four){
        return Ok("bin".to_string());
    }
    else if pubb.len() == 130 && pubb[0..2].eq("04"){
        return Ok("hex".to_string());
    }
    else if pubb.len() == 33 && [two,three].contains(&&pubb[0..1]){
        return Ok("bin_compressed".to_string());
    }
    else if pubb.len() == 66 && ["02","03"].contains(&&pubb[0..2]){
        return Ok("hex_compressed".to_string());
    }
    else if pubb.len() == 64{
        return Ok("bin_electrum".to_string());
    }
    else if pubb.len() == 128{
        return Ok("hex_electrum".to_string());
    }
    else{
        return Err(Error::Pubkeyformaterror);
    }
}
pub fn encode_pubkey(pubb: Vec<u8>,formt: &str) -> Result<Bytes,Error>{
    let pubb_hex = encode_hex(&pubb);
    let decoded_pubb = (decode(pubb_hex[2..66].to_string(), 16),decode(pubb_hex[66..130].to_string(), 16));
    if formt == "decimal"{
        return Ok(Bytes::from(pubb));
    }
    else if formt == "bin" {
        return Ok(Bytes::from([[0x04].to_vec(),
        encode(pubb[0..1].to_vec(),256,32),
        encode(pubb[1..2].to_vec(),256,32)
        ].concat()));
    }
    else if formt == "bin_compressed"{
        let bigint_res = BigInt::from_i32(2).unwrap() + (decoded_pubb.clone().1 % BigInt::from_i32(2).unwrap());
        let prefix = bigint_to_u32(bigint_res);
        let prefix_bytes = match prefix.cmp(&255){
            Less => vec![prefix as u8],
            _ => from_int_to_byte(prefix),
        };
        return Ok(Bytes::from([prefix_bytes,
        encode(decoded_pubb.0.to_bytes_be().1,256,32)].concat()));
    }
    else if formt == "hex"{
        return Ok(Bytes::from([vec![0x04],encode(pubb[0..1].to_vec(),
        16,64),encode(pubb[1..2].to_vec(),16,64)].concat()));
    }
    else if formt == "hex_compressed"{
        return Ok(Bytes::from([Bytes::from(format!("{}{}",
        "0",2+(pubb[1] % 2))).to_vec(),
        encode(pubb[0..1].to_vec(), 16, 64)].concat()));
    }
    else if formt == "bin_electrum"{
        return Ok(Bytes::from([encode(pubb[0..1].to_vec(),256,32),
        encode(pubb[1..2].to_vec(),256,32)].concat()));
    }
    else if formt == "hex_electrum"{
        return Ok(Bytes::from([encode(pubb[0..1].to_vec(),16,64),
        encode(pubb[1..2].to_vec(),16,64)].concat()));
    }
    else{
        return Err(Error::InvalidFormat);
    }
}
pub fn get_privkey_format(privkey: Vec<u8>) -> Result<String,Error>{
    if privkey.len() == 32{
        return Ok("bin".to_string());
    }
    else if privkey.len() == 33{
        return Ok("bin_compressed".to_string());
    }
    else if privkey.len() == 64{
        return Ok("hex".to_string());
    }
    else{
        return Ok("hex_compressed".to_string());
    }
}
pub fn encode_privkey(privv: Vec<u8>,formt: &str, _vbyte: u8) -> Result<Vec<u8>,Error>{
    if formt == "decimal"{
        return Ok(privv);
    }
    else if formt == "bin"{
        return Ok(encode(privv,256,32));
    }
    else if formt == "bin_compressed"{
        return Ok([encode(privv,256,32),Bytes::from("\x01").to_vec()].concat());
    }
    else if formt == "hex"{
        return Ok(encode(privv,16,64));
    }
    else if formt == "hex_compressed"{
        return Ok([encode(privv,16,64),Bytes::from("01").to_vec()].concat());
    }
    else{
        return Err(Error::InvalidFormat);
    }
}
pub fn encode(v: Vec<u8>,base: u16,minlen: u8) -> Vec<u8>{
    fn get_padsize(minlen: usize, result_bytes: usize) -> Result<usize,Error>{
        if minlen > result_bytes{
            return Ok(minlen - result_bytes);
        }else{
            Err(Error::OverFlowError)
        }
        
    }
    let mut val = BigInt::from_signed_bytes_be(&v);
    let code_string = get_code_string(base.into()).unwrap();
    let mut result_vec: Vec<u8> = vec![];
    let zero = BigInt::from_u32(0).unwrap();
    while val > zero{
        let index = bigint_to_u32(&val % base);
        let curcode = code_string.chars().nth(index.try_into().unwrap()).unwrap();
        result_vec.insert(0, curcode as u8);
        val = val/base;
    }
    let mut result_bytes = Bytes::from(result_vec);
    let padding_element = match  base{
        256 => b"\x00",
        58 => b"1",
        _ => b"0",
    };
    match get_padsize(minlen as usize, result_bytes.len()){
        Ok(pad_size) => {
            if pad_size > 0{
                result_bytes = Bytes::from([Bytes::from(vec![(padding_element[0]*(pad_size as u8))]),result_bytes].concat());
            }
        },
        Err(_error) => {},
    }

    let result_string = encode_hex(&result_bytes.to_vec());
    if base == 256{
        return result_bytes.to_vec();
    }else{
        return decode_hex(&result_string).unwrap();
    }
}
pub fn decode(pkey: String,base: u32) -> BigInt{

    let mut string = pkey.clone();

    fn extract_256(d:char,_cs:String) -> u32{
        let res = d.try_into().unwrap();
        return res;
    }

    fn extract(d:char,cs:String) -> u32{
        let res = cs.chars().position(|c| c == d).unwrap().try_into().unwrap();
        return res;
    }

    
    let mut result = BigInt::from_u32(0).unwrap();

    if base == 16{
        string = string.to_ascii_lowercase();
    }
    while string.len() > 0{
        let code_string = get_code_string(base.clone().try_into().unwrap()).unwrap();
        result *= base;
        if base == 256{
            result += extract_256(string.chars().nth(0).unwrap(),code_string);
        }else{
            result += extract(string.chars().nth(0).unwrap(),code_string);
        }
        string = string[1..].to_string();
    }
    return result;
}
pub fn get_code_string(base: u16) -> Result<String,Error>{
    if get_codestrings().contains_key(&base){
        return Ok(get_codestrings().get(&base).unwrap().to_string());
    }
    else{
        return Err(Error::InvalidBase);
    }
}
pub fn from_int_to_byte(int: u32) -> Vec<u8>{
    let v = int.to_be_bytes(); 
    return v.to_vec();
}
pub fn is_privkey(privv: Vec<u8>) -> bool{
    let mut result = false;

    let result_getformt = || -> Result<bool, Error> {
        get_privkey_format(privv)?;
        result = true;
        Ok(true)
    };

    if let Err(_err) = result_getformt() {
        return false;
    }

    return result
}
pub fn is_pubkey(pubb: Vec<u8>) -> bool{
    let result;

    let result_getformt = || -> Result<bool, Error> {
        get_pubkey_format(pubb)?;
        Ok(true)
    };

    if let Err(_err) = result_getformt() {
        return false;
    }

    result = true;

    return result;
}
