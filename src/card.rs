use std::path::PathBuf;
use bytes::Bytes;
use crate::{utils::IterSequenceSearch,genuineness,error::Error};
pub mod basic;
use std::convert::TryFrom;


#[derive(Clone,Debug,Eq,PartialEq)]
pub enum AuthType {
    NoAuth = 0,
    PIN = 1,
    UserKey = 2,
}

#[derive(Clone,Debug,Eq,PartialEq)]
pub enum KeyType {
    K1 = 0x00,
    R1 = 0x10
}

impl TryFrom<u8> for KeyType{
    type Error = ();

    fn try_from(v: u8) -> Result<Self, Self::Error> {
        match v{
            x if x == KeyType::K1 as u8 => Ok(KeyType::K1),
            x if x == KeyType::R1 as u8 => Ok(KeyType::R1),
            _ => Err(()),
        }
    }
}

#[derive(Clone,Debug,Eq,PartialEq)]
pub enum Derivation {
    CurrentKey = 0x00,
    Derive = 0x01,
    DeriveAndMakeCurrent = 0x02,
    PinlessPath = 0x03
}

impl TryFrom<u8> for Derivation{
    type Error = ();

    fn try_from(v: u8) -> Result<Self, Self::Error> {
        match v {
            x if x == Derivation::CurrentKey as u8 => Ok(Derivation::CurrentKey),
            x if x == Derivation::Derive as u8 => Ok(Derivation::Derive),
            x if x == Derivation::DeriveAndMakeCurrent as u8 => Ok(Derivation::DeriveAndMakeCurrent),
            x if x == Derivation::PinlessPath as u8 => Ok(Derivation::PinlessPath),
            _ => Err(()),
        }
    }
}

#[derive(Clone,Debug,Eq,PartialEq)]
pub enum CardOrigin {
    Unknown = 0,
    Original = 1,
    Fake = 2
}

#[derive(Clone,Debug,Eq,PartialEq)]
pub enum SlotIndex {
    EC256R1 = 0x01,
    RSA = 0x02,
    FIDO = 0x03
}

impl TryFrom<u8> for SlotIndex {
    type Error = ();

    fn try_from(v: u8) -> Result<Self, Self::Error> {
        match v {
            x if x == SlotIndex::EC256R1 as u8 => Ok(SlotIndex::EC256R1),
            x if x == SlotIndex::RSA as u8 => Ok(SlotIndex::RSA),
            x if x == SlotIndex::FIDO as u8 => Ok(SlotIndex::FIDO),
            _ => Err(()),
        }
    }
}

#[derive(Clone,Debug,Eq,PartialEq)] 
pub enum SeedSource {
    NoSeed = 0x00,
    Single = 'K' as isize,
    Extended = 'X' as isize,
    External = 'L' as isize,
    Internal = 'S' as isize,
    Dual = 'D' as isize
}



impl TryFrom<u8> for SeedSource {
    type Error = ();

    fn try_from(v: u8) -> Result<Self, Self::Error> {
        match v {
            x if x == SeedSource::NoSeed as u8 => Ok(SeedSource::NoSeed),
            x if x == SeedSource::Single as u8 => Ok(SeedSource::Single),
            x if x == SeedSource::Extended as u8 => Ok(SeedSource::Extended),
            x if x == SeedSource::External as u8 => Ok(SeedSource::External),
            x if x == SeedSource::Internal as u8 => Ok(SeedSource::Internal),
            x if x == SeedSource::Dual as u8 => Ok(SeedSource::Dual),
            _ => Err(()),
        }
    }
}

#[derive(Clone,Debug,Eq,PartialEq)]
pub struct CardInfo {
    serial_number: u64,
    applet_version: Vec<u8>,
    name: String,
    email: String,
    initialized: bool,
    seed: bool
}

#[derive(Clone,Debug,Eq,PartialEq)]
pub struct CardUser {
    name: String,
    email: String,
}
#[allow(dead_code)]
pub struct SignatureCheckResponse{
    message: Bytes,
    signature: Bytes,
}
// Implemented by objects that contains information about the card that is in the reader.
pub trait Base : BasePriv {
    fn select_adpu() -> Vec<u32>;
    fn card_type() -> u32;
    fn pin_rule() -> String;
    fn puk_rule(self: &Self) -> String;
    /// Returns whether the connection to the card is established and the card hasn't been changed
    fn is_alive(self: &mut Self) -> bool {
        if let Ok(certificate) = genuineness::manufacturer_certificate(self.borrow_connection()) {
            let seq = [0x03,0x02,0x01,0x02,0x02];
            if let Some(split_idx) = certificate.iter().sequence_search(&seq) {
                let after_sequence = &certificate[split_idx+seq.len()..];
                let data: [u8; 8];
                if after_sequence[0] % 16 == 8 {
                    data = after_sequence[1..9].try_into().unwrap();
                } else if after_sequence[0] % 16 == 9 {
                    data = after_sequence[2..10].try_into().unwrap();
                } else {
                    return false;
                }
                self.serial_number() == u64::from_be_bytes(data)
            } else {
                false
            }
        } else {
            false
        }
    }
    fn change_pairing_key(self: &mut Self, index: u8, pairing_key: &[u8], puk: String) -> Result<(),Error>;
    fn change_pin(self: &mut Self, new_pin: String) -> Result<(),Error>;
    fn change_puk(self: &mut Self, current_puk: String, new_puk: String) -> Result<(),Error>;
    fn init(self: &Self, name: String, email: String, pin: String, puk: String, pairing_secret: Option<Bytes>,nfc_sign: Option<bool>) -> Result<Vec<u8>,Error>;
    fn derive(self: &mut Self,key_type: Option<u8>, path: Option<PathBuf>) -> Result<(),Error>;
    fn dual_seed_public_key(self: &mut Self, pin: &str) -> Result<Bytes,Error>;
    fn dual_seed_load(self: &mut Self,data: Bytes, pin: &str)-> Result<(),Error>;
    fn extended_public_key(self: &Self) -> bool;
    fn generate_random_number(self: &mut Self, size: u8) -> Result<Bytes,Error>;
    fn generate_seed(self: &mut Self, pin: &str) -> Result<Bytes,Error>;
    fn get_public_key(self: &mut Self, derivation: u8, key_type: Option<u8>, path: Option<PathBuf>, compressed: Option<bool>) -> Result<Bytes,Error>;
    fn history(self: &mut Self, index: u8) -> Result<(u32,Bytes),Error>;
    fn info(self: &mut Self) -> CardInfo {
        let user = self.owner();
        CardInfo {
            serial_number: self.serial_number(),
            applet_version: self.borrow_applet_version().to_owned(),
            name: user.name,
            email: user.email,
            initialized: self.is_initialized(),
            seed: self.valid_key()
        }
    }
    fn is_initialized(self: &Self) -> bool;
    fn load_seed(self: &mut Self, seed: Option<Bytes>, pin: Option<String>) -> Result<(),Error>;
    fn is_open(self: &Self) -> bool {
        *self.borrow_auth_type() != AuthType::NoAuth
    }
    fn origin(self: &mut Self) -> CardOrigin {
        if *self.borrow_origin() == CardOrigin::Unknown {
            *self.borrow_origin_mut() = genuineness::origin(self.borrow_connection(),false);
        }
        self.borrow_origin().to_owned()
    }
    fn pin_authentication(self: &Self) -> bool;
    fn pinless_enabled(self: &Self) -> bool;
    fn reset(self: &mut Self, puk: &str);
    fn seed_source(self: &mut Self) -> Result<SeedSource,Error>;
    fn set_pin_authentication(self: &mut Self, status: bool, puk: &str) ->Result<(),Error>;
    fn set_pinless_path(self: &mut Self, path: String, puk: &str)-> Result<(),Error>;
    fn set_extended_public_key(self: &mut Self, status: bool, puk: &str)-> Result<(),Error>;
    fn sign(self: &mut Self, data: Bytes, derivation: Option<u8>, key_type: Option<u8>, path: Option<&str>,pin: Option<&str>,filter_eos: Option<bool>) -> Result<Bytes,Error>;
    fn signing_counter(self: &mut Self) -> Result<u32,Error>;
    fn unblock_pin(self: &mut Self, puk: String, new_pin: String) -> Result<(),Error>;
    fn user_data(self: &Self) -> Bytes;
    fn write_user_data(self: &Self, value: Bytes);
    fn user_key_add(self: &mut Self, slot_index: u8, data_info : &str, public_key: Bytes, puk: &str, cred_id : Option<Bytes>) -> Result<(),Error>;
    fn user_key_delete(self: &mut Self, slot: u8, puk_code: &str) -> Result<(),Error>;
    fn user_key_info(self: &mut Self, slot: u8) -> Result<(String,Bytes),Error>;
    fn user_key_enabled(self: &Self, slot: u8) -> bool;
    fn user_key_challenge_response_nonce(self: &mut Self) -> Result<Bytes,Error>;
    fn user_key_challenge_response_open(self: &mut Self, slot: u8, signature: Bytes) -> bool;
    fn user_key_signature_open(self: &mut Self, slot: u8, message: Bytes, signature: Bytes) -> bool;
    fn valid_key(self: &Self) -> bool;
    fn valid_pin(self: &Self,pin: String,pin_name: Option<String>) -> Result<String,Error>;
    fn valid_puk(self: &Self,puk: String,puk_name: Option<String>) -> Result<String,Error>;
    fn verify_pin(self: &mut Self, pin: &str);
    fn sign_eos(self: &mut Self,apdu: &[u32],data: Bytes,pin: &str) -> Result<Bytes,Error>;
    fn get_info(self: &mut Self) -> Result<Bytes,Error>;
    fn signature_check(self: &mut Self, nonce: Bytes) -> Result<SignatureCheckResponse,Error>;
    //
}

pub trait BasePriv {
    fn owner(self: &mut Self) -> CardUser;
    fn borrow_auth_type(self: &Self) -> &AuthType;
    fn borrow_connection(self: &mut Self) -> &mut crate::connection::Connection;
    fn serial_number(self: &Self) -> u64;
    fn borrow_applet_version(self: &Self) -> &Vec<u8>;
    fn borrow_origin(self: &Self) -> &CardOrigin;
    fn borrow_origin_mut(self: &mut Self) -> &mut CardOrigin;
}
