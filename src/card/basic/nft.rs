use super::*;
use crate::utils::{self, decode_hex};
use crate::connection::Connection;
use crate::consts::BASIC_PAIRING_SECRET;
use bytes::BytesMut;
use openssl::{nid::Nid as AlgorithmKind,ec,bn::BigNumContext,ec::{EcKey,EcGroup, EcPoint},
    derive::Deriver,pkey::PKey};
use std::path::{PathBuf};
use super::Basic;
use crate::utils::{path_to_bytes, encode_hex};
use std::convert::TryInto;
use std::vec;
use bytes::Bytes;

use crate::{error::Error, card::{AuthType, Derivation, SeedSource, CardOrigin, CardUser, KeyType, BasePriv, Base}, cryptos_functions::encode_pubkey};

pub struct NFT{
    basic_state: Basic,
}

impl NFT {
    pub fn new(connection: Connection, serial: u64, applet_version: Vec<u8>) -> Self {
        Self {
            basic_state: Basic::new(connection,serial,applet_version),
        }
    }
    pub fn with_data(self, data: Vec<u8>) -> Self {
        Self {
            basic_state: self.basic_state.with_data(data),
        }
    } 
}

impl Base for NFT {
    fn select_adpu() -> Vec<u32> {
        return [0xA0, 0x00, 0x00, 0x10, 0x00, 0x01, 0x12].to_vec();
    }
    fn card_type() -> u32 {
        unimplemented!()
    }
    fn pin_rule() -> String {
        unimplemented!()
    }
    fn puk_rule(self: &Self) -> String {
        return String::from("12 digits and/or letters");
    }
    fn change_pairing_key(self: &mut Self, index: u8, pairing_key: &[u8], puk: String) -> Result<(),Error> {
        if pairing_key.len() != 32{
            return Err(Error::InvalidPairingKeyBytes);
        }
        if index != 0{
            return Err(Error::InvalidPairingKeyBytes);
        }
        let valid_puk = self.valid_puk(puk,Some("puk".to_string())).unwrap();
        let data = [pairing_key,valid_puk.as_bytes()].concat();
        let data_bytes: Bytes = Bytes::from(data);
        let res = self.basic_state.connection.send_encrypted(&[0x80, 0xDA,index, 0x00], data_bytes,false);

        match res{
            Ok(_) => {
                Ok(())
            },
            Err(error) => {
                Err(error)
            },
        }
    }
    fn change_pin(self: &mut Self, new_pin: String) -> Result<(),Error> {
        self.basic_state.change_pin(new_pin)
    }
    fn change_puk(self: &mut Self, current_puk: String, new_puk: String) -> Result<(),Error> {
        self.basic_state.change_puk(current_puk, new_puk)
    }
    fn init(self: &Self, name: String, email: String, pin: String, puk: String, pairing_secret: Option<Bytes>,nfc_sign: Option<bool>) -> Result<Vec<u8>,Error> {
        let validated_pin = self.valid_pin(pin,Some("pin".to_string()));
        let mut nfc_sign_bool = true;
        if let Some(nfcsign) = nfc_sign{
            nfc_sign_bool = nfcsign;
        }
        if let Err(error) = validated_pin{
            return Err(error);
        }
        let valid_pin = validated_pin.unwrap();
        if name.len() > 20{
            return Err(Error::DataValidationExceptionBasicName);
        }
        if email.len() > 60{
            return Err(Error::DataValidationExceptionBasicEmail);
        }
        let mut valid_pairing_secrect = BASIC_PAIRING_SECRET;
        if let Some(vps) = pairing_secret{
            valid_pairing_secrect = vps;
        }
        let ec_group = ec::EcGroup::from_curve_name(AlgorithmKind::X9_62_PRIME256V1).unwrap();
        let session_private_key = ec::EcKey::generate(&ec_group).unwrap();
        let session_public_key = session_private_key.public_key();
        let mut bn_ctx = BigNumContext::new().unwrap();
        let session_public_key_bytes = session_public_key.to_bytes(
            &ec_group,
            ec::PointConversionForm::UNCOMPRESSED,
            &mut bn_ctx,
        ).unwrap();
        let send_public_key = {
            let mut data = Vec::new();
            data.push(session_public_key_bytes.len() as u8);
            data.into_iter()
                .chain(session_public_key_bytes.into_iter())
                .collect::<Vec<u8>>()
        };
        let aes_init_key = {
            let private_pkey = PKey::from_ec_key(session_private_key.clone())?;
            let pkey = &self.basic_state.connection.session_public_key;
            let ec_group = EcGroup::from_curve_name(AlgorithmKind::X9_62_PRIME256V1)?;
            let mut ctx = BigNumContext::new().unwrap();
            let pub_key_point = EcPoint::from_bytes(&ec_group,&decode_hex(pkey).unwrap(),&mut ctx)?;
            let pub_key = EcKey::from_public_key(&ec_group, &pub_key_point)?;
            let public_key = PKey::from_ec_key(pub_key).unwrap();
            let mut deriver = Deriver::new(&private_pkey)?;
            deriver.set_peer(&public_key)?;
            let ret = deriver.derive_to_vec()?;
            Bytes::from(ret)
        };
        let mut iv_init_key = [0; 16];
        openssl::rand::rand_bytes(&mut iv_init_key)?;
        let namelen = (name.len() as u8).to_be_bytes().to_vec();
        let emaillen = (email.len() as u8).to_be_bytes().to_vec();
        let name_coded_value = [Bytes::from(namelen),Bytes::from(name)].concat();
        let email_coded_value = [Bytes::from(emaillen),Bytes::from(email)].concat();
        let name_slice:&[u8] = &name_coded_value;
        let email_slice:&[u8] = &email_coded_value;
        let valid_pin_slice:&[u8] = &valid_pin.as_bytes();
        let puk_slice:&[u8] = &puk.as_bytes();
        let mut nfc_sign_slice = decode_hex("5A5A").unwrap();
        if nfc_sign_bool{
            nfc_sign_slice = decode_hex("A5A5").unwrap();
        }
        let nfc_sign_slice_bytes: &[u8] = &nfc_sign_slice;
        let data_slices: &[u8] = &[name_slice,email_slice,valid_pin_slice,puk_slice,nfc_sign_slice_bytes,&valid_pairing_secrect].concat();
        let mut data = BytesMut::from(data_slices);
        utils::pad_data(&mut data);
        let payload = Bytes::from(data.to_vec());
        let encrypted_payload = utils::aes_encrypt_unpadded(aes_init_key.clone(), Bytes::copy_from_slice( &iv_init_key), payload,data.len())?;
        let data_init = [Bytes::from(send_public_key),Bytes::copy_from_slice(&iv_init_key),encrypted_payload.clone()].concat();
        let apdu_init: Vec<u8> = [0x80, 0xFE, 0x00, 0x00, 82 + encrypted_payload.len() as u8].to_vec();
        let apdu_init = [apdu_init,data_init].concat();
        let (_, code1, code2) = self.basic_state.connection.send_apdu(&apdu_init)?;
        if code1 != 0x90 || code2 != 0x00{
            return Err(Error::InitializationException);
        }

        return Ok([Bytes::from([0].to_vec()),valid_pairing_secrect].concat());
    }
    fn derive(self: &mut Self, _key_type: Option<u8>, _path: Option<PathBuf>) -> Result<(),Error>{
        unimplemented!()
    }
    fn dual_seed_public_key(self: &mut Self, pin: &str) -> Result<Bytes,Error> {
        let valid_pin;
        if self.basic_state.auth_type == AuthType::PIN{
            valid_pin = self.valid_pin(pin.to_string(),Some("puk".to_string())).unwrap();
        }else{
            valid_pin = pin.clone().to_string();
        }
        let result = self.basic_state.connection.send_encrypted(&[0x80, 0xD0, 0x04, 0x00], Bytes::from(valid_pin.to_string()), false).unwrap();
        if result.len() < 65{
            return Err(Error::DataException);
        }

        return Ok(result);
    }
    fn dual_seed_load(self: &mut Self,data: Bytes, pin: &str) -> Result<(),Error>{
        let valid_pin;
        if self.borrow_auth_type() == &AuthType::PIN{
            valid_pin = self.valid_pin(pin.to_string(),Some("pin".to_string())).unwrap();
        }else{
            valid_pin = pin.clone().to_string();
        }
        let merged_bytes = Bytes::from([data,Bytes::from(valid_pin)].concat());
        self.basic_state.connection.send_encrypted(&[0x80, 0xD0, 0x05, 0x00], merged_bytes, false)?;
        if ! self.basic_state.is_open(){
            self.basic_state.auth_type = AuthType::PIN;
        }
        Ok(())
    }
    fn extended_public_key(self: &Self) -> bool {
        return (self.basic_state.data.clone().unwrap()[1] & isize::from_str_radix("00000100", 2).unwrap() as u8) != 0;
    }
    fn generate_random_number(self: &mut Self, _size: u8) -> Result<Bytes,Error> {
        unimplemented!()
    }
    fn generate_seed(self: &mut Self, pin: &str) -> Result<Bytes,Error> {
        let valid_pin;
        if &self.basic_state.auth_type == &AuthType::PIN{
            valid_pin = self.valid_pin(pin.to_string(),Some("pin".to_string())).unwrap();
        }else{
            valid_pin = pin.to_string();
        }
        let message = [0x80, 0xD4, 0x00, 0x00];
        let result = self.basic_state.connection.send_encrypted(&message, Bytes::from(valid_pin.to_string()),false);
        if let Err(_err) = &result {
            return Err(Error::KeyAlreadyGenerated);
        }

        //TODO self._data[1] ???
        let mut card_data = self.basic_state.data.clone().unwrap();
        card_data[1] += isize::from_str_radix("00100000", 2).unwrap() as u8;
        self.basic_state.data = Some(card_data);

        if ! self.is_open(){
            self.basic_state.auth_type = AuthType::PIN;
        }

        return Ok(result.unwrap());
    }
    fn get_public_key(self: &mut Self, derivation: u8, key_type: Option<u8>, path: Option<PathBuf>, compressed: Option<bool>) -> Result<Bytes,Error> {
        if ! self.basic_state.is_initialized(){
            return Err(Error::InitializationException);
        }

        if self.seed_source().unwrap() == SeedSource::NoSeed{
            return Err(Error::SeedException);
        }
        let mut keytype = 0x00;
        if let Some(some_keytype) = key_type{
            let _keytype = match some_keytype.try_into(){
                Ok(KeyType::K1) => Ok(KeyType::K1),
                Ok(KeyType::R1) => Err(Error::KeyTypeUnsupported),
                Err(_) => Err(Error::KeyTypeUnsupported),
            }.unwrap();
            keytype = some_keytype;
        }
        let matched_derivation = match derivation.try_into(){
            Ok(Derivation::CurrentKey) => Ok(Derivation::CurrentKey),
            Ok(Derivation::Derive) => Err(Error::DerivationSelectionError),
            Ok(Derivation::DeriveAndMakeCurrent) => Err(Error::DerivationSelectionError),
            Ok(Derivation::PinlessPath) => Err(Error::DerivationSelectionError),
            Err(_) => Err(Error::DerivationSelectionError),
        }.unwrap();

        if matched_derivation.ne(&Derivation::CurrentKey) {
            return Err(Error::DerivationSelectionError);
        }

        let message = [0x80, 0xC2, derivation + keytype, 1];
        let binary_path : Bytes;
        if path.is_some(){
            binary_path = path_to_bytes(path.unwrap().into_os_string().into_string().unwrap());
        }else{
            binary_path = Bytes::from("");
        }
        let data = self.basic_state.connection.send_encrypted(&message, binary_path, false);
        
        //TODO implememt hex()
        let mut result = data.unwrap();
        let mut comp_bool = false;
        if let Some(comp) = compressed{
            comp_bool = comp;
        }
        if comp_bool == true{
            result = encode_pubkey(result.to_vec(),"bin_compressed").unwrap();
        }

        return Ok(result);

    }
    fn history(self: &mut Self, index: u8) -> Result<(u32,Bytes),Error> {
        let res = self.basic_state.connection.send_encrypted(&[0x80, 0xFB, index, 0x00], Bytes::from(vec![]), false);
        match res{
            Ok(bytes) => {
                Ok((u32::from_be_bytes(bytes[..4].try_into().unwrap()),Bytes::from(bytes[4..].to_vec())))
            },
            Err(error) => Err(error),
        }
    }
    fn is_initialized(self: &Self) -> bool {
        return (self.basic_state.data.clone().unwrap()[1] & isize::from_str_radix("01000000", 2).unwrap() as u8) != 0;
    }
    fn load_seed(self: &mut Self, _seed: Option<Bytes>, _pin: Option<String>)-> Result<(),Error> {
        unimplemented!()
    }
    fn pin_authentication(self: &Self) -> bool {
        return (self.basic_state.data.clone().unwrap()[1] & isize::from_str_radix("00010000", 2).unwrap() as u8) != 0;
    }
    fn pinless_enabled(self: &Self) -> bool {
        return (self.basic_state.data.clone().unwrap()[1] & isize::from_str_radix("00001000", 2).unwrap() as u8) != 0;
    }
    fn reset(self: &mut Self, puk: &str) {
        let valid_puk = self.valid_puk(String::from(puk), None).unwrap();

        let res = self.basic_state.connection.send_encrypted(&[0x80, 0xFD, 0, 0], Bytes::from(valid_puk), false);

        match res{
            Ok(bytes) => {
                self.basic_state.auth_type = AuthType::NoAuth;
                println!("Card reset successful:{:?}",bytes);
            }
            Err(error) => {
                println!("Error resetting card: {:?}",error);
            }
        }
    }
    fn seed_source(self: &mut Self) -> Result<SeedSource,Error> {
        // unimplemented!()
        let info = self.get_info().unwrap();
        match info[0].try_into(){
            Ok(SeedSource::Dual) => Ok(SeedSource::Dual),
            Ok(SeedSource::Extended) => Ok(SeedSource::Extended),
            Ok(SeedSource::External) => Ok(SeedSource::External),
            Ok(SeedSource::Internal) => Ok(SeedSource::Internal),
            Ok(SeedSource::NoSeed) => Ok(SeedSource::NoSeed),
            Ok(SeedSource::Single) => Ok(SeedSource::Single),
            Err(_) => Err(Error::SeedException),
        }
    }
    fn set_pin_authentication(self: &mut Self, _status: bool, _puk: &str) -> Result<(),Error> {
        unimplemented!()

    }
    fn set_pinless_path(self: &mut Self, _path: String, _puk: &str) -> Result<(),Error> {
        unimplemented!()
    }
    fn set_extended_public_key(self: &mut Self, status: bool, puk: &str) -> Result<(),Error>{
        if self.seed_source().unwrap() == SeedSource::NoSeed{
            return Err(Error::SeedException);
        }

        let valid_puk = self.valid_puk(puk.to_string(), None).unwrap();
        let status = status as u8;
        let data = Bytes::from([[status].to_vec(),valid_puk.as_bytes().to_vec()].concat());
        let res = self.basic_state.connection.send_encrypted(&[0x80, 0xC3, 0, 0], data, false);

        match res{
            Ok(bytes) => {println!("Extended public key set{:?}",bytes);Ok(())},
            Err(error) => {println!("Error setting extended public key{:?}",error);Err(error)},
        }
    }
    fn sign(self: &mut Self, data: Bytes, derivation: Option<u8>, key_type: Option<u8>, path: Option<&str>, pin: Option<&str>, filter_eos: Option<bool>) -> Result<Bytes,Error> {
        // unimplemented!()
        if self.seed_source().unwrap() == SeedSource::NoSeed{
            return Err(Error::SeedException);
        }
        let mut valid_pin = String::from("");
        if let Some(input_pin) = pin{
            valid_pin = self.valid_pin(input_pin.to_string(), None).unwrap_or(String::from(""));
        }

        let mut valid_derivation: u8 = 0x00;
        if let Some(input_derivation) = derivation{
            let _matched_derivation = match input_derivation.try_into(){
                Ok(Derivation::CurrentKey) => Ok(Derivation::CurrentKey),
                Ok(Derivation::Derive) => Ok(Derivation::Derive),
                Ok(Derivation::DeriveAndMakeCurrent) => Ok(Derivation::DeriveAndMakeCurrent),
                Ok(Derivation::PinlessPath) => Ok(Derivation::PinlessPath),
                Err(_) => Err(Error::DerivationSelectionError),
            }.unwrap();
            valid_derivation = input_derivation;
        }

        let mut valid_keytype = 0x00;
        if let Some(keytype) = key_type{
            let _matched_keytype = match keytype.try_into(){
                Ok(KeyType::K1) => Ok(KeyType::K1),
                Ok(KeyType::R1) => Ok(KeyType::R1),
                Err(_) => Err(Error::KeyTypeUnsupported),
            }.unwrap();
            valid_keytype = keytype;
        }

        let mut eos = false;
        if let Some(filtereos) = filter_eos{
            eos = filtereos;
        }

        let mut eos_value = 0x00;
        if eos{
            eos_value = 0x01;
        }

        let signal = [0x80, 0xC0, valid_derivation + valid_keytype, eos_value];

        let derivation_base = (valid_derivation+valid_keytype) & 0x0F;

        let mut signing_data = data;

        if [1,2].contains(&derivation_base){
            signing_data = Bytes::from([signing_data,path_to_bytes(path.unwrap().to_string())].concat());
        }

        if valid_pin != ""{
            signing_data = Bytes::from([signing_data,Bytes::from(valid_pin)].concat());
        }

        let result = self.basic_state.connection.send_encrypted(&signal, signing_data, false);
        if let Ok(res) = result{
            return Ok(res);
        }else{
            return Err(Error::DataException);
        }
        
    }
    fn signing_counter(self: &mut Self) -> Result<u32,Error> {
        let result = self.get_info().unwrap().to_vec();
        let position = 1 + (result[1] as usize) + (result[(result[1 as usize] +2)  as usize] as usize) + 2;
        let byte_array: [u8;4] = result.get(position..).unwrap().try_into().unwrap();
        let res = u32::from_be_bytes(byte_array);
        Ok(res)
    }
    fn unblock_pin(self: &mut Self, puk: String, new_pin: String)  -> Result<(),Error>{
        self.basic_state.unblock_pin(puk, new_pin)?;
        Ok(())
    }
    fn user_data(self: &Self) -> Bytes {
        unimplemented!()
    }
    fn write_user_data(self: &Self, _value: Bytes) {
        unimplemented!()
    }
    fn user_key_add(self: &mut Self, _slot_index: u8, _data_info : &str, _public_key: Bytes, _puk: &str, _cred_id : Option<Bytes>) -> Result<(),Error>{
        unimplemented!()
    }
    fn user_key_delete(self: &mut Self, _slot: u8, _puk: &str) -> Result<(),Error> {
        unimplemented!()
    }
    fn user_key_info(self: &mut Self, _slot: u8) -> Result<(String,Bytes),Error> {
        unimplemented!()
    }
    fn user_key_enabled(self: &Self, _slot: u8) -> bool {
        false
    }
    fn user_key_challenge_response_nonce(self: &mut Self) -> Result<Bytes,Error> {
        unimplemented!()
    }
    fn user_key_challenge_response_open(self: &mut Self, _slot: u8, _signature: Bytes) -> bool {
        unimplemented!()
    }
    fn user_key_signature_open(self: &mut Self, _slot: u8, _message: Bytes, _signature: Bytes) -> bool {
        unimplemented!()
    }
    fn valid_key(self: &Self) -> bool {
        return (self.basic_state.data.clone().unwrap()[1] & isize::from_str_radix("00100000", 2).unwrap() as u8) != 0;
    }
    fn valid_pin(self: &Self,pin: String, _pin_name: Option<String>) -> Result<String,Error> {
        return self.basic_state.valid_pin(pin, Some("".to_string()));
    }
    fn valid_puk(self: &Self,puk: String, _puk_name: Option<String>) -> Result<String,Error> {
        if puk.len() != 12{
            return Err(Error::DataValidationExceptionBasicG1PUK);
        }

        if ! puk.chars().all(char::is_alphanumeric){
            return Err(Error::DataValidationExceptionBasicG1PUK);
        }

        return Ok(puk);
    }
    fn verify_pin(&mut self, pin: &str) {
        // unimplemented!()
        let pin = self.valid_pin(pin.to_string(), None).unwrap();
        let apdu: Vec<u8> = vec![0x80, 0x20, 0x00, 0x00];
        match self.basic_state.connection.send_encrypted(&apdu, Bytes::from(pin), false){
            Ok(res_bytes) => {
                println!("PIN code has been verified: \n{:?}",res_bytes);
            },
            Err(_) => {println!("PIN verification failed.")},
        }
    }
    fn sign_eos(self: &mut Self,_apdu: &[u32],_data: Bytes, _pin: &str) -> Result<Bytes,Error>{
        unimplemented!()
    }

    fn get_info(self: &mut Self) -> Result<Bytes, Error>{
        let result = self.basic_state.connection.send_encrypted(&[0x80, 0xFA, 0x00, 0x00], Bytes::from(""), false);
        match result{
            Ok(bytes) => Ok(bytes),
            Err(_) => Err(Error::SecureChannelError),
        }
    }
    fn signature_check(self: &mut Self, nonce: Bytes) -> Result<SignatureCheckResponse,Error>{
        let message = [0x80, 0xF8, 0x01, 0x00];

        let res = self.basic_state.connection.send_encrypted(&message,nonce, false);
        
        match res{
            Ok(bytes) => {
                Ok(SignatureCheckResponse{ message: Bytes::from(bytes[..36].to_vec()), signature: Bytes::from(bytes[36..].to_vec()) })
            },
            Err(error) => {
                Err(error)
            },
        }
    }
}

impl BasePriv for NFT {
    fn owner(self: &mut Self) -> CardUser {
        let message = [0x80, 0xFA, 0x00, 0x00];
        let res = self.basic_state.connection.send_encrypted(&message, Bytes::from(vec![0]), false);

        match res{
            Ok(bytes) => {
                let name_length = bytes[0] as usize;
                let name = encode_hex(&bytes[1..(name_length+1)]);

                let email_length = bytes[name_length+1] as usize;
                let user_list_offset = email_length + 2 + name_length;
                let email = encode_hex(&bytes[(name_length + 2)..user_list_offset]);
                CardUser { name , email }
        },
            Err(_) => CardUser { name: "".to_string(), email: "".to_string() },
        }
    }
    fn borrow_connection(self: &mut Self) -> &mut crate::connection::Connection {
        self.basic_state.borrow_connection()
    }
    fn serial_number(self: &Self) -> u64 {
        self.basic_state.serial_number()
    }
    fn borrow_applet_version(self: &Self) -> &Vec<u8> {
        self.basic_state.borrow_applet_version()
    }
    fn borrow_origin(self: &Self) -> &CardOrigin {
        self.basic_state.borrow_origin()
    }
    fn borrow_origin_mut(self: &mut Self) -> &mut CardOrigin {
        self.basic_state.borrow_origin_mut()
    }
    fn borrow_auth_type(self: &Self) -> &AuthType {
        self.basic_state.borrow_auth_type()
    }
}