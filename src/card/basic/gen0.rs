use super::Basic;
use crate::connection::Connection;
use crate::card::*;
use crate::cryptos_functions::{encode_pubkey};
use crate::utils::{path_to_bytes,encode_hex};
use std::str;

pub struct BasicGen0 {
    basic_state: Basic,
    
}

impl BasicGen0 {
    pub fn new(connection: Connection, serial: u64, applet_version: Vec<u8>) -> Self {
        Self {
            basic_state: Basic::new(connection,serial,applet_version)
        }
    }
    pub fn with_data(self, data: Vec<u8>) -> Self {
        Self {
            basic_state: self.basic_state.with_data(data)
        }
    }
}

impl Base for BasicGen0 {
    fn select_adpu() -> Vec<u32> {
        return [0xA0, 0x00, 0x00, 0x10, 0x00, 0x01, 0x01].to_vec();
    }
    fn card_type() -> u32 {
        unimplemented!()
    }
    fn pin_rule() -> String {
        unimplemented!()
    }
    fn puk_rule(self: &Self) -> String {
        return String::from("15 digits and/or letters");
    }
    fn change_pairing_key(self: &mut Self, index: u8, pairing_key: &[u8], puk: String) -> Result<(),Error> {
        if pairing_key.len() != 32{
            return Err(Error::InvalidPairingKeyBytes);
        }
        if ! (index > 0) && (index <=7){
            return Err(Error::InvalidPairingKeyBytes);
        }
        self.valid_puk(puk,Some("puk".to_string())).unwrap();
        let data = [&[index],pairing_key].concat();
        let data_bytes: Bytes = Bytes::from(data);
        let res = self.basic_state.connection.send_encrypted(&[0x80, 0xDA,0x00, 0x00], data_bytes,false);

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
    fn init(self: &Self, name: String, email: String, pin: String, puk: String, pairing_secret: Option<Bytes>,_nfc_sign: Option<bool>) -> Result<Vec<u8>,Error> {
        let valid_puk = self.valid_puk(puk.clone(), Some("puk".to_string()));
        
        if let Err(error) = valid_puk{
            return Err(error);
        }
        let res = self.basic_state.init(name, email, pin, valid_puk.unwrap(),pairing_secret, None);

        match res{
            Ok(vec) => {
                Ok(vec)
            },
            Err(error) => {
                Err(error)
            },
        }
        // self.user_data = Some(UserData::new(self, 1, 1));
    }
    fn derive(self: &mut Self, key_type: Option<u8>, path: Option<PathBuf>) -> Result<(),Error>{ 
        let res = self.get_public_key(0x02, key_type, path, None);
        match res{
            Ok(_) => Ok(()),
            Err(error) => Err(error) ,
        }
    }
    fn dual_seed_public_key(self: &mut Self, _pin: &str) -> Result<Bytes,Error> {
        unimplemented!()
    }
    fn dual_seed_load(self: &mut Self,_data: Bytes, _pin: &str) -> Result<(),Error>{
        unimplemented!()
    }
    fn extended_public_key(self: &Self) -> bool {
        false
    }
    fn generate_random_number(self: &mut Self, _size: u8) -> Result<Bytes,Error> {
        unimplemented!()
    }
    fn generate_seed(self: &mut Self, pin: &str) -> Result<Bytes,Error> {
        let _valid_pin;
        if &self.basic_state.auth_type == &AuthType::PIN{
            _valid_pin = self.valid_pin(pin.to_string(),Some("pin".to_string())).unwrap();
        }else{
            _valid_pin = pin.to_string();
        }
        let message = [0x80, 0xD4, 0x00, 0x00];
        let result = self.basic_state.connection.send_encrypted(&message, Bytes::from(vec![]),false);
        if let Err(_err) = &result {
            return Err(Error::KeyAlreadyGenerated);
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
        let keytype = 0x00;
        if let Some(some_keytype) = key_type{
            let _keytype = match some_keytype.try_into(){
                Ok(KeyType::K1) => Ok(KeyType::K1),
                Ok(KeyType::R1) => Ok(KeyType::R1),
                Err(_) => Err(Error::KeyTypeUnsupported),
            }.unwrap();
        }
        let matched_derivation = match derivation.try_into(){
            Ok(Derivation::CurrentKey) => Ok(Derivation::CurrentKey),
            Ok(Derivation::Derive) => Ok(Derivation::Derive),
            Ok(Derivation::DeriveAndMakeCurrent) => Ok(Derivation::DeriveAndMakeCurrent),
            Ok(Derivation::PinlessPath) => Ok(Derivation::PinlessPath),
            Err(_) => Err(Error::DerivationSelectionError),
        }.unwrap();

        if [Derivation::PinlessPath,Derivation::DeriveAndMakeCurrent].contains(&matched_derivation){
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
        let mut comp_bool = true;
        if let Some(comp) = compressed{
            comp_bool = comp;
        }
        if comp_bool == true{
            result = encode_pubkey(result.to_vec(),"bin_compressed").unwrap();
        }

        return Ok(result);

    }
    fn history(self: &mut Self, _index: u8) -> Result<(u32,Bytes),Error> {
        unimplemented!()
    }
    fn is_initialized(self: &Self) -> bool {
        return (self.basic_state.data.clone().unwrap()[1] & isize::from_str_radix("01000000", 2).unwrap() as u8) != 0;
    }
    fn load_seed(self: &mut Self, seed: Option<Bytes>, pin: Option<String>)-> Result<(),Error> {
        let mut input_pin = "".to_string();
        let seed_bytes = seed.unwrap();
        if let Some(pinn) = pin{
            input_pin = pinn;
        }
        if self.basic_state.auth_type == AuthType::PIN{
            input_pin = self.valid_pin(input_pin, Some(String::from("pin"))).unwrap_or(String::from(""));
        }
        let data = Bytes::from([seed_bytes,Bytes::from(input_pin)].concat());
        let res = self.basic_state.connection.send_encrypted(&[0x80, 0xD0, 0x03, 0x00], data, false);
        
        match res{
            Ok(_bytes) => {
                let mut data_clone = self.basic_state.data.clone().unwrap();
                data_clone[0] |= 32;
                self.basic_state.data = Some(data_clone);
                if ! self.is_open(){
                    self.basic_state.auth_type = AuthType::PIN;
                }   
                Ok(())
            },
            Err(_error) => {
                Err(Error::KeyAlreadyGenerated)
            },
        }

    }
    fn pin_authentication(self: &Self) -> bool {
        true
    }
    fn pinless_enabled(self: &Self) -> bool {
        false
    }
    fn reset(self: &mut Self, puk: &str) {
        let valid_puk = self.valid_puk(String::from(puk), None).unwrap();

        let res = self.basic_state.connection.send_encrypted(&[0x80, 0xC0, 0x00, 0], Bytes::from(valid_puk), false);

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
        unimplemented!()
    }
    fn set_pin_authentication(self: &mut Self, _status: bool, _puk: &str) -> Result<(),Error> {
        unimplemented!()

    }
    fn set_pinless_path(self: &mut Self, _path: String, _puk: &str) -> Result<(),Error> {
        unimplemented!()
    }
    fn set_extended_public_key(self: &mut Self, _status: bool, _puk: &str) -> Result<(),Error>{
        unimplemented!()
    }
    fn sign(self: &mut Self, data: Bytes, derivation: Option<u8>, key_type: Option<u8>, path: Option<&str>, pin: Option<&str>, filter_eos: Option<bool>) -> Result<Bytes,Error> {
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
        unimplemented!()
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
        unimplemented!()
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

    fn signature_check(self: &mut Self, _nonce: Bytes) -> Result<SignatureCheckResponse,Error>{
        unimplemented!()
    }
}

impl BasePriv for BasicGen0 {
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