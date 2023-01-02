use bytes::{BytesMut, BufMut};

use super::Basic;
use crate::connection::Connection;
use crate::card::*;
use crate::cryptos_functions::encode_pubkey;
use crate::utils::{path_to_bytes,encode_hex,set_bit,clear_bit};
use std::convert::TryInto;
use std::vec;
pub struct BasicGen1 {
    basic_state: Basic,
}

impl BasicGen1 {
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

impl Base for BasicGen1 {
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
    fn init(self: &Self, name: String, email: String, pin: String, puk: String, pairing_secret: Option<Bytes>,_nfc_sign: Option<bool>) -> Result<Vec<u8>,Error> {
        let valid_puk = self.valid_puk(puk.clone(), Some("puk".to_string()));
        
        if let Err(error) = valid_puk{
            return Err(error);
        }
        let res = self.basic_state.init(name, email, pin, valid_puk.unwrap(),pairing_secret,None);

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
    fn derive(self: &mut Self, _key_type: Option<u8>, path: Option<PathBuf>) -> Result<(),Error>{
        let pathbuf = path.unwrap_or(PathBuf::new());
        if self.seed_source().unwrap() == SeedSource::NoSeed{
            return Err(Error::SeedException);
        }
        let message = [0x80, 0xD1, 0x08, 0x00];
        let binary_path : Bytes;
        if pathbuf.clone().into_os_string().into_string().unwrap() != ""{
            binary_path = path_to_bytes(pathbuf.into_os_string().into_string().unwrap());
        }else{
            binary_path = Bytes::from("".to_string());
        }
        let res = self.basic_state.connection.send_encrypted(&message,binary_path,false);
        match res{
            Ok(_) => Ok(()),
            Err(_) => Err(Error::DerivationOperationsUnsupported),
        }
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
    fn generate_random_number(self: &mut Self, size: u8) -> Result<Bytes,Error> {
        return self.basic_state.connection.send_encrypted(&[0x80, 0xD3, size, 0x00], Bytes::from(""), false);
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
                Ok(KeyType::R1) => Ok(KeyType::R1),
                Err(_) => Err(Error::KeyTypeUnsupported),
            }.unwrap();
            keytype = some_keytype;
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
        return (self.basic_state.data.clone().unwrap()[1] & isize::from_str_radix("00010000", 2).unwrap() as u8) != 0;
    }
    fn pinless_enabled(self: &Self) -> bool {
        return (self.basic_state.data.clone().unwrap()[1] & isize::from_str_radix("00001000", 2).unwrap() as u8) != 0;
    }
    fn reset(self: &mut Self, puk: &str) {
        let valid_puk = self.valid_puk(String::from(puk), None).unwrap();

        let res = self.basic_state.connection.send_encrypted(&[0x80, 0xFD, 0, 0], Bytes::from(valid_puk), false);

        match res{
            Ok(_bytes) => {
                self.basic_state.auth_type = AuthType::NoAuth;
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
    fn set_pin_authentication(self: &mut Self, status: bool, puk: &str) -> Result<(),Error> {
        let valid_puk = self.valid_puk(String::from(puk), None).unwrap();
        let status_bytes = Bytes::from(vec![(status != true) as u8]);
        let data = Bytes::from([status_bytes,Bytes::from(valid_puk)].concat());

        self.basic_state.connection.send_encrypted(&[0x80, 0xC3, 0, 0], data, false).unwrap();

        let mut data_vec = self.basic_state.data.clone().unwrap();
        data_vec[1] |= isize::from_str_radix("00010000", 2).unwrap() as u8;
        self.basic_state.data = Some(data_vec);
        Ok(())

    }
    fn set_pinless_path(self: &mut Self, path: String, puk: &str) -> Result<(),Error> {
        if self.seed_source().unwrap() == SeedSource::NoSeed{
            return Err(Error::SeedException);
        }
        let valid_puk = self.valid_puk(puk.to_string(), None)?;
        let pathbytes = path_to_bytes(path);
        let data = Bytes::from([valid_puk.as_bytes().to_vec(),pathbytes.to_vec()].concat());
        let res = self.basic_state.connection.send_encrypted(&[0x80, 0xC1, 0, 0], data, false);
        
        match res{
            Ok(_) => {
                let mut data = self.basic_state.data.clone().unwrap();
                data[1] |= isize::from_str_radix("00001000", 2).unwrap() as u8;
                self.basic_state.data = Some(data);
                Ok(())
            },
            Err(error) => {println!("Error setting pinless path{:?}",error);Err(error)},
        }

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
        if ! self.pin_authentication(){
            return Err(Error::PinException);
        }

        let res = self.basic_state.unblock_pin(puk, new_pin);
        match res{
            Ok(_) => Ok(()),
            Err(error) => Err(error),
        }
    }
    fn user_data(self: &Self) -> Bytes {
        unimplemented!()
    }
    fn write_user_data(self: &Self, _value: Bytes) {
        unimplemented!()
    }
    fn user_key_add(self: &mut Self, slot_index: u8, data_info : &str, public_key: Bytes, puk: &str, cred_id : Option<Bytes>) -> Result<(),Error>{
        let data_info_length = 64;
        let valid_puk = self.valid_puk(String::from(puk), None).unwrap(); 
        if data_info.len() > data_info_length{
            return Err(Error::DataException);
        }

        let mut data_info_padded = BytesMut::from(data_info.as_bytes());
        for _ in 0..(data_info_length-data_info.len()){
            data_info_padded.put_u8(0);
        }
        let slot ;

        let match_slot = match slot_index.try_into(){
            Ok(SlotIndex::EC256R1) => Ok(SlotIndex::EC256R1),
            Ok(SlotIndex::RSA) => Ok(SlotIndex::RSA),
            Ok(SlotIndex::FIDO) => Ok(SlotIndex::FIDO),
            Err(_) => Err(Error::DataException),
        }.unwrap();

        slot = slot_index;

        let mut data = Bytes::from([Bytes::from(vec![slot]),Bytes::from(data_info_padded)].concat());
        if match_slot == SlotIndex::FIDO{
            if let Some(cred) = cred_id{
                data = Bytes::from([data,Bytes::from(cred.len().to_be_bytes().to_vec()),cred].concat());
            }else{
                return Err(Error::DataException);
            }
        }
        data = Bytes::from([data,public_key,Bytes::from(valid_puk)].concat());

        let res = self.basic_state.connection.send_encrypted(&[0x80, 0xD5, 0x00, 0x00], data, false);

        match res{
            Ok(_) => {
                let mut card_data = self.basic_state.data.clone().unwrap();
                let bit_set_data = set_bit(card_data[3],slot - 1);
                card_data[3] = bit_set_data;
                self.basic_state.data = Some(card_data);
                Ok(())
            },
            Err(error) => {
                Err(error)
            }
        }
    }
    fn user_key_delete(self: &mut Self, slot: u8, puk: &str) -> Result<(),Error> {
        let valid_puk = self.valid_puk(String::from(puk), None).unwrap(); 
        let _ = match slot.try_into(){
            Ok(SlotIndex::EC256R1) => Ok(SlotIndex::EC256R1),
            Ok(SlotIndex::RSA) => Ok(SlotIndex::RSA),
            Ok(SlotIndex::FIDO) => Ok(SlotIndex::FIDO),
            Err(_) => Err(Error::DataException),
        }.unwrap();
        let data = Bytes::from([Bytes::from(vec![slot]),Bytes::from(valid_puk)].concat());
        let res = self.basic_state.connection.send_encrypted(&[0x80, 0xD7, 0x00, 0x00], data, false);

        match res{
            Ok(_) => {
                let mut card_data = self.basic_state.data.clone().unwrap();
                let bit_set_data = clear_bit(card_data[3],slot - 1);
                card_data[3] = bit_set_data;
                self.basic_state.data = Some(card_data);
                Ok(())
            },
            Err(_) => {
                Err(Error::DataException)
            },
        }
        
    }
    fn user_key_info(self: &mut Self, slot: u8) -> Result<(String,Bytes),Error> {
        let _ = match slot.try_into(){
            Ok(SlotIndex::EC256R1) => Ok(SlotIndex::EC256R1),
            Ok(SlotIndex::RSA) => Ok(SlotIndex::RSA),
            Ok(SlotIndex::FIDO) => Ok(SlotIndex::FIDO),
            Err(_) => Err(Error::DataException),
        };
        let res = self.basic_state.connection.send_encrypted(&[0x80, 0xFA, slot, 0x00], Bytes::from(vec![]), false);

        match res{
            Ok(bytes) => {
                let former = encode_hex(&bytes[64..]);
                let latter = Bytes::from(bytes[..64].to_vec());
                Ok((former,latter))
            },
            Err(error) => {
                Err(error)
            },
        }
    }
    fn user_key_enabled(self: &Self, slot: u8) -> bool {
        return (self.basic_state.data.clone().unwrap()[3] & slot) != 0;
    }
    fn user_key_challenge_response_nonce(self: &mut Self) -> Result<Bytes,Error> {
        let res = self.basic_state.connection.send_encrypted(&[0x80, 0xD6, 0x01, 0x00], Bytes::from(vec![]), false);
        match res{
            Ok(bytes) => {
                Ok(bytes)
            },
            Err(error) => Err(error),
        }
    }
    fn user_key_challenge_response_open(self: &mut Self, slot: u8, signature: Bytes) -> bool {
        let _ = match slot.try_into(){
            Ok(SlotIndex::EC256R1) => Ok(SlotIndex::EC256R1),
            Ok(SlotIndex::RSA) => Ok(SlotIndex::RSA),
            Ok(SlotIndex::FIDO) => Ok(SlotIndex::FIDO),
            Err(error) => Err(error),
        };
        let data = Bytes::from([vec![slot],signature.to_vec()].concat());

        let res = self.basic_state.connection.send_encrypted(&[0x80, 0xD6, 0x02, 0x00], data, false);

        match res{
            Ok(bytes) => {
                let result = (bytes[0] as u8) == 0x01;
                if result && ! self.is_open(){
                    self.basic_state.auth_type = AuthType::UserKey;
                }
                result
            },
            Err(error) => {println!("Error user key challenge response open:{:?}",error);false},
        }
    }
    fn user_key_signature_open(self: &mut Self, slot: u8, message: Bytes, signature: Bytes) -> bool {
        let data = Bytes::from([vec![slot],message.to_vec(),signature.to_vec()].concat());
        let res = self.basic_state.connection.send_encrypted(&[0x80, 0xD6, 0x00, 0x00], data, false);
        
        match res{
            Ok(bytes) => {
                return (bytes[0] as u8) == 0x01;
            },
            Err(error) => {println!("Error in user key signature open: \n{:?}",error);false},
        }
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

impl BasePriv for BasicGen1 {
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