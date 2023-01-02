use super::*;
use crate::utils::{self, decode_hex};
use crate::connection::Connection;
use crate::consts::BASIC_PAIRING_SECRET;
use bytes::BytesMut;
use openssl::{nid::Nid as AlgorithmKind,ec,bn::BigNumContext,ec::{EcKey,EcGroup, EcPoint},
    derive::Deriver,pkey::PKey};


pub mod gen0;
pub mod gen1;
pub mod nft;
#[allow(dead_code)]
pub struct Basic {
    connection: Connection,
    algorithm: AlgorithmKind,
    puk_length: usize,
    data: Option<Vec<u8>>,
    origin: CardOrigin,
    auth_type: AuthType,
    serial: u64,
    applet_version: Vec<u8>
}


impl Basic {
    pub fn new(mut connection: Connection, serial: u64, applet_version: Vec<u8>) -> Self {
        connection.set_pairing_secret(BASIC_PAIRING_SECRET);
        Self {
            connection,
            algorithm: AlgorithmKind::X9_62_PRIME256V1,
            puk_length: 15,
            data: None,
            origin: CardOrigin::Unknown,
            auth_type: AuthType::NoAuth,
            serial: serial,
            applet_version
        }
    }
    /// builder pattern to use with Basic::new
    fn with_data(mut self, data: Vec<u8>) -> Self {
        self.data = Some(data);
        self
    }
}

impl Base for Basic {
    fn select_adpu() -> Vec<u32> {
        unimplemented!()
    }
    fn card_type() -> u32 {
        unimplemented!()
    }
    fn pin_rule() -> String {
        unimplemented!()
    }
    fn puk_rule(self: &Self) -> String {
        unimplemented!()
    }
    fn change_pairing_key(self: &mut Self, _index: u8, _pairing_key: &[u8], _puk: String)-> std::result::Result<(), Error> {
        unimplemented!()
    }
    fn change_pin(self: &mut Self, new_pin: String) -> Result<(),Error> {
        let new_pin = self.valid_pin(new_pin,Some("new pin".to_string())).expect("Invalid PIN");
        let message = [0x80, 0x21, 0x00, 0x00];
        if ! self.is_initialized() {
            Err(Error::UninitializedCard)
        } else {
            self.connection.send_encrypted(&message, Bytes::copy_from_slice(new_pin.as_bytes()), false)?;
            if ! self.is_open() {
                self.auth_type = AuthType::PIN;
            }
            Ok(())
        } 
    }
    fn change_puk(self: &mut Self, current_puk: String, new_puk: String) -> Result<(),Error> {
        let current_puk = self.valid_puk(current_puk, Some("current puk".to_string()));
        let new_puk = self.valid_puk(new_puk, Some("new puk".to_string()));
        let message = [0x80, 0x21, 0x01, 0x00];
        if ! self.is_initialized() {
            Err(Error::UninitializedCard)
        } else {
            let value =  format!("{}{}",new_puk.unwrap(),current_puk.unwrap());
            self.connection.send_encrypted(&message, Bytes::copy_from_slice(value.as_bytes()), false)?;
            if ! self.is_open() {
                self.auth_type = AuthType::PIN;
            }
            Ok(())
        } 
    }
    fn init(self: &Self, name: String, email: String, pin: String, puk: String, pairing_secret: Option<Bytes>,_nfc_sign: Option<bool>) -> Result<Vec<u8>,Error> {
        let validated_pin = self.valid_pin(pin,Some("pin".to_string()));
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
        let mut valid_pairing_secrect = Bytes::from("Cryptnox Basic CommonPairingData");
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
            let pkey = &self.connection.session_public_key;
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
        let data_slices: &[u8] = &[name_slice,email_slice,valid_pin_slice,puk_slice,&valid_pairing_secrect].concat();
        let mut data = BytesMut::from(data_slices);
        utils::pad_data(&mut data);
        let payload = Bytes::from(data.to_vec());
        let encrypted_payload = utils::aes_encrypt_unpadded(aes_init_key.clone(), Bytes::copy_from_slice( &iv_init_key), payload,data.len())?;
        let data_init = [Bytes::from(send_public_key),Bytes::copy_from_slice(&iv_init_key),encrypted_payload.clone()].concat();
        let apdu_init: Vec<u8> = [0x80, 0xFE, 0x00, 0x00, 82 + encrypted_payload.len() as u8].to_vec();
        let apdu_init = [apdu_init,data_init].concat();
        let (_, code1, code2) = self.connection.send_apdu(&apdu_init)?;
        if code1 != 0x90 || code2 != 0x00{
            return Err(Error::InitializationException);
        }

        return Ok([Bytes::from([0].to_vec()),valid_pairing_secrect].concat());
        
    }
   
    fn derive(self: &mut Self, _key_type: Option<u8>, _path: Option<PathBuf>) -> Result<(),Error>{
        unimplemented!()
    }
    fn dual_seed_public_key(self: &mut Self, _pin: &str) -> Result<Bytes,Error> {
        unimplemented!()
    }
    fn dual_seed_load(self: &mut Self,_data: Bytes, _pin: &str) -> Result<(),Error>{
        unimplemented!()
    }
    fn extended_public_key(self: &Self) -> bool {
        unimplemented!()
    }
    fn generate_random_number(self: &mut Self, _size: u8) -> Result<Bytes,Error> {
        unimplemented!()
    }
    fn generate_seed(self: &mut Self, _pin: &str) -> Result<Bytes,Error> {
        unimplemented!()
    }
    fn get_public_key(self: &mut Self, _derivation: u8, _key_type: Option<u8>, _path: Option<PathBuf>, _compressed: Option<bool>) -> Result<Bytes,Error> {
        unimplemented!()
    }
    fn history(self: &mut Self, _index: u8) -> Result<(u32,Bytes),Error> {
        unimplemented!()
    }
    fn is_initialized(self: &Self) -> bool {
        return (self.data.as_ref().unwrap()[1] & u8::from_str_radix("01000000", 2).unwrap()) != 0;
    }
    fn load_seed(self: &mut Self, _seed: Option<Bytes>,_pinn: Option<String>)-> Result<(),Error> {
        unimplemented!()
    }
    fn pin_authentication(self: &Self) -> bool {
        unimplemented!()
    }
    fn pinless_enabled(self: &Self) -> bool {
        unimplemented!()
    }
    fn reset(self: &mut Self, _puk: &str) {
        unimplemented!()
    }
    fn seed_source(self: &mut Self) -> Result<SeedSource,Error> {
        unimplemented!()
    }
    fn set_pin_authentication(self: &mut Self, _status: bool, _puk: &str) -> Result<(),Error>{
        unimplemented!()
    }
    fn set_pinless_path(self: &mut Self, _path: String, _puk: &str) -> Result<(),Error> {
        unimplemented!()
    }
    fn set_extended_public_key(self: &mut Self, _status: bool, _puk: &str)-> Result<(),Error> {
        unimplemented!()
    }
    fn sign(self: &mut Self, _data: Bytes,_derivationn: Option<u8>, _key_type: Option<u8>, _path: Option<&str>,_pin: Option<&str>,_filter_eos: Option<bool>) -> Result<Bytes,Error>{
        unimplemented!()
    }
    fn signing_counter(self: &mut Self) -> Result<u32,Error> {
        unimplemented!()
    }
    fn unblock_pin(self: &mut Self, puk: String, new_pin: String) -> Result<(),Error> {
        let apdu = [0x80, 0x22, 0x00, 0x00].to_vec();
        let valid_puk = self.valid_puk(puk,Some("puk".to_string()))?;
        let new_pin = self.valid_pin(new_pin,Some("new pin".to_string()))?;

        let res = self.connection.send_encrypted(&apdu, Bytes::from([Bytes::from(valid_puk),Bytes::from(new_pin)].concat()), false);
        match res{
            Ok(_) => {
                if ! self.is_open(){
                    self.auth_type = AuthType::PIN;
                }
                Ok(())
            },
            Err(error) => Err(error),
        }
    
    }
    fn user_data(self: &Self) -> Bytes {
        unimplemented!()
    }
    fn write_user_data(self: &Self, _value: Bytes) {
        unimplemented!()
    }
    fn user_key_add(self: &mut Self, _slot_index: u8, _data_info : &str, _public_key: Bytes, _puk: &str, _cred_id : Option<Bytes>) ->Result<(),Error>{
        unimplemented!()
    }
    fn user_key_delete(self: &mut Self, _slot: u8, _puk_code: &str) ->Result<(),Error>{
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
        unimplemented!()
    }
    fn valid_pin(self: &Self,pin: String, _pin_name: Option<String>) -> Result<String,Error> {
        if ! (4<= pin.len() && pin.len() <= 9){
            return Err(Error::InvalidPinName);
        }
        if ! pin.chars().all(char::is_numeric){
            return Err(Error::NonNumericPinName);
        }
        let mut v: Vec<String> = Vec::new();
        for  _n in 1..= 9 - pin.len() as i32 {
            v.push(String::from("\u{0000}"));
        }
        let null_chars = v.join("");
        let padded_pin = [pin,null_chars].join("");
        return Ok(padded_pin)
    }
    fn valid_puk(self: &Self, puk: String, _puk_name: Option<String>) -> Result<String,Error> {
        if puk.len() != 12{
            return Err(Error::DataValidationExceptionBasicG1PUK);
        }

        if ! puk.chars().all(char::is_alphanumeric){
            return Err(Error::DataValidationExceptionBasicG1PUK);
        }

        return Ok(puk);
    }
    fn verify_pin(&mut self, pin: &str) {
        let pin = self.valid_pin(pin.to_string(), None).unwrap();
        let apdu: Vec<u8> = vec![0x80, 0x20, 0x00, 0x00];
        match self.connection.send_encrypted(&apdu, Bytes::from(pin), false){
            Ok(res_bytes) => {
                println!("PIN code has been verified: \n{:?}",res_bytes);
            },
            Err(_) => {println!("PIN verification failed.")},
        }
    }

    fn sign_eos(self: &mut Self, _apdu: &[u32], _data: Bytes, _pin: &str) -> Result<Bytes,Error>{
        unimplemented!()
    }

    fn get_info(self: &mut Self) -> Result<Bytes,Error> {
        unimplemented!()
    }

    fn signature_check(self: &mut Self, _nonce: Bytes) -> Result<SignatureCheckResponse,Error>{
        unimplemented!()
    }
}

impl BasePriv for Basic {
    fn owner(self: &mut Self) -> CardUser {
        unimplemented!()
    }
    fn borrow_connection(self: &mut Self) -> &mut crate::connection::Connection {
        &mut self.connection
    }
    fn serial_number(self: &Self) -> u64 {
        self.serial
    }
    fn borrow_applet_version(self: &Self) -> &Vec<u8> {
        &self.applet_version
    }
    fn borrow_origin(self: &Self) -> &CardOrigin {
        &self.origin
    }
    fn borrow_origin_mut(self: &mut Self) -> &mut CardOrigin {
        &mut self.origin
    }
    fn borrow_auth_type(self: &Self) -> &AuthType {
        &self.auth_type
    }
}
