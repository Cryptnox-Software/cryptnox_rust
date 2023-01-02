use crate::{
    error::Error,
    connection::Connection,
    card::CardOrigin,utils::{list_to_hexadecimal, IterSequenceSearch, encode_hex}
};
use openssl::{ec::{EcKey,EcGroup, EcPoint},nid::Nid, pkey::Public,bn::BigNumContext};
use regex::{Regex,Match};
use futures::{self, future::try_join_all};
use tokio::{task::{self, JoinHandle}};
use crate::utils::decode_hex;
use openssl::x509::X509;

const _ECDSA_SHA256: &str = "06082a8648ce3d04030203";
const _MANUFACTURER_CERTIFICATE_URL: &str = "https://verify.cryptnox.tech/certificates/";
const _PUBLIC_K1_OID : &str = "2a8648ce3d030107034200";


pub fn origin(connection: &mut Connection,debug: bool) -> CardOrigin {
    //todo: implement
    let certificates = _manufacturer_public_keys();
    let certificate = _manufacturer_certificate_data(connection,debug);
    let hashed_certificate = decode_hex(&sha256::digest_bytes(&certificate)).unwrap();
    let signature = _manufacturer_signature(connection,debug);

    let mut error = false;

    for public_key in certificates.iter(){
        let valid = _check_signature(&hashed_certificate,public_key.to_owned(),signature.clone());
        if valid == true{
            return CardOrigin::Original;
        }else{
            error = true;
        }
    }
    if error{
        return CardOrigin::Unknown;
    }

    return CardOrigin::Fake;
}

pub fn session_public_key(connection: &Connection, debug: bool) -> Result<String,Error>{
    let card_cert_hex = _get_card_certificate(connection,debug);
    let card_cert_msg = card_cert_hex[..148].to_string();
    let card_cert_sig_hex = card_cert_hex[148..].to_string();

    if debug{
        println!("Card msg");
        println!("{:?}",card_cert_msg);
        println!("Card sig");
        println!("{:?}",card_cert_sig_hex);
    }

    let hashed_card_cert_msg = sha256::digest_bytes(&decode_hex(&card_cert_msg).unwrap());

    let ec_group = EcGroup::from_curve_name(Nid::X9_62_PRIME256V1)?;
    let mut ctx = BigNumContext::new().unwrap();
    let pub_key = EcPoint::from_bytes(&ec_group,&_public_key(connection,false),&mut ctx)?;
    let public_key = EcKey::from_public_key(&ec_group, &pub_key)?;
    if ! _check_signature(&decode_hex(&hashed_card_cert_msg).unwrap(),public_key,decode_hex(&card_cert_sig_hex).unwrap()){
        return Err(Error::GenuineCheckException)
    }
    return Ok(card_cert_hex[18..148].to_string());
}

#[allow(arithmetic_overflow)]
// Get the manufacturer certificate from the card in connection.
pub fn manufacturer_certificate(connection: &Connection) -> Result<Vec<u8>,Error> {
    let apdu = [0x80, 0xF7, 0x00, 0x00, 0x00];
    let response = connection.send_apdu(&apdu)?;
    let ret;
    if response.0.is_empty() {
        ret = vec![];
    } else {
        let apdu = [0x80, 0xF7, 0x00, 0x01, 0x00];
        let response = [response.0,connection.send_apdu(&apdu)?.0].concat();
        let len_usize: usize = response[0].into();
        let len2_usize: usize = response[1].into();
        let length = (len_usize << 8) + len2_usize;
        if response.len() != length+2{
            return Err(Error::InvalidData);
        }
        let certificate = response[2..].into_iter().map(ToOwned::to_owned).collect();
        ret = certificate
    }
    return Ok(ret);
}


pub fn _manufacturer_public_keys() -> Vec<EcKey<Public>>{
    let rt = tokio::runtime::Runtime::new().unwrap();

    async fn fetch(url: String) -> EcKey<Public>{
        let response = reqwest::get(&url).await.unwrap();
        let certificate = response.text().await.unwrap();
        let cert = X509::from_pem(certificate.as_bytes()).unwrap();
        let pkey = cert.public_key().unwrap();
        let pub_key = pkey.ec_key().unwrap();
        return pub_key;
    }

    async fn fetch_all(certificates: Vec<&str>)-> Vec<EcKey<Public>>{
        let mut tasks: Vec<JoinHandle<EcKey<Public>>> = Vec::new();
        for certificate in certificates.iter(){
            let url = _MANUFACTURER_CERTIFICATE_URL.to_owned() + certificate;
            tasks.push(task::spawn(fetch(url)));
        }
        let results = try_join_all(tasks).await;

        return results.unwrap();
    }

    async fn fetch_certificates() -> Vec<EcKey<Public>>{
        let response = reqwest::get(_MANUFACTURER_CERTIFICATE_URL).await.unwrap();
        let data = response.text().await.unwrap();
        let re = Regex::new("href=\"(.+?crt)\"").unwrap();
        let mat: Vec<Match> = re.find_iter(&data).collect();
        let certificates = mat.iter().map(|&x| &x.as_str()[6..&x.as_str().len()-1]).collect::<Vec<&str>>();
        return fetch_all(certificates).await;
    }

    return rt.block_on(fetch_certificates())
}

pub fn _check_signature(message: &Vec<u8>, public_key: EcKey<Public>, signature: Vec<u8>) -> bool{

    let ec_sig = openssl::ecdsa::EcdsaSig::from_der(&signature).unwrap();
    let result = ec_sig.verify( message, &public_key).unwrap();

    if result == false{
        println!("Invalid signature ");
        return false;
    }
    return true;

}

pub fn _certificate_parts(connection: &Connection, _debug: bool) -> Result<Vec<Vec<u8>>,Error>{
    let certificate = manufacturer_certificate(connection)?;
    if let Some(split_idx) = certificate.iter().sequence_search(&decode_hex(_PUBLIC_K1_OID).unwrap()) {
        return Ok(vec![certificate[..split_idx].to_vec(),certificate[(split_idx+&decode_hex(_PUBLIC_K1_OID).unwrap().len())..].to_vec()]);
    } else {
        return Err(Error::GenuineCheckException);
    }
}

pub fn _public_key(connection: &Connection, debug: bool) -> Vec<u8>{
    let public_key_hex = &encode_hex(&_certificate_parts(connection, debug).unwrap()[1])[..130];
    let public_key_bytes = decode_hex(public_key_hex).unwrap();

    if debug{
        println!("card public key hex");
        println!("{:?}",public_key_hex);
    }

    return public_key_bytes;
}


pub fn _manufacturer_certificate_data(connection: &mut Connection,debug: bool) -> Vec<u8>{
    let result = [
        [&_certificate_parts(connection,debug).unwrap()[0][4..],
         &decode_hex(_PUBLIC_K1_OID).unwrap()].concat(), 
         _public_key(connection,debug)
         ].concat();
    
    if debug{
        println!("Manufacturer data");
        println!("{}",hex::encode(&result));
    }

    return result;
}

pub fn _get_card_certificate(connection: &Connection, debug: bool) -> String{
    // let nonce = rand::random::<u64>();
    let nonce: u64 = 4056893388785030453;
    let nonce_list = decode_hex(&format!("{:X}",nonce)).unwrap();
    let certificate = connection.send_apdu(&[vec![0x80, 0xF8, 0x00, 0x00, 0x08],nonce_list].concat()).unwrap().0;

    let card_cert_hex = list_to_hexadecimal(&certificate);
    
    if debug{
        println!("Card cert");
        println!("{:?}",card_cert_hex);
    }

    if u64::from_str_radix(&card_cert_hex[2..18],16).unwrap() != nonce{
        println!("Card certificate nonce is not the one provided");
        return "".to_string();
    }

    return card_cert_hex;
}

pub fn _manufacturer_signature(connection: &mut Connection, debug: bool) -> Vec<u8>{
    let certificate = manufacturer_certificate(connection).unwrap();
    if let Some(split_idx) = certificate.iter().sequence_search(&decode_hex(_ECDSA_SHA256).unwrap()) {
        let certificate_parts = vec![certificate[..split_idx].to_vec(),certificate[(split_idx+&decode_hex(_PUBLIC_K1_OID).unwrap().len())..].to_vec()];

        let sig_part_hex = encode_hex(&certificate_parts[1]);
        let signature_length = decode_hex(&sig_part_hex[0..2]).unwrap()[0] as u16;
        let mut signature = encode_hex(&certificate_parts[1])[2..].to_string();
        assert_eq!(signature.len() as u16, 2*signature_length);

        if encode_hex(&certificate_parts[1])[2..4].to_string() == "00".to_string(){
            signature = encode_hex(&certificate_parts[1])[4..].to_string();
        }

        if debug{
            println!("mft cert sig hex");
            println!("{:?}",signature);
        }
        return decode_hex(signature.as_str()).unwrap().to_vec();
    } else {
        return vec![];
    }
}

