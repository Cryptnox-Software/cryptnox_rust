use std::cmp::Ordering;
use crate::enums::FactoryReturn;
use crate::utils::encode_hex;

use crate::genuineness::{self, manufacturer_certificate};
use crate::card::basic::{Basic,gen1::BasicGen1,gen0::BasicGen0,nft::NFT};
use crate::connection::Connection;
use crate::error::Error;


pub fn get_card(mut connection: Connection,debug: bool) -> FactoryReturn{   
    let mut applet_version= vec![123];
    let mut data= vec![0x00];
    let mut serial= 123;
    let mut ret_cls = String::from("");
    for card_cls in _all_subclasses().iter(){
        let sel_response = _select(&connection, &card_cls.0, &card_cls.1, debug);
        if let Err(_err) = sel_response{
            continue
        }else{
            (applet_version, data) = sel_response.unwrap();
            serial = _serial_number(&connection, debug).unwrap();
            ret_cls = card_cls.2.clone();
        }
    }

    connection.session_public_key = genuineness::session_public_key(&mut connection,debug).unwrap();

    match ret_cls.as_str(){
        "BasicGen0" => FactoryReturn::BG0(BasicGen0::with_data(BasicGen0::new(connection, serial, applet_version), data)),
        "BasicGen1" => FactoryReturn::BG1(BasicGen1::with_data(BasicGen1::new(connection, serial, applet_version),data)),
        "NFT" => FactoryReturn::NFT(NFT::with_data(NFT::new(connection, serial, applet_version), data)),
        _ => FactoryReturn::B(Basic::new(connection, serial, applet_version))
    }
}

fn _all_subclasses() -> Vec<([u8;7],u8,String)>{
    return vec![
        ([0xA0, 0x00, 0x00, 0x10, 0x00, 0x01, 0x01],b'B',"BasicGen0".to_string()),
        ([0xA0, 0x00, 0x00, 0x10, 0x00, 0x01, 0x12],b'B',"BasicGen1".to_string()),
        ([0xA0, 0x00, 0x00, 0x10, 0x00, 0x01, 0x12],b'N',"NFT".to_string())
    ];
}

fn _select(connection: &Connection, apdu: &[u8],card_type: &u8,debug: bool) -> Result<(Vec<u8>,Vec<u8>),Error>{

    let apdu_command = &[&[0x00, 0xA4, 0x04, 0x00, 0x07],apdu].concat();
    
    let data_selected = connection.send_apdu(apdu_command)?.0;

    if data_selected.len() == 0{
        return Err(Error::DataException);
    }

    if card_type.cmp(&data_selected[0]) != Ordering::Equal{
        return Err(Error::CardTypeException);
    }

    let applet_version = data_selected[1..4].to_vec();
    let data = data_selected[4..].to_vec();

    if debug{
        println!("Applet Version");
        println!("{:?}",applet_version);
    }
    return Ok((applet_version,data))
}


fn _serial_number(connection: &Connection, _debug: bool) -> Result<u64,Error>{
    let certificate = manufacturer_certificate(&connection)?;
    let certificate_hex = encode_hex(&certificate);
    let certificate_parts = certificate_hex.split("0302010202").collect::<Vec<&str>>();
    if certificate_parts.len() <= 1{
        return Err(Error::CertificateException);
    }
    let data;
    if certificate_parts[1].chars().nth(1) == Some('8'){
        data = &certificate_parts[1][2..18];
    }
    else if certificate_parts[1].chars().nth(1) == Some('9'){
        data = &certificate_parts[1][4..20];
    }else{
        data = "";
    }
    let ret = u64::from_str_radix(data, 16).unwrap();
    return Ok(ret)
}

