use crate::reader;
use crate::{reader::Reader, utils::*, error::Error};
use bytes::{BufMut, Bytes, BytesMut};
use openssl::ec::{EcPoint};
use openssl::{
    bn::BigNumContext,
    derive::Deriver,
    ec,
    nid::Nid,
    pkey::PKey,
    sha::sha512,
};
type Result<T> = std::result::Result<T,Error>;
#[allow(dead_code)]
struct SecureChannel {
    pub(self) pairing_secret: Bytes,
    pub(self) aes_key: Bytes,
    pub(self) iv: Bytes,
    pub(self) mac_iv: Bytes,
    pub(self) mac_key: Bytes,
}
pub struct Connection {
    reader: Box<dyn Reader>,
    pairing_secret: Option<Bytes>,
    secure_channel: Option<SecureChannel>,
    pub session_public_key: String,
}

impl Connection {
    pub fn set_pairing_secret(&mut self, pairing_secret: Bytes) {
        self.pairing_secret = Some(pairing_secret);
    }
    pub fn setup_secure_channel(
        &mut self,
        pairing_secret: Bytes,
        pairing_key_index: u8,
    ) -> Result<()> {
        // X9_62_PRIME256V1 is another name for SECP256R1
        let ec_group = ec::EcGroup::from_curve_name(Nid::X9_62_PRIME256V1)?;
        let session_private_key = ec::EcKey::generate(&ec_group)?;
        let mut bn_ctx = BigNumContext::new()?;
        let session_public_key = session_private_key.public_key();
        let session_public_key_bytes = session_public_key.to_bytes(
            &ec_group,
            ec::PointConversionForm::UNCOMPRESSED,
            &mut bn_ctx,
        )?;
        //
        // session_public_key = session_private_key.public_key().public_bytes(
        //     serialization.Encoding.X962,
        //     serialization.PublicFormat.UncompressedPoint)
        let data = {
            let mut data = Vec::new();
            data.push(session_public_key_bytes.len() as u8);
            data.into_iter()
                .chain(session_public_key_bytes.into_iter())
                .collect::<Vec<u8>>()
        };
        // data = bytes.fromhex("{:x}".format(len(session_public_key)) +
        //                      session_public_key.hex())
        let resp = self.send_apdu(&[vec![0x80, 0x10, pairing_key_index, 0x00], data].concat())?;
        // apdu_osc = [0x80, 0x10, pairing_key_index, 0x00] + binary_to_list(data)
        // rep = self.send_apdu(apdu_osc)[0]
        if resp.0.len() != 32 {
            println!("Error setting up secure channel.");
            return Err(Error::SecureChannelError);
        }
        // if len(rep) != 32:
        //     raise exceptions.CryptnoxException("Bad data during secure channel opening")
        //
        let sess_salt: Vec<_> = resp.0.into_iter().take(32).collect();
        let iv = Bytes::from_iter(std::iter::repeat(1).take(16));
        // # compute session keys
        // sess_salt = bytes(rep[:32])
        // self._iv = bytes([1] * 16)
        let mut ctx = BigNumContext::new().unwrap();
        let pkey = &self.session_public_key;
        let pub_key_point = EcPoint::from_bytes(&ec_group,&decode_hex(pkey).unwrap(),&mut ctx)?;
        // let pub_key = EcKey::from_public_key(&ec_group, &pub_key_point)?;
        // let public_key = PKey::from_ec_key(pub_key).unwrap();
        let dh_secret = {
            let private_pkey = PKey::from_ec_key(session_private_key.clone())?;
            let public_key_ec = ec::EcKey::from_public_key(&ec_group, &pub_key_point)?;
            let public_key = PKey::from_ec_key(public_key_ec)?;
            let mut deriver = Deriver::new(&private_pkey)?;
            deriver.set_peer(&public_key)?;
            let ret = deriver.derive_to_vec()?;
            ret
        };
        let session_secrets = sha512(&[dh_secret, pairing_secret.clone().into_iter().collect(), sess_salt].concat());
        self.secure_channel = Some(SecureChannel {
            pairing_secret: Bytes::from(pairing_secret),
            aes_key: Bytes::from_iter(session_secrets.into_iter().take(32)),
            iv,
            mac_iv: Bytes::from_iter(std::iter::repeat(0).take(16)),
            mac_key: Bytes::from_iter(session_secrets.into_iter().skip(32)),
        });
        self.test_channel()
    }
    fn test_channel(&mut self) -> Result<()> {
        let mut data = [0; 32];
        openssl::rand::rand_bytes(&mut data)?;
        let cmd = [0x80, 0x11, 0, 0];
        let resp = self.send_encrypted(&cmd, Bytes::copy_from_slice(&data), false)?;
        if resp.len() != 32 {
            return Err(Error::SecureChannelError);
        }
        Ok(())
    }
    pub fn new(index: usize) -> Result<Self> {
        Ok(Self {
            reader: Self::initialize_reader(index)?,
            pairing_secret: None,
            secure_channel: None,
            session_public_key: "".to_owned(),
        })
    }
    fn ensure_secure_channel_opened(&mut self) -> Result<()> {
        if self.secure_channel.is_none() {
            self.setup_secure_channel(self.pairing_secret.clone().unwrap_or(Bytes::default()), 0)?;
        }
        Ok(())
    }
    fn initialize_reader(index: usize) -> Result<Box<dyn Reader>> {
        let mut retries = 0;
        let mut generic_reader = reader::get_at(index)?;
        loop {
            match generic_reader.connect() {
                Ok(_) => {
                    break;
                }
                Err(e) => {
                    retries += 1;
                    if retries >= 4 {
                        return Err(Error::ReaderError(e));
                    }
                    std::thread::sleep(std::time::Duration::from_millis(500));
                }
            }
        }
        Ok(generic_reader)
    }
    pub fn send_apdu(&self, apdu: &[u8]) -> Result<(Vec<u8>,u8,u8)> {
        let (data, status1, status2) = self.reader.send(apdu)?;
        Connection::check_response_code(status1, status2)?;
        Ok((data,status1,status2))
    }
    pub fn send_encrypted(
        &mut self,
        apdu: &[u8],
        data: Bytes,
        receive_long: bool,
    ) -> Result<Bytes> {
        self.ensure_secure_channel_opened()?;
        let (rep, mac_value) = self.encrypt(apdu, data, receive_long);
        let data_decoded = self.decode(&rep, &mac_value)?;
        let status = &data_decoded[data_decoded.len() - 2..];
        let received = &data_decoded[..data_decoded.len() - 2];
        self.secure_channel.as_mut().unwrap().iv = Bytes::copy_from_slice(&rep[..16]);
        if status[0] != 0x90 || status[1] != 0x00 {
            return Err(Error::GenericCardError{status: Bytes::copy_from_slice(status)});
        }
        Ok(Bytes::copy_from_slice(received))
    }
    fn check_response_code(status1: u8, status2: u8) -> Result<()> {
        if status1 == 0x69 && status2 == 0x82 {
            return Err(Error::SecureChannelError);
            //anyhow::bail!(
               // "raise exceptions.ConnectionException(\"Error in secure channel communication. \"\
                        //                         \"Check pairing_key.\")"
        }

        if (status1 == 0x6A && status2 == 0x80) || (status1 == 0x67 && status2 == 0x00) {
            return Err(Error::InvalidData);
            //anyhow::bail!("raise exceptions.DataValidationException(\"Data is not valid. Also check the numbers \"\
                                              //       \"you entered.\")")
        }

        if status1 == 0x6A && status2 == 0x82 {
            return Err(Error::FirmwareError);
            //anyhow::bail!("raise exceptions.FirmwareException(\"Error firmware not found. Check if Cryptnox is \"\
                                       //        \"connected\")")
        }

        if status1 == 0x63 && status2 & 0xF0 == 0xC0 {
            return Err(Error::InvalidPIN{number_of_retries: status2 - 0xC0, message: "".to_owned()});
            //anyhow::bail!("raise exceptions.PinException(number_of_retries=status2 - 0xC0)")
        }
        if status1 == 0x98 && status2 == 0x40 {
            return Err(Error::InvalidPUK{number_of_retries: status2 - 0xC0, message: "".to_owned()});
            //anyhow::bail!("raise exceptions.PukException()")
        }
        if status1 == 0x69 && status2 == 0x85 {
            return Err(Error::PinAuthenticationError);
            //anyhow::bail!(
              //  "raise exceptions.PinAuthenticationException(\"PIN code wasn't authorized\")"
            
        }
        Ok(())
    }
    fn decode(&self, rep: &Bytes, mac_value: &Bytes) -> Result<Bytes> {
        let rep_data = &rep[16..];
        let rep_mac = rep[..16].to_vec();
        let data_mac = if rep.len() >= 256 {
            [
                vec![0, (rep.len() >> 8) as u8, (rep.len() & 255) as u8],
                std::iter::repeat(0).take(13).collect::<Vec<_>>(),
            ]
            .concat()
        } else {
            [
                vec![(rep.len() & 0xFF) as u8],
                std::iter::repeat(0).take(15).collect::<Vec<_>>(),
            ]
            .concat()
        };
        let mac_datar = [data_mac, rep_data.to_vec()].concat();
        // mac_datar = bytes(data_mac_list) + rep_data
        let mac_valr: Vec<u8> = {
            let mac_datar_full = {
                let sec_chan = self.secure_channel.as_ref().unwrap();
                aes_encrypt_unpadded(
                    sec_chan.mac_key.clone(),
                    sec_chan.mac_iv.clone(),
                    Bytes::from(mac_datar.clone()),
                    mac_datar.len())
                    .unwrap()
            };
            let mac_datar_full_len = mac_datar_full.len();
            mac_datar_full
                .into_iter()
                .skip(mac_datar_full_len - 16)
                .collect()
        };
        if mac_valr != rep_mac {
            return Err(Error::SecureChannelError);
        }
        let decrypted_data = {
            let sec_chan = self.secure_channel.as_ref().unwrap();
            aes_decrypt_unpadded(sec_chan.aes_key.as_ref(),
            Some(mac_value.as_ref()),
            rep_data)?
        };
        remove_padding(&BytesMut::from_iter(decrypted_data.clone())).ok_or(Error::SecureChannelError)
    }
    fn encrypt(&self, apdu: &[u8], data: Bytes, receive_long: bool) -> (Bytes, Bytes) {
        let padded_data = {
            let mut original = BytesMut::from(data.as_ref());
            pad_data(&mut original);
            original
        };
        let data_enc = {
            let sec_chan = self.secure_channel.as_ref().unwrap();
            aes_encrypt_unpadded(
                sec_chan.aes_key.clone(),
                 sec_chan.iv.clone(),
                  Bytes::from(padded_data.clone()),
                   padded_data.len())
                   .unwrap().to_vec()
        };
        let data_len = (padded_data.len() + 16) as u32;
        let (cmdh, mac_data) = if receive_long || data_len >= 256 {
            let mut cmdh_concat_bytes = BytesMut::new();
            cmdh_concat_bytes.put_u8(0);
            cmdh_concat_bytes.put_u8((data_len >> 8) as u8);
            cmdh_concat_bytes.put_u8((data_len & 0xFF) as u8);
            let cmdh = [apdu, cmdh_concat_bytes.as_ref()].concat();
            let data_mac = [
                cmdh.clone(),
                std::iter::repeat(0).take(9).collect::<Vec<_>>(),
            ]
            .concat();
            (cmdh, data_mac)
        } else {
            let mut cmdh_concat_bytes = BytesMut::new();
            cmdh_concat_bytes.put_u8(data_len as u8);
            let cmdh = [apdu, cmdh_concat_bytes.as_ref()].concat();
            let data_mac = [
                cmdh.clone(),
                std::iter::repeat(0).take(11).collect::<Vec<_>>(),
            ]
            .concat();
            (cmdh, data_mac)
        };
        let mac_data = [mac_data, data_enc.clone()].concat();
        let mut mac_value = {
            let sec_chan = self.secure_channel.as_ref().unwrap();
            aes_encrypt_unpadded(
                sec_chan.mac_key.clone(),
                 sec_chan.mac_iv.clone(),
                  Bytes::from(mac_data.clone()),
                   mac_data.len())
                   .unwrap().to_vec().into_iter().skip(mac_data.len()-16).collect::<Vec<u8>>()
        };
        let mac_value: Vec<u8> = mac_value.drain(mac_value.len() - 16..).collect();
        let data_apdu: Vec<u8> = mac_value
            .iter()
            .chain(data_enc.iter())
            .map(ToOwned::to_owned)
            .collect();
        let rep = self
            .send_apdu(Bytes::from_iter(cmdh.into_iter().chain(data_apdu.into_iter())).as_ref())
            .unwrap();
        (Bytes::from(rep.0), Bytes::from(mac_value))
    }
}
