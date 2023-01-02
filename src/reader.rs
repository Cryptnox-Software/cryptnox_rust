use nfc1 as nfc;
use ouroboros::self_referencing;
use std::ffi::CString;
use pcsc::MAX_BUFFER_SIZE;

use crate::error::{ReaderError};

type Result<T> = std::result::Result<T,ReaderError>;

pub trait Reader {
    fn connect(self: &mut Self) -> Result<()>;
    // the tuple carries  "result and two status codes" (todo: change into Result<>)
    fn send(self: &Self, apdu: &[u8]) -> Result<(Vec<u8>, u8, u8)>;
    fn active_connection(self: &mut Self) -> bool;
}

#[self_referencing]
struct NfcReaderPriv<'a> {
    nfc_target: Option<nfc::Target>,
    nfc_context: nfc::Context<'a>,
    #[borrows(mut nfc_context)]
    #[covariant]
    nfc_device: nfc::Device<'this>,
}

impl<'a> NfcReaderPriv<'a> {
    pub fn impl_new() -> nfc::Result<Self> {
        let nfc_context = nfc::Context::new()?;
        let ret = NfcReaderPrivTryBuilder {
            nfc_context,
            nfc_target: None,
            nfc_device_builder: |ctx: &mut nfc::Context| ctx.open(),
        }
        .try_build()?;
        Ok(ret)
    }
}

pub struct NfcReader<'a> {
    private: NfcReaderPriv<'a>,
}

impl<'a> NfcReader<'a> {
    pub fn new() -> Result<Self> {
        Ok(Self {
            private: NfcReaderPriv::impl_new()?,
        })
    }
}

impl<'a> Reader for NfcReader<'a> {
    fn connect(&mut self) -> Result<()> {
        Ok(self.private.with_mut(|f| -> nfc::Result<()> {
            let dev = f.nfc_device;
            let target = f.nfc_target;
            dev.initiator_init()?;
            *target = Some(dev.initiator_select_passive_target(&nfc::Modulation {
                modulation_type: nfc::ModulationType::Iso14443a,
                baud_rate: nfc::BaudRate::Baud106,
            })?);
            Ok(())
        })?)
    }
    fn send(&self, _apdu: &[u8]) -> Result<(Vec<u8>, u8, u8)> {
        unimplemented!()
    }
    fn active_connection(&mut self) -> bool {
        self.private.with_mut(|f| {
            f.nfc_target
                .as_ref()
                .map(|target| f.nfc_device.initiator_target_is_present(target).is_ok())
                .unwrap_or(false)
        })
    }
}

pub struct SmartCardReader {
    reader_name: CString,
    card: Option<pcsc::Card>,
    pcsc_context: pcsc::Context,
}

impl SmartCardReader {
    pub fn new(index: usize) -> Result<Self> {
        let pcsc_context = pcsc::Context::establish(pcsc::Scope::User)?;
        let found_readers = pcsc_context
            .list_readers_owned()?
            .drain(..)
            .filter(|x| !x.to_string_lossy().starts_with("Yubico"))
            .collect::<Vec<_>>();
        let found_reader = found_readers
            .get(index)
            .ok_or(ReaderError::ReaderNotFound{idx: index});
        Ok(Self {
            reader_name: found_reader?.to_owned(),
            card: None,
            pcsc_context,
        })
    }
}

impl Reader for SmartCardReader {
    fn connect(&mut self) -> Result<()> {
        self.card = Some(self.pcsc_context.connect(
            &self.reader_name,
            pcsc::ShareMode::Exclusive,
            pcsc::Protocols::T1,
        )?);
        Ok(())
    }
    fn send(&self, apdu: &[u8]) -> Result<(Vec<u8>, u8, u8)> {
        let mut buf = [0; MAX_BUFFER_SIZE];
        let res_with_status = self
            .card
            .as_ref()
            .ok_or(ReaderError::FailedToEstablishConnection)?
            .transmit(apdu, &mut buf)?;
        let res = &res_with_status[..res_with_status.len() - 2];
        Ok((
            Vec::from(res),
            res_with_status[res_with_status.len() - 2],
            res_with_status[res_with_status.len() - 1],
        ))
    }
    fn active_connection(&mut self) -> bool {
        self.card.is_some()
    }
}

pub fn get_at(idx: usize) -> Result<Box<dyn Reader>> {
    let smart_card = SmartCardReader::new(idx);
    if smart_card.is_ok() {
        Ok(Box::from(smart_card?))
    } else {
        let nfc_card = NfcReader::new();
        Ok(Box::from(nfc_card.map_err(|_| {
            ReaderError::FailedToEstablishConnection
        })?))
    }
}
#[allow(dead_code)]
pub fn get() -> Result<Box<dyn Reader>> {
    get_at(0)
}
