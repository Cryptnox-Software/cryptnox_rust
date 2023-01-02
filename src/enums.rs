use crate::card::basic::{gen0::BasicGen0, gen1::BasicGen1, Basic, nft::NFT};


pub enum CryptoReturn<Tuple,String>{
    DecodedTuple(Tuple),
    KeyString(String)
}

pub enum FactoryReturn{
    BG0(BasicGen0),
    BG1(BasicGen1),
    NFT(NFT),
    B(Basic),
}