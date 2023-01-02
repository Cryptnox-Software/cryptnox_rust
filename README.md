# Cryptnox Rust Communications Library

A Rust library to use with Cryptnox smartcard applet. It provides high level functions to send instructions with the Cryptnox and to manage its lifecycle. The core module is cryptnox_rs which provides a Connection class to establish a channel of communication that can be used to initialize a card instance through the factory method.

To buy NFC enabled cards that are supported by this library go to: https://www.cryptnox.com/

## Requirements
Requires:
- Rust v1.61.0
- Cargo v1.61.0

## Installation

Add the following line in your `cargo.toml` file:
```
cryptnox_rs = "*"
```

To remove the library from your project, remove the same line of code and run `cargo build`.

## Issues

## Library use
To get the card a connection has to be established with the reader's index. The connection can then be passed to the factory that will initialize an object for the card in the reader from the correct class for the card type and version.

```
use cryptnox_rs as crs
use crs::enums::FactoryReturn

fn main() {
    println!("Starting test");
    let conn = crs::connection::Connection::new(0).unwrap();
    let card = crs::factory::get_card(conn, false);
    match card{
        FactoryReturn::BG1(bg1) => {
            println!("BG1 card found.");
            let mut card = bg1;
        },
        FactoryReturn::BG0(bg0) => {
            println!("BG0 card found.");
            let mut card = bg0;
        },
        FactoryReturn::NFT(nft) => {
            println!("BG0 card found.");
            let mut card = nft;
        },
    }

```

The factory will:

- connect to the card
- select the applet
- read the applet parameters
- select class to handle the card

The card contains basic information:

- card.serial_number : Integer : Card/applet instance Unique ID
- card.applet_version : 3 integers list : Applet version (ex. 1.2.2)

## Initialization and pairing

Right after the installation, the applet is not initialized, and the user needs to send some parameters to use the card. The initialization can be executed once. Any change of the base parameters requires a full applet reinstallation (except PIN/PUK change).

After the initialization, the card and the PC must share a common secret to be used as authenticated secure channel. This secret is required any time further, to communicate with the card (using a secure channel). The registration of this common secret is done during the init phase.

The init parameters required are :
- Name (up to 20 chars string)
- Email (up to 60 chars string)
- PIN (9 digits string)
- PUK (15 digits string)
- optional : the first Paring Secret (32 bytes bytearray)

## PIN

The PIN chosen during the initialization needs to be provided after each card reset, and a secure channel is opened.

To test a PIN string, simply use:
```
card.verify_pin(pin);
```

## Seed administration

The applet manages a 256 bits master secret called the "seed". This is the BIP32 Master Seed, and can be externally computed from a mnemonic to a binary seed using BIP39. The key pairs used for ECDSA are then computationally derived from this seed using BIP32 derivation scheme.

### Seed generation

The seed can be generated in the card using the random number generator in the java chip system (AIS 20 class DRG.3). Doing this way, the seed secret never escapes the card protection.

The method to generate a new seed key is:
```
card.generate_seed(pin);
```

### Recovery

The Cryptnox applet can load binary seed.

The seed is loaded in the card using this method:
```
card.load_seed(seed, pin);
```

Seed is 32 bytes.

Once this seed is loaded in the card using the load_seed method, this card now behaves like were (or the one) it was backup. Be aware that key derivation paths are not backup, and must be identical to retrieve the same key pairs. See derivation and key system just below for more details.

For more details about the recovery, see load_seed operation in the API documentation.

## Derivation and keys system

The card applet is fully compliant with BIP32, except the maximum depth of derivation from the master key is 8 levels. It can be turned on for the card to return extended public keys for use in applications requiring it.

The card stores the present key pair (and its parent), used for signature. This can be changed using the derive method, and also during a signature command, giving a relative path (from the present key pair), or in an absolute path (from the master key pair). See derive method in the API documentation.

Any derivation aborts any opened signing sessions and resets the authentications for signature. The generated key is used for all subsequent sign sessions.

The ability to start derivation from the parent keys allows to more efficiently switch between children of the same key. Note however that only the immediate parent of the current key is cached so one cannot use this to go back in the keys hierarchy.

For ease of use, the user can derive from the root master node key pair (absolute path) at each card startup, or even before each signature. This takes a couple of seconds. So this is better to store intermediate public keys hash and check the status to observe the current key pair in use. This off-card complex key management is not needed if the signatures volume is below one thousand per day.

See derive and sign methods in the API documentation.

## EC signature

The derivation of the key pair node can be also possible using the signature command (relative or absolute).

The card applet can sign any 256 bits hash provided, using ECDSA with 256k1 EC parameters. Most of the blockchain system used SHA2-256 to hash the message, but this card applet is agnostic from this point, since the signature is performed on a hash provided by the user. Note that this hash needs to be confirmed by the users beforehand, when they provide their EC384 signature of this hash.

The code to sign with the EC current key node is:
```
let signature = card.sign(data_hash, <u8 value of cryptnox_rs::Derivation::CURRENT_KEY>);
```

data_hash is a byte-array containing the EC hash to sign using ECDSA ecp256k1:

The signature a byte array, encoded as an ASN1 DER sequence of two INTEGER values, r and s.

See the sign method in the API documentation for more information.
