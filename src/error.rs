use thiserror::Error;
use nfc1::Error as NfcError;
use pcsc::Error as PcscError;

#[derive(Debug,Error)]
pub enum ReaderError {
    #[error("NFC error")]
    NfcError(#[from] NfcError),
    #[error("PCSC error")]
    PcscError(#[from] PcscError),
    #[error("Could not connect through neither smart card nor NFC")]
    FailedToEstablishConnection,
    #[error("Reader with index {idx:?} not found!")]
    ReaderNotFound{
        idx: usize
    },
    #[error("The connection hasn't been established")]
    NoConnectionEstablished
}

#[derive(Debug,Error)]
pub enum Error {
    #[error("The card wasn't opened with PIN code or challenge-response")]
    CardClosed,
    #[error("The card was not detected in the card reader")]
    CardNotFound,
    #[error("Keys weren't found on the card")]
    SeedError,
    #[error("The detected card is not supported by this library")]
    UnsupportedCard,
    #[error("The card hasn't been initialized")]
    UninitializedCard,
    #[error("There was an issue with certification")]
    CertificateError,
    #[error("An issue occurred in the communication with the reader")]
    ConnectionError,
    #[error("The reader returned an empty message")]
    EmptyData,
    #[error("The sent data is not valid")]
    InvalidData,
    #[error("Invalid derivation selection")]
    DerivationSelectionError,
    #[error("This operation doesn't support this derivation form.")]
    DerivationOperationsUnsupported,
    #[error("The signature wasn't compatible with EOS standard after 10 tries")]
    EOSKeyError,
    #[error("There is an issue with the firmware on the card")]
    FirmwareError,
    #[error("The detected card is not a genuine Cryptnox product")]
    GenuineCheckError,
    #[error("Key cannot be generated twice")]
    KeyAlreadyGenerated,
    #[error("Key generation error")]
    KeyGenerationError(#[from] openssl::error::ErrorStack),
    // KeyGenerationError,
    #[error("Error in turning off PIN authentication. There is no user key in the card")]
    PinAuthenticationError,
    #[error("The PIN name must have between 4 and 9 numeric characters.")]
    InvalidPinName,
    #[error("The PIN name must be numeric.")]
    NonNumericPinName,
    #[error("Invalid PIN code (Number of retries before locked: {number_of_retries:?}): {message:?}")]
    InvalidPIN{
        number_of_retries: u8,
        message: String
    },
    #[error("Invalid PUK code (Number of retries before locked: {number_of_retries:?}): {message:?}")]
    InvalidPUK{
        number_of_retries: u8,
        message: String
    },
    #[error("A reader-level issue")]
    ReaderError(#[from] ReaderError),
    #[error("Data received during public key reading is not valid")]
    ReadPublicKeyError,
    #[error("Secure channel couldn't be established")]
    SecureChannelError,
    #[error("The card is soft locked, and requires power cycle before it can be opened")]
    SoftLock,
    #[error("Trying to unlock unblocked card")]
    CardNotBlocked,
    #[error("Generic error that can mean multiple things depending on the call to the card")]
    GenericCardError{
        status: bytes::Bytes
    },
    #[error("Pairing key has to be 32 bytes.")]
    InvalidPairingKeyBytes,
    #[error("Index must be between 0 and 7.")]
    InvalidIndex,
    #[error("Keys weren't found on the card.")]
    SeedException,
    #[error("Card doesn't have this functionality.")]
    NotImplementedError,
    #[error("The PUK must have 15 numeric characters")]
    DataValidationExceptionGen0,
    #[error("The PUK must be numeric.")]
    Gen0PukNotDigit,
    #[error("Invalid PUK code was provided.")]
    PukException,
    #[error("Bad data received. Dual seed read card public key")]
    DataException,
    #[error("Card is not initialized.")]
    InitializationException,
    #[error("Card type not recognized.")]
    CardTypeException,
    #[error("No card certificate found")]
    CertificateException,
    #[error("Wrong card signature")]
    GenuineCheckException,
    #[error("Name must be less than 20 characters")]
    DataValidationExceptionBasicName,
    #[error("Email must be less than 60 characters")]
    DataValidationExceptionBasicEmail,
    #[error("PIN authentication is disabled. Can not unblock it.")]
    PinException,
    #[error("WIF does not represent privkey")]
    WIFException,
    #[error("Invalid format")]
    InvalidFormat,
    #[error("Pubkey not in recognized format")]
    Pubkeyformaterror,
    #[error("Invalid base !")]
    InvalidBase,
    #[error("Invalid data received during signature")]
    SigningException,
    #[error("The PUK must have 12 letters and/or number characters.")]
    DataValidationExceptionBasicG1PUK,
    #[error("Key type is unsupported or wrong.")]
    KeyTypeUnsupported,
    #[error("Data overflow.")]
    OverFlowError
}