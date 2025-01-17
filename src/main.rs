use alloy_primitives::Address;
// use alloy_signer::{Signer};
use k256::{ecdsa::SigningKey, sha2::Sha512, PublicKey};
use tiny_keccak::{Keccak, Hasher};
use rand::rngs::OsRng;
use anyhow::{Error, Ok, Result};
use hmac::{Hmac, Mac};


#[derive(Debug)]
pub struct Wallet {
    private_key: SigningKey,
    public_key: PublicKey,
    address: Address,
    mnemonic: Option<String>
}

impl Wallet {
    pub fn new_wallet() -> Result<Self> {
        // generating random wallet
        let private_key = SigningKey::random(&mut OsRng);
        let public_key = private_key.verifying_key().to_encoded_point(false);

        // generating Eth address (keccak256(public_key)[12:])
        let mut hasher = Keccak::v256();
        let mut hash = [0u8; 32];
        hasher.update(&public_key.as_bytes()[1..]); // skip the 0x04 prefix please
        hasher.finalize(&mut hash);
        let mut address_bytes = [0u8; 20];
        address_bytes.copy_from_slice(&hash[12..32]);
        let address = Address::from_slice(&address_bytes);

        let public_key = (*private_key.verifying_key()).into();

        Ok(Self {
            private_key,
            public_key,
            address,
            mnemonic: None
        })
    }


    //internal helper function
    fn derive_wallet_from_seed(seed: &[u8]) -> Result<Self> {
        let mut hmac = Hmac::<Sha512>::new_from_slice(b"Bitcoin seed")
                                                                            .map_err(|e| Error::msg(format!("HMAC Error : {e}")))?;
                                                                            // or I can use the .map_err(|e| format!("Error: {}", e)).into()?;
        hmac.update(seed);
        let result = hmac.finalize().into_bytes();
        
        // Use first 32 bytes as private key
        let private_key_bytes = &result[..32];
        let private_key = SigningKey::from_bytes(private_key_bytes.into())
                                                            .map_err(|e| Error::msg(format!("Invalid private key {e}")))?;
        
        let public_key = private_key.verifying_key().to_encoded_point(false);

        // generate eth address
        let mut hasher = Keccak::v256();
        let mut hash = [0u8; 32];
        hasher.update(&public_key.as_bytes()[1..]);
        hasher.finalize(&mut hash);

        let mut address_bytes = [0u8; 20];
        address_bytes.copy_from_slice(&hash[12..32]);
        let address = Address::from_slice(&address_bytes);

        let public_key = (*private_key.verifying_key()).into();

        Ok(Self {
            private_key,
            public_key,
            address,
            mnemonic: None
        })
    }

    pub fn get_address(&self) -> String {
        format!("{:#x}", self.address)
    }
}

fn main() -> Result<()> {
    let wallet = Wallet::new_wallet()?;

    println!("{:?}", wallet);

    // println!("Wallet Address: {}", wallet.get_address());

    Ok(())

    
}
