use alloy_primitives::Address;
// use alloy_signer::{Signer};
use k256::{ecdsa::SigningKey, sha2::Sha512, PublicKey};
use tiny_keccak::{Keccak, Hasher};
use rand::rngs::OsRng;
use anyhow::{Error, Ok, Result};
use bip39::{Mnemonic, MnemonicType, Language, Seed};
use hmac::{Hmac, Mac};


#[derive(Debug)]
pub struct Wallet {
    private_key: SigningKey,
    public_key: PublicKey,
    address: Address,
    mnemonic: Option<String>,
}

impl Wallet {
    pub fn new_random_wallet_generation() -> Result<Self> {
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

    pub fn new_wallet_with_mnemonics() -> Result<Self>{
        let mnemonic = Mnemonic::new(MnemonicType::Words12, Language::English);
        
        

        // get the HD wallet seed/ generate mnemonic to seed
        let seed = Seed::new(&mnemonic, "");

        let wallet = Self::derive_wallet_from_seed(&seed.as_bytes())?;

        Ok(Self {
            private_key: wallet.private_key,
            public_key: wallet.public_key,
            address: wallet.address,
            mnemonic: Some(mnemonic.phrase().to_string())
        })
    }

     // Recover wallet from mnemonic phrase
     pub fn recover_account_from_mnemonic(phrase: &str) -> Result<Self> {
        let mnemonic = Mnemonic::from_phrase(phrase, Language::English)
                                                    .map_err(|e| Error::msg(format!("Invalid Mnemonic Phrase {}",e )))?;
        let seed = Seed::new(&mnemonic, "");

        let wallet = Self::derive_wallet_from_seed(&seed.as_bytes())?;

        Ok(Self {
            private_key: wallet.private_key,
            public_key: wallet.public_key,
            address: wallet.address,
            mnemonic: Some(mnemonic.phrase().to_string())
        })
     }

     pub fn recover_account_from_private_key(private_key_hex: &str) -> Result<Self> {
        // Remove "0x" prefix if present
        let private_key_hex = private_key_hex.trim_start_matches("0x");
        
        // Convert hex string to bytes
        let private_key_bytes = hex::decode(private_key_hex)
            .map_err(|e| Error::msg(format!("Invalid private key hex format: {}", e)))?;
            
        // Create SigningKey from bytes
        let private_key = SigningKey::from_bytes(private_key_bytes.as_slice().into())
            .map_err(|e| Error::msg(format!("Invalid private key: {}", e)))?;
            
        // Get public key
        let public_key = private_key.verifying_key().to_encoded_point(false);
        
        // Generate Ethereum address
        let mut hasher = Keccak::v256();
        let mut hash = [0u8; 32];
        hasher.update(&public_key.as_bytes()[1..]); // Skip the 0x04 prefix
        hasher.finalize(&mut hash);
        
        let mut address_bytes = [0u8; 20];
        address_bytes.copy_from_slice(&hash[12..32]);
        let address = Address::from_slice(&address_bytes);
        
        let public_key = (*private_key.verifying_key()).into();
        
        Ok(Self {
            private_key,
            public_key,
            address,
            mnemonic: None  // Private key imports won't have a mnemonic
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

    pub fn get_mnemonic(&self) -> Option<&str> {
        self.mnemonic.as_deref()
    }

    pub fn export_private_key(&self) -> String {
        // Convert private key to bytes and format as hex string
        // Skip "0x" prefix as many wallets expect raw hex
        let private_key_bytes = self.private_key.to_bytes();
        hex::encode(private_key_bytes)
    }
}

fn main() -> Result<()> {
    let wallet = Wallet::new_wallet_with_mnemonics()?;

    println!("{:?}", wallet);

    println!("Wallet Address: {}\n\n", wallet.get_address());

    println!("Recovering Account.....\n\n");
    let wallet_recovery = Wallet::recover_account_from_mnemonic(wallet.get_mnemonic().unwrap());

    println!("Recovered Account is {:?}", wallet_recovery);

    println!("Recovered Account Private Key: {}\n\n", wallet_recovery.unwrap().export_private_key());
   
    // Recover wallet using the private key
    let wallet_recovery_private_key = Wallet::recover_account_from_private_key(wallet.export_private_key().as_str());
    println!("Recovered Account Address from the Private Key: {}\n\n", wallet_recovery_private_key.unwrap().get_address());

    Ok(())

    
}
