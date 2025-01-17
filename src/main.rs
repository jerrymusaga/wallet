use alloy_primitives::Address;
// use alloy_signer::{Signer};
use k256::{ecdsa::SigningKey, PublicKey};
use tiny_keccak::{Keccak, Hasher};
use rand::rngs::OsRng;
use anyhow::Result;

#[derive(Debug)]
pub struct Wallet {
    private_key: SigningKey,
    public_key: PublicKey,
    address: Address,
    mnemonic: Option<String>
}

impl Wallet {
    fn new_wallet() -> Result<Self> {
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

    pub fn get_address(&self) -> String {
        format!("{:#x}", self.address)
    }
}

fn main() -> Result<()> {
    let wallet = Wallet::new_wallet()?;

    println!("Wallet Address: {}", wallet.get_address());

    Ok(())

    
}
