use hex_literal::hex;
use hkdf::Hkdf;
use rand_core::OsRng;
use serde::{Deserialize, Serialize};
use sha2::Sha256;
use x25519_dalek::{PublicKey, StaticSecret};

use StaticSecret as PrivateKey;

#[derive(Serialize, Deserialize, Clone)]
pub struct KeyPair {
    private: PrivateKey,
    public: PublicKey,
}

#[derive(Serialize, Deserialize, Clone)]
pub struct State {
    pub key_pair: KeyPair,
    pub dh_pub: Option<PublicKey>,
    pub root_key: RootKey,
    pub chain_send: Option<ChainKey>,
    pub chain_recv: Option<ChainKey>,
    pub pn: u32,
}

#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct RootKey {
    key: [u8; 32],
}

#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct ChainKey {
    key: [u8; 32],
    count: u32,
}

impl ChainKey {
    pub fn key(&self) -> [u8; 32] {
        self.key
    }

    pub fn set_key(&mut self, key: Self) {
        self.key = key.key;
        self.count = key.count;
    }

    pub fn count(&self) -> u32 {
        self.count
    }

    pub fn set_count(&mut self, count: u32) {
        self.count = count;
    }
    pub fn inc_count(&mut self) {
        self.count += 1;
    }
}

impl KeyPair {
    pub fn new() -> Self {
        let private = PrivateKey::new(OsRng);
        let public = PublicKey::from(&private);
        KeyPair { private, public }
    }

    pub fn private(&self) -> &PrivateKey {
        &self.private
    }

    pub fn public(&self) -> PublicKey {
        self.public
    }
}

impl Default for KeyPair {
    fn default() -> Self {
        Self::new()
    }
}

impl From<([u8; 32], [u8; 32])> for KeyPair {
    fn from(keys: ([u8; 32], [u8; 32])) -> Self {
        KeyPair {
            private: PrivateKey::from(keys.0),
            public: PublicKey::from(keys.1),
        }
    }
}

impl From<[u8; 32]> for ChainKey {
    fn from(bytes: [u8; 32]) -> ChainKey {
        ChainKey {
            key: bytes,
            count: 0,
        }
    }
}

impl From<[u8; 32]> for RootKey {
    fn from(bytes: [u8; 32]) -> RootKey {
        RootKey { key: bytes }
    }
}

impl State {
    pub fn new(my_keys: KeyPair, other_pub_key: PublicKey) -> State {
        let shared_secret = my_keys.private().diffie_hellman(&other_pub_key).to_bytes();

        State {
            key_pair: my_keys,
            dh_pub: Some(other_pub_key),
            root_key: RootKey::from(shared_secret),
            chain_send: None,
            chain_recv: None,
            pn: 0,
        }
    }

    pub fn key_pair(&self) -> &KeyPair {
        &self.key_pair
    }

    pub fn dh_pub(&self) -> Option<PublicKey> {
        self.dh_pub
    }

    pub fn root_key(&self) -> &RootKey {
        &self.root_key
    }

    pub fn chain_send(&self) -> Option<&ChainKey> {
        self.chain_send.as_ref()
    }

    pub fn chain_recv(&self) -> Option<&ChainKey> {
        self.chain_recv.as_ref()
    }

    pub fn pn(&self) -> u32 {
        self.pn
    }

    pub fn set_dh_pub(&mut self, dh_pub: Option<PublicKey>) {
        self.dh_pub = dh_pub;
    }
}

pub fn kdf_root_key(
    root_key: &RootKey,
    private_key: &PrivateKey,
    public_key: &PublicKey,
) -> (RootKey, ChainKey) {
    let shared_secret = private_key.diffie_hellman(public_key);

    let info = hex!("fee1dead"); // some random hex constant is required
    let mut okm = [0u8; 64];
    Hkdf::<Sha256>::new(Some(shared_secret.as_bytes()), &root_key.key)
        .expand(&info, &mut okm)
        .expect(" ");

    (
        RootKey {
            key: okm[..32].try_into().unwrap(),
        },
        ChainKey {
            key: okm[32..64].try_into().unwrap(),
            count: 0,
        },
    )
}

pub fn kdf_chain_key(shared_secret: &ChainKey) -> (ChainKey, [u8; 32]) {
    let info = hex!("fee1dead");

    let mut okm = [0u8; 64];
    Hkdf::<Sha256>::new(None, &shared_secret.key())
        .expand(&info, &mut okm)
        .expect(" ");

    (
        ChainKey {
            key: okm[0..32].try_into().unwrap(),
            count: 0,
        },
        okm[32..64].try_into().unwrap(),
    )
}
