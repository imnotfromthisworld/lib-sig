use aes_siv::{
    aead::{Aead, KeyInit},
    Aes128SivAead, Nonce,
};
use serde::{Deserialize, Serialize};
use x25519_dalek::PublicKey;

use crate::crypto::{kdf_chain_key, kdf_root_key, KeyPair, State};

#[derive(Serialize, Deserialize, Debug)]
pub struct Message {
    pub sender_name: String,
    pub recv_name: String,
    pub msg: String,
    pub public_key: PublicKey,
}

#[derive(Serialize, Deserialize, Debug)]
pub struct EncryptedMessage {
    pub sender_name: String,
    pub recv_name: String,
    pub encrypted_msg: Vec<u8>,
    pub public_key: PublicKey,
}

impl Message {
    pub fn new(msg: String, from: String, to: String, public_key: PublicKey) -> Self {
        Message {
            sender_name: from,
            recv_name: to,
            msg,
            public_key,
        }
    }

    pub fn encrypt(&self, state: &State) -> Result<(EncryptedMessage, State), u32> {
        let new_dh = KeyPair::new();
        let (root_key, chain_key) =
            kdf_root_key(state.root_key(), new_dh.private(), &state.dh_pub().unwrap());

        let (chain_key_send, mk) = kdf_chain_key(&chain_key);

        let nonce = Nonce::from_slice(b"any unique nonce");
        let cipher = Aes128SivAead::new_from_slice(&mk).unwrap();
        let encrypted_msg = cipher.encrypt(nonce, self.msg.as_bytes()).unwrap();

        Ok((
            EncryptedMessage {
                sender_name: self.sender_name.clone(),
                recv_name: self.recv_name.clone(),
                encrypted_msg,
                public_key: new_dh.public(),
            },
            State {
                key_pair: new_dh,
                dh_pub: state.dh_pub(),
                root_key,
                chain_send: Some(chain_key_send),
                chain_recv: state.chain_recv.clone(),
                pn: state.pn(),
            },
        ))
    }
}

impl EncryptedMessage {
    pub fn decrypt(&self, state: &State) -> Result<(Message, State), u32> {
        let (root_key, chain_key) = kdf_root_key(
            state.root_key(),
            state.key_pair().private(),
            &self.public_key,
        );

        let (chain_key_recv, mk) = kdf_chain_key(&chain_key);

        let nonce = Nonce::from_slice(b"any unique nonce");
        let cipher = Aes128SivAead::new_from_slice(&mk).unwrap();
        let decrypted_msg = cipher.decrypt(nonce, self.encrypted_msg.as_ref()).unwrap();

        Ok((
            Message {
                sender_name: self.sender_name.clone(),
                recv_name: self.recv_name.clone(),
                msg: String::from_utf8(decrypted_msg).unwrap(),
                public_key: self.public_key,
            },
            State {
                key_pair: state.key_pair().clone(),
                dh_pub: Some(self.public_key),
                root_key,
                chain_send: Some(chain_key_recv),
                chain_recv: state.chain_recv.clone(),
                pn: state.pn(),
            },
        ))
    }
}
