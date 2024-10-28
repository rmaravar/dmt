use std::collections::{BTreeMap, VecDeque};
use secp256k1::{Message, Secp256k1};
use serde::Serialize;
use sha2::Digest;
use crate::types::{Addressable, Group, Item};

#[derive(Debug, Clone, Hash, Serialize)]
pub struct User<D: Addressable> {
	pub name: String,
	pub private: Vec<u8>,
	pub public: Vec<u8>,
	pub items: Vec<Item<D>>
}

impl<D: Addressable> User<D> {

	/// name - ID to be associated with the data set
	/// private, public - A secp256k1 key pair associated with the user.
	/// items - Item::Data, Item::Group associated with the user
	pub fn new(name: String, private: Vec<u8>, public: Vec<u8>, items: Vec<Item<D>>) -> User<D> {
		User { name, private, public, items }
	}

	pub(crate) fn sign_message(&self, message: String) -> Vec<u8> {
		let secp256k1 = Secp256k1::new();

		let digest: [u8; 32] = sha2::Sha256::digest(&message.as_bytes()).into();
		let secp256k1_key_pair = secp256k1::Keypair::from_seckey_slice(&secp256k1, self.private.as_slice()).unwrap();

		let signature = secp256k1.sign_schnorr(&digest, &secp256k1_key_pair);
		signature.to_byte_array().to_vec()

	}
}