use serde::Serialize;
use std::fmt::Debug;
use std::hash::Hash;
use sha2::Digest;

mod data;
mod group;
mod request;
mod user;

pub use group::Group;
pub use group::Item;

pub use data::Data;
pub use user::User;

pub trait Addressable: Serialize + Clone + Debug + AsRef<[u8]> {
	fn address(&self) -> anyhow::Result<String>  {
		Ok(hex::encode(sha2::Sha256::digest(self)))
	}
}

impl Addressable for String {

}