use crate::types::{Addressable, Group};

pub struct Put<D: Addressable> {
	pub private: Vec<u8>,
	pub public: Vec<u8>,
	pub group: Group<D>
}

impl<D: Addressable> Put<D> {
	pub fn new(private: Vec<u8>, public: Vec<u8>, group: Group<D>) -> Self {
		Self { private, public, group }
	}

}