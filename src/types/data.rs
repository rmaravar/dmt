use serde::Serialize;
use crate::types::Addressable;

#[derive(Debug, Clone, Hash, Serialize)]
pub struct Data<D: Addressable> {
	pub(crate) value: D
}

impl<D: Addressable> Data<D> {
	pub fn new(value: D) -> Self {
		Data { value }
	}
}