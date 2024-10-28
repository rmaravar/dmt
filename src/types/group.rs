use serde::Serialize;
use crate::types::Addressable;
use crate::types::data::Data;

#[derive(Debug, Clone, Hash, Serialize)]
pub struct Group<D: Addressable> {
	pub(crate) name: String,
	pub(crate) items: Vec<Item<D>>
}

impl<D: Addressable> Group<D> {
	pub fn new(name: String, items: Vec<Item<D>>) -> Self {
		Group{
			name,
			items
		}
	}
}

#[derive(Debug, Clone, Hash, Serialize)]
pub enum Item<D: Addressable> {
	Data(Data<D>),
	Group(Group<D>)
}

impl<D: Addressable> Item<D> {

	pub fn get_address(&self) -> String {
		match self {
			Item::Data(data) => {
				data.value.address().unwrap()
			}
			Item::Group(group) => {
				group.name.address().unwrap()
			}
		}
	}
}