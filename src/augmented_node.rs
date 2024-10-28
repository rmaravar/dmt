use crate::network::{NetworkNode, NodeInfo, PathInfo, SiblingInfo};
use crate::types::{Addressable, Data, Group, Item, User};
use sha2::Digest;
use std::collections::{HashMap, VecDeque};
use std::fmt::Debug;
use std::hash::Hash;

///  The distributed merkle tree is an authenticated merkel tree that is augmented with structural information that allows the tree to be persisted over a distributed hash table.
///  Network nodes are augmented with the following information:
///    - label: Allowing the node to be content addressable.
///    - parent_group_label: The content addressable identifier of the parent node.
///    - proof: Merkle proof allowing the user to verify if the node is part of the source data set.
///    - child_group_hashes: The group hashes of the children groups stored only in the Group and Source variants.
///    - child_data_hashes: The group hashes of the children data nodes stored only in the Group and Source variants.
///    - public_key: The public key associated with the source of the data set.
///    - signature: The signed group hashes + data hashes.
pub struct DistributedMerkleTree<D: Addressable> {
	nodes: Vec<NetworkNode<D>>,
}

impl<D: Addressable> DistributedMerkleTree<D> {
	/// The function used by the source of the data set to initialise distributed merkle tree
	/// The User struct contains the private key used to sign the messages.
	/// The private key is only used by the library for signing the messages and does not get stored on the DHT.
	pub fn init(user: User<D>) -> Self {
		let mut nodes = HashMap::<String, NetworkNode<D>>::new();

		let mut stack: VecDeque<(String, Group<D>)> = VecDeque::<(String, Group<D>)>::new();
		process_items_in_user(user.clone(), &mut stack, &mut nodes);

		Self::gather_nodes(&user, &mut nodes, &mut stack);

		Self { nodes: nodes.values().cloned().collect() }
	}

	/// After the merkle tree has been initialized, the source can update a node.
	/// If a new item needs to be added, the group containing the new item is provided and the function
	/// updates the tree with and a set of nodes that needs to be updated on the DHT is provided.
	pub fn update(&mut self, user: User<D>, group: Group<D>) -> Vec<NetworkNode<D>>{
		todo!()
	}

	/// Get all the network nodes in the tree.
	pub fn get_nodes(&self) -> Vec<NetworkNode<D>> {
		self.nodes.clone()
	}

	/// get the NetworkNode::Group from the tree by 'name'
	pub fn get_group_node(&self, name: String) -> Option<&NetworkNode<D>> {
		let node_label = name.clone().address().unwrap();
		self.nodes.iter().find(|network_node| {
			network_node.get_label() == node_label
		})
	}

	pub(crate) fn get_source_node(&self) -> Option<&NetworkNode<D>> {
		self.nodes.iter().find(|network_node| { matches!(network_node, NetworkNode::Source {..}) })
	}

	fn gather_nodes(user: &User<D>, mut nodes: &mut HashMap<String, NetworkNode<D>>, stack: &mut VecDeque<(String, Group<D>)>) {
		while let Some((name, group)) = stack.pop_back() {
			let mut data_roots = Vec::<String>::new();
			let mut group_roots = Vec::<String>::new();
			let mut child_group_labels = Vec::<String>::new();
			gather_child_details(&mut nodes, &group, &mut data_roots, &mut group_roots, &mut child_group_labels, &user);
			let group_hash = crate::get_tree_node_hash(group_roots.clone(), data_roots.clone());
			let label = group.name.address().unwrap();

			let message = format!("{}{}", label.clone(), group_hash.clone());

			let new_group_node = NetworkNode::Group {
				label: label.clone(),
				name: group.name.clone(),
				group_hash: Some(group_hash.clone()), // H(Gr.1 + Gr.2 + ... + Gr.n + Dr)
				parent_group_label: Some(name.clone().address().unwrap()),
				proof: PathInfo::new(Vec::new()), // Path to root
				child_group_hashes: group_roots, // [H(l1) + H(l2) + ... + H(ln)]
				child_data_hashes: data_roots, // [H(i1) + H(i2) + ... + H(in)]
				child_labels: child_group_labels, //[H(g1) + H(g2) + ... + H(gn)]
				public_key: user.clone().public,
				signature: user.sign_message(message), // S(GH)

			};
			nodes.insert(label.clone(), new_group_node);
		}
		let user_node = get_user_node(user.clone(), &nodes);
		nodes.insert(user.name.address().unwrap().clone(), user_node.clone());

		let target_hash = user_node.clone().get_root_hash().unwrap();

		for (label, node) in nodes.clone() {
			let verification_path = get_verification_path_for_node(&node, nodes.clone(), target_hash.clone());
			let updated_node = node.update_verification_path(PathInfo::new(verification_path.clone()));
			nodes.insert(label.clone(), updated_node);
		}
	}

}

fn get_verification_path_for_node<D: Addressable>(network_node: &NetworkNode<D>, nodes: HashMap<String, NetworkNode<D>>, target_hash: String) -> Vec<NodeInfo> {
	let mut node_hash = network_node.get_tree_node_hash().unwrap();
	let mut path_to_root = Vec::new();
	let mut is_group = !network_node.is_data();

	let mut parent_label_stack = VecDeque::<String>::new();
	if let Some(parent_group_label) = network_node.get_parent_group_label() {
		parent_label_stack.push_back(parent_group_label.clone());
		while let Some(label) = parent_label_stack.pop_back() {

			let current_node = nodes.get(&label).unwrap();
			let mut node_siblings = NodeInfo::new(node_hash.clone(), is_group);


			match current_node {
				NetworkNode::Data { .. } => {} // Parent can never be a data node.
				NetworkNode::Group { parent_group_label, child_data_hashes: data_roots, child_group_hashes: group_roots, group_hash, .. } => {
					node_siblings.add_group_siblings(gather_siblings(node_hash.clone(), group_roots));
					node_siblings.add_data_siblings(gather_siblings(node_hash.clone(), data_roots));
					path_to_root.push(node_siblings.clone());
					is_group = true;
					node_hash = group_hash.clone().unwrap();
					parent_label_stack.push_back(parent_group_label.clone().unwrap());
				}
				NetworkNode::Source { root_hash, child_data_hashes: data_roots, child_group_hashes: group_roots, .. } => {

					node_siblings.add_group_siblings(gather_siblings(node_hash.clone(), group_roots));
					node_siblings.add_data_siblings(gather_siblings(node_hash.clone(), data_roots));
					path_to_root.push(node_siblings.clone());

					is_group = true;
					if root_hash.clone() != target_hash {
						panic!("Root hash mismatch");
					}
				}
			}
		}
	}
	path_to_root
}

fn gather_siblings(node_hash: String, roots: &Vec<String>) -> Vec<Option<SiblingInfo>> {
	let mut position = 1;
	roots.iter()
		.enumerate()
		.map(|(index, hash)| {
			if node_hash != *hash {
				let new_sibling = Some(SiblingInfo::new((index + 1) as i32, hash.clone()));
				position += 1;
				new_sibling
			} else {
				position += 1;
				None
			}
		})
		.collect()
}


fn get_user_node<D: Addressable>(source: User<D>, nodes: &HashMap<String, NetworkNode<D>>) -> NetworkNode<D> {
	let mut group_roots = Vec::<String>::new();
	let mut data_roots = Vec::<String>::new();
	let mut child_group_labels = Vec::<String>::new();

	for item in source.clone().items {
		if let Some(child) = nodes.get(&item.get_address()) {
			match child {
				NetworkNode::Data { label, .. } => {
					data_roots.push(label.clone());
				}
				NetworkNode::Group { group_hash, label, .. } => {
					group_roots.push(group_hash.clone().unwrap());
					child_group_labels.push(label.clone());
				}
				_ => {}
			}
		}
	};
	let root_hash = crate::get_tree_node_hash(group_roots.clone(), data_roots.clone());

	let source_label = source.name.clone().address().unwrap();
	NetworkNode::Source {
		label: source_label.clone(),
		id: source.name.clone(),
		root_hash: root_hash.clone(),
		child_group_hashes: group_roots,
		child_data_hashes: data_roots,
		child_labels: child_group_labels,
		public_key: source.clone().public,
		signature: source.sign_message(format!("{}{}", source_label.clone(), root_hash.clone())),
	}
}

fn gather_child_details<D: Addressable>(nodes: &mut HashMap<String, NetworkNode<D>>, group: &Group<D>, data_roots: &mut Vec<String>, group_roots: &mut Vec<String>, child_group_labels: &mut Vec<String>, user: &User<D>) {
	for item in group.items.clone() {
		match item {
			Item::Data(data) => {
				let data_label = data.value.address().unwrap();
				data_roots.push(data_label.clone());
				let data_network_node = create_data_network_node(data.clone(), group.clone().name, user);
				nodes.insert(data_label.clone(), data_network_node);
			}
			Item::Group(group) => {
				if let Some(child_group) = nodes.get(&group.name.address().unwrap().to_string()) {
					match child_group {
						NetworkNode::Group { group_hash, .. } => {
							group_roots.push(group_hash.clone().unwrap());
							child_group_labels.push(group.name.address().unwrap())
						}
						_ => {}
					}
				}
			}
		}
	}
}

fn create_data_network_node<D: Addressable>(data: Data<D>, parent: String, user: &User<D>) -> NetworkNode<D> {
	let data_label = data.value.address().unwrap();
	NetworkNode::Data {
		label: data_label.clone(),
		parent_group_label: Some(parent.address().unwrap()),
		proof: PathInfo::new(Vec::new()),
		object: data.clone().value,
		public_key: user.clone().public,
		signature: user.sign_message(data_label.clone()),
	}
}

fn process_items_in_user<D: Addressable>(user: User<D>, stack: &mut VecDeque<(String, Group<D>)>, nodes: &mut HashMap<String, NetworkNode<D>>) {
	let mut temp_queue: VecDeque<(String, Vec<Item<D>>)> = VecDeque::<(String, Vec<Item<D>>)>::new();
	temp_queue.push_back((user.clone().name, user.clone().items));
	let user_data_items = user.clone().items.clone().iter().filter_map(|item| {
		match item {
			Item::Data(data) => { Some(Item::Data(data.clone())) }
			_ => { None }
		}
	}).collect::<Vec<Item<D>>>();

	for user_data_item in user_data_items.iter() {
		match user_data_item {
			Item::Data(data) => {
				let data_network_node = create_data_network_node(data.clone(), user.clone().name, &user.clone());
				nodes.insert(data.value.address().unwrap().clone(), data_network_node);
			}
			_ => {}
		}
	}

	while let Some((parent, items)) = temp_queue.pop_back() {
		for item in items {
			match &item {
				Item::Group(sub_group) => {
					stack.push_back((parent.clone(), sub_group.clone()));
					temp_queue.push_back((sub_group.clone().name, sub_group.clone().items));
				}
				_ => {}
			}
		}
	}
}

#[cfg(test)]

mod test {
	use crate::types::*;
	use crate::DistributedMerkleTree;

	#[test]
	pub fn test_init_node() {
		let test_user = get_user();
		let dmt = DistributedMerkleTree::init(test_user);

		assert!(!dmt.nodes.is_empty());
	}

	#[test]
	pub fn test_get_group_node() {
		let test_user = get_user();
		let dmt = DistributedMerkleTree::init(test_user);
		let expected_label = "group1".to_string().address().unwrap();

		let possible_returned_node = dmt.get_group_node("group1".to_string());
		assert!(possible_returned_node.is_some());
		assert_eq!(expected_label, possible_returned_node.unwrap().get_label())
	}

	#[test]
	pub fn test_verify_origin() {
		let test_user = get_user();
		let dmt = DistributedMerkleTree::init(test_user.clone());

		let possible_network_node = dmt.get_group_node("group1".to_string());
		assert!(possible_network_node.is_some());

		let verify_origin_result = possible_network_node.unwrap().verify_origin(&test_user.public);

		assert!(verify_origin_result.is_ok());
	}

	#[test]
	pub fn test_verify_origin_fails_for_wrong_key() {
		let test_user = get_user_with_incorrect_public_key();
		let dmt = DistributedMerkleTree::init(test_user.clone());

		let possible_network_node = dmt.get_group_node("group1".to_string());
		assert!(possible_network_node.is_some());

		let verify_origin_result = possible_network_node.unwrap().verify_origin(&test_user.public);
		assert!(verify_origin_result.err().unwrap().to_string().contains("schnorr signature could not be verified"));
	}

	#[test]
	pub fn test_verify_merkle_proof_for_valid_item_node_in_root() {
		let test_user = get_user();
		let dmt = DistributedMerkleTree::init(test_user.clone());

		let possible_network_item_node = dmt.get_group_node("group1_subgroup_1".to_string());
		assert!(possible_network_item_node.is_some());

		let possible_network_source_node = dmt.get_group_node("test".to_string());
		assert!(possible_network_source_node.is_some());

		let root_hash = possible_network_source_node.unwrap().get_tree_node_hash().unwrap();

		let verify_merkle_result = possible_network_item_node.unwrap().verify_merkle_proof(&root_hash);

		assert!(verify_merkle_result.is_ok());
	}

	fn get_user() -> User<String> {
		let data_group = get_data_group();

		let user = User {
			name: "test".to_string(),
			private: vec![30, 143, 206, 61, 180, 6, 32, 144, 216, 199, 3, 228, 223, 8, 35, 96, 20, 191, 56, 24, 143, 13, 24, 58, 145, 127, 44, 113, 172, 97, 83, 5],
			public: vec![2, 223, 87, 97, 182, 54, 89, 39, 222, 240, 22, 80, 137, 134, 120, 11, 182, 243, 237, 141, 152, 44, 143, 32, 195, 11, 25, 214, 25, 227, 27, 23, 221],
			// incorrect_public: vec![2, 108, 110, 233, 105, 179, 254, 161, 188, 95, 122, 249, 144, 160, 13, 201, 169, 230, 63, 219, 165, 61, 23, 111, 204, 170, 47, 150, 114, 170, 111, 12, 89],
			items: data_group,
		};
		user
	}
	fn get_user_with_incorrect_public_key() -> User<String> {
		let data_group = get_data_group();

		let user = User {
			name: "test".to_string(),
			private: vec![30, 143, 206, 61, 180, 6, 32, 144, 216, 199, 3, 228, 223, 8, 35, 96, 20, 191, 56, 24, 143, 13, 24, 58, 145, 127, 44, 113, 172, 97, 83, 5],
			public: vec![2, 108, 110, 233, 105, 179, 254, 161, 188, 95, 122, 249, 144, 160, 13, 201, 169, 230, 63, 219, 165, 61, 23, 111, 204, 170, 47, 150, 114, 170, 111, 12, 89],
			items: data_group,
		};
		user
	}

	fn get_data_group() -> Vec<Item<String>> {
		let item1 = Item::Data(Data { value: "item1".to_string() });
		let item2 = Item::Data(Data { value: "item2".to_string() });
		let item3 = Item::Data(Data { value: "item3".to_string() });
		let item4 = Item::Data(Data { value: "item4".to_string() });
		let item5 = Item::Data(Data { value: "item5".to_string() });
		let item6 = Item::Data(Data { value: "item6".to_string() });
		let item7 = Item::Data(Data { value: "item7".to_string() });
		let item8 = Item::Data(Data { value: "item8".to_string() });
		let item9 = Item::Data(Data { value: "item9".to_string() });

		let group1_subgroup_1_sub_subgroup = Item::Group(Group { name: "group1_subgroup_1_sub_subgroup".to_string(), items: vec![item8, item9] });
		let group1_subgroup_1 = Item::Group(Group { name: "group1_subgroup_1".to_string(), items: vec![item4, item5, group1_subgroup_1_sub_subgroup] });
		let group1_subgroup_2 = Item::Group(Group { name: "group1_subgroup_2".to_string(), items: vec![item6, item7] });
		let group1 = Item::Group(Group { name: "group1".to_string(), items: vec![item2, item3, group1_subgroup_1, group1_subgroup_2] });

		let mut data_group = Vec::new();
		data_group.push(item1);
		data_group.push(group1);
		data_group
	}
}


