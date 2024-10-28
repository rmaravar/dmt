use serde::Serialize;

#[derive(Serialize, Clone, Debug)]
pub struct SiblingInfo {
	pub position_in_group: i32,
	pub tree_node_hash: String,
}

impl SiblingInfo {
	pub fn new(position: i32, path: String) -> SiblingInfo {
		Self { position_in_group: position, tree_node_hash: path }
	}
}

#[derive(Serialize, Clone, Debug)]
pub struct NodeInfo {
	node_hash: String,
	is_group: bool,
	group_siblings: Vec<Option<SiblingInfo>>,
	data_siblings: Vec<Option<SiblingInfo>>,
}

impl NodeInfo {
	pub fn new(node_hash: String, is_group: bool) -> NodeInfo {
		Self { node_hash, is_group, group_siblings: vec![], data_siblings: vec![] }
	}

	pub fn add_group_siblings(&mut self, mut group_roots: Vec<Option<SiblingInfo>>) {
		self.group_siblings.append(&mut group_roots);
	}

	pub fn add_data_siblings(&mut self, mut data_roots: Vec<Option<SiblingInfo>>) {
		self.data_siblings.append(&mut data_roots);
	}

	pub fn get_group_siblings(&self) -> Vec<Option<SiblingInfo>> {
		self.group_siblings.clone()
	}

	pub fn get_data_siblings(&self) -> Vec<Option<SiblingInfo>> {
		self.data_siblings.clone()
	}

}


#[derive(Serialize, Clone, Debug)]
pub struct PathInfo {
	nodes_in_path: Vec<NodeInfo>,
}

impl PathInfo {
	pub fn new(path: Vec<NodeInfo>) -> PathInfo {
		Self { nodes_in_path: path }
	}

	pub fn get_nodes(&self) -> Vec<NodeInfo> {
		self.nodes_in_path.clone()
	}
}