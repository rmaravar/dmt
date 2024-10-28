use crate::network::path::PathInfo;
use crate::types::Addressable;
use anyhow::{anyhow, bail};
use secp256k1::schnorr::Signature;
use secp256k1::{PublicKey, Secp256k1};
use serde::Serialize;
use sha2::{Digest, Sha256};
use std::hash::Hash;

/// An enumeration of the nodes to be persisted over the Distributed Hash Table(DHT)
///
/// The nodes can be one of the following variants:
/// Data - The data of type D which is addressable.
/// Group - Group of the Data type. Groups can be nested.
/// Source - The Source(S) of the data set.
///
/// The nodes are content addressable. label being the address of the nodes.
/// Group and User variants use name as the content while in the Data variant uses object as the content.
/// When initialising the DistributedMerkleTree, the Source private key in Source{private} is used  to sign the
/// merkle tree node hash, identified by group_hash for Group, Source variants and label for the Data variant.
/// the user of the data set can use the signature to verify proof of origin.
/// verify_origin(&self, source_public_key) can be used by the user to verify if the data set originated from the user.
/// merkle_proof(&self, root_hash) can be used by the user to verify if node is part of the data set.
#[derive(Serialize, Clone, Debug)]
pub enum NetworkNode<D: Addressable> {
	Data {
		label: String, // H(o)
		parent_group_label: Option<String>,
		proof: PathInfo,
		object: D,
		public_key: Vec<u8>,
		signature: Vec<u8>,
	},
	Group {
		label: String,
		name: String,
		group_hash: Option<String>, // H(Gr.1 + Gr.2 + ... + Gr.n + Dr.1 + Dr.2 + ... + Dr.n)
		parent_group_label: Option<String>,
		proof: PathInfo, // Path to root
		child_group_hashes: Vec<String>, // [Gh1 + Gh2 + ... + Ghn]
		child_data_hashes: Vec<String>, // [H(i1) + H(i2) + ... + H(in)]
		child_labels: Vec<String>, //[H(g1) + H(g2) + ... + H(gn)]
		public_key: Vec<u8>,
		signature: Vec<u8>, //S(GH)
	},
	Source {
		label: String,
		id: String,
		root_hash: String,
		child_group_hashes: Vec<String>,
		child_data_hashes: Vec<String>,
		child_labels: Vec<String>, //H(i) + H(g)
		public_key: Vec<u8>,
		signature: Vec<u8>, //S(group_roots + data_roots)
	},
}

impl<D: Addressable> NetworkNode<D> {
	pub(crate) fn update_verification_path(&self, path: PathInfo) -> NetworkNode<D> {
		match self {
			NetworkNode::Data { label, parent_group_label, proof: verification_path, object, public_key, signature } => {
				NetworkNode::Data {
					label: label.clone(), // H(o)
					parent_group_label: parent_group_label.clone(),
					proof: path,
					object: object.clone(),
					public_key: public_key.clone(),
					signature: signature.clone(),
				}
			}
			NetworkNode::Group { label,name, group_hash, parent_group_label, proof: verification_path, child_group_hashes: group_roots, child_data_hashes: data_roots, child_labels: child_group_labels, public_key, signature } => {
				NetworkNode::Group {
					label: label.clone(),
					name: name.clone(),
					group_hash: group_hash.clone(), // H(Gr.1 + Gr.2 + ... + Gr.n + Dr.1 + Dr.2 + ... + Dr.n)
					parent_group_label: parent_group_label.clone(),
					proof: path, // Path to root
					child_group_hashes: group_roots.clone(), // [Gh1 + Gh2 + ... + Ghn]
					child_data_hashes: data_roots.clone(), // [H(i1) + H(i2) + ... + H(in)]
					child_labels: child_group_labels.clone(), //[H(g1) + H(g2) + ... + H(gn)]
					public_key: public_key.clone(),
					signature: signature.clone(), //S(GH)
				}
			}
			NetworkNode::Source { .. } => {
				self.clone()
			}
		}
	}

	pub(crate) fn get_label(&self) -> String {
		match self {
			NetworkNode::Data { label, .. } | NetworkNode::Group { label, .. } | NetworkNode::Source { label, .. } => {
				label.clone()
			}
		}
	}
	pub(crate) fn get_tree_node_hash(&self) -> Option<String> {
		match self {
			NetworkNode::Data { label, .. } => { Some(label.clone()) }
			NetworkNode::Group { group_hash, .. } => { group_hash.clone() }
			NetworkNode::Source { root_hash, .. } => { Some(root_hash.clone()) }
		}
	}

	pub(crate) fn is_data(&self) -> bool {
		match self {
			NetworkNode::Data { .. } => {true}
			NetworkNode::Group { .. } | NetworkNode::Source { .. }=> {false}
		}
	}

	pub(crate) fn get_parent_group_label(&self) -> Option<String> {
		match self {
			NetworkNode::Data { parent_group_label, .. } | NetworkNode::Group { parent_group_label, .. } => { parent_group_label.clone() }
			NetworkNode::Source { .. } => { None }
		}
	}

	pub(crate) fn get_group_roots(&self) -> Vec<String> {
		match self {
			NetworkNode::Data { .. } => { Vec::new() }
			NetworkNode::Group { child_group_hashes: group_roots, .. } | NetworkNode::Source { child_group_hashes: group_roots, .. } => { group_roots.clone() }
		}
	}

	pub(crate) fn get_data_roots(&self) -> Vec<String> {
		match self {
			NetworkNode::Group { child_data_hashes: data_roots, .. } | NetworkNode::Source { child_data_hashes: data_roots, .. } => { data_roots.clone() }
			NetworkNode::Data { .. } => { Vec::new() }
		}
	}

	pub(crate) fn get_child_group_labels(&self) -> Vec<String> {
		match self {
			NetworkNode::Group { child_labels: child_group_labels, .. } | NetworkNode::Source { child_labels: child_group_labels, .. } => { child_group_labels.clone() }
			NetworkNode::Data { .. } => { Vec::new() }
		}
	}

	pub(crate) fn get_root_hash(&self) -> Option<String> {
		match self {
			NetworkNode::Data { .. } | NetworkNode::Group { .. } => { None }
			NetworkNode::Source { root_hash, .. } => { Some(root_hash.clone()) }
		}
	}

	/// User verifies if the node originated from the source using the source_public_key.
	pub fn verify_origin(&self, source_public_key: &[u8]) -> anyhow::Result<()> {
		match self {
			NetworkNode::Data { label, signature, .. } => {
				Self::check_signature(label, source_public_key, signature)?;
				Ok(())
			}
			NetworkNode::Group { label, signature,group_hash, .. } => {
				let message = format!("{}{}", label, group_hash.clone().unwrap() );
				Self::check_signature(&message, source_public_key, signature)?;
				Ok(())
			}
			NetworkNode::Source { .. } => {
				bail!("Incorrect usage: verify_origin is used to verify NetworkNode::Data or NetworkNode::Group originated from the source")
			}
		}
	}

	/// User verifies if the node is part of the data set root provided by source.
	pub fn verify_merkle_proof(&self, merkle_root: &str) -> anyhow::Result<()> {

		match self {
			NetworkNode::Data { label, proof: verification_path, .. } => {
				Self::check_hashes(merkle_root, label, verification_path)
			}
			NetworkNode::Group { group_hash, proof: verification_path, .. } => {
				Self::check_hashes(merkle_root, &group_hash.clone().unwrap(), verification_path)
			}
			NetworkNode::Source { .. } => {
				bail!("Incorrect usage: verify_merkle_proof is used to verify NetworkNode::Data or NetworkNode::Group is part of the merkle root")
			}
		}
	}

	fn check_hashes(merkle_root: &str, base: &String, verification_path: &PathInfo) -> anyhow::Result<()> {
		let mut current_hash = base.clone();
		let nodes = verification_path.get_nodes();

		for node in nodes {
			let mut group_hash = String::new();
			node.get_group_siblings().iter()
				.for_each(|group_sibling| match group_sibling {
					None => {
						group_hash.push_str(current_hash.as_str());
					}
					Some(sibling_info) => {
						group_hash.push_str(&sibling_info.tree_node_hash);
					}
				});

			let mut data_hash = String::new();
			node.get_data_siblings().iter()
				.for_each(|data_sibling| {
					match data_sibling {
						None => {
							data_hash.push_str(current_hash.as_str());
						}
						Some(sibling_info) => {
							data_hash.push_str(&sibling_info.tree_node_hash);
						}
					}
				});

			let mut hasher = Sha256::new();
			hasher.update(group_hash.as_bytes());
			hasher.update(data_hash.as_bytes());
			let hash_bytes: [u8; 32] = hasher.finalize().into();

			current_hash = hex::encode(hash_bytes);
		}

		if current_hash == merkle_root {
			Ok(())
		} else { bail!("Incorrect hash: {}", current_hash); }
	}

	fn check_signature(message: &String, public_key: &[u8], signature: &Vec<u8>) -> anyhow::Result<()> {
		let secp256k1 = Secp256k1::new();

		let signature = Signature::from_byte_array(signature.clone().try_into().expect("Invalid signature"));
		let digest: [u8; 32] = sha2::Sha256::digest(message.as_bytes()).into();
		let public_key = PublicKey::from_slice(public_key)?;


		let secp_verify_result = secp256k1.verify_schnorr(&signature, &digest, &public_key.x_only_public_key().0);
		secp_verify_result
			.map_err(|secp_err| { anyhow!("schnorr signature could not be verified: {}", secp_err) })
	}
}
