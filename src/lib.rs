//! A library that provides abstractions to build an unbalanced merkle tree
//! from a nested group of data set for a user and provides a set of network
//! nodes that has been augmented with structural and authentication information
//! that can be persisted over a Distributed Hash Table (DHT).
//!
//! The implementation is an adaption from the paper
//! "Efficient Content Authentication over Distributed Hash Tables"
//! by Roberto Tamassia and Nikos Triandopoulos
//!
//! The main difference being that merkle tree is currently unbalanced.
//!
//! The library is meant to be DHT protocol agnostic. It is meant to be used by the developers of applications
//! built on DHT.
//!
//! The paper mentioned above introduces a model which consists of -
//!
//! 1. Source (S),  maintaining a data set (D)
//! 2. A distributed P2P network (N) which supports queries on D
//! 3. A user who issues queries on D and is able to -
//!     (a) Authenticate the D originates from S.
//!     (b) Verify if result of the query is part of D.
//!
//!

pub(crate) mod network;
pub(crate) mod augmented_node;
pub(crate) mod types;

pub use augmented_node::DistributedMerkleTree;
pub use network::NetworkNode;
pub use network::PathInfo;
pub use network::SiblingInfo;
pub use network::NodeInfo;
pub use types::Data;
pub use types::Group;
pub use types::Item;
pub use types::User;

use sha2::Digest;
use std::hash::Hash;

pub(crate) fn get_tree_node_hash(group_roots: Vec<String>, data_roots: Vec<String>) -> String {
	let group_hash_raw = format!("{}{}", group_roots.join(""), data_roots.join(""));
	let mut hasher = sha2::Sha256::new();
	hasher.update(group_hash_raw.as_bytes());
	let hash_bytes: [u8; 32] = hasher.finalize().into();

	hex::encode(hash_bytes)
}