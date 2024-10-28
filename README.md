# Distributed Merkle Tree

A library that provides abstractions to build an unbalanced merkle tree
 from a nested group of data set for a user and provides a set of network
 nodes that has been augmented with structural and authentication information
 that can be persisted over a Distributed Hash Table (DHT).

 The implementation is an adaption from the paper

 "Efficient Content Authentication over Distributed Hash Tables"<br>
 by Roberto Tamassia and Nikos Triandopoulos

 The main difference being that merkle tree is currently unbalanced.

 The library is meant to be DHT protocol agnostic. It is meant to be used by the developers of applications
 built on DHT.

 The paper mentioned above introduces a model which consists of -

 1. Source (S),  maintaining a data set (D)
 2. A distributed P2P network (N) which supports queries on D
 3. A user who issues queries on D and is able to -
     (a) Authenticate the D originates from S.
     (b) Verify if result of the query is part of D.


