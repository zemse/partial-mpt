use crate::{
    nibbles::Nibbles,
    nodes::{LeafValue, NodeData, Nodes},
    utils::ConsecutiveList,
    Error,
};
use ethers::{
    types::{Bytes, H256},
    utils::keccak256,
};
use std::{fmt::Debug, marker::PhantomData, str::FromStr};

const EMPTY_ROOT_STR: &str = "56e81f171bcc55a6ff8345e692c0f86e5b48e01b996cadc001622fb5e363b421";

pub trait MptKey: Clone + Debug + PartialEq {
    fn to_nibbles(&self) -> Result<Nibbles, Error>;
}

#[derive(Clone, Debug, PartialEq)]
pub struct Trie<K: MptKey, V: LeafValue> {
    root: Option<H256>,
    nodes: Nodes<V>,
    _marker: PhantomData<K>,
}

impl<K: MptKey, V: LeafValue> Trie<K, V> {
    pub fn new() -> Self {
        Trie {
            root: None,
            nodes: Nodes::new(),
            _marker: PhantomData,
        }
    }

    pub fn from_root(root: H256) -> Self {
        Trie {
            root: Some(root),
            nodes: Nodes::new(),
            _marker: PhantomData,
        }
    }

    pub fn empty() -> Self {
        Self::from_root(H256::from_str(EMPTY_ROOT_STR).unwrap())
    }

    pub fn root(&self) -> Option<H256> {
        self.root
    }

    pub fn get(&self, key: K) -> Result<V, Error> {
        if self.root.is_none() {
            return Err(Error::InternalError("root not set"));
        }

        let path = key.to_nibbles()?;

        let mut hash_current = self.root.unwrap();
        let mut i = 0;
        let u4_vec = path.to_u4_vec();
        loop {
            // if we got to an empty hash, means everything under this is empty
            if hash_current == EMPTY_ROOT_STR.parse().unwrap() {
                return Ok(V::default());
            }

            let node_data = self
                .nodes
                .get(&hash_current)
                .ok_or_else(|| Error::InternalError("node not present, please add a proof"))?;

            match node_data {
                NodeData::Leaf { key, value } => {
                    if key.to_u4_vec() == path.slice(i)?.to_u4_vec() {
                        return Ok(value.to_owned());
                    } else {
                        return Err(Error::InternalError("path mismatch"));
                    }
                }
                NodeData::Branch(arr) => {
                    let nibble = u4_vec[i] as usize;
                    if arr[nibble].is_some() {
                        hash_current = arr[nibble as usize].unwrap();
                    } else {
                        // key value is not in the root, it is resolving to empty
                        return Ok(V::default());
                    }
                    i += 1;
                }
                NodeData::Extension { key, node } => {
                    hash_current = node.to_owned();
                    i += key.len();
                }
            }
        }
    }

    pub fn set(&mut self, key: K, new_value: V) -> Result<(), Error> {
        if self.root.is_none() {
            return Err(Error::InternalError("root not set"));
        }

        let path = key.to_nibbles()?;

        let path_u4_vec = path.to_u4_vec();
        let mut hash_items = ConsecutiveList::new(self.root.unwrap());

        // if trie is empty, insert first node at root
        if hash_items.current() == EMPTY_ROOT_STR.parse().unwrap() {
            let leaf = NodeData::Leaf {
                key: path,
                value: new_value,
            };
            let (hash_leaf, _) = self.nodes.insert(leaf)?;
            self.root = Some(hash_leaf);
            return Ok(());
        }

        // keep traversing down the trie until we get the final node and update it
        let mut i = 0;
        let mut hash_updated: H256;
        loop {
            let mut current_node = self
                .nodes
                .remove(&hash_items.current())
                .ok_or_else(|| Error::InternalError("node not present, please add a proof"))?;

            current_node = match current_node {
                NodeData::Leaf { key, value } => {
                    let path_slice = path.slice(i)?;
                    i += key.len();
                    if key.to_u4_vec() == path_slice.to_u4_vec() {
                        // path exactly matches, simply update value
                        NodeData::Leaf {
                            key,
                            value: new_value.clone(),
                        }
                    } else {
                        // we have to hook both leaves under a branch
                        let branch_or_extension = self.nodes.create_branch_or_extension(
                            key,
                            value,
                            path_slice,
                            new_value.clone(),
                        )?;
                        branch_or_extension
                    }
                    // todo: if value is set to zero, then this node has to be deleted
                }
                NodeData::Branch(mut arr) => {
                    let nibble = path_u4_vec[i] as usize;
                    i += 1;
                    if arr[nibble].is_some() {
                        // set next for traversing down the branch
                        hash_items.set_next(arr[nibble as usize].unwrap())
                    } else {
                        // create a leaf and assign to the branch
                        let path_slice = path.slice(i)?;
                        i += path_slice.len();
                        let leaf_hash = self.nodes.create_leaf(path_slice, new_value.clone())?;
                        arr[nibble] = Some(leaf_hash);
                    }
                    NodeData::Branch(arr)
                }
                NodeData::Extension { key, node } => {
                    hash_items.set_next(node.to_owned());
                    i += key.len();
                    NodeData::Extension { key, node }
                }
            };

            (hash_updated, _) = self.nodes.insert(current_node)?;

            // if we got nothing to further traverse down, exit the loop
            if !hash_items.go_next() {
                assert_eq!(i, path.len(), "path will be traversed completely");
                break;
            }
        }

        if new_value == V::default() {
            // remove leaf
            if let Some(branch_hash) = hash_items.prev() {
                let mut branch_node = self.nodes.remove(&branch_hash).ok_or_else(|| {
                    Error::InternalError("branch found but still got None somehow")
                })?;
                assert!(branch_node.is_branch());
                // parent_node must be a branch or root
                let mut arr = branch_node.get_branch_arr().unwrap();
                let num_of_nodes_on_branch =
                    arr.iter().fold(
                        0,
                        |sum: i32, hash| {
                            if hash.is_some() {
                                sum + 1
                            } else {
                                sum
                            }
                        },
                    );
                if num_of_nodes_on_branch > 2 {
                    // we can just remove the leaf and stop here
                    let removal_index = arr
                        .iter()
                        .position(|el| el.is_some() && el.unwrap() == hash_items.current())
                        .ok_or(Error::InternalError(
                            "hash not found in parent node, this should ideally not happen",
                        ))?;

                    arr[removal_index] = None;
                    // update the branch node and save it
                    branch_node = NodeData::Branch(arr);
                    (hash_updated, _) = self.nodes.insert(branch_node)?;
                    hash_items.go_back();
                } else if num_of_nodes_on_branch == 2 {
                    // find the other node which we want to keep
                    let keep_index = arr
                        .iter()
                        .position(|el| el.is_some() && el.unwrap() != hash_items.current())
                        .ok_or(Error::InternalError(
                            "failed to find another element, this should ideally not happen",
                        ))?;

                    // we want to remove the branch_node and put the keep_node in that place
                    let keep_hash = arr[keep_index].unwrap();
                    let keep_node = self.nodes.remove(&keep_hash).ok_or_else(|| {
                        Error::InternalError("keep node not present, please load_proof for key, TODO display key here")
                    })?;

                    // making necessary changes to the keep_node
                    let keep_node_new = match keep_node {
                        NodeData::Leaf { key, value } => {
                            // insert nibble at begining of key
                            NodeData::Leaf {
                                key: key.prepend_nibbles(vec![keep_index as u8])?,
                                value,
                            }
                        }
                        NodeData::Branch(arr) => {
                            // insert the branch back as it is
                            self.nodes.insert(NodeData::Branch(arr))?;
                            // create an extension node which points to the branch
                            NodeData::<V>::Extension {
                                key: Nibbles::from_u4_vec(vec![keep_index as u8])?,
                                node: keep_hash,
                            }
                        }
                        NodeData::Extension { key, node } => {
                            // edit the key of this extension node and add nibble at begining of key
                            NodeData::Extension {
                                key: key.prepend_nibbles(vec![keep_index as u8])?,
                                node,
                            }
                        }
                    };

                    let (keep_hash_new, _) = self.nodes.insert(keep_node_new)?;
                    hash_items.go_back();

                    if let Some(branch_parent_hash) = hash_items.prev() {
                        let branch_parent_node =
                            self.nodes.remove(&branch_parent_hash).ok_or_else(|| {
                                Error::InternalError("parent found but still got None somehowx")
                            })?;
                        let branch_parent_node_updated = match branch_parent_node {
                            NodeData::Branch(mut arr) => {
                                // find the old branch hash and replace it with keep hash new
                                let index = arr
                                    .iter()
                                    .position(|el| el.is_some() && el.unwrap() == hash_items.current())
                                    .ok_or(Error::InternalError(
                                        "hash not found in parent node, this should ideally not happen",
                                    ))?;

                                arr[index] = Some(keep_hash_new);
                                NodeData::<V>::Branch(arr)
                            }
                            NodeData::Extension { key, node: _ } => {
                                // node must be branch hash, replace it with keep hash new
                                NodeData::<V>::Extension {
                                    key,
                                    node: keep_hash_new,
                                }
                            }
                            _ => unreachable!("this is unreachable"),
                        };
                        (hash_updated, _) = self.nodes.insert(branch_parent_node_updated)?;
                        hash_items.go_back();
                    } else {
                        hash_updated = keep_hash_new;
                    }
                } else {
                    panic!("there were less than two nodes on a branch, this can't happen");
                }
            } else {
                // leaf is directly on the root
                hash_updated = EMPTY_ROOT_STR.parse().unwrap();
            }
        }

        // keep traversing up the trie while updating the hashes until we get to the root
        loop {
            if let Some(hash_old_parent) = hash_items.prev() {
                let mut parent_node = self.nodes.remove(&hash_old_parent).ok_or_else(|| {
                    Error::InternalError("parent found but still got None somehow")
                })?;
                parent_node = match parent_node {
                    NodeData::Leaf { key: _, value: _ } => {
                        unreachable!()
                    }
                    NodeData::Branch(mut arr) => {
                        // update the hash at correct location in parent branch
                        let some_index = arr
                            .iter()
                            .position(|el| el.is_some() && el.unwrap() == hash_items.current());
                        if some_index.is_none() {
                            return Err(Error::InternalError(
                                "hash not found in parent node, this should ideally not happen",
                            ));
                        }
                        arr[some_index.unwrap()] = Some(hash_updated);
                        NodeData::Branch(arr)
                    }
                    NodeData::Extension { key, node: _ } => NodeData::Extension {
                        key,
                        node: hash_updated,
                    },
                };
                (hash_updated, _) = self.nodes.insert(parent_node)?;
                hash_items.go_back();
            } else {
                self.root = Some(hash_updated);
                break;
            }
        }

        Ok(())
    }

    pub fn remove(&mut self, key: K) -> Result<(), Error> {
        self.set(key, V::default())
    }

    pub fn load_proof(&mut self, key: K, value: V, proof: Vec<Bytes>) -> Result<(), Error> {
        if proof.len() == 0 {
            if self.root.is_some() {
                if self.root.unwrap() != EMPTY_ROOT_STR.parse().unwrap() {
                    // enforce proof to be empt
                    return Err(Error::InternalError(
                        "Root is not empty, hence some proof is needed",
                    ));
                } else if value != V::default() {
                    // enforce the values to be empty, since it is empty root
                    return Err(Error::InternalError(
                        "Value should be empty, since root is empty",
                    ));
                }
            }
            return Ok(());
        }

        // proof.len() > 0
        if self.root.is_none() {
            let proof_root = proof[0].clone();
            self.root = Some(H256::from(keccak256(proof_root)));
        }

        let mut root = self.root.unwrap();
        let mut key_current = key.clone().to_nibbles()?;

        for (i, proof_entry) in proof.iter().enumerate() {
            let hash_node_data = H256::from(keccak256(proof_entry.clone()));

            // check if node data is preimage of root
            if hash_node_data != root {
                return Err(Error::InternalError(
                    "proof entry hash does not match the node root",
                ));
            }

            // decode the node
            let node_data = NodeData::from_raw_rlp(proof_entry.to_owned())?;

            // if this is a leaf node (the last one), enforce key and value to be proper
            if let NodeData::Leaf {
                key: leaf_key,
                value: leaf_value,
            } = node_data.clone()
            {
                if leaf_key != key_current {
                    return Err(Error::InternalError("key in leaf does not match input"));
                }
                if leaf_value != value {
                    return Err(Error::InternalError("value in leaf does not match input"));
                }
            }

            let some_node_data_stored = self.nodes.get(&hash_node_data);
            if some_node_data_stored.is_none() {
                self.nodes.insert(node_data.clone())?;
            }

            match node_data {
                NodeData::Extension { key, node } => {
                    root = node;
                    // skip nibbles already included in extension key in the current key
                    key_current = key_current.slice(key.len())?;
                }
                NodeData::Branch(arr) => {
                    for _child in arr {
                        // find the appropriate child node in branch
                        let hash_next = H256::from(keccak256(proof[i + 1].clone()));
                        if _child.is_some() {
                            let child = _child.unwrap();
                            if child == hash_next {
                                root = child;
                                // skip one nibble in the current key for branch nodes
                                key_current = key_current.slice(1)?;
                                break;
                            }
                        }
                    }
                }
                _ => return Ok(()),
            };
        }

        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::{MptKey, Nibbles, NodeData, Trie, EMPTY_ROOT_STR};
    use ethers::{
        types::{BigEndianHash, Bytes, H256, U256},
        utils::{hex, keccak256},
    };

    impl MptKey for Nibbles {
        fn to_nibbles(&self) -> Result<Nibbles, crate::Error> {
            Ok(self.to_owned())
        }
    }

    impl MptKey for u64 {
        fn to_nibbles(&self) -> Result<Nibbles, crate::Error> {
            Ok(Nibbles::from_raw_path(Bytes::from(
                keccak256(H256::from_uint(&U256::from(*self))).to_vec(),
            )))
        }
    }

    #[test]
    pub fn test_trie_new_empty_1() {
        let mut trie = Trie::<Nibbles, u64>::from_root(
            "0x56e81f171bcc55a6ff8345e692c0f86e5b48e01b996cadc001622fb5e363b421"
                .parse()
                .unwrap(),
        );

        trie.load_proof(
            Nibbles::from_raw_path(
                "0x290decd9548b62a8d60345a988386fc84ba6bc95484008f6362f93160ef3e563" // hash(pad(0))
                    .parse()
                    .unwrap(),
            ),
            0,
            vec![],
        )
        .unwrap();

        assert_eq!(
            hex::encode(trie.root.unwrap()),
            "56e81f171bcc55a6ff8345e692c0f86e5b48e01b996cadc001622fb5e363b421"
        );
        assert!(trie.nodes.get(&trie.root.unwrap()).is_none());

        println!("trie {:#?}", trie);
        // assert!(false);
    }

    #[test]
    pub fn test_trie_new_one_element_1() {
        let mut trie = Trie::<Nibbles, u64>::new();

        trie.load_proof(
            Nibbles::from_raw_path(
                "0x290decd9548b62a8d60345a988386fc84ba6bc95484008f6362f93160ef3e563" // hash(pad(0))
                    .parse()
                    .unwrap(),
            ),
            8,
            vec![
                "0xe3a120290decd9548b62a8d60345a988386fc84ba6bc95484008f6362f93160ef3e56308"
                    .parse()
                    .unwrap(),
            ],
        )
        .unwrap();

        assert_eq!(
            hex::encode(trie.root.unwrap()),
            "1c2e599f5f2a6cd75de40aada2a11971863dabd7a7378f1a3b268856a95829ba"
        );
        assert_eq!(
            trie.nodes.get(&trie.root.unwrap()).unwrap().to_owned(),
            NodeData::Leaf {
                key: Nibbles::from_raw_path_str(
                    "0x290decd9548b62a8d60345a988386fc84ba6bc95484008f6362f93160ef3e563"
                ),
                value: 8,
            }
        );

        println!("trie {:#?}", trie);
        // assert!(false);
    }

    #[test]
    pub fn test_trie_new_two_element_1() {
        let mut trie = Trie::<Nibbles, u64>::new();

        trie.load_proof(
            Nibbles::from_raw_path_str("0x036b6384b5eca791c62761152d0c79bb0604c104a5fb6f4eb0703f3154bb3db0" // hash(pad(5))
               ),
            9,
            vec![
                "0xf851a0e97150c3ed221a6f46bdcd44e8a2d44825bc781fa48f797e9df2f8ceff52a43e8080808080808080808080a09487c8e7f28469b9f72cd6be094b555c3882c0653f11b208ff76bf8caee5043280808080"
                    .parse()
                    .unwrap(),
                "0xe2a0336b6384b5eca791c62761152d0c79bb0604c104a5fb6f4eb0703f3154bb3db009"
                    .parse()
                    .unwrap(),
            ],
        )
        .unwrap();

        assert_eq!(
            hex::encode(trie.root.unwrap()),
            "45e335095c8915edb03eb2dc964ad3abff45427cc3da4925a96aba38b3fe196c"
        );
        assert_eq!(
            trie.nodes.get(&trie.root.unwrap()).unwrap().to_owned(),
            NodeData::Branch([
                Some(
                    "0xe97150c3ed221a6f46bdcd44e8a2d44825bc781fa48f797e9df2f8ceff52a43e"
                        .parse()
                        .unwrap(),
                ),
                None,
                None,
                None,
                None,
                None,
                None,
                None,
                None,
                None,
                None,
                None,
                Some(
                    "0x9487c8e7f28469b9f72cd6be094b555c3882c0653f11b208ff76bf8caee50432"
                        .parse()
                        .unwrap(),
                ),
                None,
                None,
                None,
                None,
            ])
        );
        assert_eq!(
            trie.nodes
                .get_str("0xe97150c3ed221a6f46bdcd44e8a2d44825bc781fa48f797e9df2f8ceff52a43e")
                .unwrap()
                .to_owned(),
            NodeData::Leaf {
                key: Nibbles::from_encoded_path_str(
                    "0x336b6384b5eca791c62761152d0c79bb0604c104a5fb6f4eb0703f3154bb3db0"
                )
                .unwrap(),
                value: 9,
            }
        );
        assert!(trie
            .nodes
            .get_str("0x9487c8e7f28469b9f72cd6be094b555c3882c0653f11b208ff76bf8caee50432")
            .is_none());

        println!("trie {:#?}", trie);
        // assert!(false);
    }

    #[test]
    pub fn test_trie_new_three_element_1() {
        let mut trie = Trie::<Nibbles, u64>::new();

        trie.load_proof(
            Nibbles::from_raw_path_str(
                "0xc65a7bb8d6351c1cf70c95a316cc6a92839c986682d98bc35f958f4883f9d2a8" // hash(pad(5))
              ),
            20,
            vec![
                "0xf851a0c2af0751112c3efa2873802b452283ab1e2c60fde148a2f9e482ed03b8947e158080808080808080808080a0b3e6ad355d7116d0b4173e75e4c760082c8870e3b5b746cfadfea7101e834cc280808080"
                    .parse()
                    .unwrap(),
                "0xe583165a7ba0e46db0426b9d34c7b2df7baf0480777946e6b5b74a0572592b0229a4edaed944"
                    .parse()
                    .unwrap(),
                "0xf85180808080808080a00c104f2019963f0df89d54742b14cd0ad7418cb208e9bc69bf80cb296926ffe9808080a04efd8a29c04796b9c9b13af2740864e48851a89ef4292575ab5f69b3a52c06c08080808080"
                    .parse()
                    .unwrap(),
                "0xdf9d38d6351c1cf70c95a316cc6a92839c986682d98bc35f958f4883f9d2a814"
                    .parse()
                    .unwrap(),
            ],
        )
        .unwrap();

        assert_eq!(
            hex::encode(trie.root.unwrap()),
            "83c3e173e44cf782dfc14c550c322661c26728efda96977ed472c71bb94e8692"
        );
        assert_eq!(
            trie.nodes.get(&trie.root.unwrap()).unwrap().to_owned(),
            NodeData::Branch([
                Some(
                    "0xc2af0751112c3efa2873802b452283ab1e2c60fde148a2f9e482ed03b8947e15"
                        .parse()
                        .unwrap(),
                ),
                None,
                None,
                None,
                None,
                None,
                None,
                None,
                None,
                None,
                None,
                None,
                Some(
                    "0xb3e6ad355d7116d0b4173e75e4c760082c8870e3b5b746cfadfea7101e834cc2"
                        .parse()
                        .unwrap(),
                ),
                None,
                None,
                None,
                None,
            ])
        );
        assert!(trie
            .nodes
            .get_str("0xc2af0751112c3efa2873802b452283ab1e2c60fde148a2f9e482ed03b8947e15")
            .is_none());
        assert_eq!(
            trie.nodes
                .get_str("0xb3e6ad355d7116d0b4173e75e4c760082c8870e3b5b746cfadfea7101e834cc2")
                .unwrap()
                .to_owned(),
            NodeData::Extension {
                key: Nibbles::from_encoded_path_str("0x165a7b").unwrap(),
                node: "0xe46db0426b9d34c7b2df7baf0480777946e6b5b74a0572592b0229a4edaed944"
                    .parse()
                    .unwrap(),
            }
        );
        assert_eq!(
            trie.nodes
                .get_str("0xe46db0426b9d34c7b2df7baf0480777946e6b5b74a0572592b0229a4edaed944")
                .unwrap()
                .to_owned(),
            NodeData::Branch([
                None,
                None,
                None,
                None,
                None,
                None,
                None,
                Some(
                    "0x0c104f2019963f0df89d54742b14cd0ad7418cb208e9bc69bf80cb296926ffe9"
                        .parse()
                        .unwrap(),
                ),
                None,
                None,
                None,
                Some(
                    "0x4efd8a29c04796b9c9b13af2740864e48851a89ef4292575ab5f69b3a52c06c0"
                        .parse()
                        .unwrap(),
                ),
                None,
                None,
                None,
                None,
                None
            ])
        );
        assert!(trie
            .nodes
            .get_str("0x0c104f2019963f0df89d54742b14cd0ad7418cb208e9bc69bf80cb296926ffe9")
            .is_none());
        assert_eq!(
            trie.nodes
                .get_str("0x4efd8a29c04796b9c9b13af2740864e48851a89ef4292575ab5f69b3a52c06c0")
                .unwrap()
                .to_owned(),
            NodeData::Leaf {
                key: Nibbles::from_encoded_path_str(
                    "0x38d6351c1cf70c95a316cc6a92839c986682d98bc35f958f4883f9d2a8"
                )
                .unwrap(),
                value: 20,
            }
        );

        println!("trie {:#?}", trie);
        // assert!(false);
    }

    #[test]
    pub fn test_trie_load_two_proofs_1() {
        let mut trie = Trie::<Nibbles, u64>::new();

        trie.load_proof(
            Nibbles::from_raw_path_str(
                "0x405787fa12a823e0f2b7631cc41b3ba8828b3321ca811111fa75cd3aa3bb5ace", // hash(pad(2))
            ),
            4,
            vec![
                "0xf85180808080a03f39d7bf4be8677b2d7db8f944e618380c443e7615adddd29b4cba751d7acdc580808080808080a055037b5dac295c1605ec14cf282314a2870cbf448e24cf0cbc1b46fc09ad731e80808080".parse().unwrap(),
                "0xe2a0305787fa12a823e0f2b7631cc41b3ba8828b3321ca811111fa75cd3aa3bb5ace04".parse().unwrap()
            ],
        ).unwrap();

        trie.load_proof(
            Nibbles::from_raw_path_str(
                "0xc2575a0e9e593c00f959f8c92f12db2869c3395a3b0502d05e2516446f71f85b",
            ),
            9,
            vec![
                "0xf85180808080a03f39d7bf4be8677b2d7db8f944e618380c443e7615adddd29b4cba751d7acdc580808080808080a055037b5dac295c1605ec14cf282314a2870cbf448e24cf0cbc1b46fc09ad731e80808080".parse().unwrap(),
                "0xe2a032575a0e9e593c00f959f8c92f12db2869c3395a3b0502d05e2516446f71f85b09".parse().unwrap()
            ],
        ).unwrap();

        assert_eq!(
            hex::encode(trie.root.unwrap()),
            "e730900f060334776424339bad2d8fb6f53d8b2ddbf991f492d852fb119addc0"
        );

        assert_eq!(
            trie.nodes.get(&trie.root.unwrap()).unwrap().to_owned(),
            NodeData::Branch([
                None,
                None,
                None,
                None,
                Some(
                    "0x3f39d7bf4be8677b2d7db8f944e618380c443e7615adddd29b4cba751d7acdc5"
                        .parse()
                        .unwrap()
                ),
                None,
                None,
                None,
                None,
                None,
                None,
                None,
                Some(
                    "0x55037b5dac295c1605ec14cf282314a2870cbf448e24cf0cbc1b46fc09ad731e"
                        .parse()
                        .unwrap()
                ),
                None,
                None,
                None,
                None,
            ])
        );

        assert_eq!(
            trie.nodes
                .get_str("0x3f39d7bf4be8677b2d7db8f944e618380c443e7615adddd29b4cba751d7acdc5")
                .unwrap()
                .to_owned(),
            NodeData::Leaf {
                key: Nibbles::from_encoded_path_str(
                    "0x305787fa12a823e0f2b7631cc41b3ba8828b3321ca811111fa75cd3aa3bb5ace"
                )
                .unwrap(),
                value: 4,
            }
        );

        assert_eq!(
            trie.nodes
                .get_str("0x55037b5dac295c1605ec14cf282314a2870cbf448e24cf0cbc1b46fc09ad731e")
                .unwrap()
                .to_owned(),
            NodeData::Leaf {
                key: Nibbles::from_encoded_path_str(
                    "0x32575a0e9e593c00f959f8c92f12db2869c3395a3b0502d05e2516446f71f85b"
                )
                .unwrap(),
                value: 9,
            }
        );

        println!("trie {:#?}", trie);
        // assert!(false);
    }

    #[test]
    pub fn test_trie_get_1() {
        let mut trie = Trie::<Nibbles, u64>::new();

        trie.load_proof(
            Nibbles::from_raw_path_str(
                "0x405787fa12a823e0f2b7631cc41b3ba8828b3321ca811111fa75cd3aa3bb5ace", // hash(pad(2))
            ),
            4,
            vec![
                "0xf85180808080a03f39d7bf4be8677b2d7db8f944e618380c443e7615adddd29b4cba751d7acdc580808080808080a055037b5dac295c1605ec14cf282314a2870cbf448e24cf0cbc1b46fc09ad731e80808080".parse().unwrap(),
                "0xe2a0305787fa12a823e0f2b7631cc41b3ba8828b3321ca811111fa75cd3aa3bb5ace04".parse().unwrap()
            ],
         ).unwrap();

        trie.load_proof(
            Nibbles::from_raw_path_str(
                "0xc2575a0e9e593c00f959f8c92f12db2869c3395a3b0502d05e2516446f71f85b",
            ),
            9,
            vec![
                "0xf85180808080a03f39d7bf4be8677b2d7db8f944e618380c443e7615adddd29b4cba751d7acdc580808080808080a055037b5dac295c1605ec14cf282314a2870cbf448e24cf0cbc1b46fc09ad731e80808080".parse().unwrap(),
                "0xe2a032575a0e9e593c00f959f8c92f12db2869c3395a3b0502d05e2516446f71f85b09".parse().unwrap()
            ],
        ).unwrap();

        let val = trie
            .get(Nibbles::from_raw_path_str(
                "0x405787fa12a823e0f2b7631cc41b3ba8828b3321ca811111fa75cd3aa3bb5ace", // hash(pad(2))
            ))
            .unwrap();
        assert_eq!(val, 4);

        let val2 = trie
            .get(Nibbles::from_raw_path_str(
                "0xc2575a0e9e593c00f959f8c92f12db2869c3395a3b0502d05e2516446f71f85b", // hash(pad(2))
            ))
            .unwrap();
        assert_eq!(val2, 9);
    }

    #[test]
    pub fn test_trie_get_2() {
        let mut trie = Trie::<Nibbles, u64>::new();

        trie.load_proof(
            Nibbles::from_raw_path_str(
                "0xc65a7bb8d6351c1cf70c95a316cc6a92839c986682d98bc35f958f4883f9d2a8" // hash(pad(5))
              ),
            20,
            vec![
                "0xf851a0c2af0751112c3efa2873802b452283ab1e2c60fde148a2f9e482ed03b8947e158080808080808080808080a0b3e6ad355d7116d0b4173e75e4c760082c8870e3b5b746cfadfea7101e834cc280808080"
                    .parse()
                    .unwrap(),
                "0xe583165a7ba0e46db0426b9d34c7b2df7baf0480777946e6b5b74a0572592b0229a4edaed944"
                    .parse()
                    .unwrap(),
                "0xf85180808080808080a00c104f2019963f0df89d54742b14cd0ad7418cb208e9bc69bf80cb296926ffe9808080a04efd8a29c04796b9c9b13af2740864e48851a89ef4292575ab5f69b3a52c06c08080808080"
                    .parse()
                    .unwrap(),
                "0xdf9d38d6351c1cf70c95a316cc6a92839c986682d98bc35f958f4883f9d2a814"
                    .parse()
                    .unwrap(),
            ],
        )
        .unwrap();

        let val = trie
            .get(Nibbles::from_raw_path_str(
                "0xc65a7bb8d6351c1cf70c95a316cc6a92839c986682d98bc35f958f4883f9d2a8", // hash(pad(5))
            ))
            .unwrap();
        assert_eq!(val, 20);
    }

    #[test]
    pub fn test_trie_get_3_value_not_proved() {
        let mut trie = Trie::<Nibbles, u64>::new();

        trie.load_proof(
            Nibbles::from_raw_path_str(
                "0x405787fa12a823e0f2b7631cc41b3ba8828b3321ca811111fa75cd3aa3bb5ace", // hash(pad(2))
            ),
            4,
            vec![
                "0xf85180808080a03f39d7bf4be8677b2d7db8f944e618380c443e7615adddd29b4cba751d7acdc580808080808080a055037b5dac295c1605ec14cf282314a2870cbf448e24cf0cbc1b46fc09ad731e80808080".parse().unwrap(),
                "0xe2a0305787fa12a823e0f2b7631cc41b3ba8828b3321ca811111fa75cd3aa3bb5ace04".parse().unwrap()
            ],
         ).unwrap();

        assert!(trie
            .get(Nibbles::from_raw_path_str(
                "0xc2575a0e9e593c00f959f8c92f12db2869c3395a3b0502d05e2516446f71f85b",
            ))
            .is_err());
    }

    #[test]
    pub fn test_trie_get_4_empty_value() {
        let mut trie = Trie::<Nibbles, u64>::new();

        trie.load_proof(
            Nibbles::from_raw_path_str(
                "0x405787fa12a823e0f2b7631cc41b3ba8828b3321ca811111fa75cd3aa3bb5ace", // hash(pad(2))
            ),
            4,
            vec![
                "0xf85180808080a03f39d7bf4be8677b2d7db8f944e618380c443e7615adddd29b4cba751d7acdc580808080808080a055037b5dac295c1605ec14cf282314a2870cbf448e24cf0cbc1b46fc09ad731e80808080".parse().unwrap(),
                "0xe2a0305787fa12a823e0f2b7631cc41b3ba8828b3321ca811111fa75cd3aa3bb5ace04".parse().unwrap()
            ],
         ).unwrap();

        assert_eq!(
            trie.get(Nibbles::from_raw_path_str(
                "0x17fa14b0d73aa6a26d6b8720c1c84b50984f5c188ee1c113d2361e430f1b6764", // hash(pad(1234))
            ))
            .unwrap(),
            0,
        );
    }

    #[test]
    pub fn test_trie_set_1() {
        let mut trie = Trie::<Nibbles, u64>::new();

        trie.load_proof(
            Nibbles::from_raw_path_str(
                "0x405787fa12a823e0f2b7631cc41b3ba8828b3321ca811111fa75cd3aa3bb5ace", // hash(pad(2))
            ),
            4,
            vec![
                "0xf85180808080a03f39d7bf4be8677b2d7db8f944e618380c443e7615adddd29b4cba751d7acdc580808080808080a055037b5dac295c1605ec14cf282314a2870cbf448e24cf0cbc1b46fc09ad731e80808080".parse().unwrap(),
                "0xe2a0305787fa12a823e0f2b7631cc41b3ba8828b3321ca811111fa75cd3aa3bb5ace04".parse().unwrap()
            ],
        ).unwrap();

        trie.load_proof(
            Nibbles::from_raw_path_str(
                "0xc2575a0e9e593c00f959f8c92f12db2869c3395a3b0502d05e2516446f71f85b",
            ),
            9,
            vec![
                "0xf85180808080a03f39d7bf4be8677b2d7db8f944e618380c443e7615adddd29b4cba751d7acdc580808080808080a055037b5dac295c1605ec14cf282314a2870cbf448e24cf0cbc1b46fc09ad731e80808080".parse().unwrap(),
                "0xe2a032575a0e9e593c00f959f8c92f12db2869c3395a3b0502d05e2516446f71f85b09".parse().unwrap()
            ],
        ).unwrap();

        println!("trie before {:#?}", trie);
        assert_eq!(
            hex::encode(trie.root.unwrap()),
            "e730900f060334776424339bad2d8fb6f53d8b2ddbf991f492d852fb119addc0"
        );

        trie.set(
            Nibbles::from_raw_path_str(
                "0xc2575a0e9e593c00f959f8c92f12db2869c3395a3b0502d05e2516446f71f85b",
            ),
            8,
        )
        .unwrap();

        println!("trie after {:#?}", trie);
        assert_eq!(
            hex::encode(trie.root.unwrap()),
            "a8c351fd6909c41a53b213f026c3150740e6a0ce1229378b4da9cbde09981812"
        );
    }

    #[test]
    pub fn test_trie_insert_new_leaf_on_root() {
        let mut trie = Trie::<Nibbles, u64>::empty();

        trie.set(
            Nibbles::from_raw_path(
                "0x036b6384b5eca791c62761152d0c79bb0604c104a5fb6f4eb0703f3154bb3db0" // hash(pad(5))
                    .parse()
                    .unwrap(),
            ),
            5,
        )
        .unwrap();

        assert_eq!(
            hex::encode(trie.root.unwrap()),
            "45b9cf0531c2a25a0245e6729eb0d598c069c658d18f40971c1a335060a3108a"
        );
    }

    #[test]
    pub fn test_trie_insert_new_leaf_on_branch() {
        let mut trie = Trie::<Nibbles, u64>::new();

        trie.load_proof(
            Nibbles::from_raw_path_str("0x036b6384b5eca791c62761152d0c79bb0604c104a5fb6f4eb0703f3154bb3db0"), // hash(pad(5))
            5,
            vec![
                "0xf851a07d8f23b831e6f4d69ddbc6629dc8af2289ed1791a87a77de545468d8857d3f0a8080808080808080808080808080a0b1c4f7aff61e4142aadf9217f54c2f4f0c280ebb9fcd70b5eae55129905a113a80"
                    .parse()
                    .unwrap(),
                "0xe2a0336b6384b5eca791c62761152d0c79bb0604c104a5fb6f4eb0703f3154bb3db005"
                    .parse()
                    .unwrap(),
            ],
        )
        .unwrap();

        // ready made trie of 5->5 & 6->6
        println!("trie before {:#?}", trie);
        assert_eq!(
            hex::encode(trie.root.unwrap()),
            "27b40440e189f435994e57d1a944cbcd8002910812a7eac1b331fcc17b31fcb1"
        );

        // now inserting 7->7
        trie.set(
            Nibbles::from_raw_path_str(
                "0xa66cc928b5edb82af9bd49922954155ab7b0942694bea4ce44661d9a8736c688", // hash(pad(7))
            ),
            7,
        )
        .unwrap();

        println!("trie after {:?}", trie);

        assert_eq!(
            hex::encode(trie.root.unwrap()),
            "491b2cfba976b2e78bd9be3bc15c9964927205fc34c9954a4d61bbe8170ba533"
        );
    }

    #[test]
    pub fn test_trie_insert_new_leaf_on_leaf_1() {
        // create a trie with 3->3 and then insert 5->5.
        let mut trie = Trie::<u64, u64>::empty();
        trie.set(3, 3).unwrap();

        println!("trie before {:#?}", trie);

        assert!(
            trie.nodes.get(&trie.root.unwrap()).unwrap().is_leaf(),
            "root is leaf"
        );
        assert_eq!(
            hex::encode(trie.root.unwrap()),
            "0c4caa428075ee816af422cf4cbec78e239dc705eb534e11909f6568409bfb47"
        );

        trie.set(5, 5).unwrap();

        println!("trie after {:#?}", trie);

        assert!(
            trie.nodes.get(&trie.root.unwrap()).unwrap().is_branch(),
            "root is now a branch"
        );

        assert_eq!(
            hex::encode(trie.root.unwrap()),
            "dd7a717913d6e5803a8ec2a816e103427a36e14c2693f836d839a19b907a24b8"
        );
    }

    #[test]
    pub fn test_trie_insert_new_leaf_on_leaf_2() {
        // create a trie with 3->3 and then insert 5->5.
        let mut trie = Trie::<u64, u64>::new();

        trie.load_proof(
            891,
            891,
            vec![
                "0xf851a0745e7881bf31b835a0d5d787dc660bc6cee99caf233635453d93c792ac2f24768080808080808080808080a0b92bbcfcacad3b833b4d2a4993069af365b8ae1fb94abe5cd3f89d97ee91146280808080"
                    .parse()
                    .unwrap(),
                "0xe5a030089936d6f8866fdbcb373720029ed6c076263e72bb11506447776f2764afdb8382037b"
                    .parse()
                    .unwrap(),
            ],
        )
        .unwrap();

        println!("trie after {:#?}", trie);

        assert_eq!(
            hex::encode(trie.root.unwrap()),
            "45aaa54370d5bd38fd19a11822a5b8232956b7f59085a09be373afa481f4bb6e"
        );

        assert!(
            trie.nodes.get(&trie.root.unwrap()).unwrap().is_branch(),
            "root is now a branch"
        );
    }

    #[test]
    pub fn test_trie_remove_1_leaf_on_root() {
        // single key in the trie, after removal none remains
        let mut trie = Trie::<u64, u64>::empty();

        trie.set(2, 1).unwrap();
        assert_eq!(
            hex::encode(trie.root.unwrap()),
            "43b3f515867571cb1b6893b406551741c129ba2e6e80dbcfa92f82e879fd9d28"
        );

        trie.remove(2).unwrap();
        assert_eq!(hex::encode(trie.root.unwrap()), EMPTY_ROOT_STR);
    }

    #[test]
    pub fn test_trie_remove_2_simple_branch_update() {
        let mut trie = Trie::<u64, u64>::empty();

        trie.set(2, 1).unwrap(); // 0x405..
        assert_eq!(
            hex::encode(trie.root.unwrap()),
            "43b3f515867571cb1b6893b406551741c129ba2e6e80dbcfa92f82e879fd9d28"
        );

        trie.set(5, 1).unwrap(); // 0x036..
        assert_eq!(
            hex::encode(trie.root.unwrap()),
            "2da5223fccd774d9ebc91430acd028ec4a017afbe9eb0de0a39a24004115a70f"
        );

        trie.set(7, 1).unwrap(); // 0xa66..
        assert_eq!(
            hex::encode(trie.root.unwrap()),
            "bf30980e36d0c101f2921e9c9d7b5193d280733218953c09592857f5d76013fb"
        );

        trie.remove(7).unwrap(); // remove 0xa66..
        assert_eq!(
            hex::encode(trie.root.unwrap()),
            "2da5223fccd774d9ebc91430acd028ec4a017afbe9eb0de0a39a24004115a70f"
        );
    }

    #[test]
    pub fn test_trie_remove_3_branch_removal() {
        let mut trie = Trie::<u64, u64>::empty();

        trie.set(2, 1).unwrap(); // 0x405..
        trie.set(5, 1).unwrap(); // 0xa66..

        assert_eq!(
            hex::encode(trie.root.unwrap()),
            "2da5223fccd774d9ebc91430acd028ec4a017afbe9eb0de0a39a24004115a70f"
        );

        trie.remove(5).unwrap();

        assert_eq!(
            hex::encode(trie.root.unwrap()),
            "43b3f515867571cb1b6893b406551741c129ba2e6e80dbcfa92f82e879fd9d28"
        );
    }

    #[test]
    pub fn test_trie_remove_4_branch_removal_deep() {
        let mut trie = Trie::<u64, u64>::empty();

        // branch on root
        trie.set(1, 1).unwrap(); // b**

        // branch on 0
        trie.set(159, 1).unwrap(); // 0b** // this to be removed

        // branch at 00
        trie.set(480, 1).unwrap(); // 00**
        trie.set(581, 1).unwrap(); // 00**
        trie.set(732, 1).unwrap(); // 00**

        assert_eq!(
            hex::encode(trie.root.unwrap()),
            "3d3df778b70d54c8a8267b8bd725d74539e7152102697d3c54d0122ee4826945"
        );

        trie.remove(159).unwrap();

        assert_eq!(
            hex::encode(trie.root.unwrap()),
            "c919bde029dfebf4c4f50b9ceca10dbf0ce3b9477755301921d94c8e593fb1aa"
        );
    }
}
