use std::{
    collections::HashMap,
    fmt::{self, Debug},
};

use bytes::BytesMut;
use ethers::{
    types::{Bytes, H256},
    utils::{
        hex, keccak256,
        rlp::{self, Rlp, RlpStream},
    },
};

use crate::{nibbles::Nibbles, Error};

pub trait LeafValue: Clone + Debug + Default + PartialEq {
    fn from_raw_rlp(raw: Bytes) -> Result<Self, Error>
    where
        Self: Sized;
    fn to_raw_rlp(&self) -> Result<Bytes, Error>;
}

#[derive(Clone, Debug, PartialEq)]
pub struct Nodes<V: LeafValue>(HashMap<H256, NodeData<V>>);

impl<V: LeafValue> Nodes<V> {
    pub fn new() -> Self {
        Self(HashMap::new())
    }

    pub fn get(&self, hash: &H256) -> Option<&NodeData<V>> {
        self.0.get(hash)
    }

    #[allow(dead_code)]
    pub fn get_str(&self, hash_str: &str) -> Option<&NodeData<V>> {
        let hash = hash_str.parse::<H256>().unwrap();
        self.get(&hash)
    }

    pub fn insert(&mut self, node_data: NodeData<V>) -> Result<(H256, Option<NodeData<V>>), Error> {
        let key = node_data.hash()?;
        Ok((key, self.0.insert(key, node_data)))
    }

    pub fn remove(&mut self, hash: &H256) -> Option<NodeData<V>> {
        self.0.remove(hash)
    }

    pub fn create_leaf(&mut self, key: Nibbles, value: V) -> Result<H256, Error> {
        let (hash_leaf, _) = self.insert(NodeData::Leaf { key, value })?;
        Ok(hash_leaf)
    }

    pub fn create_branch_or_extension(
        &mut self,
        key_a: Nibbles,
        value_a: V,
        key_b: Nibbles,
        value_b: V,
    ) -> Result<NodeData<V>, Error> {
        let mut branch_node_arr: [Option<H256>; 17] = [None; 17];

        let intersection = key_a.intersect(&key_b)?;

        if intersection.len() > 0 {
            let key_a_prime = key_a.slice(intersection.len())?;
            let key_b_prime = key_b.slice(intersection.len())?;

            let nibble_a = key_a_prime.first_nibble() as usize;
            let nibble_b = key_b_prime.first_nibble() as usize;

            let hash_a = self.create_leaf(key_a_prime, value_a)?;
            let hash_b = self.create_leaf(key_b_prime, value_b)?;

            branch_node_arr[nibble_a] = Some(hash_a);
            branch_node_arr[nibble_b] = Some(hash_b);

            let (branch_hash, _) = self.insert(NodeData::Branch(branch_node_arr))?;

            Ok(NodeData::Extension {
                key: intersection,
                node: branch_hash,
            })
        } else {
            let nibble_a = key_a.first_nibble() as usize;
            let nibble_b = key_b.first_nibble() as usize;

            let key_a_prime = key_a.slice(1)?;
            let key_b_prime = key_b.slice(1)?;

            let hash_a = self.create_leaf(key_a_prime, value_a)?;
            let hash_b = self.create_leaf(key_b_prime, value_b)?;

            branch_node_arr[nibble_a] = Some(hash_a);
            branch_node_arr[nibble_b] = Some(hash_b);

            Ok(NodeData::Branch(branch_node_arr))
        }
    }
}

#[derive(Clone, PartialEq)]
pub enum NodeData<V: LeafValue> {
    // Unknown,
    Leaf { key: Nibbles, value: V },
    Branch([Option<H256>; 17]),
    Extension { key: Nibbles, node: H256 },
}

impl<V> NodeData<V>
where
    V: LeafValue,
{
    pub fn hash(&self) -> Result<H256, Error> {
        Ok(H256::from(keccak256(self.to_raw_rlp()?)))
    }

    #[allow(dead_code)]
    pub fn is_leaf(&self) -> bool {
        match self {
            NodeData::Leaf { .. } => true,
            _ => false,
        }
    }

    #[allow(dead_code)]
    pub fn is_branch(&self) -> bool {
        match self {
            NodeData::Branch(_) => true,
            _ => false,
        }
    }

    #[allow(dead_code)]
    pub fn is_extension(&self) -> bool {
        match self {
            NodeData::Extension { .. } => true,
            _ => false,
        }
    }

    pub fn get_branch_arr(&self) -> Option<[Option<H256>; 17]> {
        match self {
            NodeData::Branch(arr) => Some(arr.to_owned()),
            _ => None,
        }
    }

    #[allow(dead_code)]
    pub fn set_value_on_leaf(&mut self, new_value: V) -> Result<(), Error> {
        match self {
            NodeData::<V>::Leaf { key: _, value } => {
                *value = new_value;
                Ok(())
            }
            _ => Err(Error::InternalError(
                "set_value_on_leaf is only valid on leaf nodes",
            )),
        }
    }

    pub fn from_raw_rlp(raw: Bytes) -> Result<Self, Error> {
        let rlp = Rlp::new(&raw);
        let num_items = rlp.item_count()?;
        match num_items {
            2 => Ok({
                let val_0 = Bytes::from(rlp.at(0)?.data()?.to_owned());

                let (key, terminator) = Nibbles::from_encoded_path_with_terminator(val_0.clone())?;
                if terminator {
                    let value = Bytes::from(rlp.at(1)?.data()?.to_owned());
                    NodeData::Leaf {
                        key,
                        value: V::from_raw_rlp(value)?,
                    }
                } else {
                    let hash = rlp.at(1)?.data()?.to_owned();
                    if hash.len() != 32 {
                        return Err(Error::InternalError("invalid hash length in Extension"));
                    }
                    NodeData::Extension {
                        key,
                        node: H256::from_slice(hash.as_slice()),
                    }
                }
            }),
            17 => Ok({
                let mut arr: [Option<H256>; 17] = Default::default();
                for i in 0..17 {
                    let value = rlp.at(i)?.data()?.to_owned();
                    arr[i] = match value.len() {
                        32 => Ok(Some(H256::from_slice(value.as_slice()))),
                        0 => Ok(None),
                        _ => Err(Error::InternalError("invalid hash length in Extension")),
                    }?
                }
                NodeData::Branch(arr)
            }),
            _ => Err(Error::InternalError("Unknown num_items")),
        }
    }

    pub fn to_raw_rlp(&self) -> Result<Bytes, Error> {
        let mut rlp_stream = rlp::RlpStream::new();
        match self {
            NodeData::Leaf { key, value } => {
                let key_bm = BytesMut::from(key.encode_path(true).to_vec().as_slice());
                let value_bm = BytesMut::from(value.to_raw_rlp()?.to_vec().as_slice());

                rlp_stream.begin_list(2);
                rlp_stream.append(&key_bm);
                rlp_stream.append(&value_bm);
            }
            NodeData::Branch(arr) => {
                rlp_stream.begin_list(17);
                for entry in arr.iter() {
                    let bm = if entry.is_some() {
                        BytesMut::from(entry.to_owned().unwrap().as_bytes())
                    } else {
                        BytesMut::new()
                    };
                    rlp_stream.append(&bm);
                }
            }
            NodeData::Extension { key, node } => {
                let key_bm = BytesMut::from(key.encode_path(false).to_vec().as_slice());
                let value_bm = BytesMut::from(node.as_bytes());
                rlp_stream.begin_list(2);
                rlp_stream.append(&key_bm);
                rlp_stream.append(&value_bm);
            }
        }
        Ok(Bytes::from(rlp_stream.out().to_vec()))
    }
}

impl<V> fmt::Debug for NodeData<V>
where
    V: LeafValue,
{
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        let val = match self {
            // NodeData::Unknown => format!("Unknown"),
            NodeData::Leaf { key, value } => format!(
                "Leaf(key={}, value={:?})",
                key,
                hex::encode(value.to_owned().to_raw_rlp().unwrap())
            ),
            NodeData::Branch(branch) => format!(
                "Branch({:?}",
                branch
                    .iter()
                    .map(|node| {
                        if let Some(node) = node {
                            format!("{:?}", node)
                        } else {
                            format!("None")
                        }
                    })
                    .collect::<Vec<_>>()
                    .join(", ")
            ),
            NodeData::Extension { key, node } => {
                format!("Extension(key={}, node={:?})", key, node)
            }
        };
        write!(f, "NodeData::{}", val)
    }
}

impl LeafValue for u64 {
    fn from_raw_rlp(raw: ethers::types::Bytes) -> Result<u64, crate::Error> {
        let rlp = Rlp::new(&raw);
        let arr = rlp.data()?.to_owned();
        if arr.len() <= 8 {
            let mut val: u64 = 0;
            for byte in arr.iter() {
                val = val << 8;
                val += *byte as u64;
            }
            Ok(val)
        } else {
            Err(crate::Error::InternalError("Issue"))
        }
    }

    fn to_raw_rlp(&self) -> Result<ethers::types::Bytes, crate::Error> {
        let mut vec = Vec::<u8>::new();
        let mut flag = false;
        for i in (0..8).rev() {
            let val = (self >> i * 8) & 0xff;
            if val > 0 {
                flag = true
            }
            if flag {
                vec.push(((self >> i * 8) & 0xff).try_into().unwrap());
            }
        }
        let mut rlp_stream = RlpStream::default();
        rlp_stream.append_raw(vec.as_slice(), 1);
        Ok(Bytes::from(rlp_stream.out().to_vec()))
    }
}

#[cfg(test)]
mod tests {
    use super::{Nibbles, NodeData};
    use ethers::utils::hex;

    #[test]
    pub fn test_node_data_new_leaf_node_1() {
        let node_data = NodeData::<u64>::from_raw_rlp(
            "0xe3a120290decd9548b62a8d60345a988386fc84ba6bc95484008f6362f93160ef3e56308"
                .parse()
                .unwrap(),
        )
        .unwrap();

        println!("node_data {:#?}", node_data);

        assert_eq!(
            node_data,
            NodeData::Leaf {
                key: Nibbles::from_raw_path(
                    "0x290decd9548b62a8d60345a988386fc84ba6bc95484008f6362f93160ef3e563"
                        .parse()
                        .unwrap()
                ),
                value: 8,
            }
        );
    }

    #[test]
    pub fn test_node_data_new_leaf_node_2() {
        let input_raw_rlp =
            "e3a120290decd9548b62a8d60345a988386fc84ba6bc95484008f6362f93160ef3e56308";
        let node_data = NodeData::<u64>::from_raw_rlp(input_raw_rlp.parse().unwrap()).unwrap();
        assert_eq!(hex::encode(node_data.to_raw_rlp().unwrap()), input_raw_rlp);
    }

    #[test]
    pub fn test_node_data_new_leaf_node_3() {
        let input_raw_rlp =
            "e3a120290decd9548b62a8d60345a988386fc84ba6bc95484008f6362f93160ef3e56308";
        let mut node_data = NodeData::<u64>::from_raw_rlp(input_raw_rlp.parse().unwrap()).unwrap();
        node_data.set_value_on_leaf(1).unwrap();
        assert_eq!(
            hex::encode(node_data.to_raw_rlp().unwrap()),
            "e3a120290decd9548b62a8d60345a988386fc84ba6bc95484008f6362f93160ef3e56301" // 8 changed to 1
        );
    }

    #[test]
    pub fn test_node_data_new_extension_node_1() {
        let node_data = NodeData::<u64>::from_raw_rlp(
            "0xe583165a7ba0e46db0426b9d34c7b2df7baf0480777946e6b5b74a0572592b0229a4edaed944"
                .parse()
                .unwrap(),
        )
        .unwrap();

        println!("node_data {:#?}", node_data);

        assert_eq!(
            node_data,
            NodeData::Extension {
                key: Nibbles::from_encoded_path("0x165a7b".parse().unwrap()).unwrap(),
                node: "0xe46db0426b9d34c7b2df7baf0480777946e6b5b74a0572592b0229a4edaed944"
                    .parse()
                    .unwrap(),
            }
        );
    }

    #[test]
    pub fn test_node_data_new_extension_node_2() {
        let input_raw_rlp =
            "e583165a7ba0e46db0426b9d34c7b2df7baf0480777946e6b5b74a0572592b0229a4edaed944";
        let node_data = NodeData::<u64>::from_raw_rlp(input_raw_rlp.parse().unwrap()).unwrap();
        assert_eq!(hex::encode(node_data.to_raw_rlp().unwrap()), input_raw_rlp);
    }

    #[test]
    pub fn test_node_data_new_branch_1() {
        let node_data = NodeData::<u64>::from_raw_rlp(
            "0xf851a0e97150c3ed221a6f46bdcd44e8a2d44825bc781fa48f797e9df2f8ceff52a43e8080808080808080808080a09487c8e7f28469b9f72cd6be094b555c3882c0653f11b208ff76bf8caee5043280808080"
                .parse()
                .unwrap(),
        )
        .unwrap();

        println!("node_data {:#?}", node_data);

        assert_eq!(
            node_data,
            NodeData::Branch([
                Some(
                    "0xe97150c3ed221a6f46bdcd44e8a2d44825bc781fa48f797e9df2f8ceff52a43e"
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
                None,
                None,
                None,
                None,
                Some(
                    "0x9487c8e7f28469b9f72cd6be094b555c3882c0653f11b208ff76bf8caee50432"
                        .parse()
                        .unwrap()
                ),
                None,
                None,
                None,
                None,
            ])
        );
    }

    #[test]
    pub fn test_node_data_new_branch_2() {
        let input_raw_rlp =
            "f851a0e97150c3ed221a6f46bdcd44e8a2d44825bc781fa48f797e9df2f8ceff52a43e8080808080808080808080a09487c8e7f28469b9f72cd6be094b555c3882c0653f11b208ff76bf8caee5043280808080";
        let node_data = NodeData::<u64>::from_raw_rlp(input_raw_rlp.parse().unwrap()).unwrap();
        assert_eq!(hex::encode(node_data.to_raw_rlp().unwrap()), input_raw_rlp);
    }
}
