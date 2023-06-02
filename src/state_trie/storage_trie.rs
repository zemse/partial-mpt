use crate::{nibbles::Nibbles, nodes::LeafValue, trie::Trie, Error};

use ethers::{
    types::{BigEndianHash, Bytes, H256, U256},
    utils::rlp::{Rlp, RlpStream},
};

#[derive(Debug, Clone, PartialEq)]
pub struct StorageTrie(Trie<U256>);

impl StorageTrie {
    pub fn new() -> Self {
        StorageTrie(Trie::new())
    }

    pub fn from_root(root: H256) -> Self {
        StorageTrie(Trie::from_root(root))
    }

    pub fn set_root(&mut self, root: H256) -> Result<(), Error> {
        self.0.set_root(root)
    }

    pub fn root(&self) -> Option<H256> {
        self.0.root
    }

    pub fn get_value(&self, key: U256) -> Result<U256, Error> {
        let path = Nibbles::from_uint(key)?;
        self.0.get_value(path)
    }

    pub fn set_value(&mut self, key: U256, new_value: U256) -> Result<(), Error> {
        let path = Nibbles::from_uint(key)?;
        self.0.set_value(path, new_value)
    }

    pub fn load_proof(&mut self, key: U256, value: U256, proof: Vec<Bytes>) -> Result<(), Error> {
        let path = Nibbles::from_uint(key)?;
        self.0.load_proof(path, value, proof)
    }
}

impl LeafValue for U256 {
    fn from_raw_rlp(raw: ethers::types::Bytes) -> Result<Self, crate::Error> {
        let rlp = Rlp::new(&raw);
        let bytes = rlp.data()?.to_owned();
        Ok(U256::from_big_endian(bytes.to_vec().as_slice()))
    }

    fn to_raw_rlp(&self) -> Result<ethers::types::Bytes, crate::Error> {
        if self.is_zero() {
            return Ok(Bytes::from(vec![0]));
        }

        let mut vec = H256::from_uint(&self).as_bytes().to_vec();
        loop {
            if vec[0] == 0 {
                vec.remove(0);
            } else {
                break;
            }
        }

        let mut rlp_stream = RlpStream::default();
        rlp_stream.append_raw(vec.as_slice(), 1);
        Ok(Bytes::from(rlp_stream.out().to_vec()))
    }
}
