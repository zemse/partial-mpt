use crate::{
    nibbles::Nibbles,
    nodes::LeafValue,
    trie::{MptKey, Trie},
    Error,
};

use bytes::BytesMut;
use ethers::{
    types::{BigEndianHash, Bytes, H256, U256},
    utils::{
        keccak256,
        rlp::{self, Rlp},
    },
};

pub type StorageTrie = Trie<U256, U256>;

impl MptKey for U256 {
    fn to_nibbles(&self) -> Result<Nibbles, Error> {
        Ok(Nibbles::from_raw_path(Bytes::from(
            H256::from(keccak256(Bytes::from(
                H256::from_uint(self).as_bytes().to_vec(),
            )))
            .as_bytes()
            .to_vec(),
        )))
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

        Ok(Bytes::from(
            rlp::encode(&BytesMut::from(vec.as_slice())).to_vec(),
        ))
    }
}

#[cfg(test)]
mod tests {
    use std::str::FromStr;

    use ethers::{
        types::{Bytes, U256},
        utils::hex,
    };

    use crate::{nodes::LeafValue, trie::MptKey};

    #[test]
    pub fn test_from_uint_1() {
        let nibbles = U256::from(0).to_nibbles().unwrap();
        assert_eq!(
            hex::encode(nibbles.to_raw_path()),
            "290decd9548b62a8d60345a988386fc84ba6bc95484008f6362f93160ef3e563"
        );
    }

    #[test]
    pub fn test_from_uint_2() {
        let nibbles = U256::from(2).to_nibbles().unwrap();
        assert_eq!(
            hex::encode(nibbles.to_raw_path()),
            "405787fa12a823e0f2b7631cc41b3ba8828b3321ca811111fa75cd3aa3bb5ace"
        );
    }

    #[test]
    pub fn test_u256_from_raw_rlp() {
        let value = U256::from_raw_rlp(Bytes::from_str("0x8456bfa79d").unwrap()).unwrap();
        let expected = U256::from(0x56bfa79d);
        assert_eq!(value, expected);
    }

    #[test]
    pub fn test_u256_to_raw_rlp() {
        let value = U256::from(0x56bfa79d).to_raw_rlp().unwrap();
        let expected = Bytes::from_str("0x8456bfa79d").unwrap();
        assert_eq!(value, expected);
    }
}
