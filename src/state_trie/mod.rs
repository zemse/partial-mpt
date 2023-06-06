use crate::Error;
use ethers::types::{Address, EIP1186ProofResponse, H256, U256};
use std::collections::HashMap;

mod account_trie;
pub use account_trie::{AccountData, AccountTrie};

mod storage_trie;
pub use storage_trie::StorageTrie;

#[derive(Clone, Debug, PartialEq)]
pub struct StateTrie {
    pub account_trie: AccountTrie,
    storage_tries: HashMap<H256, StorageTrie>,
}

impl StateTrie {
    pub fn new() -> Self {
        StateTrie {
            account_trie: AccountTrie::new(),
            storage_tries: HashMap::new(),
        }
    }

    pub fn from_root(root: H256) -> Self {
        StateTrie {
            account_trie: AccountTrie::from_root(root),
            storage_tries: HashMap::new(),
        }
    }

    pub fn root(&self) -> Option<H256> {
        self.account_trie.root()
    }

    pub fn get_storage_trie(&mut self, storage_root: H256) -> StorageTrie {
        if !self.storage_tries.contains_key(&storage_root) {
            StorageTrie::from_root(storage_root)
        } else {
            self.storage_tries.get(&storage_root).unwrap().to_owned()
        }
    }

    pub fn get_storage_at(&mut self, address: Address, key: U256) -> Result<U256, Error> {
        let account_data = self.account_trie.get(address)?;
        self.get_storage_trie(account_data.storage_root).get(key)
    }

    pub fn set_storage_value(
        &mut self,
        address: Address,
        slot: U256,
        value: U256,
    ) -> Result<(), Error> {
        let mut account_data = self.account_trie.get(address)?;
        let mut storage_trie = self
            .storage_tries
            .remove(&account_data.storage_root)
            .expect("storage trie not present, this should not happen");
        storage_trie.set(slot, value)?;
        account_data.storage_root = storage_trie.root().unwrap();
        self.storage_tries
            .insert(storage_trie.root().unwrap(), storage_trie);
        self.account_trie.set(address, account_data)?;
        Ok(())
    }

    pub fn load_proof(&mut self, proof: EIP1186ProofResponse) -> Result<(), Error> {
        self.account_trie.load_proof(
            proof.address,
            AccountData {
                balance: proof.balance,
                nonce: U256::from(proof.nonce.as_u64()),
                code_hash: proof.code_hash,
                storage_root: proof.storage_hash,
            },
            proof.account_proof,
        )?;

        let mut storage_trie = self.get_storage_trie(proof.storage_hash);
        for proof in proof.storage_proof {
            storage_trie.load_proof(
                U256::from_big_endian(proof.key.as_bytes()),
                proof.value,
                proof.proof,
            )?;
        }
        self.storage_tries.insert(proof.storage_hash, storage_trie);

        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use std::env;
    use std::str::FromStr;

    use super::{EIP1186ProofResponse, StateTrie, U256};
    use ethers::core::utils::hex;
    use ethers::providers::{Middleware, Provider};
    use ethers::types::{BigEndianHash, BlockId, BlockNumber, StorageProof, H256};
    use ethers::utils::keccak256;

    #[test]
    pub fn test_geth_dev_state_1() {
        // a contract was deployed on geth --dev
        // slot[1] = 2
        // slot[2] = 4
        let mut trie = StateTrie::new();

        // contract
        trie.load_proof(EIP1186ProofResponse {
            address: "0x730E01e70B028b44a9387119d78E1392E4848Cbc"
                .parse()
                .unwrap(),
            account_proof: vec![
                "0xf90151a0bfa1a037624f2e96cc598c63c0db6249cb0e507c2015af3e2ecb8b16b58f92b7a0ab8cdb808c8303bb61fb48e276217be9770fa83ecf3f90f2234d558885f5abf1a0d5a5048c1d78dafd61d8181577c08d6cd2b52fde48040a676be755dc69a275db80a01a697e814758281972fcd13bc9707dbcd2f195986b05463d7b78426508445a04a0b5d7a91be5ee273cce27e2ad9a160d2faadd5a6ba518d384019b68728a4f62f4a0c2c799b60a0cd6acd42c1015512872e86c186bcf196e85061e76842f3b7cf86080a02e0d86c3befd177f574a20ac63804532889077e955320c9361cd10b7cc6f580980a06301b39b2ea8a44df8b0356120db64b788e71f52e1d7a6309d0d2e5b86fee7cb8080a01b7779e149cadf24d4ffb77ca7e11314b8db7097e4d70b2a173493153ca2e5a0a066a7662811491b3d352e969506b420d269e8b51a224f574b3b38b3463f43f0098080".parse().unwrap(),
                "0xf869a03a7a2ee9b4f54ecbf2e04737a19215c0864d20c9a332db61d093e9ec95b2e87ab846f8440180a029cf2043d2a8fd3c4ed584f1afd2976a366f90a84446c1bd73e251e097b1748ca02e3b8d783952495f405666042a1ceb57bd6848afbbc1f2aad92bc2b5f8169a16".parse().unwrap(),
            ],
            balance: "0x0".parse().unwrap(),
            code_hash: "0x2e3b8d783952495f405666042a1ceb57bd6848afbbc1f2aad92bc2b5f8169a16"
                .parse()
                .unwrap(),
            nonce: "0x1".parse().unwrap(),
            storage_hash: "0x29cf2043d2a8fd3c4ed584f1afd2976a366f90a84446c1bd73e251e097b1748c"
                .parse()
                .unwrap(),
            storage_proof: vec![
                StorageProof {
                    key: "0x0000000000000000000000000000000000000000000000000000000000000001".parse().unwrap(),
                    value: "0x2".parse().unwrap(),
                    proof: vec![
                        "0xf85180808080a03f39d7bf4be8677b2d7db8f944e618380c443e7615adddd29b4cba751d7acdc5808080808080a0236e8f61ecde6abfebc6c529441f782f62469d8a2cc47b7aace2c136bd3b1ff08080808080".parse().unwrap(),
                        "0xe2a0310e2d527612073b26eecdfd717e6a320cf44b4afac2b0732d9fcbe2b7fa0cf602".parse().unwrap()
                    ],
                },
                StorageProof {
                    key: "0x0000000000000000000000000000000000000000000000000000000000000002".parse().unwrap(),
                    value: "0x4".parse().unwrap(),
                    proof: vec![
                        "0xf85180808080a03f39d7bf4be8677b2d7db8f944e618380c443e7615adddd29b4cba751d7acdc5808080808080a0236e8f61ecde6abfebc6c529441f782f62469d8a2cc47b7aace2c136bd3b1ff08080808080".parse().unwrap(),
                        "0xe2a0305787fa12a823e0f2b7631cc41b3ba8828b3321ca811111fa75cd3aa3bb5ace04".parse().unwrap()
                    ],
                }
            ],
        }).unwrap();

        // tx sender
        trie.load_proof(EIP1186ProofResponse {
            address: "0x3736b9d9d35d8c4f41d98a412fe9211024453575"
                .parse()
                .unwrap(),
            account_proof: vec![
                "0xf90151a0bfa1a037624f2e96cc598c63c0db6249cb0e507c2015af3e2ecb8b16b58f92b7a0ab8cdb808c8303bb61fb48e276217be9770fa83ecf3f90f2234d558885f5abf1a0d5a5048c1d78dafd61d8181577c08d6cd2b52fde48040a676be755dc69a275db80a01a697e814758281972fcd13bc9707dbcd2f195986b05463d7b78426508445a04a0b5d7a91be5ee273cce27e2ad9a160d2faadd5a6ba518d384019b68728a4f62f4a0c2c799b60a0cd6acd42c1015512872e86c186bcf196e85061e76842f3b7cf86080a02e0d86c3befd177f574a20ac63804532889077e955320c9361cd10b7cc6f580980a06301b39b2ea8a44df8b0356120db64b788e71f52e1d7a6309d0d2e5b86fee7cb8080a01b7779e149cadf24d4ffb77ca7e11314b8db7097e4d70b2a173493153ca2e5a0a066a7662811491b3d352e969506b420d269e8b51a224f574b3b38b3463f43f0098080".parse().unwrap(),
                "0xf889a03e19976962fea3751225213669050369b7cd26650bc43815007705e945b5aa57b866f86403a0ffffffffffffffffffffffffffffffffffffffffffffffffffff546059ae3c82a056e81f171bcc55a6ff8345e692c0f86e5b48e01b996cadc001622fb5e363b421a0c5d2460186f7233c927e7db2dcc703c0e500b653ca82273b7bfad8045d85a470".parse().unwrap(),
            ],
            balance: "0xffffffffffffffffffffffffffffffffffffffffffffffffffff546059ae3c82".parse().unwrap(),
            code_hash: "0xc5d2460186f7233c927e7db2dcc703c0e500b653ca82273b7bfad8045d85a470"
                .parse()
                .unwrap(),
            nonce: "0x3".parse().unwrap(),
            storage_hash: "0x56e81f171bcc55a6ff8345e692c0f86e5b48e01b996cadc001622fb5e363b421"
                .parse()
                .unwrap(),
            storage_proof: vec![],
        }).unwrap();

        assert_eq!(
            hex::encode(trie.root().unwrap()),
            "60bfaa2e6e61adcd645ce3aefc05c3bda2ed31f95fdd8bd5422dc2b8c78ae909"
        );

        trie.account_trie
            .set_nonce(
                "0x3736b9d9d35d8c4f41d98a412fe9211024453575"
                    .parse()
                    .unwrap(),
                U256::from(4),
            )
            .unwrap();
        trie.account_trie
            .set_balance(
                "0x3736b9d9d35d8c4f41d98a412fe9211024453575"
                    .parse()
                    .unwrap(),
                "0xffffffffffffffffffffffffffffffffffffffffffffffffffff45eff0fafd74"
                    .parse()
                    .unwrap(),
            )
            .unwrap();
        trie.set_storage_value(
            "0x730E01e70B028b44a9387119d78E1392E4848Cbc"
                .parse()
                .unwrap(),
            "0x1".parse().unwrap(),
            "0x8".parse().unwrap(),
        )
        .unwrap();

        assert_eq!(
            hex::encode(trie.root().unwrap()),
            "bf04d56bcfb758b80412e16f9d84ce369ba87534b4226f0d2d41482a2127e811"
        );
    }

    #[tokio::test]
    #[cfg_attr(not(feature = "test-live"), ignore)]
    pub async fn test_mainnet_block_1000024() {
        // https://etherscan.io/block/1000024
        test_mainnet_block(
            1000024,
            vec![
                ("0xD34DA389374CAAD1A048FBDC4569AAE33fD5a375", vec![]), // miner
                ("0x2a65aca4d5fc5b5c859090a6c34d164135398226", vec![]), // tx1 - sender
                ("0xf27b8f9e16d5b673c0a730f1994e1a588b221620", vec![]), // tx1 - dest
                ("0x45c1392523399c1ce21ead4ecb808606c189fac2", vec![]), // tx2 - sender
                (
                    "0xc7696b27830dd8aa4823a1cba8440c27c36adec4", // tx2 - dest
                    vec![
                        H256::from_uint(&U256::from(8)),
                        H256::from_uint(&U256::from(9)),
                        H256::from_uint(&U256::from(0xa)),
                        H256::from_uint(&U256::from(0xb)),
                    ],
                ),
                ("0x120a270bbc009644e35f0bb6ab13f95b8199c4ad", vec![]), // tx3 - sender
                ("0x640d323222b99f3477339ff1639dcd66a93819fe", vec![]), // tx3 - dest
            ],
        )
        .await;
    }

    #[tokio::test]
    #[cfg_attr(not(feature = "test-live"), ignore)]
    pub async fn test_mainnet_block_2000002() {
        // https://etherscan.io/block/2000002
        test_mainnet_block(
            2000002,
            vec![
                ("0xAdd823F3B2a13fA365f03d8D59ac3f017b15dB02", vec![]), // miner
                ("0xEA674fdDe714fd979de3EdF0F56AA9716B898ec8", vec![]), // tx1 - sender
                ("0xCFc4EC1faA4f91F6E917e9e556320c841DA8588d", vec![]), // tx1 - dest
                ("0xBa562F24005910e25dfaf2A42FeA4C0BF8A2D1c5", vec![]), // tx2 - dest
                ("0xA5cebfe4aCc8d63B3257AC7f33677B987693072a", vec![]), // tx3 - dest
                ("0x8d0e7c2C82970C9d1B7d598Be20F2bA0f13E6537", vec![]), // tx4 - dest
                ("0xE68D2582D54Cd865C8FecD9733525d60BE68af67", vec![]), // tx5 - sender
                (
                    "0xBB9bc244D798123fDe783fCc1C72d3Bb8C189413", // tx5 - dest
                    vec![H256::from_str(
                        "0x26e91fb58c30a80e3b2a8a4e671deffbfb6d0327c8e58a194296183d922ee994",
                    )
                    .unwrap()],
                ),
                ("0x5410C4c59A719EeF345869c204eC8Dcac2dfD718", vec![]), // tx6 - sender
                ("0xa795B4DDBF17570f2c8f5e75a13EF94DB6757F32", vec![]), // tx6 - dest
                ("0x4B8a25120682Dc5a5696D21C6D65f98442C7752F", vec![]), // tx7 - sender
                (
                    "0xb4bfEfC30A60B87380e377F8B96CC3b2E65A8F64", // tx7 - dest
                    vec![H256::from_uint(&U256::from(7))],
                ),
                ("0xe77f55ea0c862c78dd02dcf8828e5046c98ef97c", vec![]), // tx7 - internal
                ("0x5ec0f3f946525abc4cccb433e6fc54df6d55e192", vec![]), // tx7 - internal
                ("0x6bd0F7D1c3b3eB168b9CA96BD7872A41e2D4EEc5", vec![]), // tx8 - sender
                ("0xAA1A6e3e6EF20068f7F8d8C835d2D22fd5116444", vec![]), // tx8 - dest
                ("0x4af482be804f3c925f0b405d871fa53acaa91fbb", vec![]), // tx8 - internal
                ("0x32Be343B94f860124dC4fEe278FDCBD38C102D88", vec![]), // tx9 - sender
                ("0x06c69F734A0240Cb31678412F04EB0CE8F39258b", vec![]), // tx9 - dest
                ("0x147184Ef469cE9Bba3d08aF16F0b6d31CAC35ac8", vec![]), // tx10 - sender
                ("0x695055f1EA55c36EC7E3Bd43D1736511ac8daB61", vec![]), // tx10 - dest
            ],
        )
        .await;
    }

    pub async fn test_mainnet_block(block_number: u64, accounts_touched: Vec<(&str, Vec<H256>)>) {
        let rpc_url = env::var("RPC").expect("pass RPC env var");
        let provider = Provider::try_from(rpc_url).unwrap();

        let prev_block_number = Some(BlockId::Number(BlockNumber::from(block_number - 1)));
        let current_block_number = Some(BlockId::Number(BlockNumber::from(block_number)));

        let prev_block = provider
            .get_block(prev_block_number.unwrap())
            .await
            .unwrap()
            .unwrap();
        let mut state_trie = StateTrie::from_root(prev_block.state_root);

        // download EIP-1186 state proofs.
        for (address, slots) in accounts_touched.clone() {
            let proof = provider
                .get_proof(address, slots, prev_block_number)
                .await
                .unwrap();

            state_trie.load_proof(proof).unwrap();
        }

        // update state on our trie.
        for (address_str, slots) in accounts_touched {
            let address = address_str.parse().unwrap();

            let new_balance = provider
                .get_balance(address, current_block_number)
                .await
                .unwrap();
            let new_nonce = provider
                .get_transaction_count(address, current_block_number)
                .await
                .unwrap();
            let new_code_hash = H256::from(keccak256(
                provider
                    .get_code(address, current_block_number)
                    .await
                    .unwrap(),
            ));

            state_trie
                .account_trie
                .set_balance(address, new_balance)
                .unwrap();
            state_trie
                .account_trie
                .set_nonce(address, new_nonce)
                .unwrap();
            state_trie
                .account_trie
                .set_code_hash(address, new_code_hash)
                .unwrap();

            for slot in slots {
                let value = provider
                    .get_storage_at(address, slot, current_block_number)
                    .await
                    .unwrap();
                let _slot = U256::from_big_endian(slot.as_bytes());
                let _value = U256::from_big_endian(value.as_bytes());
                state_trie
                    .set_storage_value(address, _slot, _value)
                    .unwrap();
            }
        }

        let current_block = provider
            .get_block(current_block_number.unwrap())
            .await
            .unwrap()
            .unwrap();

        let calculated_root = state_trie.root().unwrap();

        assert_eq!(calculated_root, current_block.state_root);
    }
}
