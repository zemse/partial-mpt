use crate::Error;
use ethers::types::{Address, EIP1186ProofResponse, H256, U256};
use std::collections::HashMap;

mod account_trie;
pub use account_trie::{AccountData, AccountTrie};

mod storage_trie;
pub use storage_trie::StorageTrie;

#[derive(Clone, Debug, Default, PartialEq)]
pub struct StateTrie {
    pub account_trie: AccountTrie,
    storage_tries: HashMap<H256, StorageTrie>,
}

impl StateTrie {
    pub fn from_root(root: H256) -> Self {
        StateTrie {
            account_trie: AccountTrie::from_root(root),
            storage_tries: HashMap::default(),
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
    use ethers::types::{Address, BigEndianHash, BlockId, BlockNumber, StorageProof, H256};
    use ethers::utils::keccak256;

    #[test]
    pub fn test_geth_dev_state_1() {
        // a contract was deployed on geth --dev
        // slot[1] = 2
        // slot[2] = 4
        let mut trie = StateTrie::default();

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
                // ("0xD34DA389374CAAD1A048FBDC4569AAE33fD5a375", vec![]), // miner
                // ("0x2a65aca4d5fc5b5c859090a6c34d164135398226", vec![]), // tx1 - sender
                // ("0xf27b8f9e16d5b673c0a730f1994e1a588b221620", vec![]), // tx1 - dest
                // ("0x45c1392523399c1ce21ead4ecb808606c189fac2", vec![]), // tx2 - sender
                (
                    "0xc7696b27830dd8aa4823a1cba8440c27c36adec4", // tx2 - dest
                    vec![
                        H256::from_uint(&U256::from(8)),
                        H256::from_uint(&U256::from(9)),
                        H256::from_uint(&U256::from(0xa)),
                        H256::from_uint(&U256::from(0xb)),
                    ],
                ),
                // ("0x120a270bbc009644e35f0bb6ab13f95b8199c4ad", vec![]), // tx3 - sender
                // ("0x640d323222b99f3477339ff1639dcd66a93819fe", vec![]), // tx3 - dest
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
                // ("0xAdd823F3B2a13fA365f03d8D59ac3f017b15dB02", vec![]), // miner
                // ("0xEA674fdDe714fd979de3EdF0F56AA9716B898ec8", vec![]), // tx1 - sender
                // ("0xCFc4EC1faA4f91F6E917e9e556320c841DA8588d", vec![]), // tx1 - dest
                // ("0xBa562F24005910e25dfaf2A42FeA4C0BF8A2D1c5", vec![]), // tx2 - dest
                // ("0xA5cebfe4aCc8d63B3257AC7f33677B987693072a", vec![]), // tx3 - dest
                // ("0x8d0e7c2C82970C9d1B7d598Be20F2bA0f13E6537", vec![]), // tx4 - dest
                // ("0xE68D2582D54Cd865C8FecD9733525d60BE68af67", vec![]), // tx5 - sender
                (
                    "0xBB9bc244D798123fDe783fCc1C72d3Bb8C189413", // tx5 - dest
                    vec![H256::from_str(
                        "0x26e91fb58c30a80e3b2a8a4e671deffbfb6d0327c8e58a194296183d922ee994",
                    )
                    .unwrap()],
                ),
                // ("0x5410C4c59A719EeF345869c204eC8Dcac2dfD718", vec![]), // tx6 - sender
                // ("0xa795B4DDBF17570f2c8f5e75a13EF94DB6757F32", vec![]), // tx6 - dest
                // ("0x4B8a25120682Dc5a5696D21C6D65f98442C7752F", vec![]), // tx7 - sender
                (
                    "0xb4bfEfC30A60B87380e377F8B96CC3b2E65A8F64", // tx7 - dest
                    vec![H256::from_uint(&U256::from(7))],
                ),
                // ("0x6bd0F7D1c3b3eB168b9CA96BD7872A41e2D4EEc5", vec![]), // tx8 - sender
                // ("0xAA1A6e3e6EF20068f7F8d8C835d2D22fd5116444", vec![]), // tx8 - dest
                // ("0x32Be343B94f860124dC4fEe278FDCBD38C102D88", vec![]), // tx9 - sender
                // ("0x06c69F734A0240Cb31678412F04EB0CE8F39258b", vec![]), // tx9 - dest
                // ("0x147184Ef469cE9Bba3d08aF16F0b6d31CAC35ac8", vec![]), // tx10 - sender
                // ("0x695055f1EA55c36EC7E3Bd43D1736511ac8daB61", vec![]), // tx10 - dest
                ("0xe77f55ea0c862c78dd02dcf8828e5046c98ef97c", vec![]), // tx7 - internal
                ("0x5ec0f3f946525abc4cccb433e6fc54df6d55e192", vec![]), // tx7 - internal
                ("0x4af482be804f3c925f0b405d871fa53acaa91fbb", vec![]), // tx8 - internal
            ],
        )
        .await;
    }

    #[tokio::test]
    #[cfg_attr(not(feature = "test-live"), ignore)]
    pub async fn test_mainnet_block_17000187() {
        // https://etherscan.io/block/17000187
        test_mainnet_block(
            17000187,
            // only include internal tx addresses, and slots changed
            vec![
                // generated with help of etherscan-scrapper state diff tool
                (
                    "0x223c067f8cf28ae173ee5cafea60ca44c335fecb",
                    vec![
                        h256("0x4ed5cc1799140f8970f6cb1e2b26eb6f4bcb5d9f47b28a05c7b53990726b6316"),
                        h256("0x559b56bd34a05a78c8e05fb25a99f5bfdb4d0187b8312c1f13c4a43bffc44a1c"),
                        h256("0x67f6511307d36032b2e9898c6cfc32bd1d44c3678188fab0a274788aadcd4ea9"),
                        h256("0x741c3ce27b9496848ce3d746dfbb350a81bf84761afd1c73e2e336b4761531f8"),
                        h256("0x8381f7ae1ed45cef1a1f91a1147448f95d1b9754b5deab7fefc519f0204a231a"),
                        h256("0x8a0a9473d29e8c7b8736e7fa14a1b564ab279b85070147afa03510d5e3876718"),
                        h256("0xa829c1a2c447151400e2f59ea5cd3bb2c721284d710ba9ae38d33f79262766f5"),
                        h256("0xd5a64edbcdbf33ad317d05930f46688f52e3894c119dcb77a171fe0e2b828645"),
                        h256("0xd8868749a549cdf3dd788aa13f8ba78de70fbfe32b778b11fe6231b1a7b2afeb"),
                        h256("0xebfe13cda419e512112a28e25b50d0851d30747991323298d2d973c8ca707299"),
                    ],
                ),
                ("0xd2fef1b7430f09248199c050d6ef88438db3412b", vec![]),
                (
                    "0xdefa4e8a7bcba345f687a2f1456f5edd9ce97202",
                    vec![
                        h256("0x8e7bd20143abadbb1c5cafefe7d7c5d642fa57fb71a0e6bf4857fa892ace0cb2"),
                        h256("0xb4ee76afbe01a813128bda1bb169a7b1775426a16cebc5ca2756ef072f0c130d"),
                    ],
                ),
                (
                    "0x000000000000ad05ccc4f10045630fb830b95127",
                    vec![
                        h256("0x05873c04107d9a1c355ffcc1d65c20deccc12d1155f84ec452aa707c1e31c485"),
                        h256("0x581bd4b3c52be7d5b894791147ff5c91f9aaaf494a5f209885c25b77e81a065c"),
                        h256("0x765107b61378a6b71d38aa9b8dc45546c56ef73a6e876380fb6990e895289e79"),
                        h256("0x7d2d28222eb638fdf3d65cce8281eba6c28276742ceedeed5d4b2928cd59f7ff"),
                        h256("0x88660ca3dd80a41d8e83eeef12df1cf1f509718c1427d560b3e62e88ce061b79"),
                        h256("0x955ba99f920729174d6e0f5f8b9e60dccb11adfab0d8c7162786c4e4f36563b9"),
                        h256("0xac6ed68286b1e05cd2ebb5852b3baecc2ff853fee497fdb5adb207a4170bfdc1"),
                        h256("0xb4982e75182d708ae9d930cba208cb7890a7babe25bfebca9c0964898103d2ec"),
                        h256("0xe2aed8ef98b607bcdaabf99019b01f8edc4b94dcf0633b67de60b6e960cbde49"),
                        h256("0xf0c35f9df9da887a10383fb2fc9c8627b7252bc0765d56d9f68c86e692b356d3"),
                        h256("0xf1eeeff8b324f435b3fdf264b4d206e53eb67eb2d18085b09fa0c95700a3bfb1"),
                        h256("0xfbb3e5ac86e9cbde1ce472bb799f41bb0b3fc776285db1294d61ad10ff83ca36"),
                    ],
                ),
                ("0xa9c501101c7b165090abb56e95efe1129df9deac", vec![]),
                ("0xc74d7f6557a37086819f8757394bab8339175644", vec![]),
                (
                    "0xf8209a55a4579207610a9ecd080bf3b8899d0e69",
                    vec![
                        h256("0x0f855abb425e56be71ca5f41ba64693017288350b1dc51c9488e7932362f0f31"),
                        h256("0x1d8b3b4cd580c40fcee564e25b0de53511f67b52afc8a5ca6e9796aa6907fd70"),
                        h256("0x2866278dff3c88097dcbaf36d12715e5f4d5cd309777287eaa27ec795fde677e"),
                        h256("0x47153833bf554111cd1f0d6f19f5b928adcdeb05b059132c111d0277125c53ae"),
                        h256("0x4a973af77728ddab7b48612b67c1d115fa20f766287e9ad5d7c2f118b1870bdc"),
                        h256("0x85cd0176aac07ae7d728794d55969ce1ef7e66877ed0b03b95ad2ae41aae6824"),
                        h256("0x9cd2d01ded64acdd811a7584d4b7ec2fe309e0f0eda2f72dcf8cfd717574523d"),
                        h256("0xb87ce1a1a088fefe63e85d2e1e5a87753c4a2b1424952dd26eeee91cca58002a"),
                        h256("0xcce71f475fe43afd6414efed2a3597909dec86bf719157e83f3eb7fb08a4ee2e"),
                        h256("0xf3d95b9636fd2337d434d540524d2d32c84eaae6f688d567a2d12196c7614ecb"),
                    ],
                ),
                ("0xfaf3d9f29eb3c452a5f55333eb30a71e05ca0d7b", vec![]),
                (
                    "0x32400084c286cf3e17e7b677ea9583e60a000324",
                    vec![
                        h256("0x0000000000000000000000000000000000000000000000000000000000000011"),
                        h256("0x302f86ca25b61bbb68b67dee865a898a25a7808a3a42f509abb2c40b151d18a6"),
                        h256("0x302f86ca25b61bbb68b67dee865a898a25a7808a3a42f509abb2c40b151d18a7"),
                    ],
                ),
                (
                    "0x7b12d855445073987d45ea97b1af3554f05e4ef4",
                    vec![
                        h256("0x0000000000000000000000000000000000000000000000000000000000000000"),
                        h256("0x0000000000000000000000000000000000000000000000000000000000000001"),
                        h256("0x0000000000000000000000000000000000000000000000000000000000000004"),
                        h256("0x000000000000000000000000000000000000000000000000000000000000003d"),
                        h256("0x7f110f67a16c8a756ff06ae3a45a7a031dee65b9b3aa77480c6741f08a15ed4f"),
                        h256("0x7f110f67a16c8a756ff06ae3a45a7a031dee65b9b3aa77480c6741f08a15ed50"),
                        h256("0x7f110f67a16c8a756ff06ae3a45a7a031dee65b9b3aa77480c6741f08a15ed51"),
                    ],
                ),
                (
                    "0x8355dbe8b0e275abad27eb843f3eaf3fc855e525",
                    vec![
                        h256("0x4edbdc8504b37c6703b007021f1c680218a1eb68f35811ab755c23663f2d286b"),
                        h256("0xa4b963403dffa17904235058edbfb3145b04ee6aaafceb0cf39390abba810d16"),
                        h256("0xa968518babf3e68e7ce381ad2c64a5d6e04f917fa359e30e71f4634d8e9a3e0d"),
                    ],
                ),
                (
                    "0xc02aaa39b223fe8d0a0e5c4f27ead9083c756cc2",
                    vec![
                        h256("0x865a6a6392c535c7918948bd344e26e4ea1c6dd78a498b858e48ac288c232e6d"),
                        h256("0xf88e7b8bfd936f5fe4e26ed7fba8916753e028879b7aeafe0a3f899f75b619d1"),
                        h256("0x7601405ddb1e286b59c5ecf315554572c02d24fcac647c3f4771d43a3b18d3c7"),
                        h256("0xf88e7b8bfd936f5fe4e26ed7fba8916753e028879b7aeafe0a3f899f75b619d1"),
                    ],
                ),
                (
                    "0x34bff2dbf20cf39db042cb68d42d6d06fdbd85d3",
                    vec![
                        h256("0x0000000000000000000000000000000000000000000000000000000000000000"),
                        h256("0x63e0bd48312faa8e0a7e4d671ca876d828603bb8f9737bb4ea121f262d95c5d8"),
                        h256("0xb3a417db84a0c1ea9f7fb81726fd220d585e052c64ae94980a282e770cc3591a"),
                    ],
                ),
                (
                    "0xb846f231b102f98e727d2b9403822025f53a16c9",
                    vec![
                        h256("0x0b7b9bb96073fee0e0e0ff8cf9cd791f1869eb1f1fd64f6e0e23a446cf4cb94a"),
                        h256("0xf4c3ac6f6addda300b3fa09a902ac6f69ede11ccdd54f35269c76d7809f972fa"),
                        h256("0x0b7b9bb96073fee0e0e0ff8cf9cd791f1869eb1f1fd64f6e0e23a446cf4cb94a"),
                        h256("0xe89ad6fcb24dd33070a4f3b3f19fcedcf0ae43b3578e4a8afda85e0ad96f3a8e"),
                    ],
                ),
                (
                    "0xcda3d331eee54e5b2224270e40f24d96abd469d0",
                    vec![
                        h256("0x0000000000000000000000000000000000000000000000000000000000000008"),
                        h256("0x0000000000000000000000000000000000000000000000000000000000000009"),
                        h256("0x000000000000000000000000000000000000000000000000000000000000000a"),
                        h256("0x0000000000000000000000000000000000000000000000000000000000000008"),
                    ],
                ),
                (
                    "0x34b6f33a5d88fca1b8f78a510bc81673611a68f0",
                    vec![
                        h256("0x777c769dc952b1c37981a3295de630891614b5d3b68be3496e0436ccb4a2b72f"),
                        h256("0xad48816186e86821c4acbba1997d893141d45ec5ee1db2731bd4b4d1dde5cb12"),
                        h256("0xe536cd49fce012151cdde3d9afc024d885695ef64673b9874adf011c76214865"),
                        h256("0x0000000000000000000000000000000000000000000000000000000000000008"),
                        h256("0x0000000000000000000000000000000000000000000000000000000000000009"),
                        h256("0x000000000000000000000000000000000000000000000000000000000000000a"),
                    ],
                ),
                (
                    "0xd098e127664e069a9d23fbd7260c350d5fe4b762",
                    vec![
                        h256("0x0000000000000000000000000000000000000000000000000000000000000002"),
                        h256("0x777c769dc952b1c37981a3295de630891614b5d3b68be3496e0436ccb4a2b72f"),
                        h256("0xde9a891e34e7a23fc0a635179096ff893d75af517f9656744b23d09615649ac5"),
                    ],
                ),
                (
                    "0x0fe0ed7f146cb12e4b9759aff4fa8d34571802ca",
                    vec![
                        h256("0x2d39f701dd19906860d2244928568bb36c7bc2de5ff4539715f11d5c633b7bbf"),
                        h256("0x129083dd67f8dd2cb530539087ee1554f5b559ab4d285fc8d8c3b2c684671ce6"),
                        h256("0x7601405ddb1e286b59c5ecf315554572c02d24fcac647c3f4771d43a3b18d3c7"),
                    ],
                ),
                (
                    "0x86ac86af1fd9a2cb586a19e325be5d68439a6f31",
                    vec![
                        h256("0x0000000000000000000000000000000000000000000000000000000000000000"),
                        h256("0x0211af8eab958379d8d05707843dfacf56049244e26c2f4f151affa0fffac006"),
                        h256("0x152e6b9a3615cd112cb841c8ccb9eda76ba2e6c5384b74024e278d344defa0dc"),
                        h256("0x0000000000000000000000000000000000000000000000000000000000000000"),
                        h256("0x2bc459b44bf35451fea5aa6500dd6d4b12e1461acffc64d20bb15bbaa5353d41"),
                        h256("0x98ea38872026529b4b56a83df4b50e8143da79063584859223c7308ac5232d3a"),
                    ],
                ),
                (
                    "0x162fcc2f28a5578983db2f92a2c49ce017929253",
                    vec![
                        h256("0x0000000000000000000000000000000000000000000000000000000000000065"),
                        h256("0x000000000000000000000000000000000000000000000000000000000000006c"),
                        h256("0x32fc32e8e6a367a782c09a02fa01aab4c63a2b183ce5fee9b74a77503c0667c7"),
                    ],
                ),
                (
                    "0xe7d3982e214f9dfd53d23a7f72851a7044072250",
                    vec![
                        h256("0x47c0af10abef115aa6d20afe6445384b4c0b5191d6a10c5f3bdefc5746497c30"),
                        h256("0x73ebe2e83b2db87beceedf6a6e9b809f1393403496b4b6e52e26f15059a7f02c"),
                        h256("0x73ebe2e83b2db87beceedf6a6e9b809f1393403496b4b6e52e26f15059a7f02e"),
                        h256("0x73ebe2e83b2db87beceedf6a6e9b809f1393403496b4b6e52e26f15059a7f02f"),
                        h256("0x73ebe2e83b2db87beceedf6a6e9b809f1393403496b4b6e52e26f15059a7f030"),
                        h256("0x73ebe2e83b2db87beceedf6a6e9b809f1393403496b4b6e52e26f15059a7f031"),
                        h256("0x8ca5112eed2c6ac8cf9072253f1c272d0a234f7b0d784544d3e6342af28208fe"),
                        h256("0x8ca5112eed2c6ac8cf9072253f1c272d0a234f7b0d784544d3e6342af28208ff"),
                    ],
                ),
                (
                    "0x11a2e73bada26f184e3d508186085c72217dc014",
                    vec![h256(
                        "0x0000000000000000000000000000000000000000000000000000000000000001",
                    )],
                ),
                ("0xda98fff5bb4f3f12af1181ada590b511ef5ef7a2", vec![]),
            ],
        )
        .await;
    }

    fn h256(str: &str) -> H256 {
        H256::from_str(str).unwrap()
    }

    pub async fn test_mainnet_block(block_number: u64, account_slots: Vec<(&str, Vec<H256>)>) {
        let rpc_url = env::var("RPC").expect("pass RPC env var");
        let provider = Provider::try_from(rpc_url).unwrap();

        let prev_block_number = Some(BlockId::Number(BlockNumber::from(block_number - 1)));
        let current_block_number = Some(BlockId::Number(BlockNumber::from(block_number)));

        let prev_block = provider
            .get_block(prev_block_number.unwrap())
            .await
            .unwrap()
            .unwrap();
        let current_block = provider
            .get_block_with_txs(current_block_number.unwrap())
            .await
            .unwrap()
            .unwrap();

        let mut state_trie = StateTrie::from_root(prev_block.state_root);

        // pick addresses which might have their state changed from block data
        let mut account_slots_parsed: Vec<(Address, Vec<H256>)> = account_slots
            .clone()
            .iter()
            .map(|(addr, slots)| (addr.parse::<Address>().unwrap(), slots.clone()))
            .collect();
        account_slots_parsed.push((current_block.author.unwrap(), vec![]));
        for tx in current_block.transactions {
            account_slots_parsed.push((tx.from, vec![]));
            if tx.to.is_some() {
                account_slots_parsed.push((tx.to.unwrap(), vec![]));
            } else {
                let contract_address = ethers::utils::get_contract_address(tx.from, tx.nonce);
                account_slots_parsed.push((contract_address, vec![]));
            }
        }

        // download EIP-1186 state proofs for addresses and slots
        for (address, slots) in account_slots_parsed.clone() {
            let proof = provider
                .get_proof(address, slots, prev_block_number)
                .await
                .unwrap();

            state_trie.load_proof(proof).unwrap();
        }

        // update state on our trie.
        for (address, slots) in account_slots_parsed {
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

        let calculated_root = state_trie.root().unwrap();
        assert_eq!(calculated_root, current_block.state_root);
    }
}
