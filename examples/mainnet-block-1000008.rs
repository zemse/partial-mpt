use ethers::{
    providers::{Middleware, Provider},
    types::{Address, BlockId, BlockNumber, H256},
};
use partial_mpt::StateTrie;

#[tokio::main]
async fn main() {
    let rpc_url = "https://eth-mainnet.g.alchemy.com/v2/bXp-Zt6_5bRUBJd7hSvPN3As6FTtUF4d";
    let provider = Provider::try_from(rpc_url).unwrap();

    let prev_block_number = Some(BlockId::Number(BlockNumber::from(1000007)));
    let current_block_number = Some(BlockId::Number(BlockNumber::from(1000008)));

    let prev_block = provider
        .get_block(prev_block_number.unwrap())
        .await
        .unwrap()
        .unwrap();
    let mut state_trie = StateTrie::from_root(prev_block.state_root);

    // block 1000008 only has one tx where sender sends funds to receiver.
    let sender_address = "0x2a65Aca4D5fC5B5C859090a6c34d164135398226"
        .parse::<Address>()
        .unwrap();
    let receiver_address = "0xb6046a76bD03474b16aD52B1fC581CD5a2465Bd3"
        .parse::<Address>()
        .unwrap();
    let miner_address = "0x68795C4AA09D6f4Ed3E5DeDDf8c2AD3049A601da"
        .parse::<Address>()
        .unwrap();

    // download EIP-1186 state proofs for these three accounts.
    let proof_sender = provider
        .get_proof(sender_address, vec![H256::zero()], prev_block_number)
        .await
        .unwrap();
    let proof_receiver = provider
        .get_proof(receiver_address, vec![H256::zero()], prev_block_number)
        .await
        .unwrap();
    let proof_miner = provider
        .get_proof(miner_address, vec![H256::zero()], prev_block_number)
        .await
        .unwrap();

    state_trie.load_proof(proof_sender).unwrap();
    state_trie.load_proof(proof_receiver).unwrap();
    state_trie.load_proof(proof_miner).unwrap();

    // sender balance decreases, nonce increases.
    // receiver and miner both balance increases.
    let sender_new_balance = provider
        .get_balance(sender_address, current_block_number)
        .await
        .unwrap();
    let sender_new_nonce = provider
        .get_transaction_count(sender_address, current_block_number)
        .await
        .unwrap();
    let receiver_new_balance = provider
        .get_balance(receiver_address, current_block_number)
        .await
        .unwrap();
    let miner_new_balance = provider
        .get_balance(miner_address, current_block_number)
        .await
        .unwrap();

    state_trie
        .account_trie
        .set_balance(sender_address, sender_new_balance)
        .unwrap();
    state_trie
        .account_trie
        .set_nonce(sender_address, sender_new_nonce)
        .unwrap();
    state_trie
        .account_trie
        .set_balance(receiver_address, receiver_new_balance)
        .unwrap();
    state_trie
        .account_trie
        .set_balance(miner_address, miner_new_balance)
        .unwrap();

    // now our trie should have calculated the state root correctly.
    let current_block = provider
        .get_block(current_block_number.unwrap())
        .await
        .unwrap()
        .unwrap();
    assert_eq!(state_trie.root().unwrap(), current_block.state_root);
    println!("state root matched!");
}
