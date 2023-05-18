use ethers::{
    providers::{Middleware, Provider},
    types::{Address, BlockId, BlockNumber, H256, U256},
};
use partial_mpt::StateTrie;

#[tokio::main]
async fn main() {
    // gm, u know how the ethereum's state root would look like if all ETH on zero address is burnt?!
    //
    // if this api key doesn't work pls use your own
    let rpc_url = "https://eth-mainnet.g.alchemy.com/v2/bXp-Zt6_5bRUBJd7hSvPN3As6FTtUF4d";
    let provider = Provider::try_from(rpc_url).unwrap();
    let latest = BlockId::Number(BlockNumber::Latest);
    let latest_block = provider.get_block(latest).await.unwrap().unwrap();

    // lets create a partial state trie starting from the latest block's state root
    let mut state_trie = StateTrie::from_root(latest_block.state_root);

    // download EIP-1186 state proof for 0x0000000000000000000000000000000000000000.
    state_trie
        .load_proof(
            provider
                .get_proof(Address::zero(), vec![H256::zero()], Some(latest))
                .await
                .unwrap(),
        )
        .unwrap();

    println!("state root current: {:?}", state_trie.root());

    // yay eth burn!
    state_trie
        .account_trie
        .set_balance(Address::zero(), U256::from(0))
        .unwrap();

    println!("state root after burn: {:?}", state_trie.root());
}
