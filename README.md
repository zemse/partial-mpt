# partial merkle patricia trie

helps to calculate new root of a huge trie after changing few nodes without loading the entire trie.

## usage

```rust
use partial_mpt::StateTrie;

// create a new trie
let mut state_trie = StateTrie::from_root(block.state_root);

// load proofs for keys to change
state_trie.load_proof(provider.get_proof(address, vec![slot], block.num))

// set value for the key, would give error if proof is not loaded already
state_trie.set_storage_value(address, slot, new_value)

// new root
state_trie.root()
```

## examples

- [eth burn](./examples/eth-burn.rs)
- [mainnet block](./examples/mainnet-block-1000008.rs)

to run the example, clone this project and `cargo run --example eth-burn`.

## tests

- to run local tests use `cargo test` 
- to run specific tests e.g. `cargo test trie::tests::test_node_data`
- to run all tests including [live mainnet block tests](./src/state_trie/mod.rs#209) use `RPC="https://eth-mainnet.url" cargo test --features test-live`

## rationale

mainnet fork clients do not calculate state root since it's hardly required in smart contract development. but in a recent [hackathon](https://github.com/zemse/zk-proof-of-evm-challenge), i had to write a chunk of this code in a hurry. just seperating it out for convenience along with some bug fixes and more tests.

## license

MIT