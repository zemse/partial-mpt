# partial merkle patricia trie

helps to calculate new root of a huge trie after changing few nodes without loading the entire trie.

## install

add to `Cargo.toml` file's dependencies section

```toml
[dependencies]
partial-mpt = { git = "https://github.com/zemse/partial-mpt.git" }
```

## usage

```rust
use partial_mpt::StateTrie;

// create a new trie
let mut state_trie = StateTrie::from_root(latest_block.state_root);

// load proofs for keys to change
state_trie.load_proof(provider.get_proof(address, Vec::from([slot]), latest))

// set value for the key, would give error if proof is not loaded already
state_trie.set_storage_value(address, slot, new_value)

// new root
state_trie.root()
```

## examples

- [eth burn](./examples/eth-burn.rs)
- [mainnet block 1000008](./examples/block-1000008.rs)

to run the example, clone this project and `cargo run --example eth-burn`.

## contributing

- to run all tests `cargo test` 
- to run specific tests e.g. `cargo test trie::tests::test_node_data`