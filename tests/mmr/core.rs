use std::sync::Arc;

use accumulators::{
    hasher::{
        keccak::KeccakHasher, stark_pedersen::StarkPedersenHasher,
        stark_poseidon::StarkPoseidonHasher, Hasher,
    },
    mmr::{map_leaf_index_to_element_index, AppendResult, PeaksOptions, Proof, ProofOptions, MMR},
    store::{memory::InMemoryStore, sqlite::SQLiteStore, SubKey},
};

const LEAVES: [&str; 5] = ["1", "2", "3", "4", "5"];
async fn setup() -> (
    (MMR, Vec<AppendResult>),
    (MMR, Vec<AppendResult>),
    (MMR, Vec<AppendResult>),
) {
    let store = InMemoryStore::default();
    let poseidon_hasher = Arc::new(StarkPoseidonHasher::new(Some(false)));
    let keccak_hasher = Arc::new(KeccakHasher::new());
    let pedersen_hasher = Arc::new(StarkPedersenHasher::new());
    let mut append_result_pedersen: Vec<AppendResult> = vec![];
    let mut append_result_keccak: Vec<AppendResult> = vec![];
    let mut append_result_poseidon: Vec<AppendResult> = vec![];

    let store = Arc::new(store);

    let mut poseidon_mmr = MMR::new(store.clone(), poseidon_hasher.clone(), None);
    let mut keccak_mmr = MMR::new(store.clone(), keccak_hasher.clone(), None);
    let mut pedersen_mmr = MMR::new(store.clone(), pedersen_hasher.clone(), None);

    for leaf in LEAVES {
        append_result_poseidon.push(poseidon_mmr.append(leaf.to_string()).await.unwrap());
        append_result_keccak.push(keccak_mmr.append(leaf.to_string()).await.unwrap());
        append_result_pedersen.push(pedersen_mmr.append(leaf.to_string()).await.unwrap());
    }

    (
        (poseidon_mmr, append_result_poseidon),
        (keccak_mmr, append_result_keccak),
        (pedersen_mmr, append_result_pedersen),
    )
}
//================================================================================================
// Tests for rewind
//================================================================================================

#[tokio::test]
async fn test_rewind_scenario() {
    // 1) Set up an MMR with 5 initial leaves (the default in `LEAVES`)
    let (mut mmr, appended_results) = setup().await.0;
    // n = 5 leaves
    let n = appended_results.len();
    let leaf_index = n - 1;

    // 2) Grab the element index + value for the last leaf
    let last_leaf_result = appended_results.last().unwrap();
    let last_leaf_index = last_leaf_result.element_index;
    // The leaf value is "5" from the global `LEAVES` array
    let last_leaf_value = LEAVES[LEAVES.len() - 1];

    // 3) Get a proof for the last leaf
    let original_proof = mmr
        .get_proof(last_leaf_index, None)
        .await
        .expect("Failed to get proof for last leaf");

    println!(
        "pre addition elements & leaves count: {} {}",
        mmr.elements_count.get().await.unwrap(),
        mmr.leaves_count.get().await.unwrap()
    );

    let new_leaf_count = 3;

    // 4) Append b=3 new leaves
    for i in 0..new_leaf_count {
        mmr.append(format!("new_leaf_{}", i))
            .await
            .expect("Failed to append new leaf");
    }

    println!(
        "post addition elements & leaves count: {} {}",
        mmr.elements_count.get().await.unwrap(),
        mmr.leaves_count.get().await.unwrap()
    );

    // 5) Rewind back to when there were n=5 leaves
    let pruned_leaf_indices = mmr
        .rewind(leaf_index)
        .await
        .expect("Failed to rewind to original size");

    assert_eq!(pruned_leaf_indices.len(), new_leaf_count);

    println!("rewind complete");
    println!(
        "post rewind elements & leaves count: {} {}",
        mmr.elements_count.get().await.unwrap(),
        mmr.leaves_count.get().await.unwrap()
    );

    // 6) Get that same proof again (for the same leaf index)
    let rewound_proof = mmr
        .get_proof(last_leaf_index, None)
        .await
        .expect("Failed to get proof after rewinding");

    // 7) Confirm the proof *before* and *after* rewinding are the same
    assert_eq!(original_proof, rewound_proof);

    // 8) Verify the rewound proof is still valid
    assert!(mmr
        .verify_proof(rewound_proof, last_leaf_value.to_string(), None)
        .await
        .expect("Failed to verify rewound proof"));
}

#[tokio::test]
async fn test_rewind_mid_leaf() {
    // 1) Set up an MMR with 5 initial leaves
    let (mut mmr, appended_results) = setup().await.0; // Poseidon again
                                                       // n = 5
    let n = appended_results.len();

    // 2) Pick a *middle* leaf, e.g. the 3rd leaf
    //    appended_results are in insertion order, so index=2 is the 3rd leaf.
    let mid_leaf_result = &appended_results[2];
    let mid_leaf_index = mid_leaf_result.element_index;
    let mid_leaf_value = LEAVES[2]; // "3"

    // 3) Get a proof for that middle leaf
    let original_proof = mmr
        .get_proof(mid_leaf_index, None)
        .await
        .expect("Failed to get proof for mid leaf");

    // 4) Append b=3 new leaves
    for i in 0..3 {
        mmr.append(format!("middle_rewind_leaf_{}", i))
            .await
            .expect("Failed to append new leaf");
    }

    // 5) Rewind back to n=5
    mmr.rewind(n - 1)
        .await
        .expect("Failed to rewind to original size");

    // 6) Get the same leaf's proof again
    let rewound_proof = mmr
        .get_proof(mid_leaf_index, None)
        .await
        .expect("Failed to get proof after rewinding");

    // 7) Confirm they match
    assert_eq!(original_proof, rewound_proof);

    // 8) Verify that proof is still valid
    assert!(mmr
        .verify_proof(rewound_proof, mid_leaf_value.to_string(), None)
        .await
        .expect("Failed to verify rewound proof for mid leaf"));
}

#[tokio::test]
async fn test_simulated_proof_generation() {
    // this test should setup an MMR with n leaves, then create a proof for the nth leaf, then add `b` new leaves, then call the get_proof function with the nth leaf's element index and with the element count as `n` as it was originally generated, then verify these proofs are the same and valid
    let (mmr, append_result) = setup().await.0;
    let mut mmr = mmr;
    let n = append_result.len();
    let b = 5;
    let proof = mmr.get_proof(n, None).await.unwrap();
    mmr.append("6".to_string()).await.unwrap();
    let proof_post_add = mmr
        .get_proof(
            n,
            Some(ProofOptions {
                elements_count: Some(map_leaf_index_to_element_index(n - 1)),
                formatting_opts: None,
            }),
        )
        .await
        .unwrap();
    assert_eq!(proof, proof_post_add);
}

#[tokio::test]
async fn test_noop_rewind() {
    // 1) Set up an MMR with 5 initial leaves
    let (mut mmr, appended_results) = setup().await.0;
    let n = appended_results.len();
    let leaf_index = n - 1;

    // Get the current state
    let original_elements_count = mmr.elements_count.get().await.unwrap();
    let original_leaves_count = mmr.leaves_count.get().await.unwrap();
    let original_root = mmr.bag_the_peaks(None).await.unwrap();

    // 2) Rewind to current leaf index (should be a no-op)
    mmr.rewind(leaf_index)
        .await
        .expect("Failed to perform no-op rewind");

    // 3) Verify nothing changed
    assert_eq!(
        mmr.elements_count.get().await.unwrap(),
        original_elements_count,
        "Elements count should not change after no-op rewind"
    );
    assert_eq!(
        mmr.leaves_count.get().await.unwrap(),
        original_leaves_count,
        "Leaves count should not change after no-op rewind"
    );
    assert_eq!(
        mmr.bag_the_peaks(None).await.unwrap(),
        original_root,
        "Root hash should not change after no-op rewind"
    );
}

//================================================================================================
// Tests for append
//================================================================================================

#[tokio::test]
async fn should_compute_parent_tree_for_pedersen_hasher() {
    let pedersen_init = setup().await.2;

    let last_leaf_element_index = pedersen_init.1.last().unwrap().element_index;
    let appended_leaf = "6".to_string();

    let hasher = Arc::new(StarkPedersenHasher::new());
    let node3 = hasher
        .hash(vec![LEAVES[0].to_string(), LEAVES[1].to_string()])
        .unwrap();
    let node6 = hasher
        .hash(vec![LEAVES[2].to_string(), LEAVES[3].to_string()])
        .unwrap();
    let node7 = hasher.hash(vec![node3, node6]).unwrap();
    let node10 = hasher
        .hash(vec![LEAVES[4].to_string(), appended_leaf.clone()])
        .unwrap();
    let bag = hasher.hash(vec![node7.clone(), node10.clone()]).unwrap();
    let root = hasher.hash(vec!["10".to_string(), bag.clone()]).unwrap();
    let mut pedersen_mmr = pedersen_init.0;

    assert_eq!(
        pedersen_mmr.append(appended_leaf).await.unwrap(),
        AppendResult {
            element_index: 9,
            leaves_count: 6,
            elements_count: 10,
            root_hash: root,
        }
    );
    assert_eq!(
        pedersen_mmr
            .get_peaks(PeaksOptions {
                elements_count: None,
                formatting_opts: None,
            })
            .await
            .unwrap(),
        vec![node7, node10]
    );
    assert_eq!(pedersen_mmr.bag_the_peaks(None).await.unwrap(), bag);
    let proof = pedersen_mmr
        .get_proof(last_leaf_element_index, None)
        .await
        .unwrap();
    assert!(pedersen_mmr
        .verify_proof(proof, LEAVES[LEAVES.len() - 1].to_string(), None)
        .await
        .unwrap())
}

#[tokio::test]
async fn should_compute_parent_tree_for_poseidon_hasher() {
    let poseidon_init = setup().await.0;

    let last_leaf_element_index = poseidon_init.1.last().unwrap().element_index;
    let appended_leaf = "6".to_string();

    let hasher = Arc::new(StarkPoseidonHasher::new(None));
    let node3 = hasher
        .hash(vec![LEAVES[0].to_string(), LEAVES[1].to_string()])
        .unwrap();
    let node6 = hasher
        .hash(vec![LEAVES[2].to_string(), LEAVES[3].to_string()])
        .unwrap();
    let node7 = hasher.hash(vec![node3, node6]).unwrap();
    let node10 = hasher
        .hash(vec![LEAVES[4].to_string(), appended_leaf.clone()])
        .unwrap();
    let bag = hasher.hash(vec![node7.clone(), node10.clone()]).unwrap();
    let root = hasher.hash(vec!["10".to_string(), bag.clone()]).unwrap();
    let mut poseidon_mmr = poseidon_init.0;

    assert_eq!(
        poseidon_mmr.append(appended_leaf).await.unwrap(),
        AppendResult {
            element_index: 9,
            leaves_count: 6,
            elements_count: 10,
            root_hash: root,
        }
    );
    assert_eq!(
        poseidon_mmr
            .get_peaks(PeaksOptions {
                elements_count: None,
                formatting_opts: None,
            })
            .await
            .unwrap(),
        vec![node7, node10]
    );
    assert_eq!(poseidon_mmr.bag_the_peaks(None).await.unwrap(), bag);
    let proof = poseidon_mmr
        .get_proof(last_leaf_element_index, None)
        .await
        .unwrap();
    assert!(poseidon_mmr
        .verify_proof(proof, LEAVES[LEAVES.len() - 1].to_string(), None)
        .await
        .unwrap())
}

#[tokio::test]
async fn should_compute_parent_tree_for_keccak_hasher() {
    let keccak_init = setup().await.1;

    let last_leaf_element_index = keccak_init.1.last().unwrap().element_index;
    let appended_leaf = "6".to_string();

    let hasher = Arc::new(KeccakHasher::new());
    let node3 = hasher
        .hash(vec![LEAVES[0].to_string(), LEAVES[1].to_string()])
        .unwrap();
    let node6 = hasher
        .hash(vec![LEAVES[2].to_string(), LEAVES[3].to_string()])
        .unwrap();
    let node7 = hasher.hash(vec![node3, node6]).unwrap();
    let node10 = hasher
        .hash(vec![LEAVES[4].to_string(), appended_leaf.clone()])
        .unwrap();
    let bag = hasher.hash(vec![node7.clone(), node10.clone()]).unwrap();
    let root = hasher.hash(vec!["10".to_string(), bag.clone()]).unwrap();
    let mut keccak_mmr = keccak_init.0;

    assert_eq!(
        keccak_mmr.append(appended_leaf).await.unwrap(),
        AppendResult {
            element_index: 9,
            leaves_count: 6,
            elements_count: 10,
            root_hash: root,
        }
    );
    assert_eq!(
        keccak_mmr
            .get_peaks(PeaksOptions {
                elements_count: None,
                formatting_opts: None,
            })
            .await
            .unwrap(),
        vec![node7, node10]
    );
    assert_eq!(keccak_mmr.bag_the_peaks(None).await.unwrap(), bag);
    let proof = keccak_mmr
        .get_proof(last_leaf_element_index, None)
        .await
        .unwrap();
    assert!(keccak_mmr
        .verify_proof(proof, LEAVES[LEAVES.len() - 1].to_string(), None)
        .await
        .unwrap())
}

//================================================================================================
// Tests for get and verify proof
//================================================================================================

#[tokio::test]
async fn should_generate_and_verify_non_expiring_proof_for_pedersen_hasher() {
    let (pedersen_mmr, appends_results_for_pedersen) = setup().await.2;
    let mut proofs: Vec<Proof> = vec![];
    for result in appends_results_for_pedersen {
        let pedersen_mmr_clone = &pedersen_mmr;

        let proof = pedersen_mmr_clone
            .get_proof(
                result.element_index,
                Some(ProofOptions {
                    elements_count: Some(result.elements_count),
                    formatting_opts: None,
                }),
            )
            .await
            .unwrap();

        proofs.push(proof);
    }

    for (idx, proof) in proofs.iter().enumerate() {
        assert!(pedersen_mmr
            .verify_proof(
                proof.clone(),
                LEAVES[idx].to_string(),
                Some(ProofOptions {
                    elements_count: Some(proof.elements_count),
                    formatting_opts: None,
                })
            )
            .await
            .unwrap());
    }
}

#[tokio::test]
async fn should_generate_and_verify_non_expiring_proof_for_keccak_hasher() {
    let (keccak_mmr, appends_results_for_keccak) = setup().await.1;
    let mut proofs: Vec<Proof> = vec![];
    for result in appends_results_for_keccak {
        let keccak_mmr_clone = &keccak_mmr;

        let proof = keccak_mmr_clone
            .get_proof(
                result.element_index,
                Some(ProofOptions {
                    elements_count: Some(result.elements_count),
                    formatting_opts: None,
                }),
            )
            .await
            .unwrap();

        proofs.push(proof);
    }

    for (idx, proof) in proofs.iter().enumerate() {
        assert!(keccak_mmr
            .verify_proof(
                proof.clone(),
                LEAVES[idx].to_string(),
                Some(ProofOptions {
                    elements_count: Some(proof.elements_count),
                    formatting_opts: None,
                })
            )
            .await
            .unwrap());
    }
}

#[tokio::test]
async fn should_generate_and_verify_non_expiring_proof_for_poseidon_hasher() {
    let (poseidon_mmr, appends_results_for_poseidon) = setup().await.0;
    let mut proofs: Vec<Proof> = vec![];
    for result in appends_results_for_poseidon {
        let poseidon_mmr_clone = &poseidon_mmr;

        let proof = poseidon_mmr_clone
            .get_proof(
                result.element_index,
                Some(ProofOptions {
                    elements_count: Some(result.elements_count),
                    formatting_opts: None,
                }),
            )
            .await
            .unwrap();

        proofs.push(proof);
    }

    for (idx, proof) in proofs.iter().enumerate() {
        assert!(poseidon_mmr
            .verify_proof(
                proof.clone(),
                LEAVES[idx].to_string(),
                Some(ProofOptions {
                    elements_count: Some(proof.elements_count),
                    formatting_opts: None,
                })
            )
            .await
            .unwrap());
    }
}

//================================================================================================
// Tests for get and verify multiple proofs
//================================================================================================

#[tokio::test]
async fn should_generate_multiple_proofs_for_pedersen_hasher() {
    let (pedersen_mmr, appends_results_for_pedersen) = setup().await.2;

    let element_indexes: Vec<_> = appends_results_for_pedersen
        .iter()
        .map(|r| r.element_index)
        .collect();

    let proofs = pedersen_mmr
        .get_proofs(element_indexes, None)
        .await
        .expect("Failed to get proofs");

    for (idx, proof) in proofs.iter().enumerate() {
        assert!(pedersen_mmr
            .verify_proof(proof.clone(), LEAVES[idx].to_string(), None)
            .await
            .unwrap())
    }
}

#[tokio::test]
async fn should_generate_multiple_proofs_for_keccak_hasher() {
    let (keccak_mmr, appends_results_for_keccak) = setup().await.1;

    let element_indexes: Vec<_> = appends_results_for_keccak
        .iter()
        .map(|r| r.element_index)
        .collect();

    let proofs = keccak_mmr
        .get_proofs(element_indexes, None)
        .await
        .expect("Failed to get proofs");

    for (idx, proof) in proofs.iter().enumerate() {
        assert!(keccak_mmr
            .verify_proof(proof.clone(), LEAVES[idx].to_string(), None)
            .await
            .unwrap())
    }
}

#[tokio::test]
async fn should_generate_multiple_proofs_for_poseidon_hasher() {
    let (poseidon_mmr, appends_results_for_poseidon) = setup().await.0;

    let element_indexes: Vec<_> = appends_results_for_poseidon
        .iter()
        .map(|r| r.element_index)
        .collect();

    let proofs = poseidon_mmr
        .get_proofs(element_indexes, None)
        .await
        .expect("Failed to get proofs");

    for (idx, proof) in proofs.iter().enumerate() {
        assert!(poseidon_mmr
            .verify_proof(proof.clone(), LEAVES[idx].to_string(), None)
            .await
            .unwrap())
    }
}

#[tokio::test]
async fn test_get_peaks() {
    let store = InMemoryStore::default();
    let hasher = Arc::new(StarkPoseidonHasher::new(Some(false)));

    let store = Arc::new(store);

    let mut mmr = MMR::new(store.clone(), hasher.clone(), None);

    mmr.append("1".to_string()).await.unwrap();

    let peaks = mmr
        .get_peaks(PeaksOptions {
            elements_count: None,
            formatting_opts: None,
        })
        .await
        .unwrap();

    assert_eq!(peaks, vec!["1".to_string()]);

    mmr.append("2".to_string()).await.unwrap();

    let peaks = mmr
        .get_peaks(PeaksOptions {
            elements_count: None,
            formatting_opts: None,
        })
        .await
        .unwrap();

    assert_eq!(
        peaks,
        vec![hasher.hash(vec!["1".to_string(), "2".to_string()]).unwrap()]
    );

    mmr.append("3".to_string()).await.unwrap();

    let peaks = mmr
        .get_peaks(PeaksOptions {
            elements_count: None,
            formatting_opts: None,
        })
        .await
        .unwrap();

    assert_eq!(
        peaks,
        vec![
            hasher.hash(vec!["1".to_string(), "2".to_string()]).unwrap(),
            "3".to_string()
        ]
    );
}

#[tokio::test]
async fn should_append_to_poseidon_mmr() {
    let store = InMemoryStore::default();
    let hasher = Arc::new(StarkPoseidonHasher::new(Some(false)));

    let store = Arc::new(store);

    let mut mmr = MMR::new(store.clone(), hasher.clone(), None);

    // Act
    // let mut mmr = CoreMMR::create_with_genesis(store, hasher.clone(), None).unwrap();
    let append_result1 = mmr.append("1".to_string()).await.unwrap();

    assert_eq!(
        append_result1,
        AppendResult {
            element_index: 1,
            leaves_count: 1,
            elements_count: 1,
            root_hash: "0xb2b24ff607f861b3ed0a9868eeef700b7607ac6d71664afdd14a1f4c33f97d"
                .to_string(),
        }
    );

    assert_eq!(mmr.bag_the_peaks(None).await.unwrap(), "1");

    let append_result2 = mmr.append("2".to_string()).await.unwrap();

    assert_eq!(
        append_result2,
        AppendResult {
            element_index: 2,
            leaves_count: 2,
            elements_count: 3,
            root_hash: "0x97e6c17ea05508f6aef7a8195dee3da638bc44d22cbfff3a1f4d9ad215eb6d"
                .to_string(),
        }
    );

    assert_eq!(
        mmr.bag_the_peaks(None).await.unwrap(),
        "0x5d44a3decb2b2e0cc71071f7b802f45dd792d064f0fc7316c46514f70f9891a"
    );

    let append_result4 = mmr.append("4".to_string()).await.unwrap();
    assert_eq!(
        append_result4,
        AppendResult {
            element_index: 4,
            leaves_count: 3,
            elements_count: 4,
            root_hash: "0x5caaf1cd5b1cf12d50730bb1e0c8a00ef696332a9019a4c7668deb11060620e"
                .to_string(),
        }
    );

    assert_eq!(
        mmr.bag_the_peaks(None).await.unwrap(),
        "0x6f31a64a67c46b553960ae6b72bcf9fa3ccc6a4d6344e3799412e2c73a059b2"
    );
    let append_result5 = mmr.append("5".to_string()).await.unwrap();
    assert_eq!(
        append_result5,
        AppendResult {
            element_index: 5,
            leaves_count: 4,
            elements_count: 7,
            root_hash: "0x173b5ce39844d1534c8f545a3102fc28947f17ac3e16850413173291eb3e41b"
                .to_string(),
        }
    );
    assert_eq!(
        mmr.bag_the_peaks(None).await.unwrap(),
        "0x43c59debacab61e73dec9edd73da27738a8be14c1e123bb38f9634220323c4f"
    );
    let append_result8 = mmr.append("8".to_string()).await.unwrap();
    assert_eq!(
        append_result8,
        AppendResult {
            element_index: 8,
            leaves_count: 5,
            elements_count: 8,
            root_hash: "0x69c66f988b4b7942b56d9bebebdb0d6cf33f800e272ebf3cc7bd47d4f0d8641"
                .to_string(),
        }
    );

    assert_eq!(
        mmr.bag_the_peaks(None).await.unwrap(),
        "0x49da356656c3153d59f9be39143daebfc12e05b6a93ab4ccfa866a890ad78f"
    );

    let proof1 = mmr.get_proof(1, None).await.unwrap();

    assert_eq!(
        proof1,
        Proof {
            element_index: 1,
            element_hash: "1".to_string(),
            siblings_hashes: vec![
                "2".to_string(),
                "0x384f427301be8e1113e6dd91088cb46e25a8f6426a997b2f842a39596bf45f4".to_string()
            ],
            peaks_hashes: vec![
                "0x43c59debacab61e73dec9edd73da27738a8be14c1e123bb38f9634220323c4f".to_string(),
                "8".to_string()
            ],
            elements_count: 8
        }
    );

    mmr.verify_proof(proof1, "1".to_string(), None)
        .await
        .unwrap();

    let proof2 = mmr.get_proof(2, None).await.unwrap();

    assert_eq!(
        proof2,
        Proof {
            element_index: 2,
            element_hash: "2".to_string(),
            siblings_hashes: vec![
                "1".to_string(),
                "0x384f427301be8e1113e6dd91088cb46e25a8f6426a997b2f842a39596bf45f4".to_string()
            ],
            peaks_hashes: vec![
                "0x43c59debacab61e73dec9edd73da27738a8be14c1e123bb38f9634220323c4f".to_string(),
                "8".to_string()
            ],
            elements_count: 8
        }
    );

    mmr.verify_proof(proof2, "2".to_string(), None)
        .await
        .unwrap();

    let proof4 = mmr.get_proof(4, None).await.unwrap();

    assert_eq!(
        proof4,
        Proof {
            element_index: 4,
            element_hash: "4".to_string(),
            siblings_hashes: vec![
                "5".to_string(),
                "0x5d44a3decb2b2e0cc71071f7b802f45dd792d064f0fc7316c46514f70f9891a".to_string()
            ],
            peaks_hashes: vec![
                "0x43c59debacab61e73dec9edd73da27738a8be14c1e123bb38f9634220323c4f".to_string(),
                "8".to_string()
            ],
            elements_count: 8
        }
    );

    mmr.verify_proof(proof4, "4".to_string(), None)
        .await
        .unwrap();

    let proof5 = mmr.get_proof(5, None).await.unwrap();

    assert_eq!(
        proof5,
        Proof {
            element_index: 5,
            element_hash: "5".to_string(),
            siblings_hashes: vec![
                "4".to_string(),
                "0x5d44a3decb2b2e0cc71071f7b802f45dd792d064f0fc7316c46514f70f9891a".to_string()
            ],
            peaks_hashes: vec![
                "0x43c59debacab61e73dec9edd73da27738a8be14c1e123bb38f9634220323c4f".to_string(),
                "8".to_string()
            ],
            elements_count: 8
        }
    );

    mmr.verify_proof(proof5, "5".to_string(), None)
        .await
        .unwrap();
}

#[tokio::test]
async fn should_append_duplicate_to_mmr() {
    let store = SQLiteStore::new(":memory:", None, Some("test"))
        .await
        .unwrap();
    let hasher = Arc::new(StarkPoseidonHasher::new(Some(false)));

    let store = Arc::new(store);

    let mut mmr = MMR::new(store, hasher, None);
    let _ = mmr.append("4".to_string()).await;
    let _ = mmr.append("4".to_string()).await;

    let _root = mmr.bag_the_peaks(None).await.unwrap();
}

#[tokio::test]
async fn test_append_for_mmr() {
    let store = InMemoryStore::default();
    let store_rc = Arc::new(store);
    let hasher = Arc::new(StarkPoseidonHasher::new(Some(false)));

    let mut mmr = MMR::new(store_rc, hasher, None);

    mmr.append("1".to_string()).await.expect("Failed to append");
    mmr.append("2".to_string()).await.expect("Failed to append");
    mmr.append("3".to_string()).await.expect("Failed to append");
    let example_value = "4".to_string();
    let example_append = mmr
        .append(example_value.clone())
        .await
        .expect("Failed to append");

    let proof = mmr
        .get_proof(example_append.element_index, None)
        .await
        .expect("Failed to get proof");

    assert!(mmr
        .verify_proof(proof, example_value, None)
        .await
        .expect("Failed to verify proof"));
}

//================================================================================================
// Tests for create_with_genesis
//================================================================================================

#[tokio::test]
async fn test_create_with_genesis_for_keccak() {
    // Arrange
    let store = InMemoryStore::default();
    let hasher = Arc::new(KeccakHasher::new());
    let store = Arc::new(store);

    // Act
    let core_mmr = MMR::create_with_genesis(store, hasher.clone(), None)
        .await
        .unwrap();

    assert_eq!(
        core_mmr.root_hash.get(SubKey::None).await.unwrap().unwrap(),
        hasher
            .hash(vec!["1".to_string(), hasher.get_genesis().unwrap()])
            .unwrap()
    );
}

#[tokio::test]
async fn test_create_with_genesis_for_poseidon() {
    // Arrange
    let store = InMemoryStore::default();
    let hasher = Arc::new(StarkPoseidonHasher::new(Some(false)));
    let store = Arc::new(store);

    // Act
    let core_mmr = MMR::create_with_genesis(store, hasher.clone(), None)
        .await
        .unwrap();

    assert_eq!(
        core_mmr.root_hash.get(SubKey::None).await.unwrap().unwrap(),
        hasher
            .hash(vec!["1".to_string(), hasher.get_genesis().unwrap()])
            .unwrap()
    );
}

//================================================================================================
// Tests for get root hash from createWithGenesis with mix of hex and non-hex values
//================================================================================================

#[tokio::test]
async fn should_get_a_stable_root_hash_for_given_args_keccak_hasher() {
    let store = InMemoryStore::default();
    let hasher = Arc::new(KeccakHasher::new());
    let store = Arc::new(store);

    let mut mmr = MMR::create_with_genesis(store, hasher.clone(), None)
        .await
        .unwrap();

    assert_eq!(mmr.leaves_count.get().await.unwrap(), 1);

    mmr.append("1".to_string()).await.unwrap();
    mmr.append("0x1".to_string()).await.unwrap();
    mmr.append("2".to_string()).await.unwrap();
    mmr.append("0x2".to_string()).await.unwrap();
    mmr.append("3".to_string()).await.unwrap();
    mmr.append("0x3".to_string()).await.unwrap();

    let stable_bag = "0x46d676ef5c3e8c6668ec577baee408f7b149d05b3ea31f4f2ad0d2a0ddc2a9b3";

    let element_count = mmr.leaves_count.get().await.unwrap();

    assert_eq!(element_count, 7);
    let bag = mmr.bag_the_peaks(None).await.unwrap();

    assert_eq!(&bag, stable_bag);

    let element_count = mmr.leaves_count.get().await.unwrap();

    let root_hash = mmr.calculate_root_hash(&bag, element_count).unwrap();

    let stable_root_hash = "0xe336600238639f1ea4e2d78db1c8353a896487fa8fb9f2c3898888817008b77b";

    assert_eq!(stable_root_hash, root_hash);
}

#[tokio::test]
async fn should_get_a_stable_root_hash_for_given_args_poseidon_hasher() {
    let store = InMemoryStore::default();
    let hasher = Arc::new(StarkPoseidonHasher::new(Some(false)));
    let store = Arc::new(store);

    let mut mmr = MMR::create_with_genesis(store, hasher.clone(), None)
        .await
        .unwrap();

    assert_eq!(mmr.leaves_count.get().await.unwrap(), 1);

    mmr.append("1".to_string()).await.unwrap();
    mmr.append("0x1".to_string()).await.unwrap();
    mmr.append("2".to_string()).await.unwrap();
    mmr.append("0x2".to_string()).await.unwrap();
    mmr.append("3".to_string()).await.unwrap();
    mmr.append("0x3".to_string()).await.unwrap();

    let stable_bag = "0x1b6fe636cf8f005b539f3d5c9ca5b5f435e995ecf51894fd3045a5e8389d467";

    let element_count = mmr.leaves_count.get().await.unwrap();

    assert_eq!(element_count, 7);
    let bag = mmr.bag_the_peaks(None).await.unwrap();

    assert_eq!(&bag, stable_bag);

    let element_count = mmr.leaves_count.get().await.unwrap();

    let root_hash = mmr.calculate_root_hash(&bag, element_count).unwrap();

    let stable_root_hash = "0x113e2abc1e91aa48aa7c12940061c924437fcd27829b8594de54a0cea57d232";

    assert_eq!(stable_root_hash, root_hash);
}

#[tokio::test]
async fn timestamp_remappers_test() {
    let store = InMemoryStore::default();
    let hasher = Arc::new(StarkPoseidonHasher::new(Some(false)));
    let store = Arc::new(store);

    let mut mmr = MMR::new(store, hasher.clone(), None);

    mmr.append("1715180160".to_string()).await.unwrap();
    mmr.append("1715180172".to_string()).await.unwrap();

    let element_count = mmr.elements_count.get().await.unwrap();
    println!("element_count: {}", element_count);
    let bag = mmr.bag_the_peaks(Some(element_count)).await.unwrap();
    println!("bag: {}", bag);
    let root_hash = mmr.calculate_root_hash(&bag, element_count).unwrap();
    println!("root_hash: {}", root_hash);

    let correct_root_hash = "0x32f5a2949cac3d06e854701c5a2a00ed51c0475a31c1bc17cc6d3ec46425e9";
    assert_eq!(correct_root_hash, root_hash);
}
