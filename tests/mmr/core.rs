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
    let pruned_leaf_hashes = mmr
        .rewind(leaf_index)
        .await
        .expect("Failed to rewind to original size");

    assert_eq!(pruned_leaf_hashes.len(), new_leaf_count);

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

#[tokio::test]
async fn test_rewind_pruned_leaves() {
    use std::collections::HashSet;

    // 1) Set up an MMR with 5 initial leaves (["1", "2", "3", "4", "5"])
    let (mut mmr, appended_results) = setup().await.0;
    assert_eq!(appended_results.len(), 5);

    // 2) Append 3 new leaves
    let new_leaves = ["x0", "x1", "x2"];
    for leaf in &new_leaves {
        mmr.append((*leaf).to_string())
            .await
            .expect("Failed to append new leaf");
    }

    // The leaf index for the 5th leaf is 4 (since indexing starts at 0),
    // so rewinding to 4 effectively prunes leaves #5, #6, and #7
    let rewind_target = 4;

    // 3) Call rewind(...) and capture which leaves get pruned
    let pruned_leaf_hashes = mmr
        .rewind(rewind_target)
        .await
        .expect("Failed to rewind MMR");

    // 4) Validate that the returned leaves are exactly our 3 newly appended leaves
    //    Because the store returns them in a HashMap, there’s no guaranteed order;
    //    we compare sets to avoid ordering confusion.
    let expected_set: HashSet<String> = new_leaves.iter().map(|s| s.to_string()).collect();
    let actual_set: HashSet<String> = pruned_leaf_hashes.into_iter().collect();
    assert_eq!(
        expected_set, actual_set,
        "The pruned leaves should match the newly appended leaves"
    );

    // 5) Finally, confirm that the MMR is back to having only the original 5 leaves
    let leaves_count_after = mmr.leaves_count.get().await.unwrap();
    assert_eq!(leaves_count_after, 5, "We should have 5 leaves now");

    // Optionally, confirm the last leaf's proof is still valid, etc.:
    let last_leaf_idx = appended_results.last().unwrap().element_index; // index for "5"
    let proof = mmr.get_proof(last_leaf_idx, None).await.unwrap();
    let last_leaf_value = LEAVES[LEAVES.len() - 1]; // "5"
    assert!(
        mmr.verify_proof(proof, last_leaf_value.to_string(), None)
            .await
            .expect("Failed to verify proof"),
        "The proof for the 5th leaf should remain valid after rewind"
    );
}

#[cfg(test)]
mod batch_operations_tests {
    use std::sync::Arc;
    use std::time::Instant;

    use accumulators::{
        hasher::{
            keccak::KeccakHasher, stark_pedersen::StarkPedersenHasher,
            stark_poseidon::StarkPoseidonHasher,
        },
        mmr::MMR,
        store::{memory::InMemoryStore, sqlite::SQLiteStore, SubKey},
    };

    async fn setup_mmrs() -> (MMR, MMR, MMR) {
        let store = Arc::new(InMemoryStore::default());
        
        let poseidon_hasher = Arc::new(StarkPoseidonHasher::new(Some(false)));
        let keccak_hasher = Arc::new(KeccakHasher::new());
        let pedersen_hasher = Arc::new(StarkPedersenHasher::new());
        
        let poseidon_mmr = MMR::new(store.clone(), poseidon_hasher, None);
        let keccak_mmr = MMR::new(store.clone(), keccak_hasher, None);
        let pedersen_mmr = MMR::new(store.clone(), pedersen_hasher, None);
        
        (poseidon_mmr, keccak_mmr, pedersen_mmr)
    }
    
    #[tokio::test]
    async fn test_batch_append_basic() {
        let (mut poseidon_mmr, _, _) = setup_mmrs().await;
        
        let leaves = vec![
            "1".to_string(),
            "2".to_string(),
            "3".to_string(),
            "4".to_string(),
            "5".to_string()
        ];
        
        let results = poseidon_mmr.batch_append(leaves.clone()).await.unwrap();
        
        assert_eq!(results.len(), 5, "Should return 5 result objects");
        assert_eq!(poseidon_mmr.leaves_count.get().await.unwrap(), 5, "Should have 5 leaves");
        assert_eq!(results[0].element_index, 1, "First element index should be 1");
        
        for i in 1..results.len() {
            assert!(results[i].element_index > results[i-1].element_index, 
                "Element indices should be increasing");
        }
    }
    
    #[tokio::test]
    async fn test_batch_append_matches_individual_appends() {
        let (mut batch_mmr, _, _) = setup_mmrs().await;
        let (mut individual_mmr, _, _) = setup_mmrs().await;
        
        let leaves = vec![
            "1".to_string(),
            "2".to_string(),
            "3".to_string(),
            "4".to_string(),
            "5".to_string()
        ];
        
        let batch_results = batch_mmr.batch_append(leaves.clone()).await.unwrap();
        
        let mut individual_results = Vec::new();
        for leaf in &leaves {
            individual_results.push(individual_mmr.append(leaf.clone()).await.unwrap());
        }
        
        assert_eq!(
            batch_mmr.leaves_count.get().await.unwrap(),
            individual_mmr.leaves_count.get().await.unwrap(),
            "Leaf counts should match"
        );
        
        assert_eq!(
            batch_mmr.elements_count.get().await.unwrap(),
            individual_mmr.elements_count.get().await.unwrap(),
            "Element counts should match"
        );
        
        let batch_root = batch_mmr.root_hash.get(SubKey::None).await.unwrap();
        let individual_root = individual_mmr.root_hash.get(SubKey::None).await.unwrap();
        assert_eq!(batch_root, individual_root, "Root hashes should match");
        
        for (batch_result, individual_result) in batch_results.iter().zip(individual_results.iter()) {
            assert_eq!(batch_result.element_index, individual_result.element_index, "Element indices should match");
            assert_eq!(batch_result.leaves_count, individual_result.leaves_count, "Leaf counts should match");
            assert_eq!(batch_result.elements_count, individual_result.elements_count, "Element counts should match");
            assert_eq!(batch_result.root_hash, individual_result.root_hash, "Root hashes should match");
        }
    }
    
    #[tokio::test]
    async fn test_batch_append_proof_validation() {
        let (mut mmr, _, _) = setup_mmrs().await;
        
        let leaves = vec![
            "1".to_string(),
            "2".to_string(),
            "3".to_string(),
            "4".to_string(),
            "5".to_string()
        ];
        
        let results = mmr.batch_append(leaves.clone()).await.unwrap();
        
        for (i, result) in results.iter().enumerate() {
            let proof = mmr.get_proof(result.element_index, None).await.unwrap();
            let is_valid = mmr.verify_proof(proof, leaves[i].clone(), None).await.unwrap();
            
            assert!(is_valid, "Proof for leaf {} should be valid", i);
        }
    }
    
    #[tokio::test]
    async fn test_batch_append_empty() {
        let (mut mmr, _, _) = setup_mmrs().await;
        
        let results = mmr.batch_append(Vec::new()).await.unwrap();
        
        assert!(results.is_empty(), "Empty batch should return empty results");
        assert_eq!(mmr.leaves_count.get().await.unwrap(), 0, "Leaf count should remain 0");
        assert_eq!(mmr.elements_count.get().await.unwrap(), 0, "Element count should remain 0");
    }
    
    #[tokio::test]
    async fn test_batch_append_single_item() {
        let (mut batch_mmr, _, _) = setup_mmrs().await;
        let (mut individual_mmr, _, _) = setup_mmrs().await;
        
        let leaf = "single_item".to_string();
        let batch_results = batch_mmr.batch_append(vec![leaf.clone()]).await.unwrap();
        let individual_result = individual_mmr.append(leaf.clone()).await.unwrap();
        
        assert_eq!(batch_results.len(), 1, "Should have 1 result");
        assert_eq!(
            batch_results[0].element_index,
            individual_result.element_index,
            "Element indices should match"
        );
        assert_eq!(
            batch_results[0].root_hash,
            individual_result.root_hash,
            "Root hashes should match"
        );
    }
    
    #[tokio::test]
    async fn test_batch_append_performance() {
        let (mut batch_mmr, _, _) = setup_mmrs().await;
        let (mut individual_mmr, _, _) = setup_mmrs().await;
        
        let leaf_count = 100;
        let leaves: Vec<String> = (0..leaf_count)
            .map(|i| format!("leaf_{}", i))
            .collect();
        
        let batch_start = Instant::now();
        let _ = batch_mmr.batch_append(leaves.clone()).await.unwrap();
        let batch_duration = batch_start.elapsed();
        
        let individual_start = Instant::now();
        for leaf in &leaves {
            let _ = individual_mmr.append(leaf.clone()).await.unwrap();
        }
        let individual_duration = individual_start.elapsed();
        
        println!("Batch append time: {:?}", batch_duration);
        println!("Individual append time: {:?}", individual_duration);
        
        assert_eq!(batch_mmr.leaves_count.get().await.unwrap(), leaf_count, "Batch MMR should have correct leaf count");
        assert_eq!(individual_mmr.leaves_count.get().await.unwrap(), leaf_count, "Individual MMR should have correct leaf count");
    }
    
    #[tokio::test]
    async fn test_batch_append_with_existing_leaves() {
        let (mut mmr, _, _) = setup_mmrs().await;
        
        let initial_leaves = vec!["initial_1".to_string(), "initial_2".to_string()];
        for leaf in &initial_leaves {
            mmr.append(leaf.clone()).await.unwrap();
        }
        
        let initial_leaf_count = mmr.leaves_count.get().await.unwrap();
        assert_eq!(initial_leaf_count, 2, "Should have 2 initial leaves");
        
        let batch_leaves = vec!["batch_1".to_string(), "batch_2".to_string(), "batch_3".to_string()];
        let results = mmr.batch_append(batch_leaves.clone()).await.unwrap();
        
        let final_leaf_count = mmr.leaves_count.get().await.unwrap();
        assert_eq!(final_leaf_count, 5, "Should have 5 total leaves");
        
        let initial_proof = mmr.get_proof(1, None).await.unwrap();
        let is_valid_initial = mmr.verify_proof(initial_proof, initial_leaves[0].clone(), None).await.unwrap();
        assert!(is_valid_initial, "Proof for initial leaf should be valid");
        
        let batch_proof = mmr.get_proof(results[1].element_index, None).await.unwrap();
        let is_valid_batch = mmr.verify_proof(batch_proof, batch_leaves[1].clone(), None).await.unwrap();
        assert!(is_valid_batch, "Proof for batch leaf should be valid");
    }
    
    #[tokio::test]
    async fn test_batch_append_all_hashers() {
        let (mut poseidon_mmr, mut keccak_mmr, mut pedersen_mmr) = setup_mmrs().await;
        
        let leaves = vec![
            "1".to_string(),
            "2".to_string(),
            "3".to_string(),
            "4".to_string(),
            "5".to_string()
        ];
        
        let poseidon_results = poseidon_mmr.batch_append(leaves.clone()).await.unwrap();
        let keccak_results = keccak_mmr.batch_append(leaves.clone()).await.unwrap();
        let pedersen_results = pedersen_mmr.batch_append(leaves.clone()).await.unwrap();
        
        assert_eq!(poseidon_mmr.leaves_count.get().await.unwrap(), 5);
        assert_eq!(keccak_mmr.leaves_count.get().await.unwrap(), 5);
        assert_eq!(pedersen_mmr.leaves_count.get().await.unwrap(), 5);
        
        let poseidon_root = poseidon_results.last().unwrap().root_hash.clone();
        let keccak_root = keccak_results.last().unwrap().root_hash.clone();
        let pedersen_root = pedersen_results.last().unwrap().root_hash.clone();
        
        assert_ne!(poseidon_root, keccak_root, "Different hashers should produce different roots");
        assert_ne!(poseidon_root, pedersen_root, "Different hashers should produce different roots");
        assert_ne!(keccak_root, pedersen_root, "Different hashers should produce different roots");
    }
    
    #[tokio::test]
    async fn test_batch_append_with_sqlite() {
        let store = SQLiteStore::new(":memory:", Some(true), Some("test"))
            .await
            .unwrap();
        let store = Arc::new(store);
        let hasher = Arc::new(StarkPoseidonHasher::new(Some(false)));
        
        let mut mmr = MMR::new(store, hasher, None);
        
        let leaves = vec![
            "1".to_string(),
            "2".to_string(),
            "3".to_string(),
            "4".to_string(),
            "5".to_string()
        ];
        
        let results = mmr.batch_append(leaves.clone()).await.unwrap();
        
        assert_eq!(mmr.leaves_count.get().await.unwrap(), 5, "Should have 5 leaves");
        
        for (i, result) in results.iter().enumerate() {
            let proof = mmr.get_proof(result.element_index, None).await.unwrap();
            let is_valid = mmr.verify_proof(proof, leaves[i].clone(), None).await.unwrap();
            
            assert!(is_valid, "Proof for leaf {} should be valid with SQLite store", i);
        }
    }
    
    #[tokio::test]
    async fn test_bag_the_peaks_in_memory() {
        let (mmr, _, _) = setup_mmrs().await;
        
        // let leaves = vec![
        //     "1".to_string(),
        //     "2".to_string(),
        //     "3".to_string(),
        //     "4".to_string(),
        //     "5".to_string()
        // ];
        
        // let results = mmr.batch_append(leaves.clone()).await.unwrap();
        
        let peaks_from_storage = mmr.get_peaks(accumulators::mmr::PeaksOptions {
            elements_count: None,
            formatting_opts: None,
        }).await.unwrap();
        
        let bagged_peaks_from_storage = mmr.bag_the_peaks(None).await.unwrap();
        let bagged_peaks_in_memory = mmr.bag_the_peaks_in_memory(&peaks_from_storage).unwrap();
        
        assert_eq!(
            bagged_peaks_from_storage, 
            bagged_peaks_in_memory,
            "In-memory and storage-based peak bagging should match"
        );
    }
    
    #[tokio::test]
    async fn test_rewind_after_batch_append() {
        let (mut mmr, _, _) = setup_mmrs().await;
        
        let first_batch = vec![
            "1".to_string(),
            "2".to_string(),
            "3".to_string(),
        ];
        
        mmr.batch_append(first_batch.clone()).await.unwrap();
        
        let root_after_first = mmr.root_hash.get(SubKey::None).await.unwrap().unwrap();
        
        let second_batch = vec![
            "4".to_string(),
            "5".to_string(),
        ];
        
        mmr.batch_append(second_batch.clone()).await.unwrap();
        
        assert_eq!(mmr.leaves_count.get().await.unwrap(), 5, "Should have 5 leaves before rewind");
        
        let pruned = mmr.rewind(2).await.unwrap();
        
        assert_eq!(pruned.len(), 2, "Should have pruned 2 leaves");
        assert!(pruned.contains(&second_batch[0]), "Should contain first leaf from second batch");
        assert!(pruned.contains(&second_batch[1]), "Should contain second leaf from second batch");
        assert_eq!(mmr.leaves_count.get().await.unwrap(), 3, "Should have 3 leaves after rewind");
        
        let root_after_rewind = mmr.root_hash.get(SubKey::None).await.unwrap().unwrap();
        assert_eq!(root_after_first, root_after_rewind, "Root should match state after first batch");
    }
    
    #[tokio::test]
    async fn test_large_batch_append() {
        let (mut mmr, _, _) = setup_mmrs().await;
        
        const BATCH_SIZE: usize = 1000;
        let large_batch: Vec<String> = (0..BATCH_SIZE)
            .map(|i| format!("large_batch_item_{}", i))
            .collect();
        
        let results = mmr.batch_append(large_batch.clone()).await.unwrap();
        
        assert_eq!(results.len(), BATCH_SIZE, "Should have results for all items");
        assert_eq!(mmr.leaves_count.get().await.unwrap(), BATCH_SIZE, "Should have correct leaf count");
        
        let indices_to_check = [0, BATCH_SIZE / 2, BATCH_SIZE - 1];
        
        for &idx in &indices_to_check {
            let element_idx = results[idx].element_index;
            let proof = mmr.get_proof(element_idx, None).await.unwrap();
            let is_valid = mmr.verify_proof(proof, large_batch[idx].clone(), None).await.unwrap();
            
            assert!(is_valid, "Proof for item {} should be valid", idx);
        }
    }
}