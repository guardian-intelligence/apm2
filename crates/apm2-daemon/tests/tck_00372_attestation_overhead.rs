//! TCK-00372: Attestation overhead contract and fallback safety.
//!
//! This harness measures direct vs batched receipt verification envelopes,
//! evaluates the `<1%` overhead gate at `10^6` and `10^8`, projects to `10^12`,
//! and validates automatic batched->direct fallback behavior.

use std::time::Instant;

use apm2_core::consensus::{
    AttestationOverheadGate, AttestationProjectionModel, AttestationScaleMeasurement,
    SCALE_EFFECTS_10E6, SCALE_EFFECTS_10E8, SCALE_EFFECTS_10E12,
};
use apm2_core::crypto::{HASH_SIZE, Signer};
use apm2_daemon::identity::{
    AlgorithmTag, AuthoritySealV1, BatchFallbackReason, BatchOverheadPolicy, BatchSealVerifier,
    CellGenesisV1, CellIdV1, DirectVerificationFallback, IssuerId, KeySetIdV1, LedgerAnchorV1,
    MerkleInclusionProof, MerkleProofSibling, PolicyRootId, PublicKeyIdV1, ReceiptMultiProofV1,
    ReceiptPointerError, ReceiptPointerV1, ReceiptPointerVerifier, SealKind, SetTag, SubjectKind,
    ZERO_TIME_ENVELOPE_REF, compute_receipt_leaf_hash,
};

const TEST_SUBJECT_KIND: &str = "apm2.tool_execution_receipt.v1";
const SAMPLE_COUNT: usize = 96;
const BATCH_SIZE: usize = 256;
const BATCH_SIZE_F64: f64 = 256.0;
const SCALE_EFFECTS_10E6_F64: f64 = 1_000_000.0;
const SCALE_EFFECTS_10E8_F64: f64 = 100_000_000.0;

fn p99(values: &mut [u64]) -> u64 {
    assert!(!values.is_empty(), "p99 requires non-empty sample set");
    values.sort_unstable();
    let idx = ((values.len() * 99).div_ceil(100)).saturating_sub(1);
    values[idx]
}

fn u64_to_f64_saturating(value: u64) -> f64 {
    f64::from(u32::try_from(value).unwrap_or(u32::MAX))
}

fn usize_to_f64_saturating(value: usize) -> f64 {
    f64::from(u32::try_from(value).unwrap_or(u32::MAX))
}

fn test_cell_id() -> CellIdV1 {
    let genesis_hash = [0xAA; HASH_SIZE];
    let policy_root_key = PublicKeyIdV1::from_key_bytes(AlgorithmTag::Ed25519, &[0xBB; 32]);
    let policy_root = PolicyRootId::Single(policy_root_key);
    let genesis = CellGenesisV1::new(genesis_hash, policy_root, "tck-00372.local").unwrap();
    CellIdV1::from_genesis(&genesis)
}

fn make_direct_seal_with_time_ref(
    signer: &Signer,
    receipt_hash: &[u8; 32],
    time_envelope_ref: [u8; 32],
) -> AuthoritySealV1 {
    let cell_id = test_cell_id();
    let pkid = PublicKeyIdV1::from_key_bytes(AlgorithmTag::Ed25519, &signer.public_key_bytes());
    let subject_kind = SubjectKind::new(TEST_SUBJECT_KIND).unwrap();
    let ledger_anchor = LedgerAnchorV1::ConsensusIndex { index: 1 };

    let seal_unsigned = AuthoritySealV1::new(
        cell_id.clone(),
        IssuerId::PublicKey(pkid.clone()),
        subject_kind.clone(),
        *receipt_hash,
        ledger_anchor.clone(),
        time_envelope_ref,
        SealKind::SingleSig,
        vec![vec![0u8; 64]],
    )
    .unwrap();

    let signature = signer.sign(&seal_unsigned.domain_separated_preimage());
    AuthoritySealV1::new(
        cell_id,
        IssuerId::PublicKey(pkid),
        subject_kind,
        *receipt_hash,
        ledger_anchor,
        time_envelope_ref,
        SealKind::SingleSig,
        vec![signature.to_bytes().to_vec()],
    )
    .unwrap()
}

fn make_batch_seal_with_time_ref(
    signer: &Signer,
    batch_root: &[u8; 32],
    time_envelope_ref: [u8; 32],
) -> AuthoritySealV1 {
    let cell_id = test_cell_id();
    let pkid = PublicKeyIdV1::from_key_bytes(AlgorithmTag::Ed25519, &signer.public_key_bytes());
    let subject_kind = SubjectKind::new(TEST_SUBJECT_KIND).unwrap();
    let ledger_anchor = LedgerAnchorV1::ConsensusIndex { index: 1 };

    let seal_unsigned = AuthoritySealV1::new(
        cell_id.clone(),
        IssuerId::PublicKey(pkid.clone()),
        subject_kind.clone(),
        *batch_root,
        ledger_anchor.clone(),
        time_envelope_ref,
        SealKind::MerkleBatch,
        vec![vec![0u8; 64]],
    )
    .unwrap();

    let signature = signer.sign(&seal_unsigned.domain_separated_preimage());
    AuthoritySealV1::new(
        cell_id,
        IssuerId::PublicKey(pkid),
        subject_kind,
        *batch_root,
        ledger_anchor,
        time_envelope_ref,
        SealKind::MerkleBatch,
        vec![signature.to_bytes().to_vec()],
    )
    .unwrap()
}

fn build_merkle_tree(receipt_hashes: &[[u8; 32]]) -> ([u8; 32], Vec<MerkleInclusionProof>) {
    let leaf_hashes: Vec<[u8; 32]> = receipt_hashes
        .iter()
        .map(compute_receipt_leaf_hash)
        .collect();
    let n = leaf_hashes.len().next_power_of_two();
    let mut layer = leaf_hashes.clone();
    layer.resize(n, [0u8; 32]);

    let mut layers: Vec<Vec<[u8; 32]>> = vec![layer.clone()];
    while layer.len() > 1 {
        let mut next = Vec::with_capacity(layer.len() / 2);
        for chunk in layer.chunks(2) {
            let mut hasher = blake3::Hasher::new();
            hasher.update(&chunk[0]);
            hasher.update(&chunk[1]);
            next.push(*hasher.finalize().as_bytes());
        }
        layers.push(next.clone());
        layer = next;
    }

    let root = layer[0];
    let mut proofs = Vec::with_capacity(receipt_hashes.len());
    for (leaf_idx, leaf_hash) in leaf_hashes.iter().enumerate().take(receipt_hashes.len()) {
        let mut siblings = Vec::new();
        let mut idx = leaf_idx;
        for layer in &layers[..layers.len() - 1] {
            let sibling_idx = idx ^ 1;
            if sibling_idx < layer.len() {
                siblings.push(MerkleProofSibling {
                    hash: layer[sibling_idx],
                    is_left: sibling_idx < idx,
                });
            }
            idx /= 2;
        }
        proofs.push(MerkleInclusionProof {
            leaf_hash: *leaf_hash,
            siblings,
        });
    }

    (root, proofs)
}

fn make_receipt_hashes(seed: u8, count: usize) -> Vec<[u8; 32]> {
    let mut hashes: Vec<[u8; 32]> = (0..count)
        .map(|idx| {
            let mut bytes = [0u8; 8];
            bytes.copy_from_slice(&(idx as u64).to_le_bytes());
            let mut hasher = blake3::Hasher::new();
            hasher.update(&[seed]);
            hasher.update(&bytes);
            *hasher.finalize().as_bytes()
        })
        .collect();
    hashes.sort_unstable();
    hashes
}

#[test]
fn tck_00372_attestation_overhead_contract_scales_and_projection() {
    let signer = Signer::generate();
    let receipt_hashes = make_receipt_hashes(0x42, BATCH_SIZE);
    let (batch_root, batch_proofs) = build_merkle_tree(&receipt_hashes);

    let batch_seal = make_batch_seal_with_time_ref(&signer, &batch_root, [0xAA; 32]);
    let batch_seal_hash = *blake3::hash(&batch_seal.canonical_bytes()).as_bytes();
    let multiproof = ReceiptMultiProofV1::new(
        batch_root,
        receipt_hashes.clone(),
        batch_seal_hash,
        batch_proofs,
    )
    .unwrap();

    let mut direct_material = Vec::with_capacity(receipt_hashes.len());
    for receipt_hash in &receipt_hashes {
        let seal = make_direct_seal_with_time_ref(&signer, receipt_hash, [0xAA; 32]);
        let seal_hash = *blake3::hash(&seal.canonical_bytes()).as_bytes();
        let ptr = ReceiptPointerV1::new_direct(*receipt_hash, seal_hash).unwrap();
        direct_material.push((ptr, seal));
    }

    let mut direct_samples_us = Vec::with_capacity(SAMPLE_COUNT);
    let mut batch_samples_us = Vec::with_capacity(SAMPLE_COUNT);

    for _ in 0..SAMPLE_COUNT {
        let start = Instant::now();
        for (ptr, seal) in &direct_material {
            ReceiptPointerVerifier::verify_direct(
                ptr,
                seal,
                &signer.verifying_key(),
                TEST_SUBJECT_KIND,
                true,
            )
            .expect("direct verification baseline");
        }
        direct_samples_us.push(u64::try_from(start.elapsed().as_micros()).unwrap_or(u64::MAX));

        let start = Instant::now();
        ReceiptPointerVerifier::verify_multiproof(
            &multiproof,
            &batch_seal,
            BatchSealVerifier::SingleKey(&signer.verifying_key()),
            TEST_SUBJECT_KIND,
            true,
        )
        .expect("batched multiproof verification");
        batch_samples_us.push(u64::try_from(start.elapsed().as_micros()).unwrap_or(u64::MAX));
    }

    let direct_batch_p99_us = u64_to_f64_saturating(p99(&mut direct_samples_us).max(1));
    let batched_batch_p99_us = u64_to_f64_saturating(p99(&mut batch_samples_us).max(1));

    let direct_cpu_per_effect_p99 = direct_batch_p99_us / BATCH_SIZE_F64;
    let batched_cpu_per_effect_p99 = batched_batch_p99_us / BATCH_SIZE_F64;

    let direct_bytes_per_batch: f64 = direct_material
        .iter()
        .map(|(ptr, seal)| {
            usize_to_f64_saturating(
                ptr.canonical_bytes()
                    .len()
                    .saturating_add(seal.canonical_bytes().len()),
            )
        })
        .sum();
    let batched_bytes_per_batch = usize_to_f64_saturating(
        multiproof
            .canonical_bytes()
            .len()
            .saturating_add(batch_seal.canonical_bytes().len()),
    );

    let direct_bytes_per_effect = direct_bytes_per_batch / BATCH_SIZE_F64;
    let batched_bytes_per_effect = batched_bytes_per_batch / BATCH_SIZE_F64;

    let measured_10e6 = AttestationScaleMeasurement::new(
        SCALE_EFFECTS_10E6,
        direct_cpu_per_effect_p99 * SCALE_EFFECTS_10E6_F64,
        batched_cpu_per_effect_p99 * SCALE_EFFECTS_10E6_F64,
        direct_bytes_per_effect * SCALE_EFFECTS_10E6_F64,
        batched_bytes_per_effect * SCALE_EFFECTS_10E6_F64,
    )
    .unwrap();
    let measured_10e8 = AttestationScaleMeasurement::new(
        SCALE_EFFECTS_10E8,
        direct_cpu_per_effect_p99 * SCALE_EFFECTS_10E8_F64,
        batched_cpu_per_effect_p99 * SCALE_EFFECTS_10E8_F64,
        direct_bytes_per_effect * SCALE_EFFECTS_10E8_F64,
        batched_bytes_per_effect * SCALE_EFFECTS_10E8_F64,
    )
    .unwrap();

    let gate = AttestationOverheadGate::default();
    gate.enforce(&measured_10e6)
        .expect("10^6 overhead must satisfy <1% gate");
    gate.enforce(&measured_10e8)
        .expect("10^8 overhead must satisfy <1% gate");

    let model = AttestationProjectionModel::new(measured_10e6, measured_10e8).unwrap();
    let projected_10e12 = model.project_10e12();
    assert_eq!(projected_10e12.effects, SCALE_EFFECTS_10E12);
    gate.enforce(&projected_10e12)
        .expect("10^12 projection must satisfy <1% gate");

    println!(
        "TCK-00372 measurement: batch_size={BATCH_SIZE}, direct_batch_p99_us={direct_batch_p99_us:.3}, batched_batch_p99_us={batched_batch_p99_us:.3}",
    );
    println!(
        "TCK-00372 scale 10^6: cpu_overhead_ratio={:.6}, network_overhead_ratio={:.6}",
        measured_10e6.cpu_overhead_ratio(),
        measured_10e6.network_overhead_ratio()
    );
    println!(
        "TCK-00372 scale 10^8: cpu_overhead_ratio={:.6}, network_overhead_ratio={:.6}",
        measured_10e8.cpu_overhead_ratio(),
        measured_10e8.network_overhead_ratio()
    );
    println!(
        "TCK-00372 projection 10^12: cpu_overhead_ratio={:.6}, network_overhead_ratio={:.6}",
        projected_10e12.cpu_overhead_ratio(),
        projected_10e12.network_overhead_ratio()
    );

    assert!(measured_10e6.cpu_overhead_ratio() <= 0.01);
    assert!(measured_10e6.network_overhead_ratio() <= 0.01);
    assert!(measured_10e8.cpu_overhead_ratio() <= 0.01);
    assert!(measured_10e8.network_overhead_ratio() <= 0.01);
    assert!(projected_10e12.cpu_overhead_ratio() <= 0.01);
    assert!(projected_10e12.network_overhead_ratio() <= 0.01);
}

#[test]
fn tck_00372_integrity_failure_triggers_automatic_direct_fallback() {
    let signer = Signer::generate();
    let receipt_hashes = make_receipt_hashes(0x61, 2);
    let (batch_root, proofs) = build_merkle_tree(&receipt_hashes);

    let batch_seal = make_batch_seal_with_time_ref(&signer, &batch_root, [0xAA; 32]);
    let batch_seal_hash = *blake3::hash(&batch_seal.canonical_bytes()).as_bytes();
    let mut tampered = proofs[0].clone();
    tampered.siblings[0].hash = [0xFE; 32];
    let batch_ptr =
        ReceiptPointerV1::new_batch(receipt_hashes[0], batch_seal_hash, tampered).unwrap();

    let direct_seal = make_direct_seal_with_time_ref(&signer, &receipt_hashes[0], [0xAA; 32]);
    let direct_seal_hash = *blake3::hash(&direct_seal.canonical_bytes()).as_bytes();
    let direct_ptr = ReceiptPointerV1::new_direct(receipt_hashes[0], direct_seal_hash).unwrap();

    let result = ReceiptPointerVerifier::verify_batch_with_fallback(
        &batch_ptr,
        &batch_seal,
        BatchSealVerifier::SingleKey(&signer.verifying_key()),
        TEST_SUBJECT_KIND,
        true,
        Some(DirectVerificationFallback {
            pointer: &direct_ptr,
            seal: &direct_seal,
            verifying_key: &signer.verifying_key(),
        }),
        None,
    )
    .expect("integrity failure should fallback to direct");

    assert_eq!(result.receipt_hash, receipt_hashes[0]);
}

#[test]
fn tck_00372_freshness_and_degradation_fallback_are_fail_closed() {
    let signer = Signer::generate();
    let receipt_hashes = make_receipt_hashes(0x71, 2);
    let (batch_root, proofs) = build_merkle_tree(&receipt_hashes);

    // Freshness failure on batch path: zero temporal binding.
    let stale_batch_seal =
        make_batch_seal_with_time_ref(&signer, &batch_root, ZERO_TIME_ENVELOPE_REF);
    let stale_batch_hash = *blake3::hash(&stale_batch_seal.canonical_bytes()).as_bytes();
    let batch_ptr =
        ReceiptPointerV1::new_batch(receipt_hashes[0], stale_batch_hash, proofs[0].clone())
            .unwrap();

    let temporal_direct_seal =
        make_direct_seal_with_time_ref(&signer, &receipt_hashes[0], [0xAB; 32]);
    let temporal_direct_hash = *blake3::hash(&temporal_direct_seal.canonical_bytes()).as_bytes();
    let direct_ptr = ReceiptPointerV1::new_direct(receipt_hashes[0], temporal_direct_hash).unwrap();

    let fresh_result = ReceiptPointerVerifier::verify_batch_with_fallback(
        &batch_ptr,
        &stale_batch_seal,
        BatchSealVerifier::SingleKey(&signer.verifying_key()),
        TEST_SUBJECT_KIND,
        true,
        Some(DirectVerificationFallback {
            pointer: &direct_ptr,
            seal: &temporal_direct_seal,
            verifying_key: &signer.verifying_key(),
        }),
        None,
    )
    .expect("freshness failure must fallback to direct");
    assert_eq!(fresh_result.receipt_hash, receipt_hashes[0]);

    // Degradation failure with no fallback must fail closed.
    let valid_batch_seal = make_batch_seal_with_time_ref(&signer, &batch_root, [0xAA; 32]);
    let valid_batch_hash = *blake3::hash(&valid_batch_seal.canonical_bytes()).as_bytes();
    let valid_batch_ptr =
        ReceiptPointerV1::new_batch(receipt_hashes[0], valid_batch_hash, proofs[0].clone())
            .unwrap();
    let degraded_policy = BatchOverheadPolicy::new(0.001, 0.001, 0.01, 0.01);

    let err = ReceiptPointerVerifier::verify_batch_with_fallback(
        &valid_batch_ptr,
        &valid_batch_seal,
        BatchSealVerifier::SingleKey(&signer.verifying_key()),
        TEST_SUBJECT_KIND,
        false,
        None,
        Some(degraded_policy),
    )
    .expect_err("degradation without direct fallback must deny");

    assert!(matches!(
        err,
        ReceiptPointerError::FallbackUnavailable {
            reason: BatchFallbackReason::Degradation,
            ..
        }
    ));
}

#[test]
fn tck_00372_quorum_batch_fallback_still_fail_closed_when_direct_material_mismatched() {
    let signer_a = Signer::generate();
    let signer_b = Signer::generate();
    let signer_c = Signer::generate();

    let receipt_hashes = make_receipt_hashes(0x81, 2);
    let (batch_root, proofs) = build_merkle_tree(&receipt_hashes);

    let member_a =
        PublicKeyIdV1::from_key_bytes(AlgorithmTag::Ed25519, &signer_a.public_key_bytes());
    let member_b =
        PublicKeyIdV1::from_key_bytes(AlgorithmTag::Ed25519, &signer_b.public_key_bytes());
    let member_c =
        PublicKeyIdV1::from_key_bytes(AlgorithmTag::Ed25519, &signer_c.public_key_bytes());
    let keyset_id = KeySetIdV1::from_descriptor(
        "ed25519",
        SetTag::Threshold,
        2,
        &[member_a, member_b, member_c],
        None,
    )
    .unwrap();

    let subject_kind = SubjectKind::new(TEST_SUBJECT_KIND).unwrap();
    let ledger_anchor = LedgerAnchorV1::ConsensusIndex { index: 7 };
    let cell_id = test_cell_id();
    let seal_unsigned = AuthoritySealV1::new(
        cell_id.clone(),
        IssuerId::Quorum(keyset_id.clone()),
        subject_kind.clone(),
        batch_root,
        ledger_anchor.clone(),
        [0xAA; 32],
        SealKind::MerkleBatch,
        vec![vec![0u8; 64], vec![0u8; 64]],
    )
    .unwrap();
    let preimage = seal_unsigned.domain_separated_preimage();
    let sig_a = signer_a.sign(&preimage).to_bytes().to_vec();
    let sig_b = signer_b.sign(&preimage).to_bytes().to_vec();
    let quorum_batch_seal = AuthoritySealV1::new(
        cell_id,
        IssuerId::Quorum(keyset_id),
        subject_kind,
        batch_root,
        ledger_anchor,
        [0xAA; 32],
        SealKind::MerkleBatch,
        vec![sig_a, sig_b],
    )
    .unwrap();

    let seal_hash = *blake3::hash(&quorum_batch_seal.canonical_bytes()).as_bytes();
    let mut tampered = proofs[0].clone();
    tampered.siblings[0].hash = [0xDD; 32];
    let batch_ptr = ReceiptPointerV1::new_batch(receipt_hashes[0], seal_hash, tampered).unwrap();

    let wrong_direct_seal =
        make_direct_seal_with_time_ref(&signer_a, &receipt_hashes[1], [0xAA; 32]);
    let wrong_direct_hash = *blake3::hash(&wrong_direct_seal.canonical_bytes()).as_bytes();
    let wrong_direct_ptr =
        ReceiptPointerV1::new_direct(receipt_hashes[1], wrong_direct_hash).unwrap();
    let quorum_keys = vec![
        signer_a.verifying_key(),
        signer_b.verifying_key(),
        signer_c.verifying_key(),
    ];

    let err = ReceiptPointerVerifier::verify_batch_with_fallback(
        &batch_ptr,
        &quorum_batch_seal,
        BatchSealVerifier::QuorumThreshold {
            verifying_keys: &quorum_keys,
            threshold: 2,
            weights: None,
        },
        TEST_SUBJECT_KIND,
        true,
        Some(DirectVerificationFallback {
            pointer: &wrong_direct_ptr,
            seal: &wrong_direct_seal,
            verifying_key: &signer_a.verifying_key(),
        }),
        None,
    )
    .expect_err("mismatched direct fallback material must fail closed");

    assert!(matches!(
        err,
        ReceiptPointerError::FallbackVerificationFailed {
            reason: BatchFallbackReason::IntegrityFailure,
            ..
        }
    ));
}
