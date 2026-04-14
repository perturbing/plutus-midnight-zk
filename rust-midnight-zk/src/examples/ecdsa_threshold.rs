//! Proves knowledge of T=4 out of N=5 Bitcoin ECDSA signatures on a public
//! message, and writes the four Plutus test-vector files to disk.
//!
//! Output: {base_dir}/ecdsa-threshold/
//!   ecdsa_threshold_plutus_vk.json       – extended Plutus VK
//!   ecdsa_threshold_circuit_params.json  – 10 circuit-structure scalars
//!   ecdsa_threshold_rotation_sets.json   – rotation set metadata
//!   ecdsa_threshold_plutus_proof.json    – structured GWC proof
//!   ecdsa_threshold_plutus_instance.json – public inputs as 32-byte LE hex strings

use ff::Field;
use group::{Curve, GroupEncoding};
use midnight_circuits::{
    field::foreign::{params::MultiEmulationParams as MEP, AssignedField},
    instructions::{
        ArithInstructions, AssignmentInstructions, DecompositionInstructions, EccInstructions,
        PublicInputInstructions, ZeroInstructions,
    },
    testing_utils::ecdsa::{ECDSASig, Ecdsa},
    types::{AssignedForeignPoint, InnerValue, Instantiable},
    CircuitField,
};
use midnight_curves::{
    k256::{Fq as K256Scalar, K256},
    Fq as Scalar,
};
use midnight_proofs::{circuit::{Layouter, Value}, plonk::Error};
use midnight_zk_stdlib::{utils::plonk_api::filecoin_srs, Relation, ZkStdLib, ZkStdLibArch};
use rand::{prelude::SliceRandom, rngs::OsRng, SeedableRng};
use rand_chacha::ChaCha8Rng;
use crate::circuit_params::write_json_all_artifacts;

type F = Scalar;

const N: usize = 5;
const T: usize = 4;

type PK = K256;
type MsgHash = K256Scalar;

#[derive(Clone, Default)]
pub struct BitcoinThresholdECDSA;

impl Relation for BitcoinThresholdECDSA {
    type Error = Error;
    type Instance = (MsgHash, [PK; N]);
    type Witness = [(PK, ECDSASig); T];

    fn format_instance((msg_hash, pks): &Self::Instance) -> Result<Vec<F>, Error> {
        Ok([
            AssignedField::<F, K256Scalar, MEP>::as_public_input(msg_hash),
            pks.iter()
                .flat_map(AssignedForeignPoint::<F, K256, MEP>::as_public_input)
                .collect::<Vec<_>>(),
        ]
        .into_iter()
        .flatten()
        .collect())
    }

    fn circuit(
        &self,
        std_lib: &ZkStdLib,
        layouter: &mut impl Layouter<F>,
        instance: Value<Self::Instance>,
        witness: Value<Self::Witness>,
    ) -> Result<(), Error> {
        let secp256k1_curve = std_lib.secp256k1_curve();
        let secp256k1_scalar = std_lib.secp256k1_scalar();
        let secp256k1_base = secp256k1_curve.base_field_chip();

        let msg_hash = secp256k1_scalar.assign_as_public_input(layouter, instance.unzip().0)?;

        let pks = secp256k1_curve.assign_many(layouter, &instance.unzip().1.transpose_array())?;
        pks.iter()
            .try_for_each(|pk| secp256k1_curve.constrain_as_public_input(layouter, pk))?;

        let signatures = witness.transpose_array();
        let selected_pks_values = signatures.map(|v| v.map(|(pk, _)| pk));
        let selected_sigs_values = signatures.map(|v| v.map(|(_, s)| s));

        let assigned_selected_pks =
            secp256k1_curve.k_out_of_n_points(layouter, &pks, &selected_pks_values)?;

        let alpha: AssignedField<F, K256Scalar, _> =
            secp256k1_scalar.assign_fixed(layouter, K256Scalar::from(42u64))?;

        let mut alpha_powers: [_; T] = core::array::from_fn(|_| alpha.clone());
        for i in 1..T {
            alpha_powers[i] = secp256k1_scalar.mul(layouter, &alpha_powers[i - 1], &alpha, None)?;
        }

        let neg_s_i_times_alpha_i = selected_sigs_values
            .iter()
            .zip(alpha_powers.iter())
            .map(|(sig_i, alpha_i)| {
                let neg_s_i = secp256k1_scalar.assign(layouter, sig_i.map(|sig| -sig.get_s()))?;
                secp256k1_scalar.mul(layouter, &neg_s_i, alpha_i, None)
            })
            .collect::<Result<Vec<_>, Error>>()?;

        let r_i_as_le_bytes = selected_sigs_values
            .iter()
            .map(|sig_i| std_lib.assign_many(layouter, &sig_i.map(|v| v.get_r()).transpose_array()))
            .collect::<Result<Vec<_>, Error>>()?;

        let r_i_as_scalar = r_i_as_le_bytes
            .iter()
            .map(|bytes| secp256k1_scalar.assigned_from_le_bytes(layouter, bytes))
            .collect::<Result<Vec<_>, Error>>()?;

        let r_i_as_base = r_i_as_le_bytes
            .iter()
            .map(|bytes| secp256k1_base.assigned_from_le_bytes(layouter, bytes))
            .collect::<Result<Vec<_>, Error>>()?;

        let r_i_times_alpha_i = r_i_as_scalar
            .iter()
            .zip(alpha_powers.iter())
            .map(|(r_i, alpha_i)| secp256k1_scalar.mul(layouter, r_i, alpha_i, None))
            .collect::<Result<Vec<_>, Error>>()?;

        let k_points = signatures
            .iter()
            .zip(r_i_as_base.iter())
            .map(|(val, r_i)| {
                let k_point_y_val = val.zip(instance.unzip().0).zip(r_i.value()).map(
                    |(((pk_i, sig_i), msg_hash), r_i)| {
                        let gen = K256::generator();
                        let r_as_scalar = K256Scalar::from_bytes_le(&sig_i.get_r()).unwrap();
                        let s_inv = sig_i.get_s().invert().unwrap();
                        let k_point = gen * (s_inv * msg_hash) + pk_i * (s_inv * r_as_scalar);
                        assert_eq!(r_i, k_point.to_affine().x());
                        k_point.to_affine().y()
                    },
                );
                let y_i = secp256k1_base.assign(layouter, k_point_y_val)?;
                secp256k1_curve.point_from_coordinates(layouter, r_i, &y_i)
            })
            .collect::<Result<Vec<_>, Error>>()?;

        let sum_alphas = {
            let terms = alpha_powers
                .iter()
                .map(|alpha_i| (K256Scalar::ONE, alpha_i.clone()))
                .collect::<Vec<_>>();
            secp256k1_scalar.linear_combination(layouter, &terms, K256Scalar::ZERO)
        }?;
        let sum_alphas_times_msg_hash =
            secp256k1_scalar.mul(layouter, &sum_alphas, &msg_hash, None)?;

        let gen = secp256k1_curve.assign_fixed(layouter, K256::generator())?;
        let mut bases = vec![gen];
        bases.extend(assigned_selected_pks);
        bases.extend(k_points);

        let mut scalars = vec![sum_alphas_times_msg_hash];
        scalars.extend(r_i_times_alpha_i);
        scalars.extend(neg_s_i_times_alpha_i);

        let res = secp256k1_curve.msm(layouter, &scalars, &bases)?;

        secp256k1_curve.assert_zero(layouter, &res)
    }

    fn used_chips(&self) -> ZkStdLibArch {
        ZkStdLibArch {
            secp256k1: true,
            nr_pow2range_cols: 4,
            ..ZkStdLibArch::default()
        }
    }

    fn write_relation<W: std::io::Write>(&self, _writer: &mut W) -> std::io::Result<()> {
        Ok(())
    }

    fn read_relation<R: std::io::Read>(_reader: &mut R) -> std::io::Result<Self> {
        Ok(BitcoinThresholdECDSA)
    }
}

pub fn run(base_dir: &str) {
    const K: u32 = 16;
    let srs = filecoin_srs(K);

    let relation = BitcoinThresholdECDSA;
    let vk = midnight_zk_stdlib::setup_vk(&srs, &relation);
    let pk = midnight_zk_stdlib::setup_pk(&relation, &vk);

    let mut rng = ChaCha8Rng::seed_from_u64(0xba5eba11);
    let msg_hash = K256Scalar::random(&mut rng);

    let keys: [_; N] = core::array::from_fn(|_| Ecdsa::keygen(&mut rng));
    let pks = keys.map(|(pk, _)| pk);

    let mut indices: Vec<usize> = (0..N).collect();
    indices.shuffle(&mut rng);

    let mut idxs_of_known_sigs = indices[..T].to_vec();
    idxs_of_known_sigs.sort();

    let signatures: [(PK, ECDSASig); T] = idxs_of_known_sigs
        .into_iter()
        .map(|i| (keys[i].0, Ecdsa::sign(&keys[i].1, &msg_hash, &mut rng)))
        .collect::<Vec<_>>()
        .try_into()
        .unwrap();

    signatures.iter().for_each(|(pk, sig)| {
        assert!(Ecdsa::verify(pk, &msg_hash, sig));
    });

    let instance = (msg_hash, pks);
    let witness = signatures;

    let proof = midnight_zk_stdlib::prove::<
        BitcoinThresholdECDSA,
        midnight_proofs::transcript::Blake2b256,
    >(&srs, &pk, &relation, &instance, witness, OsRng)
    .expect("proof generation failed");

    assert!(
        midnight_zk_stdlib::verify::<
            BitcoinThresholdECDSA,
            midnight_proofs::transcript::Blake2b256,
        >(&srs.verifier_params(), &vk, &instance, None, &proof).is_ok(),
        "internal verify failed"
    );

    let pi = BitcoinThresholdECDSA::format_instance(&instance).expect("format_instance failed");
    write_json_all_artifacts(
        &format!("{base_dir}/ecdsa-threshold"),
        "ecdsa_threshold",
        vk.vk(),
        srs.s_g2().to_bytes().as_ref(),
        &proof,
        &pi,
    );
}
