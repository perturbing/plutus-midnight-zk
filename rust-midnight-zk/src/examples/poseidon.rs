//! Proves knowledge of a Poseidon hash preimage and writes the four Plutus
//! test-vector files to disk.
//!
//! Circuit: given public Poseidon digest h, prove knowledge of [w0, w1, w2]
//! such that h = Poseidon(w0, w1, w2).
//!
//! Output: {base_dir}/poseidon/
//!   poseidon_plutus_vk.json       – extended Plutus VK
//!   poseidon_circuit_params.json  – 10 circuit-structure scalars
//!   poseidon_rotation_sets.json   – rotation set metadata
//!   poseidon_plutus_proof.json    – structured GWC proof
//!   poseidon_plutus_instance.json – public inputs as 32-byte LE hex strings

use ff::Field;
use group::GroupEncoding;
use midnight_circuits::{
    hash::poseidon::PoseidonChip,
    instructions::{hash::HashCPU, AssignmentInstructions, PublicInputInstructions},
};
use midnight_proofs::{circuit::{Layouter, Value}, plonk::Error};
use midnight_zk_stdlib::{utils::plonk_api::filecoin_srs, Relation, ZkStdLib, ZkStdLibArch};
use rand::rngs::OsRng;
use rand::SeedableRng;
use rand_chacha::ChaCha8Rng;
use crate::circuit_params::write_json_all_artifacts;

type F = midnight_curves::Fq;

#[derive(Clone, Default)]
pub struct PoseidonExample;

impl Relation for PoseidonExample {
    type Error = Error;
    type Instance = F;
    type Witness = [F; 3];

    fn format_instance(instance: &Self::Instance) -> Result<Vec<F>, Error> {
        Ok(vec![*instance])
    }

    fn circuit(
        &self,
        std_lib: &ZkStdLib,
        layouter: &mut impl Layouter<F>,
        _instance: Value<Self::Instance>,
        witness: Value<Self::Witness>,
    ) -> Result<(), Error> {
        let assigned_message = std_lib.assign_many(layouter, &witness.transpose_array())?;
        let output = std_lib.poseidon(layouter, &assigned_message)?;
        std_lib.constrain_as_public_input(layouter, &output)
    }

    fn used_chips(&self) -> ZkStdLibArch {
        ZkStdLibArch { poseidon: true, ..ZkStdLibArch::default() }
    }

    fn write_relation<W: std::io::Write>(&self, _writer: &mut W) -> std::io::Result<()> {
        Ok(())
    }

    fn read_relation<R: std::io::Read>(_reader: &mut R) -> std::io::Result<Self> {
        Ok(PoseidonExample)
    }
}

pub fn run(base_dir: &str) {
    const K: u32 = 6;
    let srs = filecoin_srs(K);

    let relation = PoseidonExample;
    let vk = midnight_zk_stdlib::setup_vk(&srs, &relation);
    let pk = midnight_zk_stdlib::setup_pk(&relation, &vk);

    let mut rng = ChaCha8Rng::from_entropy();
    let witness: [F; 3] = core::array::from_fn(|_| F::random(&mut rng));
    let instance = <PoseidonChip<F> as HashCPU<F, F>>::hash(&witness);

    let proof = midnight_zk_stdlib::prove::<
        PoseidonExample,
        midnight_proofs::transcript::Blake2b256,
    >(&srs, &pk, &relation, &instance, witness, OsRng)
    .expect("proof generation failed");

    assert!(
        midnight_zk_stdlib::verify::<
            PoseidonExample,
            midnight_proofs::transcript::Blake2b256,
        >(&srs.verifier_params(), &vk, &instance, None, &proof).is_ok(),
        "internal verify failed"
    );

    let pi = PoseidonExample::format_instance(&instance).expect("format_instance failed");
    write_json_all_artifacts(
        &format!("{base_dir}/poseidon"),
        "poseidon",
        vk.vk(),
        srs.s_g2().to_bytes().as_ref(),
        &proof,
        &pi,
    );
}
