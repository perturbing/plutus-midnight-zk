//! Proves knowledge of a SHA-256 preimage and writes the four Plutus test-vector
//! files to disk.
//!
//! Circuit: given public SHA-256 digest x, prove knowledge of w ∈ {0,1}^192
//! such that x = SHA-256(w).
//!
//! Output: {base_dir}/sha-preimage/
//!   sha_preimage_plutus_vk.json       – extended Plutus VK
//!   sha_preimage_circuit_params.json  – 10 circuit-structure scalars
//!   sha_preimage_rotation_sets.json   – rotation set metadata
//!   sha_preimage_plutus_proof.json    – structured GWC proof
//!   sha_preimage_plutus_instance.json – public inputs as 32-byte LE hex strings

use group::GroupEncoding;
use midnight_circuits::{
    instructions::{AssignmentInstructions, PublicInputInstructions},
    types::{AssignedByte, Instantiable},
};
use midnight_proofs::{circuit::{Layouter, Value}, plonk::Error};
use midnight_zk_stdlib::{utils::plonk_api::filecoin_srs, Relation, ZkStdLib, ZkStdLibArch};
use rand::rngs::OsRng;
use sha2::Digest;
use crate::circuit_params::write_json_all_artifacts;

type F = midnight_curves::Fq;

const K: u32 = 13;

#[derive(Clone, Default)]
pub struct ShaPreImageCircuit;

impl Relation for ShaPreImageCircuit {
    type Error = Error;
    type Instance = [u8; 32];
    type Witness = [u8; 24]; // 192-bit preimage

    fn format_instance(instance: &Self::Instance) -> Result<Vec<F>, Error> {
        Ok(instance.iter().flat_map(AssignedByte::<F>::as_public_input).collect())
    }

    fn circuit(
        &self,
        std_lib: &ZkStdLib,
        layouter: &mut impl Layouter<F>,
        _instance: Value<Self::Instance>,
        witness: Value<Self::Witness>,
    ) -> Result<(), Error> {
        let witness_bytes = witness.transpose_array();
        let assigned_input = std_lib.assign_many(layouter, &witness_bytes)?;
        let output = std_lib.sha2_256(layouter, &assigned_input)?;
        output.iter().try_for_each(|b| std_lib.constrain_as_public_input(layouter, b))
    }

    fn used_chips(&self) -> ZkStdLibArch {
        ZkStdLibArch { sha2_256: true, ..ZkStdLibArch::default() }
    }

    fn write_relation<W: std::io::Write>(&self, _writer: &mut W) -> std::io::Result<()> {
        Ok(())
    }

    fn read_relation<R: std::io::Read>(_reader: &mut R) -> std::io::Result<Self> {
        Ok(ShaPreImageCircuit)
    }
}

pub fn run(base_dir: &str) {
    let srs = filecoin_srs(K);

    let relation = ShaPreImageCircuit;
    let vk = midnight_zk_stdlib::setup_vk(&srs, &relation);
    let pk = midnight_zk_stdlib::setup_pk(&relation, &vk);

    let mut witness = [0u8; 24];
    let preimage = b"hello world";
    witness[..preimage.len()].copy_from_slice(preimage);

    let instance: [u8; 32] = sha2::Sha256::digest(witness).into();
    let proof = midnight_zk_stdlib::prove::<
        ShaPreImageCircuit,
        midnight_proofs::transcript::Blake2b256,
    >(&srs, &pk, &relation, &instance, witness, OsRng)
    .expect("proof generation failed");

    assert!(
        midnight_zk_stdlib::verify::<
            ShaPreImageCircuit,
            midnight_proofs::transcript::Blake2b256,
        >(&srs.verifier_params(), &vk, &instance, None, &proof).is_ok(),
        "internal verify failed"
    );

    let pi = ShaPreImageCircuit::format_instance(&instance).expect("format_instance failed");
    write_json_all_artifacts(
        &format!("{base_dir}/sha-preimage"),
        "sha_preimage",
        vk.vk(),
        srs.s_g2().to_bytes().as_ref(),
        &proof,
        &pi,
    );
}
