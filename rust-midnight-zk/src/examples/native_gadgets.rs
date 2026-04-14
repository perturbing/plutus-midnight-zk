//! Demonstrates native arithmetic/bitwise/control-flow gadgets in ZkStdLib, and
//! writes the Plutus test-vector files to disk.
//!
//! Output: {base_dir}/native-gadgets/
//!   native_gadgets_plutus_vk.json       – extended Plutus VK
//!   native_gadgets_circuit_params.json  – 10 circuit-structure scalars
//!   native_gadgets_rotation_sets.json   – rotation set metadata
//!   native_gadgets_plutus_proof.json    – structured GWC proof
//!   native_gadgets_plutus_instance.json – public inputs as 32-byte LE hex strings

use ff::Field;
use group::GroupEncoding;
use midnight_circuits::instructions::{
    ArithInstructions, AssertionInstructions, AssignmentInstructions, BinaryInstructions,
    BitwiseInstructions, ControlFlowInstructions, DecompositionInstructions,
    PublicInputInstructions,
};
use midnight_proofs::{circuit::{Layouter, Value}, plonk::Error};
use midnight_zk_stdlib::{utils::plonk_api::filecoin_srs, Relation, ZkStdLib};
use rand::rngs::OsRng;
use crate::circuit_params::write_json_all_artifacts;

type F = midnight_curves::Fq;

#[derive(Clone, Default)]
pub struct NativeGadgetExample;

impl Relation for NativeGadgetExample {
    type Error = Error;
    type Instance = F;
    type Witness = (F, F);

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
        let (a, b) = witness.unzip();
        let x = std_lib.assign(layouter, a)?;
        let y = std_lib.assign(layouter, b)?;

        let bit = std_lib.assign_fixed(layouter, true)?;

        let and_result = std_lib.band(layouter, &x, &y, 5)?;
        let nand_result = std_lib.bnot(layouter, &and_result, 5)?;

        std_lib.band(layouter, &x, &y, 16)?;
        std_lib.bor(layouter, &x, &y, 16)?;
        std_lib.bxor(layouter, &x, &y, 16)?;
        std_lib.bnot(layouter, &x, 16)?;

        let x_y = std_lib.mul(layouter, &x, &y, None)?;
        let y_x = std_lib.mul(layouter, &y, &x, None)?;
        std_lib.assert_equal(layouter, &x_y, &y_x)?;

        let bits = std_lib.assigned_to_le_bits(layouter, &x, None, true)?;
        std_lib.assigned_to_be_bits(layouter, &y, Some(9), false)?;
        std_lib.assigned_from_le_bits(layouter, &bits)?;
        let _ = std_lib.and(layouter, &bits)?;
        let _ = std_lib.or(layouter, &bits)?;
        let _ = std_lib.xor(layouter, &bits)?;

        let _ = std_lib.add_and_mul(
            layouter,
            (F::ONE, &x),
            (F::ONE, &y),
            (F::ZERO, &x),
            F::ZERO,
            F::ONE,
        )?;

        let bytes = std_lib.assigned_to_be_bytes(layouter, &x, Some(1))?;
        std_lib.assigned_from_be_bytes(layouter, &bytes)?;

        let _ = std_lib.lower_than(layouter, &x, &y, 16)?;

        let not_bit = std_lib.not(layouter, &bit)?;
        let new_y = std_lib.select(layouter, &not_bit, &x, &y)?;
        std_lib.cond_assert_equal(layouter, &bit, &new_y, &y)?;

        std_lib.constrain_as_public_input(layouter, &nand_result)
    }

    fn write_relation<W: std::io::Write>(&self, _writer: &mut W) -> std::io::Result<()> {
        Ok(())
    }

    fn read_relation<R: std::io::Read>(_reader: &mut R) -> std::io::Result<Self> {
        Ok(NativeGadgetExample)
    }
}

pub fn run(base_dir: &str) {
    const K: u32 = 11;
    let srs = filecoin_srs(K);

    let relation = NativeGadgetExample;
    let vk = midnight_zk_stdlib::setup_vk(&srs, &relation);
    let pk = midnight_zk_stdlib::setup_pk(&relation, &vk);

    let witness = {
        let a = F::from(30); // 01111
        let b = F::from(15); // 11110
        (a, b)
    };
    let instance = F::from(17); // 10001 (a nand b)

    let proof = midnight_zk_stdlib::prove::<
        NativeGadgetExample,
        midnight_proofs::transcript::Blake2b256,
    >(&srs, &pk, &relation, &instance, witness, OsRng)
    .expect("proof generation failed");

    assert!(
        midnight_zk_stdlib::verify::<
            NativeGadgetExample,
            midnight_proofs::transcript::Blake2b256,
        >(&srs.verifier_params(), &vk, &instance, None, &proof).is_ok(),
        "internal verify failed"
    );

    let pi = NativeGadgetExample::format_instance(&instance).expect("format_instance failed");
    write_json_all_artifacts(
        &format!("{base_dir}/native-gadgets"),
        "native_gadgets",
        vk.vk(),
        srs.s_g2().to_bytes().as_ref(),
        &proof,
        &pi,
    );
}
