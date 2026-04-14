//! Proves knowledge of a JubJub scalar w such that result = w·G + 0·H, and
//! writes the four Plutus test-vector files to disk.
//!
//! Circuit: given public JubJub point P = w·G (two Fq coordinates), prove
//! knowledge of scalar w.
//!
//! Output: {base_dir}/ecc/
//!   ecc_plutus_vk.json       – extended Plutus VK
//!   ecc_circuit_params.json  – 10 circuit-structure scalars
//!   ecc_rotation_sets.json   – rotation set metadata
//!   ecc_plutus_proof.json    – structured GWC proof
//!   ecc_plutus_instance.json – public inputs as 32-byte LE hex strings

use ff::Field;
use group::{Group, GroupEncoding};
use midnight_circuits::{
    ecc::{curves::CircuitCurve, native::AssignedScalarOfNativeCurve},
    instructions::{
        AssignmentInstructions, ConversionInstructions, EccInstructions, PublicInputInstructions,
    },
    types::{AssignedNativePoint, Instantiable},
};
use midnight_curves::{Fr as JubjubScalar, JubjubExtended as Jubjub, JubjubSubgroup};
use midnight_proofs::{circuit::{Layouter, Value}, plonk::Error};
use midnight_zk_stdlib::{utils::plonk_api::filecoin_srs, Relation, ZkStdLib, ZkStdLibArch};
use rand::rngs::OsRng;
use crate::circuit_params::write_json_all_artifacts;

type F = midnight_curves::Fq;

#[derive(Clone, Default)]
pub struct EccExample;

impl Relation for EccExample {
    type Error = Error;
    type Instance = JubjubSubgroup;
    type Witness = JubjubScalar;

    fn format_instance(instance: &Self::Instance) -> Result<Vec<F>, Error> {
        Ok(AssignedNativePoint::<Jubjub>::as_public_input(instance))
    }

    fn circuit(
        &self,
        std_lib: &ZkStdLib,
        layouter: &mut impl Layouter<F>,
        _instance: Value<Self::Instance>,
        witness: Value<Self::Witness>,
    ) -> Result<(), Error> {
        let scalar = std_lib.jubjub().assign(layouter, witness)?;

        let native_value = std_lib.assign(layouter, Value::known(F::default()))?;
        let scalar_from_native: AssignedScalarOfNativeCurve<Jubjub> =
            std_lib.jubjub().convert(layouter, &native_value)?;

        let generator: AssignedNativePoint<Jubjub> = std_lib
            .jubjub()
            .assign_fixed(layouter, <JubjubSubgroup as Group>::generator())?;

        let one = std_lib.assign_fixed(layouter, <Jubjub as CircuitCurve>::Base::ONE)?;
        let extra_base = std_lib.hash_to_curve(layouter, &[one])?;

        let result = std_lib.jubjub().msm(
            layouter,
            &[scalar, scalar_from_native],
            &[generator, extra_base],
        )?;

        std_lib.jubjub().constrain_as_public_input(layouter, &result)
    }

    fn used_chips(&self) -> ZkStdLibArch {
        ZkStdLibArch {
            jubjub: true,
            poseidon: true,
            ..ZkStdLibArch::default()
        }
    }

    fn write_relation<W: std::io::Write>(&self, _writer: &mut W) -> std::io::Result<()> {
        Ok(())
    }

    fn read_relation<R: std::io::Read>(_reader: &mut R) -> std::io::Result<Self> {
        Ok(EccExample)
    }
}

pub fn run(base_dir: &str) {
    const K: u32 = 11;
    let srs = filecoin_srs(K);

    let relation = EccExample;
    let vk = midnight_zk_stdlib::setup_vk(&srs, &relation);
    let pk = midnight_zk_stdlib::setup_pk(&relation, &vk);

    let witness = JubjubScalar::random(&mut OsRng);
    let instance = JubjubSubgroup::generator() * witness;

    let proof = midnight_zk_stdlib::prove::<
        EccExample,
        midnight_proofs::transcript::Blake2b256,
    >(&srs, &pk, &relation, &instance, witness, OsRng)
    .expect("proof generation failed");

    assert!(
        midnight_zk_stdlib::verify::<
            EccExample,
            midnight_proofs::transcript::Blake2b256,
        >(&srs.verifier_params(), &vk, &instance, None, &proof).is_ok(),
        "internal verify failed"
    );

    let pi = EccExample::format_instance(&instance).expect("format_instance failed");
    write_json_all_artifacts(
        &format!("{base_dir}/ecc"),
        "ecc",
        vk.vk(),
        srs.s_g2().to_bytes().as_ref(),
        &proof,
        &pi,
    );
}
