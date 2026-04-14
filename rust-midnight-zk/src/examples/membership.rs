//! Demonstrates multi-set membership using the MapChip in ZkStdLib, and writes
//! the Plutus test-vector files to disk.
//!
//! Membership in set S_i is indicated by a 1 in the i-th bit of a field element.
//! The proof shows membership in a subset of sets without revealing full membership.
//!
//! Output: {base_dir}/membership/
//!   membership_plutus_vk.json       – extended Plutus VK
//!   membership_circuit_params.json  – 10 circuit-structure scalars
//!   membership_rotation_sets.json   – rotation set metadata
//!   membership_plutus_proof.json    – structured GWC proof
//!   membership_plutus_instance.json – public inputs as 32-byte LE hex strings

use ff::{Field, PrimeField};
use group::GroupEncoding;
use midnight_circuits::{
    field::AssignedNative,
    hash::poseidon::PoseidonChip,
    instructions::{
        map::{MapCPU, MapInstructions},
        AssertionInstructions, AssignmentInstructions, BitwiseInstructions,
        PublicInputInstructions,
    },
    map::cpu::MapMt,
};
use midnight_proofs::{circuit::{Layouter, Value}, plonk::Error};
use midnight_zk_stdlib::{utils::plonk_api::filecoin_srs, Relation, ZkStdLib, ZkStdLibArch};
use rand::rngs::OsRng;
use crate::circuit_params::write_json_all_artifacts;

type F = midnight_curves::Fq;
type SuccinctRepr = F;
type Set = F;
type Map = MapMt<F, PoseidonChip<F>>;

#[derive(Clone, Default)]
pub struct MembershipExample;

impl Relation for MembershipExample {
    type Error = Error;
    type Instance = (SuccinctRepr, Set);
    type Witness = (F, Set, Map);

    fn format_instance(instance: &Self::Instance) -> Result<Vec<F>, Error> {
        Ok(vec![instance.0, instance.1])
    }

    fn circuit(
        &self,
        std_lib: &ZkStdLib,
        layouter: &mut impl Layouter<F>,
        instance: Value<Self::Instance>,
        witness: Value<Self::Witness>,
    ) -> Result<(), Error> {
        let element = std_lib.assign(layouter, witness.clone().map(|(element, _, _)| element))?;
        let member_sets = std_lib.assign(
            layouter,
            witness.clone().map(|(_, member_sets, _)| member_sets),
        )?;

        let mut map = std_lib.map_gadget().clone();
        map.init(layouter, witness.map(|(_, _, mt_map)| mt_map))?;

        std_lib.constrain_as_public_input(layouter, &map.succinct_repr())?;
        let proven_sets: AssignedNative<F> = std_lib
            .assign_as_public_input(layouter, instance.map(|(_, proven_sets)| proven_sets))?;

        let value = map.get(layouter, &element)?;
        std_lib.assert_equal(layouter, &value, &member_sets)?;

        let res = std_lib.band(layouter, &proven_sets, &member_sets, F::NUM_BITS as usize)?;
        std_lib.assert_equal(layouter, &res, &proven_sets)
    }

    fn used_chips(&self) -> ZkStdLibArch {
        ZkStdLibArch {
            poseidon: true,
            ..ZkStdLibArch::default()
        }
    }

    fn write_relation<W: std::io::Write>(&self, _writer: &mut W) -> std::io::Result<()> {
        Ok(())
    }

    fn read_relation<R: std::io::Read>(_reader: &mut R) -> std::io::Result<Self> {
        Ok(MembershipExample)
    }
}

pub fn run(base_dir: &str) {
    const K: u32 = 13;
    let srs = filecoin_srs(K);

    let relation = MembershipExample;
    let vk = midnight_zk_stdlib::setup_vk(&srs, &relation);
    let pk = midnight_zk_stdlib::setup_pk(&relation, &vk);

    let mut mt = MapMt::<F, PoseidonChip<F>>::new(&F::ZERO);

    // Insert 100 values in set 7 (bit index 7).
    for _ in 0..100 {
        mt.insert(&F::random(OsRng), &F::from(0b1000_0000));
    }

    // Insert F::ONE in sets 3, 5, and 7.
    mt.insert(&F::ONE, &F::from(0b1010_1000));

    // Prove membership in sets 3 and 7 only, without revealing membership in set 5.
    let proof_set = F::from(0b1000_1000);

    let mut sets_bytes = <F as PrimeField>::Repr::default();
    sets_bytes.as_mut()[0] = 0b1010_1000;
    let sets = F::from_repr(sets_bytes).unwrap();

    let witness = (F::ONE, sets, mt.clone());
    let instance = (mt.succinct_repr(), proof_set);

    let proof = midnight_zk_stdlib::prove::<
        MembershipExample,
        midnight_proofs::transcript::Blake2b256,
    >(&srs, &pk, &relation, &instance, witness, OsRng)
    .expect("proof generation failed");

    assert!(
        midnight_zk_stdlib::verify::<
            MembershipExample,
            midnight_proofs::transcript::Blake2b256,
        >(&srs.verifier_params(), &vk, &instance, None, &proof).is_ok(),
        "internal verify failed"
    );

    let pi = MembershipExample::format_instance(&instance).expect("format_instance failed");
    write_json_all_artifacts(
        &format!("{base_dir}/membership"),
        "membership",
        vk.vk(),
        srs.s_g2().to_bytes().as_ref(),
        &proof,
        &pi,
    );
}
