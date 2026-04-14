//! Demonstrates a Schnorr signature scheme using Poseidon (native hash) and
//! JubJub (native curve), and writes the Plutus test-vector files to disk.
//!
//! Output: {base_dir}/schnorr-sig/
//!   schnorr_sig_plutus_vk.json       – extended Plutus VK
//!   schnorr_sig_circuit_params.json  – 10 circuit-structure scalars
//!   schnorr_sig_rotation_sets.json   – rotation set metadata
//!   schnorr_sig_plutus_proof.json    – structured GWC proof
//!   schnorr_sig_plutus_instance.json – public inputs as 32-byte LE hex strings

use ff::Field;
use group::{Group, GroupEncoding};
use midnight_circuits::{
    ecc::native::AssignedScalarOfNativeCurve,
    hash::poseidon::PoseidonChip,
    instructions::{
        hash::HashCPU, AssertionInstructions, AssignmentInstructions, DecompositionInstructions,
        EccInstructions, PublicInputInstructions,
    },
    types::{AssignedNativePoint, Instantiable},
};
use midnight_curves::{Fr as JubjubScalar, JubjubAffine, JubjubExtended as Jubjub, JubjubSubgroup};
use midnight_proofs::{circuit::{Layouter, Value}, plonk::Error};
use midnight_zk_stdlib::{utils::plonk_api::filecoin_srs, Relation, ZkStdLib, ZkStdLibArch};
use rand::{RngCore, SeedableRng, rngs::OsRng};
use rand_chacha::ChaCha8Rng;
use crate::circuit_params::write_json_all_artifacts;

type F = midnight_curves::Fq;
type SchnorrPK = JubjubSubgroup;
type SchnorrSK = JubjubScalar;
type Message = F;

#[derive(Clone, Default)]
pub struct SchnorrSignature {
    s: JubjubScalar,
    e_bytes: [u8; 32],
}

fn keygen(mut rng: impl RngCore) -> (SchnorrPK, SchnorrSK) {
    let sk = JubjubScalar::random(&mut rng);
    let pk = JubjubSubgroup::generator() * sk;
    (pk, sk)
}

fn sign(message: Message, secret_key: &SchnorrSK, mut rng: impl RngCore) -> SchnorrSignature {
    let k = JubjubScalar::random(&mut rng);
    let r = JubjubSubgroup::generator() * k;

    let (rx, ry) = get_coords(&r);
    let (pkx, pky) = get_coords(&(JubjubSubgroup::generator() * secret_key));

    let h = PoseidonChip::hash(&[pkx, pky, rx, ry, message]);
    let e_bytes = h.to_bytes_le();

    let s = {
        let mut buff = [0u8; 64];
        buff[..32].copy_from_slice(&e_bytes);
        let e = JubjubScalar::from_bytes_wide(&buff);
        k - e * secret_key
    };

    SchnorrSignature { s, e_bytes }
}

fn verify_schnorr(sig: &SchnorrSignature, pk: &SchnorrPK, m: Message) -> bool {
    let mut buff = [0u8; 64];
    buff[..32].copy_from_slice(&sig.e_bytes);
    let e = JubjubScalar::from_bytes_wide(&buff);

    let rv = JubjubSubgroup::generator() * sig.s + pk * e;

    let (rx, ry) = get_coords(&rv);
    let (pkx, pky) = get_coords(pk);

    let h = PoseidonChip::hash(&[pkx, pky, rx, ry, m]);
    h.to_bytes_le() == sig.e_bytes
}

fn get_coords(point: &JubjubSubgroup) -> (F, F) {
    let point: &Jubjub = point.into();
    let point: JubjubAffine = point.into();
    (point.get_u(), point.get_v())
}

#[derive(Clone, Default)]
pub struct SchnorrExample;

impl Relation for SchnorrExample {
    type Error = Error;
    type Instance = (SchnorrPK, Message);
    type Witness = SchnorrSignature;

    fn format_instance((pk, msg): &Self::Instance) -> Result<Vec<F>, Error> {
        Ok([
            AssignedNativePoint::<Jubjub>::as_public_input(pk),
            vec![*msg],
        ]
        .concat())
    }

    fn circuit(
        &self,
        std_lib: &ZkStdLib,
        layouter: &mut impl Layouter<F>,
        instance: Value<Self::Instance>,
        witness: Value<Self::Witness>,
    ) -> Result<(), Error> {
        let jubjub = &std_lib.jubjub();

        let (pk_val, m_val) = instance.map(|(pk, m)| (pk, m)).unzip();
        let pk: AssignedNativePoint<Jubjub> = jubjub.assign_as_public_input(layouter, pk_val)?;
        let message = std_lib.assign_as_public_input(layouter, m_val)?;

        let (sig_s_val, sig_e_bytes_val) = witness.map(|sig| (sig.s, sig.e_bytes)).unzip();
        let sig_s: AssignedScalarOfNativeCurve<Jubjub> =
            std_lib.jubjub().assign(layouter, sig_s_val)?;
        let sig_e_bytes = std_lib.assign_many(layouter, &sig_e_bytes_val.transpose_array())?;

        let generator: AssignedNativePoint<Jubjub> =
            (std_lib.jubjub()).assign_fixed(layouter, <JubjubSubgroup as Group>::generator())?;

        let sig_e = std_lib.jubjub().scalar_from_le_bytes(layouter, &sig_e_bytes)?;

        // rv = s * G + e * Pk
        let rv =
            (std_lib.jubjub()).msm(layouter, &[sig_s, sig_e.clone()], &[generator, pk.clone()])?;

        let coords = |p| (jubjub.x_coordinate(p), jubjub.y_coordinate(p));
        let (pkx, pky) = coords(&pk);
        let (rx, ry) = coords(&rv);

        // ev = hash( PK.x || PK.y || r.x || r.y || m)
        let h = std_lib.poseidon(layouter, &[pkx, pky, rx, ry, message])?;
        let ev_bytes = std_lib.assigned_to_le_bytes(layouter, &h, None)?;

        assert_eq!(ev_bytes.len(), sig_e_bytes.len());
        (ev_bytes.iter().zip(sig_e_bytes.iter()))
            .try_for_each(|(ev, e)| std_lib.assert_equal(layouter, ev, e))
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
        Ok(SchnorrExample)
    }
}

pub fn run(base_dir: &str) {
    const K: u32 = 11;
    let srs = filecoin_srs(K);
    let mut rng = ChaCha8Rng::seed_from_u64(0xf001ba11);

    let relation = SchnorrExample;
    let vk = midnight_zk_stdlib::setup_vk(&srs, &relation);
    let pk_circuit = midnight_zk_stdlib::setup_pk(&relation, &vk);

    let (schnorr_pk, sk) = keygen(&mut rng);
    let m = F::random(&mut rng);
    let sig = sign(m, &sk, &mut rng);

    assert!(verify_schnorr(&sig, &schnorr_pk, m));

    let instance = (schnorr_pk, m);
    let witness = sig;

    let proof = midnight_zk_stdlib::prove::<
        SchnorrExample,
        midnight_proofs::transcript::Blake2b256,
    >(&srs, &pk_circuit, &relation, &instance, witness, OsRng)
    .expect("proof generation failed");

    assert!(
        midnight_zk_stdlib::verify::<
            SchnorrExample,
            midnight_proofs::transcript::Blake2b256,
        >(&srs.verifier_params(), &vk, &instance, None, &proof).is_ok(),
        "internal verify failed"
    );

    let pi = SchnorrExample::format_instance(&instance).expect("format_instance failed");
    write_json_all_artifacts(
        &format!("{base_dir}/schnorr-sig"),
        "schnorr_sig",
        vk.vk(),
        srs.s_g2().to_bytes().as_ref(),
        &proof,
        &pi,
    );
}
