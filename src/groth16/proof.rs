use substrate_bn::{AffineG1, AffineG2};

#[derive(Debug)]
pub(crate) struct Groth16Proof {
    pub(crate) ar: AffineG1,
    pub(crate) krs: AffineG1,
    pub(crate) bs: AffineG2,
    pub(crate) commitments: Vec<AffineG1>,
    pub(crate) commitment_pok: AffineG1,
}
