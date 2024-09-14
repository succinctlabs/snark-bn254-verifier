use bn::{CurveError, FieldError, GroupError};
use thiserror::Error;

#[derive(Error, Debug)]
pub enum Error {
    // Cryptographic Errors
    #[error("BSB22 Commitment number mismatch")]
    Bsb22CommitmentMismatch,
    #[error("Challenge already computed")]
    ChallengeAlreadyComputed,
    #[error("Challenge not found")]
    ChallengeNotFound,
    #[error("Previous challenge not computed")]
    PreviousChallengeNotComputed,
    #[error("Pairing check failed")]
    PairingCheckFailed,
    #[error("Invalid point in subgroup check")]
    InvalidPoint,

    // Mathematical Errors
    #[error("Beyond the modulus")]
    BeyondTheModulus,
    #[error("Ell too large")]
    EllTooLarge,
    #[error("Inverse not found")]
    InverseNotFound,
    #[error("Opening linear polynomial mismatch")]
    OpeningPolyMismatch,

    // Input Errors
    #[error("DST too large")]
    DSTTooLarge,
    #[error("Invalid number of digests")]
    InvalidNumberOfDigests,
    #[error("Invalid witness")]
    InvalidWitness,
    #[error("Invalid x length")]
    InvalidXLength,
    #[error("Unexpected flag")]
    UnexpectedFlag,
    #[error("Invalid data")]
    InvalidData,

    // Conversion Errors
    #[error("Failed to get Fr from random bytes")]
    FailedToGetFrFromRandomBytes,
    #[error("Failed to get x")]
    FailedToGetX,
    #[error("Failed to get y")]
    FailedToGetY,

    // External Library Errors
    #[error("Field Error")]
    FieldError(FieldError),
    #[error("Group Error")]
    GroupError(GroupError),
    #[error("Curve Error")]
    CurveError(CurveError),

    // Serialization Errors
    #[error("Serialization Error")]
    SerializationError,
}
