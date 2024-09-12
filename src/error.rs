use thiserror::Error;

#[derive(Error, Debug)]
pub enum Error {
    #[error("Beyond the modulus")]
    BeyondTheModulus,
    #[error("BSB22 Commitment number mismatch")]
    Bsb22CommitmentMismatch,
    #[error("Challenge already computed")]
    ChallengeAlreadyComputed,
    #[error("Challenge not found")]
    ChallengeNotFound,
    #[error("DST too large")]
    DSTTooLarge,
    #[error("Ell too large")]
    EllTooLarge,
    #[error("Failed to get Fr from random bytes")]
    FailedToGetFrFromRandomBytes,
    #[error("Failed to get x")]
    FailedToGetX,
    #[error("Failed to get y")]
    FailedToGetY,
    #[error("Inverse not found")]
    InverseNotFound,
    #[error("Invalid number of digests")]
    InvalidNumberOfDigests,
    #[error("Invalid point in subgroup check")]
    InvalidPoint,
    #[error("Invalid witness")]
    InvalidWitness,
    #[error("Invalid x length")]
    InvalidXLength,
    #[error("Opening linear polynomial mismatch")]
    OpeningPolyMismatch,
    #[error("Pairing check failed")]
    PairingCheckFailed,
    #[error("Previous challenge not computed")]
    PreviousChallengeNotComputed,
    #[error("Unexpected flag")]
    UnexpectedFlag,
}
