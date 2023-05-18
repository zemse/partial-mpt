use ethers::core::utils::rlp;

#[derive(Debug)]
pub enum Error {
    RlpDecoderError(rlp::DecoderError),
    InternalError(&'static str),
}

impl From<rlp::DecoderError> for Error {
    fn from(err: rlp::DecoderError) -> Self {
        Error::RlpDecoderError(err)
    }
}
