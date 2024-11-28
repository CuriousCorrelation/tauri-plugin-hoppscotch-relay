use thiserror::Error;

#[derive(Debug, Error, Clone)]
pub enum RelayError {
    #[error("Invalid method")]
    InvalidMethod,

    #[error("Invalid URL")]
    InvalidUrl,

    #[error("Invalid headers")]
    InvalidHeaders,

    #[error("Request cancelled")]
    RequestCancelled,

    #[error("Certificate rrror")]
    CertificateError,

    #[error("Request run error: {0}")]
    RequestRunError(String),

    #[error("Curl error: {0}")]
    Curl(#[from] curl::Error),

    #[error("Unsupported `Content-Type`")]
    UnsupportedContent,

    #[error("Request not found")]
    RequestNotFound,
}

pub type RelayResult<T> = std::result::Result<T, RelayError>;
