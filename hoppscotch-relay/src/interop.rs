use bytes::Bytes;
use chrono::{DateTime, Utc};
use curl::easy::{Handler, WriteError};
use futures::Stream;
use serde::{Deserialize, Serialize};
use serde_json::Value;
use std::collections::HashMap;
use std::fmt;
use std::pin::Pin;
use strum::Display;
use url::Url;

#[derive(Debug, Clone, Serialize, Deserialize, Display)]
#[serde(rename_all = "UPPERCASE")]
pub enum Method {
    Get,
    Post,
    Put,
    Delete,
    Patch,
    Head,
    Options,
    Connect,
    Trace,
}

#[derive(Serialize, Deserialize)]
#[serde(tag = "kind", content = "content")]
pub enum ContentType {
    Text {
        content: String,
        #[serde(skip_serializing_if = "Option::is_none")]
        media_type: Option<String>,
    },
    Json(Value),
    Form(Vec<(String, String)>),
    Binary {
        content: Vec<u8>,
        #[serde(skip_serializing_if = "Option::is_none")]
        media_type: Option<String>,
    },
    Multipart(Vec<(String, Vec<u8>)>),
    Urlencoded(HashMap<String, String>),
    #[serde(skip)]
    Stream(Pin<Box<dyn Stream<Item = Result<Bytes, std::io::Error>> + Send + 'static>>),
}

impl fmt::Debug for ContentType {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            ContentType::Text {
                content,
                media_type,
            } => f
                .debug_struct("Text")
                .field("content", content)
                .field("media_type", media_type)
                .finish(),
            ContentType::Json(value) => f.debug_tuple("Json").field(value).finish(),
            ContentType::Form(data) => f.debug_tuple("Form").field(data).finish(),
            ContentType::Binary {
                content,
                media_type,
            } => f
                .debug_struct("Binary")
                .field("content", &format!("<{} bytes>", content.len()))
                .field("media_type", media_type)
                .finish(),
            ContentType::Multipart(parts) => f
                .debug_tuple("Multipart")
                .field(
                    &parts
                        .iter()
                        .map(|(name, data)| (name, format!("<{} bytes>", data.len())))
                        .collect::<Vec<_>>(),
                )
                .finish(),
            ContentType::Urlencoded(data) => f.debug_tuple("Urlencoded").field(data).finish(),
            ContentType::Stream(_) => write!(f, "Stream(<streaming data>)"),
        }
    }
}

impl Clone for ContentType {
    fn clone(&self) -> Self {
        match self {
            ContentType::Text {
                content,
                media_type,
            } => ContentType::Text {
                content: content.clone(),
                media_type: media_type.clone(),
            },
            ContentType::Json(value) => ContentType::Json(value.clone()),
            ContentType::Form(data) => ContentType::Form(data.clone()),
            ContentType::Binary {
                content,
                media_type,
            } => ContentType::Binary {
                content: content.clone(),
                media_type: media_type.clone(),
            },
            ContentType::Multipart(parts) => ContentType::Multipart(parts.clone()),
            ContentType::Urlencoded(data) => ContentType::Urlencoded(data.clone()),
            ContentType::Stream(_) => {
                panic!("Cannot clone streaming content - streams are not clonable")
            }
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "kind")]
pub enum AuthType {
    None,
    Basic {
        username: String,
        password: String,
    },
    Bearer {
        token: String,
    },
    Digest {
        username: String,
        password: String,
        #[serde(skip_serializing_if = "Option::is_none")]
        realm: Option<String>,
        #[serde(skip_serializing_if = "Option::is_none")]
        nonce: Option<String>,
        #[serde(skip_serializing_if = "Option::is_none")]
        opaque: Option<String>,
        #[serde(skip_serializing_if = "Option::is_none")]
        algorithm: Option<DigestAlgorithm>,
        #[serde(skip_serializing_if = "Option::is_none")]
        qop: Option<DigestQop>,
    },
    OAuth2 {
        access_token: String,
        #[serde(skip_serializing_if = "Option::is_none")]
        token_type: Option<String>,
        #[serde(skip_serializing_if = "Option::is_none")]
        refresh_token: Option<String>,
    },
    ApiKey {
        key: String,
        r#in: ApiKeyLocation,
        name: String,
    },
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "UPPERCASE")]
pub enum DigestAlgorithm {
    Md5,
    Sha256,
    Sha512,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum DigestQop {
    Auth,
    AuthInt,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum ApiKeyLocation {
    Header,
    Query,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "kind")]
pub enum CertificateType {
    Pem { cert: Vec<u8>, key: Vec<u8> },
    Pfx { data: Vec<u8>, password: String },
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Security {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub certificates: Option<Certificates>,
    #[serde(default)]
    pub validate_certificates: bool,
    #[serde(default)]
    pub verify_host: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Certificates {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub client: Option<CertificateType>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub ca: Option<Vec<Vec<u8>>>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Proxy {
    pub url: Url,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub auth: Option<ProxyAuth>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub certificates: Option<ProxyCertificates>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProxyAuth {
    pub username: String,
    pub password: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProxyCertificates {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub ca: Option<Vec<u8>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub client: Option<CertificateType>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RequestOptions {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub timeout: Option<std::time::Duration>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub timeout_connect: Option<std::time::Duration>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub timeout_tls: Option<std::time::Duration>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub follow_redirects: Option<bool>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub max_redirects: Option<u32>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub retry: Option<RetryConfig>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub cookies: Option<bool>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub decompress: Option<bool>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub keep_alive: Option<bool>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub tcp_keep_alive: Option<bool>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub tcp_no_delay: Option<bool>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub ip_version: Option<IpVersion>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RetryConfig {
    pub count: u32,
    pub interval: std::time::Duration,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum IpVersion {
    V4,
    V6,
    Any,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Request {
    pub url: Url,
    pub method: Method,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub headers: Option<HashMap<String, Vec<String>>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub params: Option<HashMap<String, String>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub content: Option<ContentType>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub auth: Option<AuthType>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub security: Option<Security>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub proxy: Option<Proxy>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub options: Option<RequestOptions>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Response {
    pub status: u16,
    pub status_text: String,
    pub headers: HashMap<String, Vec<String>>,
    pub content: ContentType,
    pub meta: ResponseMeta,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ResponseMeta {
    pub timing: TimingInfo,
    pub size: SizeInfo,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub tls: Option<TlsInfo>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub redirects: Option<Vec<RedirectInfo>>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TimingInfo {
    pub start: i64,
    pub end: i64,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub phases: Option<TimingPhases>,
    pub total: i64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TimingPhases {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub dns: Option<i64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub connect: Option<i64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub tls: Option<i64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub send: Option<i64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub wait: Option<i64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub receive: Option<i64>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SizeInfo {
    pub headers: u64,
    pub body: u64,
    pub total: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TlsInfo {
    pub protocol: String,
    pub cipher: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub certificates: Option<Vec<CertificateInfo>>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CertificateInfo {
    pub subject: String,
    pub issuer: String,
    pub valid_from: String,
    pub valid_to: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RedirectInfo {
    pub url: Url,
    pub status: u16,
    pub headers: HashMap<String, Vec<String>>,
}

// Event-related types
#[derive(Debug, Clone, Serialize)]
#[serde(tag = "phase", content = "data")]
pub enum ProgressEvent {
    Upload { loaded: u64, total: Option<u64> },
    Download { loaded: u64, total: Option<u64> },
}

#[derive(Debug, Clone, Serialize)]
pub struct StateChangeEvent {
    pub state: RequestState,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum RequestState {
    Preparing,
    Connecting,
    Sending,
    Waiting,
    Receiving,
    Done,
}

#[derive(Debug, Clone, Serialize)]
pub struct AuthChallengeEvent {
    pub r#type: AuthChallengeType,
    pub params: HashMap<String, String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum AuthChallengeType {
    Basic,
    Digest,
    OAuth2,
}

#[derive(Debug, Clone, Serialize)]
pub struct CookieEvent {
    pub domain: String,
    pub name: String,
    pub value: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub path: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub expires: Option<DateTime<Utc>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub secure: Option<bool>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub http_only: Option<bool>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub same_site: Option<CookieSameSite>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum CookieSameSite {
    Strict,
    Lax,
    None,
}

#[derive(Debug, Clone, Serialize)]
pub struct ErrorEvent {
    pub phase: ErrorPhase,
    pub error: InterceptorError,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum ErrorPhase {
    Preparation,
    Connection,
    Request,
    Response,
}

#[derive(Debug, Clone, Serialize)]
#[serde(tag = "kind")]
pub enum InterceptorError {
    UnsupportedFeature {
        feature: String,
        message: String,
        interceptor: String,
        alternatives: Option<Vec<AlternativeInfo>>,
    },
    Network {
        message: String,
        cause: Option<String>,
    },
    Timeout {
        message: String,
        phase: Option<TimeoutPhase>,
    },
    Certificate {
        message: String,
        cause: Option<String>,
    },
    Auth {
        message: String,
        cause: Option<String>,
    },
    Proxy {
        message: String,
        cause: Option<String>,
    },
    Parse {
        message: String,
        cause: Option<String>,
    },
    Protocol {
        message: String,
        cause: Option<String>,
    },
    Abort {
        message: String,
    },
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AlternativeInfo {
    pub interceptor: String,
    pub description: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum TimeoutPhase {
    Connect,
    Tls,
    Response,
}

#[derive(Debug, Clone)]
pub enum RequestEvent {
    Progress(ProgressEvent),
    StateChange(StateChangeEvent),
    AuthChallenge(AuthChallengeEvent),
    Cookie(CookieEvent),
    Error(ErrorEvent),
}

pub struct SubscribeResponse {
    pub unsubscribe: Box<dyn FnOnce() -> () + Send>,
}

pub struct SubscribeOptions {
    pub request_id: String,
    pub callbacks: SubscribeCallbacks,
}

pub struct SubscribeCallbacks {
    pub on_progress: Box<dyn Fn(ProgressEvent) + Send + Sync>,
    pub on_state_change: Box<dyn Fn(StateChangeEvent) + Send + Sync>,
    pub on_auth_challenge: Box<dyn Fn(AuthChallengeEvent) + Send + Sync>,
    pub on_cookie_received: Box<dyn Fn(CookieEvent) + Send + Sync>,
    pub on_error: Box<dyn Fn(ErrorEvent) + Send + Sync>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CancelOptions {
    pub request_id: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RunOptions {
    pub id: String,
    pub url: String,
    pub method: Method,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub headers: Option<HashMap<String, Vec<String>>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub params: Option<HashMap<String, String>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub content: Option<ContentType>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub auth: Option<AuthType>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub security: Option<Security>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub proxy: Option<Proxy>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub options: Option<RequestOptions>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RunResponse {
    pub status: u16,
    pub status_text: String,
    pub headers: HashMap<String, Vec<String>>,
    pub content: ContentType,
    pub meta: ResponseMeta,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RequestData {
    headers: Vec<String>,
    body: Vec<u8>,
    total_bytes: u64,
    received_bytes: u64,
}

impl Handler for RequestData {
    fn write(&mut self, data: &[u8]) -> Result<usize, WriteError> {
        self.body.extend_from_slice(data);
        self.received_bytes += data.len() as u64;
        Ok(data.len())
    }

    fn header(&mut self, data: &[u8]) -> bool {
        if let Ok(header) = String::from_utf8(data.to_vec()) {
            self.headers.push(header.trim().to_string());
        }
        true
    }
}
