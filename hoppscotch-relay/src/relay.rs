use curl::easy::{Easy2, Handler, List, WriteError};
use openssl::{pkcs12::Pkcs12, x509::X509};
use std::collections::HashMap;
use std::ffi::CStr;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use crate::interop::*;
use crate::RelayError;

struct RequestHandler {
    headers: Vec<String>,
    data: Vec<u8>,
    total_bytes: u64,
    received_bytes: u64,
    start_time: i64,
    callbacks: Option<SubscribeCallbacks>,
    tls_info: Option<TlsConnectionInfo>,
    redirect_history: Vec<RedirectInfo>,
}

struct TlsConnectionInfo {
    protocol: String,
    cipher: String,
    certificates: Vec<CertificateInfo>,
}

impl RequestHandler {
    fn new(callbacks: Option<SubscribeCallbacks>) -> Self {
        RequestHandler {
            headers: Vec::new(),
            data: Vec::new(),
            total_bytes: 0,
            received_bytes: 0,
            start_time: SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap()
                .as_secs() as i64,
            callbacks,
            tls_info: None,
            redirect_history: Vec::new(),
        }
    }

    fn handle_state_change(&self, state: RequestState) {
        if let Some(ref callbacks) = self.callbacks {
            (callbacks.on_state_change)(StateChangeEvent { state });
        }
    }

    fn handle_progress(&self, loaded: u64, total: Option<u64>, is_upload: bool) {
        if let Some(ref callbacks) = self.callbacks {
            let event = if is_upload {
                ProgressEvent::Upload { loaded, total }
            } else {
                ProgressEvent::Download { loaded, total }
            };
            (callbacks.on_progress)(event);
        }
    }

    fn handle_auth_challenge(&self, auth_type: AuthChallengeType, params: HashMap<String, String>) {
        if let Some(ref callbacks) = self.callbacks {
            (callbacks.on_auth_challenge)(AuthChallengeEvent {
                r#type: auth_type,
                params,
            });
        }
    }

    fn handle_cookie(&self, event: CookieEvent) {
        if let Some(ref callbacks) = self.callbacks {
            (callbacks.on_cookie_received)(event);
        }
    }
}

impl Handler for RequestHandler {
    fn write(&mut self, data: &[u8]) -> Result<usize, WriteError> {
        self.data.extend_from_slice(data);
        self.received_bytes += data.len() as u64;
        self.handle_progress(self.received_bytes, Some(self.total_bytes), false);
        Ok(data.len())
    }

    fn header(&mut self, data: &[u8]) -> bool {
        if let Ok(s) = String::from_utf8(data.to_vec()) {
            self.headers.push(s.trim().to_string());

            // Track redirects
            if s.starts_with("Location:") {
                if let Some(status) = self
                    .headers
                    .iter()
                    .find(|h| h.starts_with("HTTP/"))
                    .and_then(|h| h.split_whitespace().nth(1))
                    .and_then(|s| Some(s.parse::<u16>().unwrap()))
                {
                    let mut headers = HashMap::new();
                    for header in &self.headers {
                        if let Some((key, value)) = header.split_once(':') {
                            headers
                                .entry(key.trim().to_string())
                                .or_insert_with(Vec::new)
                                .push(value.trim().to_string());
                        }
                    }

                    let url = s.trim_start_matches("Location:").trim().to_string();
                    self.redirect_history.push(RedirectInfo {
                        url: url.parse().unwrap(),
                        status,
                        headers,
                    });
                }
            }
        }
        true
    }

    fn progress(&mut self, dltotal: f64, dlnow: f64, ultotal: f64, ulnow: f64) -> bool {
        if dltotal > 0.0 {
            self.handle_progress(dlnow as u64, Some(dltotal as u64), false);
        }
        if ultotal > 0.0 {
            self.handle_progress(ulnow as u64, Some(ultotal as u64), true);
        }
        true
    }

    fn ssl_ctx(&mut self, ssl_ctx: *mut libc::c_void) -> Result<(), curl::Error> {
        unsafe {
            let ssl_ctx = ssl_ctx as *mut openssl_sys::SSL_CTX;
            let ssl = openssl_sys::SSL_new(ssl_ctx);

            // Get TLS protocol version
            let protocol = CStr::from_ptr(openssl_sys::SSL_get_version(ssl))
                .to_string_lossy()
                .into_owned();

            // Get cipher
            let cipher = CStr::from_ptr(openssl_sys::SSL_CIPHER_get_name(
                openssl_sys::SSL_get_current_cipher(ssl),
            ))
            .to_string_lossy()
            .into_owned();

            // Get peer certificates
            let mut certs = Vec::new();
            let cert_chain = openssl_sys::SSL_get_peer_cert_chain(ssl);
            if !cert_chain.is_null() {
                let cert_count = openssl_sys::OPENSSL_sk_num(cert_chain as *mut _);

                for i in 0..cert_count {
                    let cert_ptr = openssl_sys::OPENSSL_sk_value(cert_chain as *mut _, i)
                        as *mut openssl_sys::X509;

                    if !cert_ptr.is_null() {
                        let subject = todo!();
                        let issuer = todo!();
                        let valid_from = todo!();
                        let valid_to = todo!();

                        certs.push(CertificateInfo {
                            subject,
                            issuer,
                            valid_from,
                            valid_to,
                        });
                    }
                }
            }

            self.tls_info = Some(TlsConnectionInfo {
                protocol,
                cipher,
                certificates: certs,
            });

            // Clean up
            openssl_sys::SSL_free(ssl);
        }
        Ok(())
    }
}

pub struct RequestManager {
    multi: curl::multi::Multi,
    handles: HashMap<String, curl::multi::Easy2Handle<RequestHandler>>,
    retry_state: HashMap<String, RetryState>,
}

struct RetryState {
    attempt: u32,
    next_retry: SystemTime,
}

impl RequestManager {
    pub fn new() -> Self {
        RequestManager {
            multi: curl::multi::Multi::new(),
            handles: HashMap::new(),
            retry_state: HashMap::new(),
        }
    }

    fn configure_easy(
        &self,
        easy: &mut Easy2<RequestHandler>,
        options: &RunOptions,
    ) -> Result<(), RelayError> {
        // Basic request setup
        easy.url(&options.url).unwrap();
        match options.method {
            Method::Get => easy.get(true).unwrap(),
            Method::Post => easy.post(true).unwrap(),
            Method::Put => easy.put(true).unwrap(),
            Method::Delete => easy.custom_request("DELETE").unwrap(),
            Method::Patch => easy.custom_request("PATCH").unwrap(),
            Method::Head => easy.custom_request("HEAD").unwrap(),
            Method::Options => easy.custom_request("OPTIONS").unwrap(),
            Method::Connect => easy.custom_request("CONNECT").unwrap(),
            Method::Trace => easy.custom_request("TRACE").unwrap(),
        }

        // Headers
        if let Some(headers) = &options.headers {
            let mut list = List::new();
            for (key, values) in headers {
                for value in values {
                    list.append(&format!("{}: {}", key, value)).unwrap();
                }
            }
            easy.http_headers(list).unwrap();
        }

        // Content handling
        if let Some(content) = &options.content {
            match content {
                ContentType::Text {
                    content,
                    media_type,
                } => {
                    easy.post_field_size(content.len() as u64).unwrap();
                    easy.post_fields_copy(content.as_bytes()).unwrap();
                    if let Some(media_type) = media_type {
                        let mut list = List::new();
                        list.append(&format!("Content-Type: {}", media_type))
                            .unwrap();
                        easy.http_headers(list).unwrap();
                    }
                }
                ContentType::Json(value) => {
                    let content = serde_json::to_string(value).unwrap();
                    easy.post_field_size(content.len() as u64).unwrap();
                    easy.post_fields_copy(content.as_bytes()).unwrap();
                    let mut list = List::new();
                    list.append("Content-Type: application/json").unwrap();
                    easy.http_headers(list).unwrap();
                }
                ContentType::Form(form_data) => {
                    let mut form = curl::easy::Form::new();
                    for (key, value) in form_data {
                        form.part(key).contents(value.as_bytes()).add().unwrap();
                    }
                    easy.httppost(form).unwrap();
                }
                ContentType::Binary {
                    content,
                    media_type,
                } => {
                    easy.post_field_size(content.len() as u64).unwrap();
                    easy.post_fields_copy(content).unwrap();
                    if let Some(media_type) = media_type {
                        let mut list = List::new();
                        list.append(&format!("Content-Type: {}", media_type))
                            .unwrap();
                        easy.http_headers(list).unwrap();
                    }
                }
                ContentType::Multipart(parts) => {
                    let mut form = curl::easy::Form::new();
                    for (name, data) in parts {
                        form.part(&name).buffer(&name, data.to_vec()).add().unwrap();
                    }
                    easy.httppost(form).unwrap();
                }
                ContentType::Urlencoded(params) => {
                    let content = form_urlencoded::Serializer::new(String::new())
                        .extend_pairs(params)
                        .finish();
                    easy.post_field_size(content.len() as u64).unwrap();
                    easy.post_fields_copy(content.as_bytes()).unwrap();
                    let mut list = List::new();
                    list.append("Content-Type: application/x-www-form-urlencoded")
                        .unwrap();
                    easy.http_headers(list).unwrap();
                }
                ContentType::Stream(_stream) => {
                    // For streaming content, we need to set up a read callback
                    // This is a simplified example - proper implementation would need
                    // to handle backpressure and async streams
                    return Err(RelayError::UnsupportedContent);
                }
            }
        }

        // Authentication
        if let Some(auth) = &options.auth {
            match auth {
                AuthType::None => {}
                AuthType::Basic { username, password } => {
                    easy.username(username).unwrap();
                    easy.password(password).unwrap();
                    easy.http_auth(&curl::easy::Auth::new().basic(true))
                        .unwrap();
                }
                AuthType::Bearer { token } => {
                    let mut list = List::new();
                    list.append(&format!("Authorization: Bearer {}", token))
                        .unwrap();
                    easy.http_headers(list).unwrap();
                }
                AuthType::Digest {
                    username,
                    password,
                    realm: _,
                    nonce: _,
                    opaque: _,
                    algorithm: _,
                    qop: _,
                } => {
                    easy.username(username).unwrap();
                    easy.password(password).unwrap();
                    easy.http_auth(&curl::easy::Auth::new().digest(true))
                        .unwrap();
                }
                AuthType::OAuth2 {
                    access_token,
                    token_type,
                    refresh_token: _,
                } => {
                    let mut list = List::new();
                    let token_type = token_type.as_deref().unwrap_or("Bearer");
                    list.append(&format!("Authorization: {} {}", token_type, access_token))
                        .unwrap();
                    easy.http_headers(list).unwrap();
                }
                AuthType::ApiKey {
                    key,
                    r#in: location,
                    name,
                } => match location {
                    ApiKeyLocation::Header => {
                        let mut list = List::new();
                        list.append(&format!("{}: {}", name, key)).unwrap();
                        easy.http_headers(list).unwrap();
                    }
                    ApiKeyLocation::Query => {
                        let url = if options.url.contains('?') {
                            format!("{}&{}={}", options.url, name, key)
                        } else {
                            format!("{}.unwrap(){}={}", options.url, name, key)
                        };
                        easy.url(&url).unwrap();
                    }
                },
            }
        }

        // Security configuration
        if let Some(security) = &options.security {
            if let Some(certs) = &security.certificates {
                // Client certificate handling
                if let Some(client_cert) = &certs.client {
                    match client_cert {
                        CertificateType::Pem { cert, key } => {
                            easy.ssl_cert_blob(cert).unwrap();
                            easy.ssl_key_blob(key).unwrap();
                        }
                        CertificateType::Pfx { data, password } => {
                            // Parse PKCS#12 data
                            let pkcs12 = Pkcs12::from_der(data)
                                .and_then(|p| p.parse2(password))
                                .unwrap();

                            // Convert to PEM format for curl
                            let pem_cert = pkcs12.cert.unwrap().to_pem().unwrap();
                            let pem_key = pkcs12.pkey.unwrap().private_key_to_pem_pkcs8().unwrap();

                            easy.ssl_cert_blob(&pem_cert).unwrap();
                            easy.ssl_key_blob(&pem_key).unwrap();
                        }
                    }
                }

                // CA certificates
                if let Some(ca_certs) = &certs.ca {
                    for cert in ca_certs {
                        easy.ssl_cainfo_blob(cert).unwrap();
                    }
                }
            }

            easy.ssl_verify_peer(security.validate_certificates)
                .unwrap();
            easy.ssl_verify_host(security.verify_host).unwrap();
        }

        // Request options
        if let Some(options) = &options.options {
            if let Some(timeout) = options.timeout {
                easy.timeout(timeout).unwrap();
            }
            if let Some(timeout) = options.timeout_connect {
                easy.connect_timeout(timeout).unwrap();
            }
            if let Some(_timeout) = options.timeout_tls {
                // TLS timeout is not directly supported by curl-rust,
                // would need custom implementation
            }
            if let Some(follow) = options.follow_redirects {
                easy.follow_location(follow).unwrap();
            }
            if let Some(max) = options.max_redirects {
                easy.max_redirections(max).unwrap();
            }
            if let Some(decompress) = options.decompress {
                easy.http_content_decoding(decompress).unwrap();
            }
            if let Some(keep_alive) = options.keep_alive {
                easy.tcp_keepalive(keep_alive).unwrap();
                if keep_alive {
                    // Set reasonable defaults for keepalive settings
                    easy.tcp_keepidle(Duration::from_secs(120)).unwrap();
                    easy.tcp_keepintvl(Duration::from_secs(60)).unwrap();
                }
            }
            if let Some(tcp_nodelay) = options.tcp_no_delay {
                easy.tcp_nodelay(tcp_nodelay).unwrap();
            }
            if let Some(ip_version) = &options.ip_version {
                match ip_version {
                    IpVersion::V4 => easy.ip_resolve(curl::easy::IpResolve::V4).unwrap(),
                    IpVersion::V6 => easy.ip_resolve(curl::easy::IpResolve::V6).unwrap(),
                    IpVersion::Any => easy.ip_resolve(curl::easy::IpResolve::Any).unwrap(),
                }
            }
        }

        // Proxy configuration
        if let Some(proxy) = &options.proxy {
            easy.proxy(proxy.url.as_str()).unwrap();

            if let Some(auth) = &proxy.auth {
                easy.proxy_username(&auth.username).unwrap();
                easy.proxy_password(&auth.password).unwrap();
            }

            if let Some(certs) = &proxy.certificates {
                if let Some(ca) = &certs.ca {
                    easy.proxy_ssl_cainfo_blob(ca).unwrap();
                }
                if let Some(client_cert) = &certs.client {
                    match client_cert {
                        CertificateType::Pem { cert, key } => {
                            easy.proxy_sslcert_blob(cert).unwrap();
                            easy.proxy_sslkey_blob(key).unwrap();
                        }
                        CertificateType::Pfx { data, password } => {
                            let pkcs12 = Pkcs12::from_der(data)
                                .and_then(|p| p.parse2(password))
                                .map_err(|_| RelayError::CertificateError)
                                .unwrap();

                            let pem_cert = pkcs12.cert.unwrap().to_pem().unwrap();
                            let pem_key = pkcs12.pkey.unwrap().private_key_to_pem_pkcs8().unwrap();

                            easy.proxy_sslcert_blob(&pem_cert).unwrap();
                            easy.proxy_sslkey_blob(&pem_key).unwrap();
                        }
                    }
                }
            }
        }

        Ok(())
    }

    fn create_response(
        &self,
        easy: &Easy2<RequestHandler>,
        handler: &RequestHandler,
    ) -> Result<RunResponse, RelayError> {
        let end_time = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs() as i64;

        // Determine content type and structure
        let content = match String::from_utf8(handler.data.clone()) {
            Ok(text) => {
                // Try to parse as JSON if content type indicates JSON
                if easy
                    .content_type()
                    .map(|ct| ct.unwrap().contains("application/json"))
                    .unwrap_or(false)
                {
                    if let Ok(json) = serde_json::from_str(&text) {
                        ContentType::Json(json)
                    } else {
                        ContentType::Text {
                            content: text,
                            media_type: easy.content_type().unwrap().map(String::from),
                        }
                    }
                } else {
                    ContentType::Text {
                        content: text,
                        media_type: easy.content_type().unwrap().map(String::from),
                    }
                }
            }
            Err(_) => ContentType::Binary {
                content: handler.data.clone(),
                media_type: easy.content_type().unwrap().map(String::from),
            },
        };

        // Get timing information
        let total_time = easy.total_time().unwrap();
        let connect_time = easy.connect_time().unwrap();
        let pretransfer_time = easy.pretransfer_time().unwrap();
        let starttransfer_time = easy.starttransfer_time().unwrap();

        // Convert TLS information if available
        let tls = handler.tls_info.as_ref().map(|info| TlsInfo {
            protocol: info.protocol.clone(),
            cipher: info.cipher.clone(),
            certificates: Some(info.certificates.clone()),
        });

        // Build response
        Ok(RunResponse {
            status: easy.response_code().unwrap() as u16,
            status_text: http_status_text(easy.response_code().unwrap() as u16),
            headers: parse_headers(&handler.headers),
            content,
            meta: ResponseMeta {
                timing: TimingInfo {
                    start: handler.start_time,
                    end: end_time,
                    phases: Some(TimingPhases {
                        dns: Some(easy.namelookup_time().unwrap().as_millis() as i64),
                        connect: Some(connect_time.as_millis() as i64),
                        tls: easy.appconnect_time().ok().map(|t| t.as_millis() as i64),
                        send: Some((pretransfer_time - connect_time).as_millis() as i64),
                        wait: Some((starttransfer_time - pretransfer_time).as_millis() as i64),
                        receive: Some((total_time - starttransfer_time).as_millis() as i64),
                    }),
                    total: total_time.as_millis() as i64,
                },
                size: SizeInfo {
                    headers: easy.header_size().unwrap(),
                    body: handler.received_bytes,
                    total: easy.header_size().unwrap() + handler.received_bytes,
                },
                tls,
                redirects: if handler.redirect_history.is_empty() {
                    None
                } else {
                    Some(handler.redirect_history.clone())
                },
            },
        })
    }

    fn should_retry(
        &self,
        options: &RunOptions,
        response: &Result<RunResponse, RelayError>,
    ) -> bool {
        if let Some(retry_config) = options.options.as_ref().and_then(|o| o.retry.as_ref()) {
            if let Some(state) = self.retry_state.get(&options.id) {
                if state.attempt >= retry_config.count {
                    return false;
                }

                match response {
                    Ok(resp) => {
                        // Retry on 5xx status codes
                        resp.status >= 500 && resp.status < 600
                    }
                    Err(RelayError::Curl(err)) => {
                        // Retry on network errors
                        err.is_operation_timedout()
                            || err.is_couldnt_connect()
                            || err.is_recv_error()
                            || err.is_send_error()
                    }
                    _ => false,
                }
            } else {
                true // First attempt
            }
        } else {
            false // No retry config
        }
    }

    pub fn run(&mut self, options: RunOptions) -> Result<RunResponse, RelayError> {
        let mut result = None;

        loop {
            let handler = RequestHandler::new(None);
            let mut easy = Easy2::new(handler);
            self.configure_easy(&mut easy, &options).unwrap();

            let handle = self.multi.add2(easy).unwrap();
            self.handles.insert(options.id.clone(), handle);

            while self.multi.perform().unwrap() > 0 {
                let mut fds = Vec::new();
                self.multi.wait(&mut fds, Duration::from_secs(1)).unwrap();
            }

            if let Some(handle) = self.handles.remove(&options.id) {
                let easy = self.multi.remove2(handle).unwrap();
                let handler = easy.get_ref();
                result = Some(self.create_response(&easy, handler));

                if let Some(retry_config) = options.options.as_ref().and_then(|o| o.retry.as_ref())
                {
                    let result = result.clone().unwrap();
                    if self.should_retry(&options, &result) {
                        let state =
                            self.retry_state
                                .entry(options.id.clone())
                                .or_insert(RetryState {
                                    attempt: 0,
                                    next_retry: SystemTime::now(),
                                });

                        state.attempt += 1;
                        state.next_retry = SystemTime::now() + retry_config.interval;

                        std::thread::sleep(retry_config.interval);
                        continue;
                    }
                }
            }

            break;
        }

        self.retry_state.remove(&options.id);
        result.unwrap_or(Err(RelayError::RequestNotFound))
    }

    pub fn subscribe(
        &mut self,
        options: SubscribeOptions,
    ) -> Result<SubscribeResponse, RelayError> {
        // Configure callbacks for the multi handle
        self.multi
            .socket_function(move |_socket, events, _token| {
                if events.input() {
                    (options.callbacks.on_state_change)(StateChangeEvent {
                        state: RequestState::Receiving,
                    });
                } else if events.output() {
                    (options.callbacks.on_state_change)(StateChangeEvent {
                        state: RequestState::Sending,
                    });
                }
            })
            .unwrap();

        // Return unsubscribe handle
        Ok(SubscribeResponse {
            unsubscribe: Box::new(move || {
                // Cleanup subscription resources
            }),
        })
    }

    pub fn cancel(&mut self, options: CancelOptions) -> Result<(), RelayError> {
        if let Some(handle) = self.handles.remove(&options.request_id) {
            self.multi.remove2(handle).unwrap();
            self.retry_state.remove(&options.request_id);
            Ok(())
        } else {
            Err(RelayError::RequestNotFound)
        }
    }
}

fn parse_headers(raw_headers: &[String]) -> HashMap<String, Vec<String>> {
    let mut headers = HashMap::new();
    for header in raw_headers {
        if let Some((key, value)) = header.split_once(':') {
            headers
                .entry(key.trim().to_string())
                .or_insert_with(Vec::new)
                .push(value.trim().to_string());
        }
    }
    headers
}

fn http_status_text(code: u16) -> String {
    match code {
        100 => "Continue",
        101 => "Switching Protocols",
        200 => "OK",
        201 => "Created",
        202 => "Accepted",
        203 => "Non-Authoritative Information",
        204 => "No Content",
        205 => "Reset Content",
        206 => "Partial Content",
        300 => "Multiple Choices",
        301 => "Moved Permanently",
        302 => "Found",
        303 => "See Other",
        304 => "Not Modified",
        305 => "Use Proxy",
        307 => "Temporary Redirect",
        308 => "Permanent Redirect",
        400 => "Bad Request",
        401 => "Unauthorized",
        402 => "Payment Required",
        403 => "Forbidden",
        404 => "Not Found",
        405 => "Method Not Allowed",
        406 => "Not Acceptable",
        407 => "Proxy Authentication Required",
        408 => "Request Timeout",
        409 => "Conflict",
        410 => "Gone",
        411 => "Length Required",
        412 => "Precondition Failed",
        413 => "Payload Too Large",
        414 => "URI Too Long",
        415 => "Unsupported Media Type",
        416 => "Range Not Satisfiable",
        417 => "Expectation Failed",
        422 => "Unprocessable Entity",
        428 => "Precondition Required",
        429 => "Too Many Requests",
        431 => "Request Header Fields Too Large",
        500 => "Internal Server Error",
        501 => "Not Implemented",
        502 => "Bad Gateway",
        503 => "Service Unavailable",
        504 => "Gateway Timeout",
        505 => "HTTP Version Not Supported",
        511 => "Network Authentication Required",
        _ => "Unknown Status Code",
    }
    .to_string()
}
