import { invoke } from '@tauri-apps/api/core'

export type Method =
  | "GET"
  | "POST"
  | "PUT"
  | "DELETE"
  | "PATCH"
  | "HEAD"
  | "OPTIONS"
  | "CONNECT"
  | "TRACE"

export type ContentType =
  | { kind: "text"; content: string; mediaType?: string }
  | { kind: "json"; content: unknown }
  | { kind: "form"; content: FormData }
  | { kind: "binary"; content: Uint8Array; mediaType?: string }
  | { kind: "multipart"; content: FormData }
  | { kind: "urlencoded"; content: Record<string, string> }
  | { kind: "stream"; content: ReadableStream }

export type AuthType =
  | { kind: "none" }
  | { kind: "basic"; username: string; password: string }
  | { kind: "bearer"; token: string }
  | {
    kind: "digest"
    username: string
    password: string
    realm?: string
    nonce?: string
    opaque?: string
    algorithm?: "MD5" | "SHA-256" | "SHA-512"
    qop?: "auth" | "auth-int"
  }
  | {
    kind: "oauth2"
    accessToken: string
    tokenType?: string
    refreshToken?: string
  }
  | {
    kind: "apikey"
    key: string
    in: "header" | "query"
    name: string
  }

export type CertificateType =
  | {
    kind: "pem"
    cert: Uint8Array
    key: Uint8Array
  }
  | {
    kind: "pfx"
    data: Uint8Array
    password: string
  }

export interface Request {
  url: string
  method: Method
  headers?: Record<string, string | string[]>
  params?: Record<string, string>
  content?: ContentType
  auth?: AuthType

  security?: {
    certificates?: {
      client?: CertificateType
      ca?: Array<Uint8Array>
    }
    validateCertificates: boolean
    verifyHost: boolean
  }

  proxy?: {
    url: string
    auth?: {
      username: string
      password: string
    }
    certificates?: {
      ca?: Uint8Array
      client?: CertificateType
    }
  }

  options?: {
    timeout?: number
    timeoutConnect?: number
    timeoutTLS?: number
    followRedirects?: boolean
    maxRedirects?: number
    retry?: {
      count: number
      interval: number
      conditions?: Array<(res: Response) => boolean>
    }
    cookies?: boolean
    decompress?: boolean
    keepAlive?: boolean
    tcpKeepAlive?: boolean
    tcpNoDelay?: boolean
    ipVersion?: "v4" | "v6" | "any"
  }
}

export interface RequestEvents {
  progress: {
    phase: 'upload' | 'download'
    loaded: number
    total?: number
  }
  stateChange: {
    state: 'preparing' | 'connecting' | 'sending' | 'waiting' | 'receiving' | 'done'
  }
  authChallenge: {
    type: 'basic' | 'digest' | 'oauth2'
    params: Record<string, string>
  }
  cookieReceived: {
    domain: string
    name: string
    value: string
    path?: string
    expires?: Date
    secure?: boolean
    httpOnly?: boolean
    sameSite?: 'Strict' | 'Lax' | 'None'
  }
  error: {
    phase: 'preparation' | 'connection' | 'request' | 'response'
    error: InterceptorError
  }
}

export type EventEmitter<T> = {
  on<K extends keyof T>(event: K, handler: (payload: T[K]) => void): () => void
  once<K extends keyof T>(event: K, handler: (payload: T[K]) => void): () => void
  off<K extends keyof T>(event: K, handler: (payload: T[K]) => void): void
}

export type ContentCapability =
  | 'Text'
  | 'Json'
  | 'FormData'
  | 'Binary'
  | 'Multipart'
  | 'Urlencoded'
  | 'Streaming'
  | 'Compression'

export type AuthCapability =
  | 'Basic'
  | 'Bearer'
  | 'Digest'
  | 'OAuth2'
  | 'Mtls'
  | 'ApiKey'

export type SecurityCapability =
  | 'ClientCertificates'
  | 'CaCertificates'
  | 'CertificateValidation'
  | 'HostVerification'

export type ProxyCapability =
  | 'Http'
  | 'Https'
  | 'Socks'
  | 'Authentication'
  | 'Certificates'

export type AdvancedCapability =
  | 'Retry'
  | 'Redirects'
  | 'Timeout'
  | 'Cookies'
  | 'KeepAlive'
  | 'TcpOptions'
  | 'Ipv6'

export interface Capabilities {
  content: Set<ContentCapability>
  auth: Set<AuthCapability>
  security: Set<SecurityCapability>
  proxy: Set<ProxyCapability>
  advanced: Set<AdvancedCapability>
}

export type UnsupportedFeatureError = {
  kind: "unsupported_feature"
  feature: string
  message: string
  interceptor: string
  alternatives?: Array<{
    interceptor: string
    description: string
  }>
}

export type InterceptorError =
  | UnsupportedFeatureError
  | { kind: "network"; message: string; cause?: unknown }
  | { kind: "timeout"; message: string; phase?: "connect" | "tls" | "response" }
  | { kind: "certificate"; message: string; cause?: unknown }
  | { kind: "auth"; message: string; cause?: unknown }
  | { kind: "proxy"; message: string; cause?: unknown }
  | { kind: "parse"; message: string; cause?: unknown }
  | { kind: "protocol"; message: string; cause?: unknown }
  | { kind: "abort"; message: string }

export interface Response {
  status: number
  statusText: string
  headers: Record<string, string | string[]>
  content: ContentType

  meta: {
    timing: {
      start: number
      end: number
      phases?: {
        dns?: number
        connect?: number
        tls?: number
        send?: number
        wait?: number
        receive?: number
      }
      total: number
    }
    size: {
      headers: number
      body: number
      total: number
    }
    tls?: {
      protocol: string
      cipher: string
      certificates?: Array<{
        subject: string
        issuer: string
        validFrom: string
        validTo: string
      }>
    }
    redirects?: Array<{
      url: string
      status: number
      headers: Record<string, string | string[]>
    }>
  }
}


type NativeContent = {
  type: 'text' | 'bytes' | 'multipart' | 'urlencoded'
  data: unknown
  mediaType?: string
}

type SecurityConfig = {
  certificates?: {
    client?: {
      type: 'client_cert'
      kind: 'pem' | 'pfx'
      cert?: number[]
      key?: number[]
      data?: number[]
      password?: string
    }
    ca?: Array<{
      type: 'ca_cert'
      data: number[]
    }>
  }
  validateCertificates?: boolean
  verifyHost?: boolean
}

type ProxyConfig = {
  url: string
  auth?: {
    username: string
    password: string
  }
  certificates?: {
    ca?: number[]
    client?: {
      kind: 'pem' | 'pfx'
      cert?: number[]
      key?: number[]
      data?: number[]
      password?: string
    }
  }
}

type RequestOptions = {
  timeout?: number
  timeoutConnect?: number
  timeoutTLS?: number
  followRedirects?: boolean
  maxRedirects?: number
  retry?: {
    count: number
    interval: number
  }
  cookies?: boolean
  decompress?: boolean
  keepAlive?: boolean
  tcpKeepAlive?: boolean
  tcpNoDelay?: boolean
  ipVersion?: "v4" | "v6" | "any"
}

export type RunOptions = {
  id: string
  url: string
  method: Method
  headers?: Record<string, string | string[]>
  params?: Record<string, string>
  content?: NativeContent
  auth?: AuthType
  security?: SecurityConfig
  proxy?: ProxyConfig
  options?: RequestOptions
}

export type RunResponse = {
  status: number
  statusText: string
  headers: Record<string, string | string[]>
  content: NativeContent
  meta: {
    timing: {
      start: number
      end: number
      phases?: {
        dns?: number
        connect?: number
        tls?: number
        send?: number
        wait?: number
        receive?: number
      }
      total: number
    }
    size: {
      headers: number
      body: number
      total: number
    }
    tls?: {
      protocol: string
      cipher: string
      certificates?: Array<{
        subject: string
        issuer: string
        validFrom: string
        validTo: string
      }>
    }
    redirects?: Array<{
      url: string
      status: number
      headers: Record<string, string | string[]>
    }>
  }
}

export type SubscribeOptions = {
  requestId: string
  callbacks: {
    onProgress: (data: RequestEvents['progress']) => void
    onStateChange: (data: RequestEvents['stateChange']) => void
    onAuthChallenge: (data: RequestEvents['authChallenge']) => void
    onCookieReceived: (data: RequestEvents['cookieReceived']) => void
    onError: (data: RequestEvents['error']) => void
  }
}

export type SubscribeResponse = {
  unsubscribe: () => void
}

export type CancelOptions = {
  requestId: string
}

// No response type needed for cancel - it's a void op
export type CancelResponse = void


export async function run(options: RunOptions): Promise<RunResponse> {
  return await invoke<RunResponse>('plugin:hoppscotch-relay|run', { options })
}

export async function subscribe(options: SubscribeOptions): Promise<SubscribeResponse> {
  return await invoke<SubscribeResponse>('plugin:hoppscotch-relay|subscribe', { options })
}

export async function cancel(options: CancelOptions): Promise<CancelResponse> {
  return await invoke<CancelResponse>('plugin:hoppscotch-relay|cancel', { options })
}
