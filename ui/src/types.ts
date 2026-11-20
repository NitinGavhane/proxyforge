export interface FlowRow {
  id: number;
  started: number;
  duration_ms: number;
  scheme: string;
  http_version: string;
  method: string;
  host: string;
  port: number;
  path: string;
  query: string;
  status: number;
  err?: string;
  origin: string;
  mitm: boolean;
  tunnel: boolean;
  tls_client?: string;
  tls_server?: string;
  truncated: boolean;
  req_size: number;
  resp_size: number;
  ws_count: number;
  comment: string;
  highlight: string;
}

export interface WSMessage {
  id: number;
  ts: number;
  direction: "c2s" | "s2c";
  opcode: number;
  opcode_name: string;
  fin: boolean;
  compressed: boolean;
  size: number;
  payload_b64: string;
}

export interface Header {
  k: string;
  v: string;
}

export interface FullFlow {
  id: number;
  started: string;
  duration_ms: number;
  origin: string;
  mitm: boolean;
  tunnel: boolean;
  tls_client?: string;
  tls_server?: string;
  truncated: boolean;
  ws_count?: number;
  err?: string;
  comment: string;
  highlight: string;
  request: {
    method: string;
    scheme: string;
    host: string;
    port: number;
    path: string;
    version: string;
    headers: Header[];
    trailer: Header[];
    body_truncated: boolean;
  };
  response?: {
    status: number;
    status_text: string;
    version: string;
    headers: Header[];
    trailer: Header[];
    body_truncated: boolean;
  };
  req_body_b64?: string;
  resp_body_b64?: string;
}

export interface Status {
  version: string;
  uptime_s: number;
  flows: number;
}
