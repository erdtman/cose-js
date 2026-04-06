/// <reference types="node" />

export interface Headers {
  p?: Record<string, unknown>;
  u?: Record<string, unknown>;
}

export interface SignerKey {
  d: Buffer;
  x?: Buffer;
  y?: Buffer;
  kid?: string;
}

export interface VerifierKey {
  x: Buffer;
  y: Buffer;
  kid?: string;
}

export interface Signer {
  key: SignerKey;
  p?: Record<string, unknown>;
  u?: Record<string, unknown>;
  externalAAD?: Buffer;
}

export interface Verifier {
  key: VerifierKey | Buffer;
  externalAAD?: Buffer;
}

export interface Recipient {
  key: Buffer | RecipientECKey;
  p?: Record<string, unknown>;
  u: Record<string, unknown>;
  sender?: { d: Buffer };
}

export interface RecipientECKey {
  crv: string;
  x: Buffer;
  y: Buffer;
  d: Buffer;
  kid?: string;
}

export interface CreateOptions {
  encodep?: 'empty';
  excludetag?: boolean;
  externalAAD?: Buffer;
  randomSource?: (bytes: number) => Buffer;
  contextIv?: Buffer;
}

export interface ReadOptions {
  defaultType?: number;
  externalAAD?: Buffer;
  contextIv?: Buffer;
}

export interface MACOptions {
  encodep?: 'empty';
  excludetag?: boolean;
}

export namespace sign {
  const SignTag: number;
  const Sign1Tag: number;

  function create(
    headers: Headers,
    payload: Buffer,
    signers: Signer | Signer[],
    options?: CreateOptions
  ): Promise<Buffer>;

  function verify(
    payload: Buffer,
    verifier: Verifier,
    options?: ReadOptions
  ): Promise<Buffer>;

  function verifySync(
    payload: Buffer,
    verifier: Verifier,
    options?: ReadOptions
  ): Buffer;
}

export namespace encrypt {
  const EncryptTag: number;
  const Encrypt0Tag: number;

  function create(
    headers: Headers,
    payload: Buffer,
    recipients: Recipient | Recipient[],
    options?: CreateOptions
  ): Promise<Buffer>;

  function read(
    data: Buffer,
    key: Buffer,
    options?: ReadOptions
  ): Promise<Buffer>;
}

export namespace mac {
  const MAC0Tag: number;
  const MACTag: number;

  function create(
    headers: Headers,
    payload: Buffer,
    recipients: Recipient | Recipient[],
    externalAAD?: Buffer,
    options?: MACOptions
  ): Promise<Buffer>;

  function read(
    data: Buffer,
    key: Buffer,
    externalAAD?: Buffer,
    options?: ReadOptions
  ): Promise<Buffer>;
}

export namespace common {
  const EMPTY_BUFFER: Buffer;

  const HeaderParameters: {
    partyUNonce: number;
    static_key_id: number;
    static_key: number;
    ephemeral_key: number;
    alg: number;
    crit: number;
    content_type: number;
    ctyp: number;
    kid: number;
    IV: number;
    Partial_IV: number;
    counter_signature: number;
    x5chain: number;
  };

  function TranslateHeaders(header: Record<string, unknown>): Map<number, unknown>;
  function TranslateKey(key: Record<string, unknown>): Map<number, unknown>;
  function xor(a: Buffer, b: Buffer): Buffer;
  function runningInNode(): boolean;
}
