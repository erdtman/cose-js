import cbor from 'cbor';
import crypto from 'isomorphic-webcrypto';
import * as common from './common';
import { CreateOptions } from './sign';
import { ReadOptions } from './encrypt';
const Tagged = cbor.Tagged;
const EMPTY_BUFFER = common.EMPTY_BUFFER;

export const MAC0Tag = 17;
export const MACTag = 97;

const CutTo = {
  4: 8,
  5: 32,
  6: 48,
  7: 64
};

const context = {};
context[MAC0Tag] = 'MAC0';
context[MACTag] = 'MAC';

export type MACstructure = [
  'MAC0' | 'MAC1',
  any,
  string,//bstr
  string//bstr
];

async function importKey(algname: string, key: ArrayBuffer | Buffer) {
  let hash_match = algname.match(/^(?:HS|SHA-)(\d+)/);
  if (!hash_match) throw new Error("Unsupported algorithm, " + algname);
  const hash = 'SHA-' + hash_match[1];
  return await crypto.subtle.importKey("raw", key, { name: "HMAC", hash }, false, ["sign"]);
}

const iv = new Uint8Array(16);
export async function aesCbcMac(key: Uint8Array, msg: Uint8Array, len: number): Promise<Buffer> {
  const padLen = msg.length % 16 ? 16 - (msg.length % 16) : 0;
  const paddedMsg = new Uint8Array(msg.length + padLen);
  paddedMsg.set(msg, 0);

  const crypto_key = await crypto.subtle.importKey("raw", key, { name: "AES-CBC" }, false, ["encrypt"]);
  const enc = await crypto.subtle.encrypt({ name: "AES-CBC", iv }, crypto_key, paddedMsg);

  const tagStart = enc.byteLength - 16 - 16; // webcrypto always does pkcs7 padding
  const tag = enc.slice(tagStart, tagStart + len);
  return Buffer.from(tag);
};


async function doMac(context: string, p: any, externalAAD: ArrayBuffer, payload: any, algTag: number, key: ArrayBuffer | Buffer): Promise<Buffer> {
  const MACstructure = [
    context, // 'MAC0' or 'MAC1', // context
    p, // protected
    externalAAD, // bstr,
    payload // bstr
  ];

  const toBeMACed = cbor.encode(MACstructure);
  const algname = common.AlgFromTags(algTag);
  const aesMacNum = algname.match(/^AES-MAC-\d+\/(\d+)/)
  if (aesMacNum) {
    return await aesCbcMac(Buffer.from(key), Buffer.from(toBeMACed), +aesMacNum[1] / 8);
  } else {
    const crypto_key = await importKey(algname, key);
    const buffer = await crypto.subtle.sign("HMAC", crypto_key, toBeMACed);
    return Buffer.from(buffer);
  }
}

export type Recipient = {
  key: Buffer | ArrayBuffer,
  u?: common.HeaderPU["u"]
};

export type Recipients = Recipient | Recipient[];

export type HMACHeader = {
  p: common.HeaderPU["p"],
  u?: common.HeaderPU["u"]
};

export async function create(headers: HMACHeader, payload: any, recipients: Recipients, externalAAD?: ArrayBuffer | Buffer, options?: CreateOptions) {
  options = options || {};
  externalAAD = externalAAD || EMPTY_BUFFER;
  const original_u = headers.u || {};
  const original_p = headers.p || {};

  const p = common.TranslateHeaders(original_p);
  const u = common.TranslateHeaders(original_u);

  const alg = p.get(common.HeaderParameters.alg) || u.get(common.HeaderParameters.alg);

  if (typeof alg !== "number") {
    throw new Error('Missing mandatory parameter \'alg\'');
  }

  const predictableP = (!p.size) ? EMPTY_BUFFER : cbor.encode(p);
  if (p.size === 0 && options.encodep === 'empty') {
    var p_buffer: Buffer | ArrayBuffer = EMPTY_BUFFER;
  } else {
    var p_buffer: Buffer | ArrayBuffer = cbor.encode(p);
  }
  // TODO check crit headers
  if (Array.isArray(recipients)) {
    if (recipients.length === 0) {
      throw new Error('There has to be at least one recipent');
    }
    if (recipients.length > 1) {
      throw new Error('MACing with multiple recipents is not implemented');
    }
    var [recipient] = recipients;
    var context = "MAC";
    var tagNum = MACTag;
    var after_tag: any[][] | null = [[EMPTY_BUFFER, common.TranslateHeaders(recipient.u), EMPTY_BUFFER]];
  } else {
    var recipient = recipients;
    var context = "MAC0";
    var tagNum = MAC0Tag;
    var after_tag: any[][] | null = null;
  }
  let tag = await doMac(context, predictableP, externalAAD, payload, alg, recipient.key);
  tag = tag.slice(0, CutTo[alg]);
  let maced = [p_buffer, u, payload, tag];
  if (after_tag) maced.push(after_tag);
  return cbor.encode(options.excludetag ? maced : new Tagged(tagNum, maced));
};

export async function read(data: ArrayBuffer | Uint8Array, key: Buffer | ArrayBuffer, externalAAD?: Buffer | ArrayBuffer, options?: ReadOptions) {
  options = options || {};
  externalAAD = externalAAD || EMPTY_BUFFER;

  let obj = await cbor.decodeFirst(data);
  let type = options.defaultType ? options.defaultType : MAC0Tag;
  if (obj instanceof Tagged) {
    if (obj.tag !== MAC0Tag && obj.tag !== MACTag) {
      throw new Error('Unexpected cbor tag, \'' + obj.tag + '\'');
    }
    type = obj.tag;
    obj = obj.value;
  }

  const expected_length = type === MAC0Tag ? 4 : 5;
  if (!(Array.isArray(obj) && obj.length === expected_length)) {
    throw new Error('Expecting Array of lenght ' + expected_length);
  }

  let [p, u, payload, tag] = obj;
  p = (!p.length) ? EMPTY_BUFFER : cbor.decode(p);
  p = (!p.size) ? EMPTY_BUFFER : p;
  u = (!u.size) ? EMPTY_BUFFER : u;

  // TODO validate protected header
  const alg = (p !== EMPTY_BUFFER) ? p.get(common.HeaderParameters.alg) : (u !== EMPTY_BUFFER) ? u.get(common.HeaderParameters.alg) : undefined;
  p = (!p.size) ? EMPTY_BUFFER : cbor.encode(p);

  let calcTag = await doMac(context[type], p, externalAAD, payload, alg, key)
  calcTag = calcTag.slice(0, CutTo[alg]);

  if (!uint8ArrayEquals(tag, calcTag)) {
    throw new Error('Tag mismatch');
  }

  return payload;
};

function uint8ArrayEquals(a: Uint8Array, b: Uint8Array): boolean {
  return a.length === b.length && a.every((v, i) => b[i] === v);
}