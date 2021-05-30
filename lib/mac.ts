import cbor from 'cbor';
import aesCbcMac from 'aes-cbc-mac';
import node_crypto from 'crypto';
import * as common from './common';
import { CreateOptions } from './sign';
import { ReadOptions } from './encrypt';
const Tagged = cbor.Tagged;
const EMPTY_BUFFER = common.EMPTY_BUFFER;

export const MAC0Tag = 17;
export const MACTag = 97;

const AlgFromTags = {
  4: 'SHA-256_64',
  5: 'SHA-256',
  6: 'SHA-384',
  7: 'SHA-512',
  14: 'AES-MAC-128/64',
  15: 'AES-MAC-256/64',
  25: 'AES-MAC-128/128',
  26: 'AES-MAC-256/128'
};

const COSEAlgToNodeAlg = {
  'SHA-256_64': 'sha256',
  'SHA-256': 'sha256',
  'HS256': 'sha256',
  'SHA-384': 'sha384',
  'SHA-512': 'sha512',
  'AES-MAC-128/64': 'aes-cbc-mac-64',
  'AES-MAC-128/128': 'aes-cbc-mac-128',
  'AES-MAC-256/64': 'aes-cbc-mac-64',
  'AES-MAC-256/128': 'aes-cbc-mac-128'
};

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

async function doMac(context: string, p: any, externalAAD: any, payload: any, alg: string, key: any): Promise<Buffer> {
  const MACstructure = [
    context, // 'MAC0' or 'MAC1', // context
    p, // protected
    externalAAD, // bstr,
    payload // bstr
  ];

  const toBeMACed = cbor.encode(MACstructure);
  if (alg === 'aes-cbc-mac-64') {
    return aesCbcMac.create(key, toBeMACed, 8);
  } else if (alg === 'aes-cbc-mac-128') {
    return aesCbcMac.create(key, toBeMACed, 16);
  } else {
    const hmac = node_crypto.createHmac(alg, key);
    return new Promise((resolve) => {
      hmac.end(toBeMACed, function () {
        resolve(hmac.read());
      });
    })
  }
}

export function create(headers: any, payload: any, recipents: any, externalAAD?: Buffer, options?: CreateOptions) {
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

  if (recipents.length === 0) {
    throw new Error('There has to be at least one recipent');
  }

  const predictableP = (!p.size) ? EMPTY_BUFFER : cbor.encode(p);
  if (p.size === 0 && options.encodep === 'empty') {
    var p_buffer = EMPTY_BUFFER;
  } else {
    var p_buffer = cbor.encode(p) as Buffer;
  }
  // TODO check crit headers
  if (Array.isArray(recipents)) {
    if (recipents.length > 1) {
      throw new Error('MACing with multiple recipents is not implemented');
    }
    const recipent = recipents[0];
    return doMac('MAC',
      predictableP,
      externalAAD,
      payload,
      COSEAlgToNodeAlg[AlgFromTags[alg]],
      recipent.key)
      .then((tag) => {
        tag = tag.slice(0, CutTo[alg]);
        const ru = common.TranslateHeaders(recipent.u);
        const rp = EMPTY_BUFFER;
        const maced = [p_buffer, u, payload, tag, [[rp, ru, EMPTY_BUFFER]]];
        return cbor.encode(options.excludetag ? maced : new Tagged(MACTag, maced));
      });
  } else {
    return doMac('MAC0',
      predictableP,
      externalAAD,
      payload,
      COSEAlgToNodeAlg[AlgFromTags[alg]],
      recipents.key)
      .then((tag) => {
        tag = tag.slice(0, CutTo[alg]);
        const maced = [p_buffer, u, payload, tag];
        return cbor.encode(options.excludetag ? maced : new Tagged(MAC0Tag, maced));
      });
  }
};

export function read(data: any, key: any, externalAAD?: Buffer, options?: ReadOptions) {
  options = options || {};
  externalAAD = externalAAD || EMPTY_BUFFER;

  return cbor.decodeFirst(data)
    .then((obj) => {
      let type = options.defaultType ? options.defaultType : MAC0Tag;
      if (obj instanceof Tagged) {
        if (obj.tag !== MAC0Tag && obj.tag !== MACTag) {
          throw new Error('Unexpected cbor tag, \'' + obj.tag + '\'');
        }
        type = obj.tag;
        obj = obj.value;
      }

      if (!Array.isArray(obj)) {
        throw new Error('Expecting Array');
      }

      if (type === MAC0Tag && obj.length !== 4) {
        throw new Error('Expecting Array of lenght 4');
      }
      if (type === MACTag && obj.length !== 5) {
        throw new Error('Expecting Array of lenght 5');
      }

      let [p, u, payload, tag] = obj;
      p = (!p.length) ? EMPTY_BUFFER : cbor.decode(p);
      p = (!p.size) ? EMPTY_BUFFER : p;
      u = (!u.size) ? EMPTY_BUFFER : u;

      // TODO validate protected header
      const alg = (p !== EMPTY_BUFFER) ? p.get(common.HeaderParameters.alg) : (u !== EMPTY_BUFFER) ? u.get(common.HeaderParameters.alg) : undefined;
      p = (!p.size) ? EMPTY_BUFFER : cbor.encode(p);
      if (!AlgFromTags[alg]) {
        throw new Error('Unknown algorithm, ' + alg);
      }
      if (!COSEAlgToNodeAlg[AlgFromTags[alg]]) {
        throw new Error('Unsupported algorithm, ' + AlgFromTags[alg]);
      }

      return doMac(context[type], p, externalAAD, payload, COSEAlgToNodeAlg[AlgFromTags[alg]], key)
        .then((calcTag) => {
          calcTag = calcTag.slice(0, CutTo[alg]);

          if (tag.toString('hex') !== calcTag.toString('hex')) {
            throw new Error('Tag mismatch');
          }

          return payload;
        });
    });
};
