import cbor from 'cbor';
import elliptic from 'elliptic';
import node_crypto from 'crypto';
import * as common from './common';
const EMPTY_BUFFER = common.EMPTY_BUFFER;
const Tagged = cbor.Tagged;
const EC = elliptic.ec;

export const SignTag = 98;
export const Sign1Tag = 18;

export type CoseAlgorithmName = 'ES256' | 'ES384' | 'ES512' | 'RS256' | 'RS384' | 'RS512';

const AlgFromTags: { [n: number]: { sign: CoseAlgorithmName; digest: string } } = {
  "-7": { 'sign': 'ES256', 'digest': 'SHA-256' },
  "-35": { 'sign': 'ES384', 'digest': 'SHA-384' },
  "-36": { 'sign': 'ES512', 'digest': 'SHA-512' },
  "-257": { 'sign': 'RS256', 'digest': 'SHA-256' },
  "-258": { 'sign': 'RS384', 'digest': 'SHA-384' },
  "-259": { 'sign': 'RS512', 'digest': 'SHA-512' },
};

const COSEAlgToNodeAlg: { [alg in CoseAlgorithmName]: { sign: string, digest?: string } } = {
  'ES256': { 'sign': 'p256', 'digest': 'sha256' },
  'ES384': { 'sign': 'p384', 'digest': 'sha384' },
  'ES512': { 'sign': 'p521', 'digest': 'sha512' },
  'RS256': { 'sign': 'RSA-SHA256' },
  'RS384': { 'sign': 'RSA-SHA384' },
  'RS512': { 'sign': 'RSA-SHA512' }
};

async function doSign(SigStructure: any[], signer, alg) {
  return new Promise((resolve, reject) => {
    if (!AlgFromTags[alg]) {
      throw new Error('Unknown algorithm, ' + alg);
    }
    if (!COSEAlgToNodeAlg[AlgFromTags[alg].sign]) {
      throw new Error('Unsupported algorithm, ' + AlgFromTags[alg].sign);
    }

    let ToBeSigned = cbor.encode(SigStructure);

    let sig;
    if (AlgFromTags[alg].sign.startsWith('ES')) {
      const hash = node_crypto.createHash(COSEAlgToNodeAlg[AlgFromTags[alg].sign].digest);
      hash.update(ToBeSigned);
      ToBeSigned = hash.digest();
      const ec = new EC(COSEAlgToNodeAlg[AlgFromTags[alg].sign].sign);
      const key = ec.keyFromPrivate(signer.key.d);
      const signature = key.sign(ToBeSigned);
      const bitLength = Math.ceil(ec.curve._bitLength / 8);
      sig = Buffer.concat([signature.r.toArrayLike(Buffer, undefined, bitLength), signature.s.toArrayLike(Buffer, undefined, bitLength)]);
    } else {
      const sign = node_crypto.createSign(COSEAlgToNodeAlg[AlgFromTags[alg].sign].sign);
      sign.update(ToBeSigned);
      sign.end();
      sig = sign.sign(signer.key);
    }

    resolve(sig);
  });
}

export interface CreateOptions {
  encodep?: string,
  excludetag?: boolean,
}

export function create(headers, payload, signers, options?: CreateOptions) {
  options = options || {};
  let u = headers.u || {};
  let p = headers.p || {};

  p = common.TranslateHeaders(p);
  u = common.TranslateHeaders(u);
  let bodyP = p || {};
  bodyP = (bodyP.size === 0) ? EMPTY_BUFFER : cbor.encode(bodyP);
  if (Array.isArray(signers)) {
    if (signers.length === 0) {
      throw new Error('There has to be at least one signer');
    }
    if (signers.length > 1) {
      throw new Error('Only one signer is supported');
    }
    // TODO handle multiple signers
    const signer = signers[0];
    const externalAAD = signer.externalAAD || EMPTY_BUFFER;
    let signerP = signer.p || {};
    let signerU = signer.u || {};

    signerP = common.TranslateHeaders(signerP);
    signerU = common.TranslateHeaders(signerU);
    const alg = signerP.get(common.HeaderParameters.alg);
    signerP = (signerP.size === 0) ? EMPTY_BUFFER : cbor.encode(signerP);

    const SigStructure = [
      'Signature',
      bodyP,
      signerP,
      externalAAD,
      payload
    ];
    return doSign(SigStructure, signer, alg).then((sig) => {
      if (p.size === 0 && options.encodep === 'empty') {
        p = EMPTY_BUFFER;
      } else {
        p = cbor.encode(p);
      }
      const signed = [p, u, payload, [[signerP, signerU, sig]]];
      return cbor.encode(options.excludetag ? signed : new Tagged(SignTag, signed));
    });
  } else {
    const signer = signers;
    const externalAAD = signer.externalAAD || EMPTY_BUFFER;
    const alg = p.get(common.HeaderParameters.alg) || u.get(common.HeaderParameters.alg);
    const SigStructure = [
      'Signature1',
      bodyP,
      externalAAD,
      payload
    ];
    return doSign(SigStructure, signer, alg).then((sig) => {
      if (p.size === 0 && options.encodep === 'empty') {
        p = EMPTY_BUFFER;
      } else {
        p = cbor.encode(p);
      }
      const signed = [p, u, payload, sig];
      return cbor.encodeCanonical(options.excludetag ? signed : new Tagged(Sign1Tag, signed));
    });
  }
};

async function doVerify(SigStructure: any[], verifier: Verifier, alg, sig): Promise<undefined> {
  if (!AlgFromTags[alg]) {
    throw new Error('Unknown algorithm, ' + alg);
  }
  if (!COSEAlgToNodeAlg[AlgFromTags[alg].sign]) {
    throw new Error('Unsupported algorithm, ' + AlgFromTags[alg].sign);
  }
  const ToBeSigned = cbor.encode(SigStructure);

  if (AlgFromTags[alg].sign.startsWith('ES')) {
    const hash = node_crypto.createHash(COSEAlgToNodeAlg[AlgFromTags[alg].sign].digest);
    hash.update(ToBeSigned);
    const msgHash = hash.digest();

    const pub = { 'x': verifier.key.x, 'y': verifier.key.y };
    const ec = new EC(COSEAlgToNodeAlg[AlgFromTags[alg].sign].sign);
    const key = ec.keyFromPublic(pub);
    sig = { 'r': sig.slice(0, sig.length / 2), 's': sig.slice(sig.length / 2) };
    if (key.verify(msgHash, sig)) {
      return;
    } else {
      throw new Error('Signature missmatch');
    }
  } else {
    const verifierKey = verifier.key.key;
    if (!verifierKey) throw new Error("Missing verifier.key.key");
    const verify = node_crypto.createVerify(COSEAlgToNodeAlg[AlgFromTags[alg].sign].sign);
    verify.update(ToBeSigned);
    if (verify.verify({ key: verifierKey, type: verifier.key.type }, sig)) {
      return;
    } else {
      throw new Error('Signature missmatch');
    }
  }
}

export type Signer = [any, Map<any, any>]

function getSigner(signers: Signer[], verifier: Verifier): Signer {
  for (let i = 0; i < signers.length; i++) {
    const kid = signers[i][1].get(common.HeaderParameters.kid); // TODO create constant for header locations
    if (kid.equals(Buffer.from(verifier.key.kid, 'utf8'))) {
      return signers[i];
    }
  }
}

function getCommonParameter(first, second, parameter) {
  let result;
  if (first.get) {
    result = first.get(parameter);
  }
  if (!result && second.get) {
    result = second.get(parameter);
  }
  return result;
}


interface Verifier {
  externalAAD?: Buffer,
  key: {
    x?: Buffer,
    y?: Buffer,
    kid?: string,
    key?: string | Buffer;
    type?: 'pkcs1' | 'spki';
  },
}

interface VerifyOptions {
  defaultType?: number,
}

export async function verify(payload: Buffer, verifier: Verifier, options?: VerifyOptions) {
  options = options || {};
  let obj = await cbor.decodeFirst(payload);
  let type = options.defaultType ? options.defaultType : SignTag;
  if (obj instanceof Tagged) {
    if (obj.tag !== SignTag && obj.tag !== Sign1Tag) {
      throw new Error('Unexpected cbor tag, \'' + obj.tag + '\'');
    }
    type = obj.tag;
    obj = obj.value;
  }

  if (!Array.isArray(obj)) {
    throw new Error('Expecting Array');
  }

  if (obj.length !== 4) {
    throw new Error('Expecting Array of lenght 4');
  }

  let [p, u, plaintext, signers] = obj;

  if (type === SignTag && !Array.isArray(signers)) {
    throw new Error('Expecting signature Array');
  }

  p = (!p.length) ? EMPTY_BUFFER : cbor.decodeFirstSync(p);
  u = (!u.size) ? EMPTY_BUFFER : u;

  let signer = (type === SignTag ? getSigner(signers, verifier) : signers);

  if (!signer) {
    throw new Error('Failed to find signer with kid' + verifier.key.kid);
  }

  if (type === SignTag) {
    const externalAAD = verifier.externalAAD || EMPTY_BUFFER;
    let [signerP, , sig] = signer;
    signerP = (!signerP.length) ? EMPTY_BUFFER : signerP;
    p = (!p.size) ? EMPTY_BUFFER : cbor.encode(p);
    const signerPMap = cbor.decode(signerP);
    const alg = signerPMap.get(common.HeaderParameters.alg);
    const SigStructure = [
      'Signature',
      p,
      signerP,
      externalAAD,
      plaintext
    ];
    await doVerify(SigStructure, verifier, alg, sig);
    return plaintext;
  } else {
    const externalAAD = verifier.externalAAD || EMPTY_BUFFER;

    const alg = getCommonParameter(p, u, common.HeaderParameters.alg);
    p = (!p.size) ? EMPTY_BUFFER : cbor.encode(p);
    const SigStructure = [
      'Signature1',
      p,
      externalAAD,
      plaintext
    ];
    await doVerify(SigStructure, verifier, alg, signer);
    return plaintext;
  }
};
