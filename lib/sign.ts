import cbor from 'cbor';
import webcrypto from 'isomorphic-webcrypto';
import * as common from './common';
const EMPTY_BUFFER = common.EMPTY_BUFFER;
const Tagged = cbor.Tagged;

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

const COSEAlgToWebCryptoAlg: { [alg in CoseAlgorithmName]: { sign: string, digest?: string } } = {
  'ES256': { 'sign': 'P-256', 'digest': 'SHA-256' },
  'ES384': { 'sign': 'P-384', 'digest': 'SHA-384' },
  'ES512': { 'sign': 'P-521', 'digest': 'SHA-512' },
  'RS256': { 'sign': 'RSA-SHA256' },
  'RS384': { 'sign': 'RSA-SHA384' },
  'RS512': { 'sign': 'RSA-SHA512' }
};

async function doSign(SigStructure: any[], signer: Signer, alg): Promise<ArrayBuffer> {
  const { digest: hash } = getAlgorithmParams(alg);
  let ToBeSigned = cbor.encode(SigStructure);
  return await webcrypto.subtle.sign({ name: "ECDSA", hash }, signer.key, ToBeSigned);
}

export interface CreateOptions {
  encodep?: string,
  excludetag?: boolean,
}

export interface Signer {
  externalAAD?: Buffer;
  key: CryptoKey;
  u?: {
    kid: number | string
  };
  p?: { alg: string };
}

export type Signers = Signer | Signer[];

export async function create(headers: common.HeaderPU, payload, signers: Signers, options?: CreateOptions) {
  options = options || {};
  const p = common.TranslateHeaders(headers.p || {});
  const u = common.TranslateHeaders(headers.u || {});
  const bodyP = (p.size === 0) ? EMPTY_BUFFER : cbor.encode(p);
  const p_buffer = (p.size === 0 && options.encodep === 'empty') ? EMPTY_BUFFER : cbor.encode(p);
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
    const signerPMap = common.TranslateHeaders(signer.p || {});
    const signerU = common.TranslateHeaders(signer.u || {});
    const alg = signerPMap.get(common.HeaderParameters.alg);
    const signerP = (signerPMap.size === 0) ? EMPTY_BUFFER : cbor.encode(signerPMap);

    const SigStructure = [
      'Signature',
      bodyP,
      signerP,
      externalAAD,
      payload
    ];
    const sig = await doSign(SigStructure, signer, alg);
    const signed = [p_buffer, u, payload, [[signerP, signerU, sig]]];
    return cbor.encode(options.excludetag ? signed : new Tagged(SignTag, signed));
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
    const sig = await doSign(SigStructure, signer, alg);
    const signed = [p_buffer, u, payload, sig];
    return cbor.encodeCanonical(options.excludetag ? signed : new Tagged(Sign1Tag, signed));
  }
};


function getAlgorithmParams(alg: number): { sign: string, digest?: string } {
  if (!AlgFromTags[alg]) {
    throw new Error('Unknown algorithm, ' + alg);
  }
  const algname = COSEAlgToWebCryptoAlg[AlgFromTags[alg].sign];
  if (!algname) {
    throw new Error('Unsupported algorithm, ' + AlgFromTags[alg].sign);
  }
  return algname;
}

async function doVerify(SigStructure: any[], verifier: Verifier, alg, sig) {
  const { digest: hash } = getAlgorithmParams(alg);
  const ToBeSigned = cbor.encode(SigStructure);
  const verified = await webcrypto.subtle.verify({ name: "ECDSA", hash }, verifier.key, sig, ToBeSigned);
  if (!verified) {
    throw new Error('Signature mismatch');
  }
}

type EncodedSigner = [any, Map<any, any>]

function getSigner(signers: EncodedSigner[], verifier: Verifier): EncodedSigner {
  if (verifier.kid == null) throw new Error("Missing kid");
  const kid_buf = Buffer.from(verifier.kid, 'utf8');
  for (let i = 0; i < signers.length; i++) {
    const kid = signers[i][1].get(common.HeaderParameters.kid); // TODO create constant for header locations
    if (kid.equals(kid_buf)) {
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
  key: CryptoKey,
  kid?: string, // key identifier
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
    throw new Error('Failed to find signer with kid' + verifier.kid);
  }


  if (type === SignTag) {
    const externalAAD = verifier.externalAAD || EMPTY_BUFFER;
    var [signerP, , sig] = signer;
    signerP = (!signerP.length) ? EMPTY_BUFFER : signerP;
    p = (!p.size) ? EMPTY_BUFFER : cbor.encode(p);
    const signerPMap = cbor.decode(signerP);
    var alg = signerPMap.get(common.HeaderParameters.alg);
    var SigStructure = [
      'Signature',
      p,
      signerP,
      externalAAD,
      plaintext
    ];
  } else {
    const externalAAD = verifier.externalAAD || EMPTY_BUFFER;
    var alg = getCommonParameter(p, u, common.HeaderParameters.alg);
    p = (!p.size) ? EMPTY_BUFFER : cbor.encode(p);
    var SigStructure = [
      'Signature1',
      p,
      externalAAD,
      plaintext
    ];
    var sig = signer;
  }
  await doVerify(SigStructure, verifier, alg, sig);
  return plaintext;
};
