import * as cbor from 'cbor-web';
import webcrypto from 'isomorphic-webcrypto';
import * as common from './common';
const EMPTY_BUFFER = common.EMPTY_BUFFER;
const Tagged = cbor.Tagged;

export {webcrypto, cbor}; // Re-export webcrypto to let users create their keys

export const SignTag = 98;
export const Sign1Tag = 18;

async function doSign(SigStructure: any[], signer: Signer, alg): Promise<ArrayBuffer> {
  let ToBeSigned = cbor.encode(SigStructure);
  return await webcrypto.subtle.sign(getAlgorithmParams(alg), signer.key, ToBeSigned);
}

export interface CreateOptions {
  encodep?: string,
  excludetag?: boolean,
}

export interface Signer {
  externalAAD?: Buffer | ArrayBuffer;
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
    const alg = signerPMap.get(common.HeaderParameters.alg) || signerU.get(common.HeaderParameters.alg);
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


function getAlgorithmParams(alg: number): AlgorithmIdentifier | RsaPssParams | EcdsaParams {
  const cose_name = common.AlgFromTags(alg);
  if (cose_name.startsWith('ES')) return { 'name': 'ECDSA', 'hash': 'SHA-' + cose_name.slice(2) }
  else if (cose_name.startsWith('RS')) return { "name": "RSASSA-PKCS1-v1_5" }
  else if (cose_name.startsWith('PS')) return { name: "RSA-PSS", saltLength: +cose_name.slice(2)/8 };
  else throw new Error('Unsupported algorithm, ' + cose_name);
}

async function isSignatureCorrect(SigStructure: any[], verifier: Verifier, alg: number, sig: ArrayBuffer): Promise<boolean> {
  const ToBeSigned = cbor.encode(SigStructure);
  return webcrypto.subtle.verify(getAlgorithmParams(alg), verifier.key, sig, ToBeSigned);
}

type EncodedSigner = [any, Map<any, any>, any]

/// An async function that, given a kid, returns a verifier with a public key for it.
/// If no verifier for the key is found, it should throw an error
export type VerifierFunction = (kid:Uint8Array) => Promise<Verifier>;

interface SignerAndVerifier {
  signer: EncodedSigner;
  verifier: Verifier;
}

async function getSignerAndVerifier(signers: EncodedSigner[], verifierFn: VerifierFunction): Promise<SignerAndVerifier> {
  let error = new Error("No signer");
  for (const signer of signers) {
    const kid = signer[1].get(common.HeaderParameters.kid) as Uint8Array; // TODO create constant for header locations
    try {
      return {signer, verifier: await verifierFn(kid)};
    } catch(e) {
      error = e;
    }
  }
  throw error;
}

function createVerifierFunction(verifier: Verifier): VerifierFunction {
  if (verifier.kid == null) throw new Error("Missing kid");
  const kid_buf = new TextEncoder().encode(verifier.kid);
  return (kid:Uint8Array) =>  {
    if (common.uint8ArrayEquals(kid_buf, kid)) return Promise.resolve(verifier);
    else throw new Error("Invalid kid");
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


export interface Verifier {
  externalAAD?: ArrayBuffer | Buffer,
  key: CryptoKey,
  kid?: string, // key identifier
}

export interface VerifyOptions {
  defaultType?: number,
}

/**
 * Error thrown where a message signature could not be verified.
 * This may mean that the message was forged.
 * 
 * @member plaintext The decoded message, for which the signature is incorrect.
 */
export class SignatureMismatchError extends Error {
  /** The decoded CBOR message with an invalid signature.  */
  plaintext: any;
  constructor(plaintext: any) {
    super(`Signature mismatch: The CBOR message ${JSON.stringify(plaintext)} has an invalid signature.`);
    this.name = "SignatureMismatchError";
    this.plaintext = plaintext;
  }
}

/**
 * Verify the COSE signature of a CBOR message.
 * 
 * @throws {SignatureMismatchError} Will throw an exception if the signature is invalid.
 * @param payload A CBOR-encoded signed message
 * @param verifier The key used to check the signature
 * @returns The decoded message, if the signature was correct.
 */
export async function verify(payload: Uint8Array, verifierParam: Verifier | VerifierFunction, options?: VerifyOptions) {
  const verifierFn = (typeof verifierParam === 'function') ? verifierParam : createVerifierFunction(verifierParam);
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

  let [p, u, plaintext, signature] = obj;

  if (type === SignTag && !Array.isArray(signature)) {
    throw new Error('Expecting signature Array');
  }

  p = (!p.length) ? EMPTY_BUFFER : cbor.decodeFirstSync(p);
  u = (!u.size) ? EMPTY_BUFFER : u;


  if (type === SignTag) {
    var {signer, verifier} = await getSignerAndVerifier(signature, verifierFn);
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
    var alg = getCommonParameter(p, u, common.HeaderParameters.alg);
    const kid = getCommonParameter(p, u, common.HeaderParameters.kid);
    var verifier = await verifierFn(kid);
    const externalAAD = verifier.externalAAD || EMPTY_BUFFER;
    p = (!p.size) ? EMPTY_BUFFER : cbor.encode(p);
    var SigStructure = [
      'Signature1',
      p,
      externalAAD,
      plaintext
    ];
    var sig = signature;
  }
  if (await isSignatureCorrect(SigStructure, verifier, alg, sig)) {
    return plaintext
  } else {
    throw new SignatureMismatchError(plaintext)
  }
};
