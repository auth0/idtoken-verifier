export default IdTokenVerifier;
export type verifyCallback = (err: Error | null, payload: object | null) => any;
export type DecodedToken = {
  /**
   * - content of the JWT header.
   */
  header: any;
  /**
   * - token claims.
   */
  payload: any;
  /**
   * - encoded parts of the token.
   */
  encoded: any;
};
export type validateAccessTokenCallback = (err?: Error) => any;
/**
 * Creates a new id_token verifier
 * @constructor
 * @param {Object} parameters
 * @param {string} parameters.issuer name of the issuer of the token
 * that should match the `iss` claim in the id_token
 * @param {string} parameters.audience identifies the recipients that the JWT is intended for
 * and should match the `aud` claim
 * @param {Object} [parameters.jwksCache] cache for JSON Web Token Keys. By default it has no cache
 * @param {string} [parameters.jwksURI] A valid, direct URI to fetch the JSON Web Key Set (JWKS).
 * @param {string} [parameters.expectedAlg='RS256'] algorithm in which the id_token was signed
 * and will be used to validate
 * @param {number} [parameters.leeway=60] number of seconds that the clock can be out of sync
 * @param {number} [parameters.maxAge] max age
 * while validating expiration of the id_token
 */
declare function IdTokenVerifier(parameters: {
  issuer: string;
  audience: string;
  jwksCache?: any;
  jwksURI?: string;
  expectedAlg?: string;
  leeway?: number;
  maxAge?: number;
}): void;
declare class IdTokenVerifier {
  /**
   * Creates a new id_token verifier
   * @constructor
   * @param {Object} parameters
   * @param {string} parameters.issuer name of the issuer of the token
   * that should match the `iss` claim in the id_token
   * @param {string} parameters.audience identifies the recipients that the JWT is intended for
   * and should match the `aud` claim
   * @param {Object} [parameters.jwksCache] cache for JSON Web Token Keys. By default it has no cache
   * @param {string} [parameters.jwksURI] A valid, direct URI to fetch the JSON Web Key Set (JWKS).
   * @param {string} [parameters.expectedAlg='RS256'] algorithm in which the id_token was signed
   * and will be used to validate
   * @param {number} [parameters.leeway=60] number of seconds that the clock can be out of sync
   * @param {number} [parameters.maxAge] max age
   * while validating expiration of the id_token
   */
  constructor(parameters: {
    issuer: string;
    audience: string;
    jwksCache?: any;
    jwksURI?: string;
    expectedAlg?: string;
    leeway?: number;
    maxAge?: number;
  });
  jwksCache: any;
  expectedAlg: any;
  issuer: any;
  audience: any;
  leeway: any;
  jwksURI: any;
  maxAge: any;
  __clock: any;
  verify(token: string, requestedNonce?: string, cb: verifyCallback): any;
  getRsaVerifier(iss: any, kid: any, cb: any): void;
  decode(token: string): DecodedToken;
  validateAccessToken(
    accessToken: any,
    alg: string,
    atHash: string,
    cb: validateAccessTokenCallback
  ): any;
}
