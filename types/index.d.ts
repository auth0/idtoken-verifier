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

  /**
   * @callback verifyCallback
   * @param {?Error} err error returned if the verify cannot be performed
   * @param {?object} payload payload returned if the token is valid
   */

  /**
   * Verifies an id_token
   *
   * It will validate:
   * - signature according to the algorithm configured in the verifier.
   * - if nonce is present and matches the one provided
   * - if `iss` and `aud` claims matches the configured issuer and audience
   * - if token is not expired and valid (if the `nbf` claim is in the past)
   *
   * @method verify
   * @param {string} token id_token to verify
   * @param {string} requestedNonce nonce value that should match the one in the id_token claims
   * @param {verifyCallback} cb callback used to notify the results of the validation
   */
  verify(token: string, requestedNonce: string, cb: verifyCallback): any;

  /**
   * Verifies an id_token
   *
   * It will validate:
   * - signature according to the algorithm configured in the verifier.
   * - if `iss` and `aud` claims matches the configured issuer and audience
   * - if token is not expired and valid (if the `nbf` claim is in the past)
   *
   * @method verify
   * @param {string} token id_token to verify
   * @param {verifyCallback} cb callback used to notify the results of the validation
   */
  verify(token: string, cb: verifyCallback): any;

  getRsaVerifier(iss: any, kid: any, cb: any): void;
  /**
   * @typedef DecodedToken
   * @type {Object}
   * @property {Object} header - content of the JWT header.
   * @property {Object} payload - token claims.
   * @property {Object} encoded - encoded parts of the token.
   */
  /**
   * Decodes a well formed JWT without any verification
   *
   * @method decode
   * @param {string} token decodes the token
   * @return {DecodedToken} if token is valid according to `exp` and `nbf`
   */
  decode(token: string): DecodedToken;
  /**
   * @callback validateAccessTokenCallback
   * @param {Error} [err] error returned if the validation cannot be performed
   * or the token is invalid. If there is no error, then the access_token is valid.
   */
  /**
   * Validates an access_token based on {@link http://openid.net/specs/openid-connect-core-1_0.html#ImplicitTokenValidation}.
   * The id_token from where the alg and atHash parameters are taken,
   * should be decoded and verified before using thisfunction
   *
   * @method validateAccessToken
   * @param {string} access_token the access_token
   * @param {string} alg The algorithm defined in the header of the
   * previously verified id_token under the "alg" claim.
   * @param {string} atHash The "at_hash" value included in the payload
   * of the previously verified id_token.
   * @param {validateAccessTokenCallback} cb callback used to notify the results of the validation.
   */
  validateAccessToken(
    accessToken: any,
    alg: string,
    atHash: string,
    cb: validateAccessTokenCallback
  ): any;
}
