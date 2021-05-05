export default IdTokenVerifier;

export interface JWK {
  modulus: string;
  exp: string;
}

/**
 * Interface for a JWK cache.
 * Can use a Map object.
 */
export interface JWKSCache {
  get(key: string): JWK | undefined;
  has(key: string): boolean;
  set(key: string, value: JWK): this;
}

/**
 * Callback used to notify the results of the validation asynchronously
 * @param err error returned if the verify cannot be performed
 * @param payload payload returned if the token is valid
 */
export type verifyCallback = (err: Error | null, payload: object | null) => any;

/**
 * Object containing the decoded token.
 */
export type DecodedToken = {
  /**
   * content of the JWT header
   */
  header: any;

  /**
   * token claims
   */
  payload: any;

  /**
   * encoded parts of the token
   */
  encoded: {
    header: string;
    payload: string;
    signature: string;
  };
};

export type validateAccessTokenCallback = (err?: Error) => any;

export type IdTokenVerifierParameters = {
  /**
   * Name of the issuer of the token that should match the `iss`
   * claim in the id_token
   */
  issuer: string;
  /**
   * Identifies the recipients that the JWT is intended for and should
   * match the `aud` claim
   */
  audience: string;
  /**
   * Cache for JSON Web Token Keys; by default it has no cache
   */
  jwksCache?: JWKSCache;
  /**
   * A valid, direct URI to fetch the JSON Web Key Set (JWKS).
   * Defaults to `${id_token.iss}/.well-known/jwks.json`
   */
  jwksURI?: string;
  /**
   * Algorithm in which the id_token was signed and will be
   * used to validate
   */
  expectedAlg?: 'RS256';
  /**
   * Number of seconds that the clock can be out of sync
   * while validating expiration of the id_token
   */
  leeway?: number;
  /**
   * Max age
   */
  maxAge?: number;
};

declare function IdTokenVerifier(parameters: IdTokenVerifierParameters): void;

declare class IdTokenVerifier {
  /**
   * Creates a new id_token verifier
   */
  constructor(parameters: IdTokenVerifierParameters);

  jwksCache: JWKSCache;
  expectedAlg: string;
  issuer: string;
  audience: string;
  leeway: number;
  jwksURI: string;
  maxAge: number;

  /**
   * Verifies an id_token
   *
   * It will validate:
   * - signature according to the algorithm configured in the verifier.
   * - if nonce is present and matches the one provided
   * - if `iss` and `aud` claims matches the configured issuer and audience
   * - if token is not expired and valid (if the `nbf` claim is in the past)
   * @param token id_token to verify
   * @param requestedNonce nonce value that should match the one in the id_token claims
   * @param cb callback used to notify the results of the validation
   */
  verify(token: string, requestedNonce: any, cb: verifyCallback): any;
  verify(token: string, cb: verifyCallback): any;

  getRsaVerifier(iss: any, kid: any, cb: any): void;

  /**
   * Decodes a well formed JWT without any verification
   * @param token decodes the token
   * @returns token if it's valid according to `exp` and `nbf`
   */
  decode(token: string): DecodedToken;

  /**
   * Validates an access_token based on {@link http://openid.net/specs/openid-connect-core-1_0.html#ImplicitTokenValidation}.
   * The id_token from where the alg and atHash parameters are taken,
   * should be decoded and verified before using thisfunction
   *
   * @param access_token the access_token
   * @param alg The algorithm defined in the header of the
   * previously verified id_token under the "alg" claim.
   * @param atHash The "at_hash" value included in the payload
   * of the previously verified id_token.
   * @param cb callback used to notify the results of the validation.
   */
  validateAccessToken(
    accessToken: string,
    alg: string,
    atHash: string,
    cb: validateAccessTokenCallback
  ): void;
}
