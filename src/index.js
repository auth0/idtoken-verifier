import p from 'es6-promise';
p.polyfill();

import sha256 from 'crypto-js/sha256';
import cryptoBase64 from 'crypto-js/enc-base64';
import cryptoHex from 'crypto-js/enc-hex';

import RSAVerifier from './helpers/rsa-verifier';
import * as base64 from './helpers/base64';
import * as jwks from './helpers/jwks';
import * as error from './helpers/error';
import DummyCache from './helpers/dummy-cache';

var supportedAlg = 'RS256';
var isNumber = n => typeof n === 'number';
var defaultClock = () => new Date();
var DEFAULT_LEEWAY = 60;

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
function IdTokenVerifier(parameters) {
  var options = parameters || {};

  this.jwksCache = options.jwksCache || new DummyCache();
  this.expectedAlg = options.expectedAlg || 'RS256';
  this.issuer = options.issuer;
  this.audience = options.audience;
  this.leeway = options.leeway === 0 ? 0 : options.leeway || DEFAULT_LEEWAY;
  this.jwksURI = options.jwksURI;
  this.maxAge = options.maxAge;

  this.__clock =
    typeof options.__clock === 'function' ? options.__clock : defaultClock;

  if (this.leeway < 0 || this.leeway > 300) {
    throw new error.ConfigurationError(
      'The leeway should be positive and lower than five minutes.'
    );
  }

  if (supportedAlg !== this.expectedAlg) {
    throw new error.ConfigurationError(
      'Signature algorithm of "' +
        this.expectedAlg +
        '" is not supported. Expected the ID token to be signed with "' +
        supportedAlg +
        '".'
    );
  }
}

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
 * @param {string} [requestedNonce] nonce value that should match the one in the id_token claims
 * @param {verifyCallback} cb callback used to notify the results of the validation
 */
IdTokenVerifier.prototype.verify = function(token, requestedNonce, cb) {
  if (!cb && requestedNonce && typeof requestedNonce == 'function') {
    cb = requestedNonce;
    requestedNonce = undefined;
  }
  if (!token) {
    return cb(
      new error.TokenValidationError('ID token is required but missing'),
      null
    );
  }

  var jwt = this.decode(token);

  if (jwt instanceof Error) {
    return cb(
      new error.TokenValidationError('ID token could not be decoded'),
      null
    );
  }

  /* eslint-disable vars-on-top */
  var headerAndPayload = jwt.encoded.header + '.' + jwt.encoded.payload;
  var signature = base64.decodeToHEX(jwt.encoded.signature);

  var alg = jwt.header.alg;
  var kid = jwt.header.kid;

  var aud = jwt.payload.aud;
  var sub = jwt.payload.sub;
  var iss = jwt.payload.iss;
  var exp = jwt.payload.exp;
  var nbf = jwt.payload.nbf;
  var iat = jwt.payload.iat;
  var azp = jwt.payload.azp;
  var auth_time = jwt.payload.auth_time;
  var nonce = jwt.payload.nonce;
  var now = this.__clock();

  /* eslint-enable vars-on-top */
  var _this = this;

  if (_this.expectedAlg !== alg) {
    return cb(
      new error.TokenValidationError(
        'Signature algorithm of "' +
          alg +
          '" is not supported. Expected the ID token to be signed with "' +
          supportedAlg +
          '".'
      ),
      null
    );
  }

  this.getRsaVerifier(iss, kid, function(err, rsaVerifier) {
    if (err) {
      return cb(err, null);
    }

    if (!rsaVerifier.verify(headerAndPayload, signature)) {
      return cb(
        new error.TokenValidationError('Invalid ID token signature.'),
        null
      );
    }

    if (!iss || typeof iss !== 'string') {
      return cb(
        new error.TokenValidationError(
          'Issuer (iss) claim must be a string present in the ID token'
        ),
        null
      );
    }

    if (_this.issuer !== iss) {
      return cb(
        new error.TokenValidationError(
          'Issuer (iss) claim mismatch in the ID token, expected "' +
            _this.issuer +
            '", found "' +
            iss +
            '"'
        ),
        null
      );
    }

    if (!sub || typeof sub !== 'string') {
      return cb(
        new error.TokenValidationError(
          'Subject (sub) claim must be a string present in the ID token'
        ),
        null
      );
    }

    if (!aud || (typeof aud !== 'string' && !Array.isArray(aud))) {
      return cb(
        new error.TokenValidationError(
          'Audience (aud) claim must be a string or array of strings present in the ID token'
        ),
        null
      );
    }

    if (Array.isArray(aud) && !aud.includes(_this.audience)) {
      return cb(
        new error.TokenValidationError(
          'Audience (aud) claim mismatch in the ID token; expected "' +
            _this.audience +
            '" but was not one of "' +
            aud.join(', ') +
            '"'
        ),
        null
      );
    } else if (typeof aud === 'string' && _this.audience !== aud) {
      return cb(
        new error.TokenValidationError(
          'Audience (aud) claim mismatch in the ID token; expected "' +
            _this.audience +
            '" but found "' +
            aud +
            '"'
        ),
        null
      );
    }

    if (requestedNonce) {
      if (!nonce || typeof nonce !== 'string') {
        return cb(
          new error.TokenValidationError(
            'Nonce (nonce) claim must be a string present in the ID token'
          ),
          null
        );
      }

      if (nonce !== requestedNonce) {
        return cb(
          new error.TokenValidationError(
            'Nonce (nonce) claim value mismatch in the ID token; expected "' +
              requestedNonce +
              '", found "' +
              nonce +
              '"'
          ),
          null
        );
      }
    }

    if (Array.isArray(aud) && aud.length > 1) {
      if (!azp || typeof azp !== 'string') {
        return cb(
          new error.TokenValidationError(
            'Authorized Party (azp) claim must be a string present in the ID token when Audience (aud) claim has multiple values'
          ),
          null
        );
      }

      if (azp !== _this.audience) {
        return cb(
          new error.TokenValidationError(
            'Authorized Party (azp) claim mismatch in the ID token; expected "' +
              _this.audience +
              '", found "' +
              azp +
              '"'
          ),
          null
        );
      }
    }

    if (!exp || !isNumber(exp)) {
      return cb(
        new error.TokenValidationError(
          'Expiration Time (exp) claim must be a number present in the ID token'
        ),
        null
      );
    }

    if (!iat || !isNumber(iat)) {
      return cb(
        new error.TokenValidationError(
          'Issued At (iat) claim must be a number present in the ID token'
        ),
        null
      );
    }

    var expTime = exp + _this.leeway;
    var expTimeDate = new Date(0);
    expTimeDate.setUTCSeconds(expTime);

    if (now > expTimeDate) {
      return cb(
        new error.TokenValidationError(
          'Expiration Time (exp) claim error in the ID token; current time "' +
            now +
            '" is after expiration time "' +
            expTimeDate +
            '"'
        ),
        null
      );
    }

    if (nbf && isNumber(nbf)) {
      var nbfTime = nbf - _this.leeway;
      var nbfTimeDate = new Date(0);
      nbfTimeDate.setUTCSeconds(nbfTime);

      if (now < nbfTimeDate) {
        return cb(
          new error.TokenValidationError(
            'Not Before Time (nbf) claim error in the ID token; current time "' +
              now +
              '" is before the not before time "' +
              nbfTimeDate +
              '"'
          ),
          null
        );
      }
    }

    if (_this.maxAge) {
      if (!auth_time || !isNumber(auth_time)) {
        return cb(
          new error.TokenValidationError(
            'Authentication Time (auth_time) claim must be a number present in the ID token when Max Age (max_age) is specified'
          ),
          null
        );
      }

      var authValidUntil = auth_time + _this.maxAge + _this.leeway;
      var authTimeDate = new Date(0);

      authTimeDate.setUTCSeconds(authValidUntil);

      if (now > authTimeDate) {
        return cb(
          new error.TokenValidationError(
            `Authentication Time (auth_time) claim in the ID token indicates that too much time has passed since the last end-user authentication. Current time "${now}" is after last auth time at "${authTimeDate}"`
          ),
          null
        );
      }
    }

    return cb(null, jwt.payload);
  });
};

IdTokenVerifier.prototype.getRsaVerifier = function(iss, kid, cb) {
  var _this = this;
  var cachekey = iss + kid;

  Promise.resolve(this.jwksCache.has(cachekey))
    .then(function(hasKey) {
      if (!hasKey) {
        return jwks.getJWKS({
          jwksURI: _this.jwksURI,
          iss: iss,
          kid: kid
        });
      } else {
        return _this.jwksCache.get(cachekey);
      }
    })
    .then(function(keyInfo) {
      if (!keyInfo || !keyInfo.modulus || !keyInfo.exp) {
        throw new Error('Empty keyInfo in response');
      }
      return Promise.resolve(_this.jwksCache.set(cachekey, keyInfo)).then(
        function() {
          cb && cb(null, new RSAVerifier(keyInfo.modulus, keyInfo.exp));
        }
      );
    })
    .catch(function(err) {
      cb && cb(err);
    });
};

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
IdTokenVerifier.prototype.decode = function(token) {
  var parts = token.split('.');
  var header;
  var payload;

  if (parts.length !== 3) {
    return new error.TokenValidationError('Cannot decode a malformed JWT');
  }

  try {
    header = JSON.parse(base64.decodeToString(parts[0]));
    payload = JSON.parse(base64.decodeToString(parts[1]));
  } catch (e) {
    return new error.TokenValidationError(
      'Token header or payload is not valid JSON'
    );
  }

  return {
    header: header,
    payload: payload,
    encoded: {
      header: parts[0],
      payload: parts[1],
      signature: parts[2]
    }
  };
};

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
IdTokenVerifier.prototype.validateAccessToken = function(
  accessToken,
  alg,
  atHash,
  cb
) {
  if (this.expectedAlg !== alg) {
    return cb(
      new error.TokenValidationError(
        'Signature algorithm of "' +
          alg +
          '" is not supported. Expected "' +
          this.expectedAlg +
          '"'
      )
    );
  }
  var sha256AccessToken = sha256(accessToken);
  var hashToHex = cryptoHex.stringify(sha256AccessToken);
  var hashToHexFirstHalf = hashToHex.substring(0, hashToHex.length / 2);
  var hashFirstHalfWordArray = cryptoHex.parse(hashToHexFirstHalf);
  var hashFirstHalfBase64 = cryptoBase64.stringify(hashFirstHalfWordArray);
  var hashFirstHalfBase64SafeUrl = base64.base64ToBase64Url(
    hashFirstHalfBase64
  );
  if (hashFirstHalfBase64SafeUrl !== atHash) {
    return cb(new error.TokenValidationError('Invalid access_token'));
  }
  return cb(null);
};

export default IdTokenVerifier;
