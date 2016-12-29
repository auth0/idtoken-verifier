var RSAVerifier = require('./helpers/rsa-verifier');
var base64 = require('./helpers/base64');
var jwks = require('./helpers/jwks');
var error = require('./helpers/error');
var DummyCache = require('./helpers/dummy-cache');
var supportedAlgs = ['RS256'];

function JWTVerifier(options) {
  options = options || {};

  this.jwksCache = options.jwksCache || new DummyCache();
  this.cacheNameSpace = options.cacheNameSpace || 'com.auth0.auth.jwks.';
  this.expectedAlg = options.expectedAlg || 'RS256';
  this.expectedIss = options.expectedIss;
  this.expectedAud = options.expectedAud;
  this.leeway = options.leeway || 0;
  this.__disableExpirationCheck = options.__disableExpirationCheck || false;

  if (this.leeway < 0 || this.leeway > 60) {
    throw new error.ConfigurationError('The leeway should be positive and lower than a minute.');
  }

  if (supportedAlgs.indexOf(this.expectedAlg) === -1) {
    throw new error.ConfigurationError('Algorithm ' + this.expectedAlg +
      ' is not supported. (Expected algs: [' + supportedAlgs.join(',') + '])');
  }
}

JWTVerifier.prototype.verify = function jwtVerify(token, nonce, cb) {
  var jwt = this.decode(token);

  if (!jwt) {
    return cb(new error.TokenValidationError('Invalid token.'), false);
  }

  var headAndPayload = jwt.encoded.header + '.' + jwt.encoded.payload;
  var signature = base64.decodeToHEX(jwt.encoded.signature);

  var alg = jwt.header.alg;
  var kid = jwt.header.kid;

  var aud = jwt.payload.aud;
  var iss = jwt.payload.iss;
  var exp = jwt.payload.exp;
  var iat = jwt.payload.iat;
  var tnonce = jwt.payload.nonce || null;

  if (this.expectedIss !== iss) {
    return cb(new error.TokenValidationError('Issuer ' + iss + ' is not valid.'), false);
  }

  if (this.expectedAud !== aud) {
    return cb(new error.TokenValidationError('Audience ' + aud + ' is not valid.'), false);
  }

  if (this.expectedAlg !== alg) {
    return cb(new error.TokenValidationError('Algorithm ' + alg +
      ' is not supported. (Expected algs: [' + supportedAlgs.join(',') + '])'), false);
  }

  if (tnonce !== nonce) {
    return cb(new error.TokenValidationError('Nonce does not match.'), false);
  }

  var expirationError = this.verifyExpAndIat(exp, iat);

  if (expirationError) {
    return cb(expirationError, false);
  }

  this.getRsaVerifier(iss, kid, function (err, rsaVerifier) {
    if (err) {
      return cb(err);
    }
    if (rsaVerifier.verify(headAndPayload, signature)) {
      cb(null, true);
    } else {
      cb(new error.TokenValidationError('Invalid signature.'), false);
    }
  });
};

JWTVerifier.prototype.verifyExpAndIat = function jwtVerifyExpAndIat(exp, iat) {
  if (this.__disableExpirationCheck) {
    return null;
  }

  var now = new Date();

  var expDate = new Date(0);
  expDate.setUTCSeconds(exp + this.leeway);

  if (now > expDate) {
    return new error.TokenValidationError('Expired token.');
  }

  var iatDate = new Date(0);
  iatDate.setUTCSeconds(iat - this.leeway);

  if (now < iatDate) {
    return new error.TokenValidationError('The token was issued in the future. ' +
      'Please check your computed clock.');
  }

  return null;
};

JWTVerifier.prototype.getRsaVerifier = function jwtGetRsaVerifier(iss, kid, cb) {
  var _this = this;
  var cachekey = this.cacheNameSpace + iss + kid;

  if (!this.jwksCache.has(cachekey)) {
    jwks.getJWKS({
      iss: iss,
      kid: kid
    }, function (err, keyInfo) {
      if (err) {
        cb(err);
      }
      _this.jwksCache.set(cachekey, keyInfo);
      cb(null, new RSAVerifier(keyInfo.modulus, keyInfo.exp));
    });
  } else {
    var keyInfo = this.jwksCache.get(cachekey);
    cb(null, new RSAVerifier(keyInfo.modulus, keyInfo.exp));
  }
};

JWTVerifier.prototype.decode = function jwtDecode(token) {
  var parts = token.split('.');

  if (parts.length !== 3) {
    return null;
  }

  return {
    header: JSON.parse(base64.decodeToString(parts[0])),
    payload: JSON.parse(base64.decodeToString(parts[1])),
    encoded: {
      header: parts[0],
      payload: parts[1],
      signature: parts[2]
    }
  };
};

module.exports = JWTVerifier;
