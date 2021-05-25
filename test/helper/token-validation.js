import expect from 'expect.js';

import IdTokenVerifier from '../../src/index';
import * as error from '../../src/helpers/error';

export const DEFAULT_CONFIG = {
  issuer: '__TEST_ISSUER__',
  audience: '__TEST_AUDIENCE__'
};

function assertTokenValidationError(
  configuration,
  nonce,
  message,
  id_token,
  done
) {
  var verifier = new IdTokenVerifier(configuration);

  verifier.verify(id_token, nonce, function(err, result) {
    expect(err).to.be.a(error.TokenValidationError);
    expect(err.message).to.eql(message);
    expect(result).to.eql(null);
    done();
  });
}

function assertValidatorInitalizationError(configuration, message, done) {
  expect(function() {
    new IdTokenVerifier(configuration);
  }).to.throwException(function(err) {
    // get the exception object
    expect(err).to.be.a(error.ConfigurationError);
    expect(err.message).to.eql(message);
    done();
  });
}

function assertTokenValid(token, configuration, nonce, done) {
  var verifier = new IdTokenVerifier(configuration);

  verifier.verify(token, nonce, function(err, result) {
    expect(err).to.eql(null);
    expect(result).to.eql({
      iss: 'https://wptest.auth0.com/',
      sub: 'auth0|55d48c57d5b0ad0223c408d7',
      aud: 'gYSNlU4YC4V1YPdqq8zPQcup6rJw1Mbt',
      exp: 1482969031,
      iat: 1482933031,
      nonce: 'asfd'
    });
    done();
  });
}

export default {
  assertValidatorInitalizationError: assertValidatorInitalizationError,
  assertTokenValidationError: assertTokenValidationError,
  assertTokenValid: assertTokenValid
};
