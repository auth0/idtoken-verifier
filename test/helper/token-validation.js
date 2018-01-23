var expect = require('expect.js');

var IdTokenVerifier = require('../../src/index');
var error = require('../../src/helpers/error');

const validToken = 'eyJ0eXAiOiJKV1QiLCJhbGciOiJSUzI1NiIsImtpZCI6IlF6RTROMFpCTTBWRFF6RTJSVVUwTnpJMVF6WTFNelE0UVRrMU16QXdNRUk0UkRneE56RTRSZyJ9.eyJpc3MiOiJodHRwczovL3dwdGVzdC5hdXRoMC5jb20vIiwic3ViIjoiYXV0aDB8NTVkNDhjNTdkNWIwYWQwMjIzYzQwOGQ3IiwiYXVkIjoiZ1lTTmxVNFlDNFYxWVBkcXE4elBRY3VwNnJKdzFNYnQiLCJleHAiOjE0ODI5NjkwMzEsImlhdCI6MTQ4MjkzMzAzMSwibm9uY2UiOiJhc2ZkIn0.PPoh-pITcZ8qbF5l5rMZwXiwk5efbESuqZ0IfMUcamB6jdgLwTxq-HpOT_x5q6-sO1PBHchpSo1WHeDYMlRrOFd9bh741sUuBuXdPQZ3Zb0i2sNOAC2RFB1E11mZn7uNvVPGdPTg-Y5xppz30GSXoOJLbeBszfrVDCmPhpHKGGMPL1N6HV-3EEF77L34YNAi2JQ-b70nFK_dnYmmv0cYTGUxtGTHkl64UEDLi3u7bV-kbGky3iOOCzXKzDDY6BBKpCRTc2KlbrkO2A2PuDn27WVv1QCNEFHvJN7HxiDDzXOsaUmjrQ3sfrHhzD7S9BcCRkekRfD9g95SKD5J0Fj8NA';
const validIssuer = 'https://wptest.auth0.com/';
const validAudience = 'gYSNlU4YC4V1YPdqq8zPQcup6rJw1Mbt';
const validSub = 'auth0|55d48c57d5b0ad0223c408d7';
const validNonce = 'asfd';


function assertTokenValidationError(configuration, nonce, message, id_token, done) {
  id_token = id_token || validToken;

  var verifier = new IdTokenVerifier(configuration);

  verifier.verify(id_token, nonce, function(err, result) {
    expect(err).to.be.a(error.TokenValidationError);
    expect(err.message).to.eql(message);
    expect(result).to.not.be.ok();
    done();
  });
}

function assertValidatorInitalizationError(configuration, message, done) {
  expect(function() {
    new IdTokenVerifier(configuration);
  }).to.throwException(function (err) { // get the exception object
    expect(err).to.be.a(error.ConfigurationError);
    expect(err.message).to.eql(message);
    done();
  });
}

function assertTokenValid(configuration, nonce, id_token, expectedDecodeResult, done) {
  id_token = id_token || validToken;

  expectedDecodeResult = expectedDecodeResult || {
    iss: validIssuer,
    sub: validSub,
    aud: validAudience,
    exp: 1482969031,
    iat: 1482933031,
    nonce: validNonce
  };

  var verifier = new IdTokenVerifier(configuration);

  verifier.verify(id_token, nonce, function(err, result) {
    expect(err).to.be(null);
    expect(result).to.eql(expectedDecodeResult);
    done();
  });
}

module.exports = {
  assertValidatorInitalizationError: assertValidatorInitalizationError,
  assertTokenValidationError: assertTokenValidationError,
  assertTokenValid: assertTokenValid,
  validToken: validToken,
  validAudience: validAudience,
  validIssuer: validIssuer,
  validSub: validSub,
  validNonce: validNonce
};