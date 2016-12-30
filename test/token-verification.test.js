var expect = require('expect.js');

var CacheMock = require('./mock/cache-mock');
var helpers = require('./helper/token-validation');

var error = require('../src/helpers/error');
var IdTokenVerifier = require('../src/index');

describe('jwt-verification', function () {
  it('should verify the signature using the public key in the cache', function (done) {
    helpers.assertTokenValid(
      {
        issuer: 'https://wptest.auth0.com/',
        audience: 'gYSNlU4YC4V1YPdqq8zPQcup6rJw1Mbt',
        __disableExpirationCheck: true,
        jwksCache: CacheMock.validKey()
      },
      'asfd',
      done
    )
  });

  it('should fetch the public key and verify the token', function (done) {
    helpers.assertTokenValid(
      {
        issuer: 'https://wptest.auth0.com/',
        audience: 'gYSNlU4YC4V1YPdqq8zPQcup6rJw1Mbt',
        __disableExpirationCheck: true
      },
      'asfd',
      done
    )
  });

  it('should FAIL to verify the signature using the public key', function (done) {
    helpers.assertTokenValidationError(
      {
        issuer: 'https://wptest.auth0.com/',
        audience: 'gYSNlU4YC4V1YPdqq8zPQcup6rJw1Mbt',
        __disableExpirationCheck: true,
        jwksCache: CacheMock.invalidKey()
      },
      'asfd',
      'Invalid signature.',
      null,
      done
    );
  });

  it('should fail if the leeway is too big', function (done) {
    helpers.assertValidatorInitalizationError(
      {
        leeway: 100
      },
      'The leeway should be positive and lower than a minute.',
      done
    );
  });

  it('should fail if the leeway is negative', function (done) {
    helpers.assertValidatorInitalizationError(
      {
        leeway: -1
      },
      'The leeway should be positive and lower than a minute.',
      done
    );
  });

  it('should fail if the algorithm is not supported', function (done) {
    helpers.assertValidatorInitalizationError(
      {
        expectedAlg: 'HS256'
      },
      'Algorithm HS256 is not supported. (Expected algs: [RS256])',
      done
    );
  });

  it('should fail if the nonce does not match', function (done) {
    helpers.assertTokenValidationError(
      {
        issuer: 'https://wptest.auth0.com/',
        audience: 'gYSNlU4YC4V1YPdqq8zPQcup6rJw1Mbt',
        __disableExpirationCheck: true,
        jwksCache: CacheMock.validKey()
      },
      'invalid',
      'Nonce does not match.',
      null,
      done
    );
  });

  it('should fail if the token is not valid', function (done) {
    helpers.assertTokenValidationError(
      {},
      null,
      'Cannot decode a malformed JWT',
      'asjkdhfgakdsjhf',
      done
    );
  });

  it('should require to whitelist the iss', function (done) {
    helpers.assertTokenValidationError(
      {},
      'asfd',
      'Issuer https://wptest.auth0.com/ is not valid.',
      null,
      done
    );
  });

  it('should require to whitelist the audience', function (done) {
    helpers.assertTokenValidationError(
      {
        issuer: 'https://wptest.auth0.com/',
      },
      'asfd',
      'Audience gYSNlU4YC4V1YPdqq8zPQcup6rJw1Mbt is not valid.',
      null,
      done
    );
  });

  it('should require to whitelist the audience', function (done) {
    helpers.assertTokenValidationError(
      {
        issuer: 'https://wptest.auth0.com/',
        audience: 'gYSNlU4YC4V1YPdqq8zPQcup6rJw1Mbt',
      },
      'asfd',
      'Expired token.',
      null,
      done
    );
  });

  it('should check the token expiration', function (done) {
    helpers.assertTokenValidationError(
      {
        issuer: 'https://wptest.auth0.com/',
        audience: 'gYSNlU4YC4V1YPdqq8zPQcup6rJw1Mbt',
      },
      'asfd',
      'Expired token.',
      null,
      done
    );
  });

  it('should fail if the token alg is not the one expected', function (done) {
    helpers.assertTokenValidationError(
      {
        issuer: 'https://wptest.auth0.com/',
        audience: 'gYSNlU4YC4V1YPdqq8zPQcup6rJw1Mbt',
      },
      'asfd',
      'Algorithm HS256 is not supported. (Expected algs: [RS256])',
      'eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJpc3MiOiJodHRwczovL3dwdGVzdC5hdXRoMC5jb20vIiwic3ViIjoiYXV0aDB8NTVkNDhjNTdkNWIwYWQwMjIzYzQwOGQ3IiwiYXVkIjoiZ1lTTmxVNFlDNFYxWVBkcXE4elBRY3VwNnJKdzFNYnQiLCJleHAiOjE0ODI5NjkwMzEsImlhdCI6MTQ4MjkzMzAzMSwibm9uY2UiOiJhc2ZkIn0.PPoh-pITcZ8qbF5l5rMZwXiwk5efbESuqZ0IfMUcamB6jdgLwTxq-HpOT_x5q6-sO1PBHchpSo1WHeDYMlRrOFd9bh741sUuBuXdPQZ3Zb0i2sNOAC2RFB1E11mZn7uNvVPGdPTg-Y5xppz30GSXoOJLbeBszfrVDCmPhpHKGGMPL1N6HV-3EEF77L34YNAi2JQ-b70nFK_dnYmmv0cYTGUxtGTHkl64UEDLi3u7bV-kbGky3iOOCzXKzDDY6BBKpCRTc2KlbrkO2A2PuDn27WVv1QCNEFHvJN7HxiDDzXOsaUmjrQ3sfrHhzD7S9BcCRkekRfD9g95SKD5J0Fj8NA',
      done
    );
  });

  it('should fail with missing claims', function (done) {
    helpers.assertTokenValidationError(
      {
        issuer: 'https://wptest.auth0.com/',
        audience: 'gYSNlU4YC4V1YPdqq8zPQcup6rJw1Mbt',
      },
      'asfd',
      'Issuer undefined is not valid.',
      'eyJ0eXAiOiJKV1QiLCJhbGciOiJSUzI1NiIsImtpZCI6IlF6RTROMFpCTTBWRFF6RTJSVVUwTnpJMVF6WTFNelE0UVRrMU16QXdNRUk0UkRneE56RTRSZyJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiYWRtaW4iOnRydWV9.PPoh-pITcZ8qbF5l5rMZwXiwk5efbESuqZ0IfMUcamB6jdgLwTxq-HpOT_x5q6-sO1PBHchpSo1WHeDYMlRrOFd9bh741sUuBuXdPQZ3Zb0i2sNOAC2RFB1E11mZn7uNvVPGdPTg-Y5xppz30GSXoOJLbeBszfrVDCmPhpHKGGMPL1N6HV-3EEF77L34YNAi2JQ-b70nFK_dnYmmv0cYTGUxtGTHkl64UEDLi3u7bV-kbGky3iOOCzXKzDDY6BBKpCRTc2KlbrkO2A2PuDn27WVv1QCNEFHvJN7HxiDDzXOsaUmjrQ3sfrHhzD7S9BcCRkekRfD9g95SKD5J0Fj8NA',
      done
    );
  });

  it('should fail with corrupt token', function (done) {
    helpers.assertTokenValidationError(
      {
        issuer: 'https://wptest.auth0.com/',
        audience: 'gYSNlU4YC4V1YPdqq8zPQcup6rJw1Mbt',
      },
      'asfd',
      'Invalid signature.',
      'eyJ0eXAiOiJKV1QiLCJhbGciOiJSUzI1NiIsImtpZCI6IlF6RTROMFpCTTBWRFF6RTJSVVUwTnpJMVF6WTFNelE0UVRrMU16QXdNRUk0UkRneE56RTRSZyJ9.eyJpc3MiOiJodHRwczovL3dwdGVzdC5hdXRoMC5jb20vIiwic3ViIjoiYXV0aDB8NTVkNDhjNTdkNWIwYWQwMjIzYzQwOGQ3IiwiYXVkIjoiZ1lTTmxVNFlDNFYxWVBkcXE4elBRY3VwNnJKdzFNYnQiLCJleHAiOjk0ODI5NjkwMzEsImlhdCI6MTQ4MjkzMzAzMSwibm9uY2UiOiJhc2ZkIn0.PPoh-pITcZ8qbF5l5rMZwXiwk5efbESuqZ0IfMUcamB6jdgLwTxq-HpOT_x5q6-sO1PBHchpSo1WHeDYMlRrOFd9bh741sUuBuXdPQZ3Zb0i2sNOAC2RFB1E11mZn7uNvVPGdPTg-Y5xppz30GSXoOJLbeBszfrVDCmPhpHKGGMPL1N6HV-3EEF77L34YNAi2JQ-b70nFK_dnYmmv0cYTGUxtGTHkl64UEDLi3u7bV-kbGky3iOOCzXKzDDY6BBKpCRTc2KlbrkO2A2PuDn27WVv1QCNEFHvJN7HxiDDzXOsaUmjrQ3sfrHhzD7S9BcCRkekRfD9g95SKD5J0Fj8NA',
      done
    );
  });

  it('should validate the iat claim', function (done) {
    helpers.assertTokenValidationError(
      {
        issuer: 'https://wptest.auth0.com/',
        audience: 'gYSNlU4YC4V1YPdqq8zPQcup6rJw1Mbt',
      },
      'asfd',
      'The token was issued in the future. Please check your computed clock.',
      'eyJ0eXAiOiJKV1QiLCJhbGciOiJSUzI1NiIsImtpZCI6IlF6RTROMFpCTTBWRFF6RTJSVVUwTnpJMVF6WTFNelE0UVRrMU16QXdNRUk0UkRneE56RTRSZyJ9.eyJpc3MiOiJodHRwczovL3dwdGVzdC5hdXRoMC5jb20vIiwic3ViIjoiYXV0aDB8NTVkNDhjNTdkNWIwYWQwMjIzYzQwOGQ3IiwiYXVkIjoiZ1lTTmxVNFlDNFYxWVBkcXE4elBRY3VwNnJKdzFNYnQiLCJleHAiOjk0ODI5NjkwMzEsImlhdCI6OTQ4MjkzMzAzMSwibm9uY2UiOiJhc2ZkIn0.PPoh-pITcZ8qbF5l5rMZwXiwk5efbESuqZ0IfMUcamB6jdgLwTxq-HpOT_x5q6-sO1PBHchpSo1WHeDYMlRrOFd9bh741sUuBuXdPQZ3Zb0i2sNOAC2RFB1E11mZn7uNvVPGdPTg-Y5xppz30GSXoOJLbeBszfrVDCmPhpHKGGMPL1N6HV-3EEF77L34YNAi2JQ-b70nFK_dnYmmv0cYTGUxtGTHkl64UEDLi3u7bV-kbGky3iOOCzXKzDDY6BBKpCRTc2KlbrkO2A2PuDn27WVv1QCNEFHvJN7HxiDDzXOsaUmjrQ3sfrHhzD7S9BcCRkekRfD9g95SKD5J0Fj8NA',
      done
    );
  });

  it('should decode the token', function () {
    var id_token = 'eyJ0eXAiOiJKV1QiLCJhbGciOiJSUzI1NiIsImtpZCI6IlF6RTROMFpCTTBWRFF6RTJSVVUwTnpJMVF6WTFNelE0UVRrMU16QXdNRUk0UkRneE56RTRSZyJ9.eyJpc3MiOiJodHRwczovL3dwdGVzdC5hdXRoMC5jb20vIiwic3ViIjoiYXV0aDB8NTVkNDhjNTdkNWIwYWQwMjIzYzQwOGQ3IiwiYXVkIjoiZ1lTTmxVNFlDNFYxWVBkcXE4elBRY3VwNnJKdzFNYnQiLCJleHAiOjE0ODI5NjkwMzEsImlhdCI6MTQ4MjkzMzAzMSwibm9uY2UiOiJhc2ZkIn0.PPoh-pITcZ8qbF5l5rMZwXiwk5efbESuqZ0IfMUcamB6jdgLwTxq-HpOT_x5q6-sO1PBHchpSo1WHeDYMlRrOFd9bh741sUuBuXdPQZ3Zb0i2sNOAC2RFB1E11mZn7uNvVPGdPTg-Y5xppz30GSXoOJLbeBszfrVDCmPhpHKGGMPL1N6HV-3EEF77L34YNAi2JQ-b70nFK_dnYmmv0cYTGUxtGTHkl64UEDLi3u7bV-kbGky3iOOCzXKzDDY6BBKpCRTc2KlbrkO2A2PuDn27WVv1QCNEFHvJN7HxiDDzXOsaUmjrQ3sfrHhzD7S9BcCRkekRfD9g95SKD5J0Fj8NA';
    var verifier = new IdTokenVerifier();
    var result = verifier.decode(id_token);

    expect(result).to.eql({
      header: {
        typ: 'JWT',
        alg: 'RS256',
        kid: 'QzE4N0ZBM0VDQzE2RUU0NzI1QzY1MzQ4QTk1MzAwMEI4RDgxNzE4Rg'
      },
      payload: {
        iss: 'https://wptest.auth0.com/',
        sub: 'auth0|55d48c57d5b0ad0223c408d7',
        aud: 'gYSNlU4YC4V1YPdqq8zPQcup6rJw1Mbt',
        exp: 1482969031,
        iat: 1482933031,
        nonce: 'asfd'
      },
      encoded: {
        header: 'eyJ0eXAiOiJKV1QiLCJhbGciOiJSUzI1NiIsImtpZCI6IlF6RTROMFpCTTBWRFF6RTJSVVUwTnpJMVF6WTFNelE0UVRrMU16QXdNRUk0UkRneE56RTRSZyJ9',
        payload: 'eyJpc3MiOiJodHRwczovL3dwdGVzdC5hdXRoMC5jb20vIiwic3ViIjoiYXV0aDB8NTVkNDhjNTdkNWIwYWQwMjIzYzQwOGQ3IiwiYXVkIjoiZ1lTTmxVNFlDNFYxWVBkcXE4elBRY3VwNnJKdzFNYnQiLCJleHAiOjE0ODI5NjkwMzEsImlhdCI6MTQ4MjkzMzAzMSwibm9uY2UiOiJhc2ZkIn0',
        signature: 'PPoh-pITcZ8qbF5l5rMZwXiwk5efbESuqZ0IfMUcamB6jdgLwTxq-HpOT_x5q6-sO1PBHchpSo1WHeDYMlRrOFd9bh741sUuBuXdPQZ3Zb0i2sNOAC2RFB1E11mZn7uNvVPGdPTg-Y5xppz30GSXoOJLbeBszfrVDCmPhpHKGGMPL1N6HV-3EEF77L34YNAi2JQ-b70nFK_dnYmmv0cYTGUxtGTHkl64UEDLi3u7bV-kbGky3iOOCzXKzDDY6BBKpCRTc2KlbrkO2A2PuDn27WVv1QCNEFHvJN7HxiDDzXOsaUmjrQ3sfrHhzD7S9BcCRkekRfD9g95SKD5J0Fj8NA'
      }
    });
  });

  it('should return an error when trying to decode (not verify) a malformed token', function () {
    var id_token = 'this.is.not.a.jwt';
    var verifier = new IdTokenVerifier();
    var result = verifier.decode(id_token);
    expect(result).to.be.an(error.TokenValidationError);
    expect(result.message).to.eql('Cannot decode a malformed JWT');
  });

  it('should return an error when trying to decode (not verify) a token with invalid JSON contents', function () {
    var id_token = 'invalid.json.here';
    var verifier = new IdTokenVerifier();
    var result = verifier.decode(id_token);
    expect(result).to.be.an(error.TokenValidationError);
    expect(result.message).to.eql('Token header or payload is not valid JSON');
  });
});
