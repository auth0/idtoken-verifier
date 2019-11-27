import expect from 'expect.js';
import nodeFetch from 'node-fetch';

import CacheMock from './mock/cache-mock';
import helpers, { DEFAULT_CONFIG } from './helper/token-validation';
import sinon from 'sinon';

import * as error from '../src/helpers/error';
import IdTokenVerifier from '../src/index';
import {
  defaultToken,
  createJWT,
  DEFAULT_PAYLOAD,
  defaultExp,
  defaultExpDate,
  DEFAULT_OPTIONS
} from './helper/jwt';

const nowSeconds = () => Math.floor(Date.now() / 1000);

describe('jwt-verification', function() {
  describe('verify', () => {
    describe('with a configuration error', () => {
      it('should fail if the leeway is too big', done => {
        helpers.assertValidatorInitalizationError(
          {
            leeway: 301
          },
          'The leeway should be positive and lower than five minutes.',
          done
        );
      });

      it('should fail if the leeway is negative', done => {
        helpers.assertValidatorInitalizationError(
          {
            leeway: -1
          },
          'The leeway should be positive and lower than five minutes.',
          done
        );
      });

      it('should fail if the algorithm is not supported', done => {
        helpers.assertValidatorInitalizationError(
          {
            expectedAlg: 'HS256'
          },
          `Signature algorithm of "HS256" is not supported. Expected the ID token to be signed with "RS256".`,
          done
        );
      });

      it('should fail if the token is not valid', done => {
        helpers.assertTokenValidationError(
          {},
          null,
          'Cannot decode a malformed JWT',
          'asjkdhfgakdsjhf',
          done
        );
      });

      it('should fail if the token is not present', done => {
        helpers.assertTokenValidationError(
          {},
          null,
          'ID token is required but missing',
          null,
          done
        );
      });
    });

    it('should validate the supported algorithm before calling `getRsaVerifier`', done => {
      const spy = sinon.spy(IdTokenVerifier.prototype, 'getRsaVerifier');

      helpers.assertTokenValidationError(
        {
          issuer: 'https://wptest.auth0.com/',
          audience: 'gYSNlU4YC4V1YPdqq8zPQcup6rJw1Mbt'
        },
        'asfd',
        `Signature algorithm of "HS256" is not supported. Expected the ID token to be signed with "RS256".`,
        'eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJpc3MiOiJodHRwczovL3dwdGVzdC5hdXRoMC5jb20vIiwic3ViIjoiYXV0aDB8NTVkNDhjNTdkNWIwYWQwMjIzYzQwOGQ3IiwiYXVkIjoiZ1lTTmxVNFlDNFYxWVBkcXE4elBRY3VwNnJKdzFNYnQiLCJleHAiOjE0ODI5NjkwMzEsImlhdCI6MTQ4MjkzMzAzMSwibm9uY2UiOiJhc2ZkIn0.PPoh-pITcZ8qbF5l5rMZwXiwk5efbESuqZ0IfMUcamB6jdgLwTxq-HpOT_x5q6-sO1PBHchpSo1WHeDYMlRrOFd9bh741sUuBuXdPQZ3Zb0i2sNOAC2RFB1E11mZn7uNvVPGdPTg-Y5xppz30GSXoOJLbeBszfrVDCmPhpHKGGMPL1N6HV-3EEF77L34YNAi2JQ-b70nFK_dnYmmv0cYTGUxtGTHkl64UEDLi3u7bV-kbGky3iOOCzXKzDDY6BBKpCRTc2KlbrkO2A2PuDn27WVv1QCNEFHvJN7HxiDDzXOsaUmjrQ3sfrHhzD7S9BcCRkekRfD9g95SKD5J0Fj8NA',
        done
      );

      expect(spy.callCount).to.be(0);
      IdTokenVerifier.prototype.getRsaVerifier.restore();
    });

    describe('with a valid configuration', () => {
      afterEach(() => {
        expect(IdTokenVerifier.prototype.getRsaVerifier.callCount).to.be(1);
        IdTokenVerifier.prototype.getRsaVerifier.restore();
      });

      it('should fail when `getRsaVerifier` fails', done => {
        const error = { error: 'fail' };

        sinon
          .stub(IdTokenVerifier.prototype, 'getRsaVerifier')
          .callsFake((_, __, cb) => cb(error));

        var idv = new IdTokenVerifier();

        idv.verify(
          'eyJ0eXAiOiJKV1QiLCJhbGciOiJSUzI1NiIsImtpZCI6IlF6RTROMFpCTTBWRFF6RTJSVVUwTnpJMVF6WTFNelE0UVRrMU16QXdNRUk0UkRneE56RTRSZyJ9.eyJpc3MiOiJodHRwczovL3dwdGVzdC5hdXRoMC5jb20vIiwic3ViIjoiYXV0aDB8NTVkNDhjNTdkNWIwYWQwMjIzYzQwOGQ3IiwiYXVkIjoiZ1lTTmxVNFlDNFYxWVBkcXE4elBRY3VwNnJKdzFNYnQiLCJleHAiOjE0ODI5NjkwMzEsImlhdCI6MTQ4MjkzMzAzMSwibm9uY2UiOiJhc2ZkIn0.PPoh-pITcZ8qbF5l5rMZwXiwk5efbESuqZ0IfMUcamB6jdgLwTxq-HpOT_x5q6-sO1PBHchpSo1WHeDYMlRrOFd9bh741sUuBuXdPQZ3Zb0i2sNOAC2RFB1E11mZn7uNvVPGdPTg-Y5xppz30GSXoOJLbeBszfrVDCmPhpHKGGMPL1N6HV-3EEF77L34YNAi2JQ-b70nFK_dnYmmv0cYTGUxtGTHkl64UEDLi3u7bV-kbGky3iOOCzXKzDDY6BBKpCRTc2KlbrkO2A2PuDn27WVv1QCNEFHvJN7HxiDDzXOsaUmjrQ3sfrHhzD7S9BcCRkekRfD9g95SKD5J0Fj8NA',
          'test_nonce',
          err => {
            expect(err).to.be.eql(error);
            done();
          }
        );
      });

      it('should fail when `rsaVerifier.verify` returns false', function(done) {
        sinon
          .stub(IdTokenVerifier.prototype, 'getRsaVerifier')
          .callsFake((_, __, cb) =>
            cb(null, {
              verify: () => {
                return false;
              }
            })
          );

        helpers.assertTokenValidationError(
          {
            issuer: 'https://wptest.auth0.com/',
            audience: 'gYSNlU4YC4V1YPdqq8zPQcup6rJw1Mbt'
          },
          'asfd',
          'Invalid signature.',
          defaultToken,
          done
        );
      });

      describe('when `rsaVerifier.verify` returns true', () => {
        beforeEach(() => {
          sinon
            .stub(IdTokenVerifier.prototype, 'getRsaVerifier')
            .callsFake((_, __, cb) =>
              cb(null, {
                verify: () => {
                  return true;
                }
              })
            );
        });

        it('validates issuer presence', done => {
          const { issuer, ...options } = DEFAULT_OPTIONS;

          createJWT(DEFAULT_PAYLOAD, options)
            .then(token => {
              helpers.assertTokenValidationError(
                {},
                'oufd',
                'Issuer (iss) claim must be a string present in the ID token',
                token,
                done
              );
            })
            .catch(done);
        });

        it('validates issuer', done => {
          createJWT(DEFAULT_PAYLOAD)
            .then(token => {
              helpers.assertTokenValidationError(
                {
                  issuer: 'https://example.com/'
                },
                'asfd',
                `Issuer (iss) claim mismatch in the ID token, expected (https://example.com/), found (https://wptest.auth0.com/)`,
                token,
                done
              );
            })
            .catch(done);
        });

        it('validates presence of subject in the token', done => {
          const { sub, ...payload } = DEFAULT_PAYLOAD;

          createJWT(payload)
            .then(token => {
              helpers.assertTokenValidationError(
                DEFAULT_CONFIG,
                'ksdhf',
                'Subject (sub) claim must be a string present in the ID token',
                token,
                done
              );
            })
            .catch(done);
        });

        it('validates audience presence', done => {
          const { audience, ...options } = DEFAULT_OPTIONS;

          createJWT(DEFAULT_PAYLOAD, options)
            .then(token =>
              helpers.assertTokenValidationError(
                DEFAULT_CONFIG,
                'foidsf',
                'Audience (aud) claim must be a string or array of strings present in the ID token',
                token,
                done
              )
            )
            .catch(done);
        });

        it('validates audience string', done => {
          helpers.assertTokenValidationError(
            {
              issuer: 'https://wptest.auth0.com/',
              audience: '98fukfdjlkff'
            },
            'asfd',
            `Audience (aud) claim mismatch in the ID token; expected 98fukfdjlkff but found ${DEFAULT_CONFIG.audience}`,
            defaultToken,
            done
          );
        });

        it('validates audience as an array', done => {
          const optionsWithAudience = Object.assign({}, DEFAULT_OPTIONS, {
            audience: ['audience-1', 'audience-2']
          });

          createJWT(DEFAULT_PAYLOAD, optionsWithAudience)
            .then(token =>
              helpers.assertTokenValidationError(
                DEFAULT_CONFIG,
                'oidufldsf',
                'Audience (aud) claim mismatch in the ID token; expected gYSNlU4YC4V1YPdqq8zPQcup6rJw1Mbt but was not one of audience-1, audience-2',
                token,
                done
              )
            )
            .catch(done);
        });

        it('should validate nonce presence', done => {
          const { nonce, ...payload } = DEFAULT_PAYLOAD;

          createJWT(payload)
            .then(token =>
              helpers.assertTokenValidationError(
                DEFAULT_CONFIG,
                'lifusdflidf',
                'Nonce (nonce) claim must be a string present in the ID token',
                token,
                done
              )
            )
            .catch(done);
        });

        it('should not validate the nonce if none was given', done => {
          createJWT()
            .then(token => {
              var verifier = new IdTokenVerifier(DEFAULT_CONFIG);
              verifier.verify(token, undefined, done);
            })
            .catch(done);
        });

        it('should validate nonce', done => {
          helpers.assertTokenValidationError(
            DEFAULT_CONFIG,
            'invalid',
            'Nonce (nonce) claim value mismatch in the ID token; expected "invalid", found "asfd"',
            defaultToken,
            done
          );
        });

        it('should fail if the nonce was not a string', done => {
          const payload = Object.assign({}, DEFAULT_PAYLOAD, { nonce: 839803 });

          createJWT(payload)
            .then(token => {
              helpers.assertTokenValidationError(
                DEFAULT_CONFIG,
                'asfd',
                'Nonce (nonce) claim must be a string present in the ID token',
                token,
                done
              );
            })
            .catch(done);
        });

        it('should validate the presence of the azp claim', done => {
          const { azp, ...payload } = DEFAULT_PAYLOAD;

          createJWT(payload, {
            audience: ['audience-1', 'audience-2'],
            issuer: DEFAULT_CONFIG.issuer
          })
            .then(token => {
              helpers.assertTokenValidationError(
                {
                  issuer: DEFAULT_CONFIG.issuer,
                  audience: 'audience-1'
                },
                'asfd',
                'Authorized Party (azp) claim must be a string present in the ID token when Audience (aud) claim has multiple values',
                token,
                done
              );
            })
            .catch(done);
        });

        it('should validate that the azp claim (when present) matches the specified audience', done => {
          const payload = Object.assign({}, DEFAULT_PAYLOAD, {
            azp: 'something-different'
          });

          const options = Object.assign({}, DEFAULT_OPTIONS, {
            audience: ['audience-1', 'audience-2']
          });

          createJWT(payload, options)
            .then(token => {
              helpers.assertTokenValidationError(
                {
                  issuer: DEFAULT_CONFIG.issuer,
                  audience: 'audience-1'
                },
                'asfd',
                `Authorized Party (azp) claim mismatch in the ID token; expected "audience-1", found "something-different"`,
                token,
                done
              );
            })
            .catch(done);
        });

        it('should validate the nbf claim', done => {
          const nbfDate = new Date();
          nbfDate.setSeconds(nbfDate.getSeconds() + 100);

          const validFromDate = new Date(0);
          validFromDate.setUTCSeconds(nowSeconds() + 40);

          const payload = Object.assign({}, DEFAULT_PAYLOAD, {
            nbf: Math.floor(nbfDate.getTime() / 1000)
          });

          createJWT(payload, DEFAULT_OPTIONS)
            .then(token => {
              helpers.assertTokenValidationError(
                DEFAULT_CONFIG,
                'asfd',
                `Not Before time (nbf) claim in the ID token indicates that this token can't be used just yet. Currrent time (${new Date()}) is before ${validFromDate}`,
                token,
                done
              );
            })
            .catch(done);
        });

        it('should validate the exp claim presence', done => {
          const { expiresIn, ...options } = DEFAULT_OPTIONS;

          createJWT(DEFAULT_PAYLOAD, options)
            .then(token => {
              helpers.assertTokenValidationError(
                DEFAULT_CONFIG,
                'asfd',
                'Expiration Time (exp) claim must be a number present in the ID token',
                token,
                done
              );
            })
            .catch(done);
        });

        it('should validate the token expiration', done => {
          helpers.assertTokenValidationError(
            DEFAULT_CONFIG,
            'asfd',
            `Expiration Time (exp) claim error in the ID token; current time (${new Date()}) is after expiration time (${defaultExpDate})`,
            defaultToken,
            done
          );
        });

        it('should validate the presence of issued-at claim', done => {
          const options = Object.assign({}, DEFAULT_OPTIONS, {
            noTimestamp: true
          });

          createJWT(DEFAULT_PAYLOAD, options)
            .then(token => {
              helpers.assertTokenValidationError(
                DEFAULT_CONFIG,
                'asfd',
                'Issued At (iat) claim must be a number present in the ID token',
                token,
                done
              );
            })
            .catch(done);
        });

        it('should validate the token issued at claim', done => {
          const iat = nowSeconds() + 100;

          const payload = Object.assign({}, DEFAULT_PAYLOAD, {
            iat
          });

          createJWT(payload, DEFAULT_OPTIONS)
            .then(token => {
              helpers.assertTokenValidationError(
                DEFAULT_CONFIG,
                'asfd',
                `Issued At (iat) claim error in the ID token; current time (${new Date()}) is before issued at time (${new Date(
                  (iat - 60) * 1000
                )})`,
                token,
                done
              );
            })
            .catch(done);
        });

        it('should validate presence of auth_time when max_age was specified', done => {
          const config = Object.assign({}, DEFAULT_CONFIG, {
            maxAge: 1000
          });

          helpers.assertTokenValidationError(
            config,
            'asfd',
            'Authentication Time (auth_time) claim must be a number present in the ID token when Max Age (max_age) is specified',
            defaultToken,
            done
          );
        });

        it('should throw an error when auth_time is out of range of max_age', done => {
          const now = new Date();
          const maxAge = 1000;
          const nowSeconds = Math.floor(now.getTime() / 1000) - maxAge * 2;
          const leeway = 20;
          const validUntil = nowSeconds + maxAge + leeway;
          const validUntilDate = new Date(0);

          validUntilDate.setUTCSeconds(validUntil);

          const config = Object.assign({}, DEFAULT_CONFIG, {
            maxAge,
            leeway
          });

          const payload = Object.assign({}, DEFAULT_PAYLOAD, {
            auth_time: nowSeconds
          });

          createJWT(payload, DEFAULT_OPTIONS)
            .then(token => {
              helpers.assertTokenValidationError(
                config,
                'asfd',
                `Authentication Time (auth_time) claim in the ID token indicates that too much time has passed since the last end-user authentication. Currrent time (${now}) is after last auth at ${validUntilDate}`,
                token,
                done
              );
            })
            .catch(done);
        });

        it('should be valid when auth_time is within the leeway', done => {
          const now = new Date();
          const maxAge = 1000;
          const nowSeconds = Math.floor(now.getTime() / 1000) - 10;
          const leeway = 20;
          const validUntil = nowSeconds + maxAge + leeway;
          const validUntilDate = new Date(0);

          validUntilDate.setUTCSeconds(validUntil);

          const config = Object.assign({}, DEFAULT_CONFIG, {
            maxAge,
            leeway
          });

          const payload = Object.assign({}, DEFAULT_PAYLOAD, {
            auth_time: nowSeconds
          });

          createJWT(payload, DEFAULT_OPTIONS)
            .then(token => {
              new IdTokenVerifier(config).verify(
                token,
                'asfd',
                (err, result) => {
                  expect(err).to.be(null);
                  done();
                }
              );
            })
            .catch(done);
        });
      });
    });

    describe('without stubbing `getRsaVerifier`', () => {
      beforeEach(() => {
        global.fetch = nodeFetch;
      });

      afterEach(() => {
        global.fetch = undefined;
      });

      it('should fail with corrupt token', done => {
        helpers.assertTokenValidationError(
          DEFAULT_CONFIG,
          'asfd',
          'Invalid signature.',
          'eyJ0eXAiOiJKV1QiLCJhbGciOiJSUzI1NiIsImtpZCI6IlF6RTROMFpCTTBWRFF6RTJSVVUwTnpJMVF6WTFNelE0UVRrMU16QXdNRUk0UkRneE56RTRSZyJ9.eyJpc3MiOiJodHRwczovL3dwdGVzdC5hdXRoMC5jb20vIiwic3ViIjoiYXV0aDB8NTVkNDhjNTdkNWIwYWQwMjIzYzQwOGQ3IiwiYXVkIjoiZ1lTTmxVNFlDNFYxWVBkcXE4elBRY3VwNnJKdzFNYnQiLCJleHAiOjk0ODI5NjkwMzEsImlhdCI6MTQ4MjkzMzAzMSwibm9uY2UiOiJhc2ZkIn0.PPoh-pITcZ8qbF5l5rMZwXiwk5efbESuqZ0IfMUcamB6jdgLwTxq-HpOT_x5q6-sO1PBHchpSo1WHeDYMlRrOFd9bh741sUuBuXdPQZ3Zb0i2sNOAC2RFB1E11mZn7uNvVPGdPTg-Y5xppz30GSXoOJLbeBszfrVDCmPhpHKGGMPL1N6HV-3EEF77L34YNAi2JQ-b70nFK_dnYmmv0cYTGUxtGTHkl64UEDLi3u7bV-kbGky3iOOCzXKzDDY6BBKpCRTc2KlbrkO2A2PuDn27WVv1QCNEFHvJN7HxiDDzXOsaUmjrQ3sfrHhzD7S9BcCRkekRfD9g95SKD5J0Fj8NA',
          done
        );
      });

      it('should fetch the public key and verify the token ', done => {
        helpers.assertTokenValid(
          defaultToken,
          {
            issuer: 'https://wptest.auth0.com/',
            audience: 'gYSNlU4YC4V1YPdqq8zPQcup6rJw1Mbt',
            __disableExpirationCheck: true
          },
          'asfd',
          done
        );
      });

      it('should use cached key and verify the token ', done => {
        helpers.assertTokenValid(
          defaultToken,
          {
            issuer: 'https://wptest.auth0.com/',
            audience: 'gYSNlU4YC4V1YPdqq8zPQcup6rJw1Mbt',
            __disableExpirationCheck: true,
            jwksCache: CacheMock.validKey()
          },
          'asfd',
          done
        );
      });
    });
  });

  describe('getRsaVerifier', function() {
    it('should pass options.jwksURI through ', function(done) {
      var mockJwks = {
        getJWKS: function(options) {
          expect(options.jwksURI).to.be('https://example.com/');
          done();
        }
      };

      var revert = IdTokenVerifier.__set__({ jwks: mockJwks });
      var verifier = new IdTokenVerifier({ jwksURI: 'https://example.com/' });

      verifier.getRsaVerifier('iss', 'kid');
      revert();
    });

    it('should call callback once with error when an error is returned from jwks.getJWKS', function() {
      var mockJwks = {
        getJWKS: function() {}
      };

      var err = 'error';

      sinon.stub(mockJwks, 'getJWKS').callsFake(function(obj, cb) {
        cb(err);
      });

      var revert = IdTokenVerifier.__set__({ jwks: mockJwks });
      var callback = sinon.spy();
      var verifier = new IdTokenVerifier({ jwksCache: CacheMock.validKey() });

      verifier.getRsaVerifier('iss', 'kid', callback);

      try {
        sinon.assert.calledOnce(callback);
        expect(callback.calledWith(err)).to.be.ok();
      } finally {
        revert();
      }
    });
  });

  describe('decode', () => {
    it('should decode the token', function() {
      var id_token =
        'eyJ0eXAiOiJKV1QiLCJhbGciOiJSUzI1NiIsImtpZCI6IlF6RTROMFpCTTBWRFF6RTJSVVUwTnpJMVF6WTFNelE0UVRrMU16QXdNRUk0UkRneE56RTRSZyJ9.eyJpc3MiOiJodHRwczovL3dwdGVzdC5hdXRoMC5jb20vIiwic3ViIjoiYXV0aDB8NTVkNDhjNTdkNWIwYWQwMjIzYzQwOGQ3IiwiYXVkIjoiZ1lTTmxVNFlDNFYxWVBkcXE4elBRY3VwNnJKdzFNYnQiLCJleHAiOjE0ODI5NjkwMzEsImlhdCI6MTQ4MjkzMzAzMSwibm9uY2UiOiJhc2ZkIn0.PPoh-pITcZ8qbF5l5rMZwXiwk5efbESuqZ0IfMUcamB6jdgLwTxq-HpOT_x5q6-sO1PBHchpSo1WHeDYMlRrOFd9bh741sUuBuXdPQZ3Zb0i2sNOAC2RFB1E11mZn7uNvVPGdPTg-Y5xppz30GSXoOJLbeBszfrVDCmPhpHKGGMPL1N6HV-3EEF77L34YNAi2JQ-b70nFK_dnYmmv0cYTGUxtGTHkl64UEDLi3u7bV-kbGky3iOOCzXKzDDY6BBKpCRTc2KlbrkO2A2PuDn27WVv1QCNEFHvJN7HxiDDzXOsaUmjrQ3sfrHhzD7S9BcCRkekRfD9g95SKD5J0Fj8NA';
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
          header:
            'eyJ0eXAiOiJKV1QiLCJhbGciOiJSUzI1NiIsImtpZCI6IlF6RTROMFpCTTBWRFF6RTJSVVUwTnpJMVF6WTFNelE0UVRrMU16QXdNRUk0UkRneE56RTRSZyJ9',
          payload:
            'eyJpc3MiOiJodHRwczovL3dwdGVzdC5hdXRoMC5jb20vIiwic3ViIjoiYXV0aDB8NTVkNDhjNTdkNWIwYWQwMjIzYzQwOGQ3IiwiYXVkIjoiZ1lTTmxVNFlDNFYxWVBkcXE4elBRY3VwNnJKdzFNYnQiLCJleHAiOjE0ODI5NjkwMzEsImlhdCI6MTQ4MjkzMzAzMSwibm9uY2UiOiJhc2ZkIn0',
          signature:
            'PPoh-pITcZ8qbF5l5rMZwXiwk5efbESuqZ0IfMUcamB6jdgLwTxq-HpOT_x5q6-sO1PBHchpSo1WHeDYMlRrOFd9bh741sUuBuXdPQZ3Zb0i2sNOAC2RFB1E11mZn7uNvVPGdPTg-Y5xppz30GSXoOJLbeBszfrVDCmPhpHKGGMPL1N6HV-3EEF77L34YNAi2JQ-b70nFK_dnYmmv0cYTGUxtGTHkl64UEDLi3u7bV-kbGky3iOOCzXKzDDY6BBKpCRTc2KlbrkO2A2PuDn27WVv1QCNEFHvJN7HxiDDzXOsaUmjrQ3sfrHhzD7S9BcCRkekRfD9g95SKD5J0Fj8NA'
        }
      });
    });

    it('should return an error when trying to decode (not verify) a malformed token', function() {
      var id_token = 'this.is.not.a.jwt';
      var verifier = new IdTokenVerifier();
      var result = verifier.decode(id_token);

      expect(result).to.be.an(error.TokenValidationError);
      expect(result.message).to.eql('Cannot decode a malformed JWT');
    });

    it('should return an error when trying to decode (not verify) a token with invalid JSON contents', function() {
      var id_token = 'invalid.json.here';
      var verifier = new IdTokenVerifier();
      var result = verifier.decode(id_token);

      expect(result).to.be.an(error.TokenValidationError);
      expect(result.message).to.eql(
        'Token header or payload is not valid JSON'
      );
    });
  });

  describe('verifyExpAndIat', () => {
    it('disables validation when __disableExpirationCheck is set', () => {
      const itv = new IdTokenVerifier({ __disableExpirationCheck: true });
      const result = itv.verifyExpAndIat();

      expect(result).to.be(null);
    });

    it('validated exp presence', () => {
      const err = new IdTokenVerifier().verifyExpAndIat();

      expect(err.message).to.eql(
        'Expiration Time (exp) claim must be a number present in the ID token'
      );

      expect(err).to.be.a(error.TokenValidationError);
    });

    it('validates exp', () => {
      //2016-12-28
      const exp = '148296903';
      const err = new IdTokenVerifier().verifyExpAndIat(exp);

      expect(err.message).to.eql('Expired token.');
      expect(err).to.be.a(error.TokenValidationError);
    });

    it('validates iat', () => {
      //2439-12-07
      const exp = `${nowSeconds() + 20000}`;
      const iat = '14829690311';
      const err = new IdTokenVerifier().verifyExpAndIat(exp, iat);

      expect(err.message).to.eql(
        `Issued At (iat) claim error in the ID token; current time (${new Date()}) is before issued at time (${new Date(
          (iat - 60) * 1000
        )})`
      );

      expect(err).to.be.a(error.TokenValidationError);
    });

    it('returns null if valid', () => {
      //2439-12-07
      const exp = `${Date.now() / 1000 + 20000}`;
      //1974-09-13
      const iat = '148296903';
      const result = new IdTokenVerifier().verifyExpAndIat(exp, iat);

      expect(result).to.be(null);
    });
  });
});

describe('access_token validation', function() {
  describe('With empty access_tokens', function() {
    [null, undefined, ''].forEach(function(at) {
      it('should throw when access_token is `' + at + '`', function(done) {
        var access_token = at;
        var alg = 'RS256';
        var at_hash = 'at_hash';
        var itv = new IdTokenVerifier();

        itv.validateAccessToken(access_token, alg, at_hash, function(err) {
          expect(err.name).to.be('TokenValidationError');
          expect(err.message).to.be('Invalid access_token');
          done();
        });
      });
    });
  });

  it('should throw an error with HS256 id_token', function(done) {
    var access_token = 'YTvJYcYrrZYHUXLZK5leLnfmD5ZIA_EA';
    var alg = 'HS256';
    var at_hash = 'at_hash';
    var itv = new IdTokenVerifier();

    itv.validateAccessToken(access_token, alg, at_hash, function(err) {
      expect(err.name).to.be('TokenValidationError');

      expect(err.message).to.be(
        'Signature algorithm of "HS256" is not supported. Expected "RS256"'
      );

      done();
    });
  });

  it('should throw an error when access_token is invalid', function(done) {
    var access_token = 'not an access token';
    var alg = 'RS256';
    var at_hash = 'cdukoaUswM9bo_yzrgVcrw';
    var itv = new IdTokenVerifier();

    itv.validateAccessToken(access_token, alg, at_hash, function(err) {
      expect(err.name).to.be('TokenValidationError');
      expect(err.message).to.be('Invalid access_token');
      done();
    });
  });

  it('should validate access_token with RS256 id_token', function(done) {
    var access_token = 'YTvJYcYrrZYHUXLZK5leLnfmD5ZIA_EA';
    var alg = 'RS256';
    var at_hash = 'cdukoaUswM9bo_yzrgVcrw';
    var itv = new IdTokenVerifier();

    itv.validateAccessToken(access_token, alg, at_hash, function(err) {
      expect(err).to.be(null);
      done();
    });
  });
});
