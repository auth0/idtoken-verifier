const { assert, sinon } = require('@sinonjs/referee-sinon');
import { getJWKS } from '../src/helpers/jwks';

describe('jwks', function() {
  describe('getJWKS', function() {
    describe('requests correct url', function() {
      it('with jwksURI', function(done) {
        const fetchStub = sinon.stub().resolves({ ok: true });

        getJWKS(
          { jwksURI: 'https://example.com/jwks.json' },
          function(err, data) {
            assert.isTrue(
              fetchStub.calledWith('https://example.com/jwks.json')
            );
            done();
          },
          fetchStub
        );
      });

      it('without jwksURI', function(done) {
        const fetchStub = sinon.stub().resolves({ ok: true });

        getJWKS(
          { iss: 'https://iss.com/' },
          function(err, data) {
            assert.isTrue(
              fetchStub.calledWith('https://iss.com/.well-known/jwks.json')
            );
            done();
          },
          fetchStub
        );
      });
    });

    it('returns error in the callback when fetch fails', function() {
      return assert.rejects(
        getJWKS(
          {
            jwksURI: 'https://example.com/jwks.json',
            kid: 'some-random-key'
          },
          null,
          sinon.stub().rejects({ error: true })
        ),
        { error: true }
      );
    });

    it('returns error in the callback when jwks response is not ok', function() {
      return assert.rejects(
        getJWKS(
          {
            jwksURI: 'https://example.com/jwks.json',
            kid: 'some-random-key'
          },
          null,
          sinon.stub().rejects({
            ok: false,
            statusText: 'the-error'
          })
        ),
        { ok: false, statusText: 'the-error' }
      );
    });

    it('returns error when the kid is not present in the JWKS', function() {
      return getJWKS(
        {
          jwksURI: 'https://example.com/jwks.json',
          kid: 'some-random-key'
        },
        function(err) {
          assert.equals(
            err.message,
            `Could not find a public key for Key ID (kid) "some-random-key"`
          );
        },
        sinon.stub().resolves({
          ok: true,
          json: () =>
            Promise.resolve({
              keys: [
                {
                  kid: 'NEVBNUNBOTgxRkE5NkQzQzc4OTBEMEFFRDQ5N0Q2Qjk0RkQ1MjFGMQ'
                }
              ]
            })
        })
      );
    });

    it('returns error when the kid is not present in the JWKS (using promises)', function(done) {
      getJWKS(
        {
          jwksURI: 'https://example.com/jwks.json',
          kid: 'some-random-key'
        },
        null,
        sinon.stub().resolves({
          ok: true,
          json: () =>
            Promise.resolve({
              keys: [
                {
                  kid: 'NEVBNUNBOTgxRkE5NkQzQzc4OTBEMEFFRDQ5N0Q2Qjk0RkQ1MjFGMQ'
                }
              ]
            })
        })
      ).catch(err => {
        assert.equals(
          err.message,
          `Could not find a public key for Key ID (kid) "some-random-key"`
        );
        done();
      });
    });

    it('returns jwks', function() {
      return getJWKS(
        {
          jwksURI: 'https://example.com/jwks.json',
          kid: 'NEVBNUNBOTgxRkE5NkQzQzc4OTBEMEFFRDQ5N0Q2Qjk0RkQ1MjFGMQ'
        },
        function(err, data) {
          assert.isNull(err);

          assert.equals(data, {
            modulus:
              '946e3eb32c106a10366f36dbe775a2312d4c1495451894872f006e63f2785bce124ef45475c5cf5774c4eece00effe9f49d0175d56faf40e5b2fb992ff71241ae8e0af60a7ad140d35dc34e790f6f151e267200aac6daf83a7b9f82f221d4d1ec3a9c2a89d5b5caeef6213ecdea62535d9b16f1532522990674dfc001adef0994d8b0b2b9c8a1cb7f20a9e130d9143e8beb71f368f373f04304490da6db6274c4b51230973559c4ec075c3c9231ffb16a5473c6b43e3ef6350f9f873df647be69bef628f8b2b73da791536a0302904520f57ae0a5d841f806b44f20a92bcb75aded4f8eb159827201679c1369d4e56ee9189c3d052fcdce53fa258013cc99df1',
            exp: '010001'
          });
        },
        sinon.stub().resolves({
          ok: true,
          json: () =>
            Promise.resolve({
              // from: https://brucke.auth0.com/.well-known/jwks.json
              keys: [
                {
                  alg: 'RS256',
                  kty: 'RSA',
                  use: 'sig',
                  x5c: [
                    'MIIC6DCCAdCgAwIBAgIJftS/aE0IPdZxMA0GCSqGSIb3DQEBBQUAMBsxGTAXBgNVBAMTEGJydWNrZS5hdXRoMC5jb20wHhcNMTYwNDIwMTIyMzE1WhcNMjkxMjI4MTIyMzE1WjAbMRkwFwYDVQQDExBicnVja2UuYXV0aDAuY29tMIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAlG4+sywQahA2bzbb53WiMS1MFJVFGJSHLwBuY/J4W84STvRUdcXPV3TE7s4A7/6fSdAXXVb69A5bL7mS/3EkGujgr2CnrRQNNdw055D28VHiZyAKrG2vg6e5+C8iHU0ew6nCqJ1bXK7vYhPs3qYlNdmxbxUyUimQZ038ABre8JlNiwsrnIoct/IKnhMNkUPovrcfNo83PwQwRJDabbYnTEtRIwlzVZxOwHXDySMf+xalRzxrQ+PvY1D5+HPfZHvmm+9ij4src9p5FTagMCkEUg9XrgpdhB+Aa0TyCpK8t1re1PjrFZgnIBZ5wTadTlbukYnD0FL83OU/olgBPMmd8QIDAQABoy8wLTAMBgNVHRMEBTADAQH/MB0GA1UdDgQWBBRzW81ap53F2F/90rR4cKJeRiwI8TANBgkqhkiG9w0BAQUFAAOCAQEAecY8JHbUESSXZiPhT9CCiX//VFfLpiBZCG2dWka5E4pPs3AFc7bEospWW7w+r2W0uSL6cDMu7wpb7N7lnWkiGc64Ej89ZXvZYAbpt6glM3z+W9H+fZ767W4/aiFSrD3HAMpGs61TUa7B9Xrn7Zhj4y8L1Z4z5v4xyzl5Zy5KKA19fiPJVtVzt6tVgfpbUDh0ufhno/WPWuRPzNNl+dKRH45JRVSwcYcFR4h2+i+t+3rhUmAuyOmjeN21vWvP8gqX6+LQW/olgkyrvg4rMmN6UZNBVa75g2ptnHo3ItdHh8UPMyn0VStOamtHYFVV+4uqzxV6EU2RHJnxO1YYt8LZfw=='
                  ],
                  n:
                    'lG4-sywQahA2bzbb53WiMS1MFJVFGJSHLwBuY_J4W84STvRUdcXPV3TE7s4A7_6fSdAXXVb69A5bL7mS_3EkGujgr2CnrRQNNdw055D28VHiZyAKrG2vg6e5-C8iHU0ew6nCqJ1bXK7vYhPs3qYlNdmxbxUyUimQZ038ABre8JlNiwsrnIoct_IKnhMNkUPovrcfNo83PwQwRJDabbYnTEtRIwlzVZxOwHXDySMf-xalRzxrQ-PvY1D5-HPfZHvmm-9ij4src9p5FTagMCkEUg9XrgpdhB-Aa0TyCpK8t1re1PjrFZgnIBZ5wTadTlbukYnD0FL83OU_olgBPMmd8Q',
                  e: 'AQAB',
                  kid: 'NEVBNUNBOTgxRkE5NkQzQzc4OTBEMEFFRDQ5N0Q2Qjk0RkQ1MjFGMQ',
                  x5t: 'NEVBNUNBOTgxRkE5NkQzQzc4OTBEMEFFRDQ5N0Q2Qjk0RkQ1MjFGMQ'
                }
              ]
            })
        })
      );
    });

    it('returns jwks when the key is not first in the keys list', function() {
      return getJWKS(
        {
          jwksURI: 'https://example.com/jwks.json',
          kid: 'some-random-key'
        },
        function(err, data) {
          assert.isNull(err);
          assert.keys(data, ['modulus', 'exp']);
        },
        sinon.stub().resolves({
          ok: true,
          json: () =>
            Promise.resolve({
              keys: [
                {
                  kid: 'some-other-random-key'
                },
                {
                  n: '',
                  e: '',
                  kid: 'some-random-key'
                }
              ]
            })
        })
      );
    });

    it('returns jwks when the key is not first in the keys list (using promises)', function(done) {
      getJWKS(
        {
          jwksURI: 'https://example.com/jwks.json',
          kid: 'some-random-key'
        },
        null,
        sinon.stub().resolves({
          ok: true,
          json: () =>
            Promise.resolve({
              keys: [
                {
                  kid: 'some-other-random-key'
                },
                {
                  n: '',
                  e: '',
                  kid: 'some-random-key'
                }
              ]
            })
        })
      ).then(function(data) {
        assert.keys(data, ['modulus', 'exp']);
        done();
      });
    });
  });
});
