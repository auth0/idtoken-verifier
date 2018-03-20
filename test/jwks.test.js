var expect = require('expect.js');
var rewire = require('rewire');
var sinon = require('sinon');
var stub = sinon.stub;

var request = require('superagent');

var jwks = require('../src/helpers/jwks');

describe('jwks', function () {
  describe('getJWKS', function () {
    afterEach(function () {
      request.get.restore();
    });
    describe('requests correct url', function () {
      it('with jwksURI', function (done) {
        stub(request, 'get', function (url) {
          expect(url).to.be('https://example.com/jwks.json');
          done();
        });
        jwks.getJWKS({jwksURI: 'https://example.com/jwks.json'});
      });
      it('without jwksURI', function (done) {
        stub(request, 'get', function (url) {
          expect(url).to.be('https://iss.com/.well-known/jwks.json');
          done();
        });
        jwks.getJWKS({iss: 'https://iss.com/'});
      });
    });
    it('returns error in the callback', function (done) {
      stub(request, 'get', function () {
        return {
          end: function(cb) {
            cb({error: true});
          }
        };
      });
      jwks.getJWKS({jwksURI: 'https://example.com/jwks.json'}, function(err, data) {
        expect(err).to.be.eql({error: true});
        done();
      });
    });
    it('returns jwks', function(done) {
      stub(request, 'get', function () {
        return {
          end: function(cb) {
            cb(null, {
              // from: https://brucke.auth0.com/.well-known/jwks.json
              body: {
                "keys": [{
                    "alg": "RS256",
                    "kty": "RSA",
                    "use": "sig",
                    "x5c": ["MIIC6DCCAdCgAwIBAgIJftS/aE0IPdZxMA0GCSqGSIb3DQEBBQUAMBsxGTAXBgNVBAMTEGJydWNrZS5hdXRoMC5jb20wHhcNMTYwNDIwMTIyMzE1WhcNMjkxMjI4MTIyMzE1WjAbMRkwFwYDVQQDExBicnVja2UuYXV0aDAuY29tMIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAlG4+sywQahA2bzbb53WiMS1MFJVFGJSHLwBuY/J4W84STvRUdcXPV3TE7s4A7/6fSdAXXVb69A5bL7mS/3EkGujgr2CnrRQNNdw055D28VHiZyAKrG2vg6e5+C8iHU0ew6nCqJ1bXK7vYhPs3qYlNdmxbxUyUimQZ038ABre8JlNiwsrnIoct/IKnhMNkUPovrcfNo83PwQwRJDabbYnTEtRIwlzVZxOwHXDySMf+xalRzxrQ+PvY1D5+HPfZHvmm+9ij4src9p5FTagMCkEUg9XrgpdhB+Aa0TyCpK8t1re1PjrFZgnIBZ5wTadTlbukYnD0FL83OU/olgBPMmd8QIDAQABoy8wLTAMBgNVHRMEBTADAQH/MB0GA1UdDgQWBBRzW81ap53F2F/90rR4cKJeRiwI8TANBgkqhkiG9w0BAQUFAAOCAQEAecY8JHbUESSXZiPhT9CCiX//VFfLpiBZCG2dWka5E4pPs3AFc7bEospWW7w+r2W0uSL6cDMu7wpb7N7lnWkiGc64Ej89ZXvZYAbpt6glM3z+W9H+fZ767W4/aiFSrD3HAMpGs61TUa7B9Xrn7Zhj4y8L1Z4z5v4xyzl5Zy5KKA19fiPJVtVzt6tVgfpbUDh0ufhno/WPWuRPzNNl+dKRH45JRVSwcYcFR4h2+i+t+3rhUmAuyOmjeN21vWvP8gqX6+LQW/olgkyrvg4rMmN6UZNBVa75g2ptnHo3ItdHh8UPMyn0VStOamtHYFVV+4uqzxV6EU2RHJnxO1YYt8LZfw=="],
                    "n": "lG4-sywQahA2bzbb53WiMS1MFJVFGJSHLwBuY_J4W84STvRUdcXPV3TE7s4A7_6fSdAXXVb69A5bL7mS_3EkGujgr2CnrRQNNdw055D28VHiZyAKrG2vg6e5-C8iHU0ew6nCqJ1bXK7vYhPs3qYlNdmxbxUyUimQZ038ABre8JlNiwsrnIoct_IKnhMNkUPovrcfNo83PwQwRJDabbYnTEtRIwlzVZxOwHXDySMf-xalRzxrQ-PvY1D5-HPfZHvmm-9ij4src9p5FTagMCkEUg9XrgpdhB-Aa0TyCpK8t1re1PjrFZgnIBZ5wTadTlbukYnD0FL83OU_olgBPMmd8Q",
                    "e": "AQAB",
                    "kid": "NEVBNUNBOTgxRkE5NkQzQzc4OTBEMEFFRDQ5N0Q2Qjk0RkQ1MjFGMQ",
                    "x5t": "NEVBNUNBOTgxRkE5NkQzQzc4OTBEMEFFRDQ5N0Q2Qjk0RkQ1MjFGMQ"
                }]
            }
            });
          }
        };
      });
      jwks.getJWKS({
        jwksURI: 'https://example.com/jwks.json',
        kid: 'NEVBNUNBOTgxRkE5NkQzQzc4OTBEMEFFRDQ5N0Q2Qjk0RkQ1MjFGMQ'
      }, function(err, data) {
        expect(err).to.be(null);
        expect(data).to.be.eql({ 
          modulus: '946e3eb32c106a10366f36dbe775a2312d4c1495451894872f006e63f2785bce124ef45475c5cf5774c4eece00effe9f49d0175d56faf40e5b2fb992ff71241ae8e0af60a7ad140d35dc34e790f6f151e267200aac6daf83a7b9f82f221d4d1ec3a9c2a89d5b5caeef6213ecdea62535d9b16f1532522990674dfc001adef0994d8b0b2b9c8a1cb7f20a9e130d9143e8beb71f368f373f04304490da6db6274c4b51230973559c4ec075c3c9231ffb16a5473c6b43e3ef6350f9f873df647be69bef628f8b2b73da791536a0302904520f57ae0a5d841f806b44f20a92bcb75aded4f8eb159827201679c1369d4e56ee9189c3d052fcdce53fa258013cc99df1',
          exp: '010001'
        });
        done();
      });
    })
  });
});