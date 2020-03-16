import pem from 'pem';
import jwt from 'jsonwebtoken';

export const defaultExp = 1482969031; // this is the exp in the defaultToken below 👇

export const defaultExpDate = new Date(0);
defaultExpDate.setUTCSeconds(defaultExp + 60); // default leeway

export const defaultToken =
  'eyJ0eXAiOiJKV1QiLCJhbGciOiJSUzI1NiIsImtpZCI6IlF6RTROMFpCTTBWRFF6RTJSVVUwTnpJMVF6WTFNelE0UVRrMU16QXdNRUk0UkRneE56RTRSZyJ9.eyJpc3MiOiJodHRwczovL3dwdGVzdC5hdXRoMC5jb20vIiwic3ViIjoiYXV0aDB8NTVkNDhjNTdkNWIwYWQwMjIzYzQwOGQ3IiwiYXVkIjoiZ1lTTmxVNFlDNFYxWVBkcXE4elBRY3VwNnJKdzFNYnQiLCJleHAiOjE0ODI5NjkwMzEsImlhdCI6MTQ4MjkzMzAzMSwibm9uY2UiOiJhc2ZkIn0.PPoh-pITcZ8qbF5l5rMZwXiwk5efbESuqZ0IfMUcamB6jdgLwTxq-HpOT_x5q6-sO1PBHchpSo1WHeDYMlRrOFd9bh741sUuBuXdPQZ3Zb0i2sNOAC2RFB1E11mZn7uNvVPGdPTg-Y5xppz30GSXoOJLbeBszfrVDCmPhpHKGGMPL1N6HV-3EEF77L34YNAi2JQ-b70nFK_dnYmmv0cYTGUxtGTHkl64UEDLi3u7bV-kbGky3iOOCzXKzDDY6BBKpCRTc2KlbrkO2A2PuDn27WVv1QCNEFHvJN7HxiDDzXOsaUmjrQ3sfrHhzD7S9BcCRkekRfD9g95SKD5J0Fj8NA';

const createCertificate = () =>
  new Promise((res, rej) => {
    pem.createCertificate({ days: 1, selfSigned: true }, function(err, keys) {
      if (err) {
        return rej(err);
      }
      pem.getPublicKey(keys.certificate, function(e, p) {
        if (e) {
          return rej(e);
        }
        res({
          serviceKey: keys.serviceKey,
          certificate: keys.certificate,
          publicKey: p.publicKey
        });
      });
    });
  });

export const DEFAULT_PAYLOAD = {
  sub: 'id|123',
  nonce: 'asfd'
};

export const DEFAULT_OPTIONS = {
  expiresIn: '1h',
  audience: '__TEST_AUDIENCE__',
  issuer: '__TEST_ISSUER__'
};

export const createJWT = (
  payload = DEFAULT_PAYLOAD,
  options = DEFAULT_OPTIONS
) => {
  return createCertificate().then(cert => {
    if (typeof options.issuer == 'function') {
      options.issuer = options.issuer(DEFAULT_PAYLOAD);
    }
    return jwt.sign(payload, cert.serviceKey, {
      algorithm: 'RS256',
      keyid: 'QzE4N0ZBM0VDQzE2RUU0NzI1QzY1MzQ4QTk1MzAwMEI4RDgxNzE4Rg',
      ...options
    });
  });
};
