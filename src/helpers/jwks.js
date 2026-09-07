import urljoin from 'url-join';
import * as base64 from './base64';
import unfetch from 'unfetch';

export function process(jwks) {
  var modulus = base64.decodeToHEX(jwks.n);
  var exp = base64.decodeToHEX(jwks.e);

  return {
    modulus: modulus,
    exp: exp
  };
}

function checkStatus(response) {
  if (response.ok) {
    return response.json();
  }
  var error = new Error(response.statusText);
  error.response = response;
  return Promise.reject(error);
}

export function getJWKS(options, cb) {
  var url = options.jwksURI || urljoin(options.iss, '.well-known', 'jwks.json');

  if (url.indexOf('https://') !== 0) {
    var protocolError = new Error(
      'The JWKS URI "' + url + '" must use the HTTPS protocol'
    );
    if (cb) {
      return cb(protocolError);
    }
    return Promise.reject(protocolError);
  }

  var localFetch = typeof fetch === 'undefined' ? unfetch : fetch;
  return localFetch(url)
    .then(checkStatus)
    .then(function(data) {
      var matchingKey = null;
      var a;
      var key;
      // eslint-disable-next-line no-plusplus
      for (a = 0; a < data.keys.length && matchingKey === null; a++) {
        key = data.keys[a];

        if (key.kid === options.kid) {
          matchingKey = key;
        }
      }
      if (!matchingKey) {
        throw new Error(
          'Could not find a public key for Key ID (kid) "' + options.kid + '"'
        );
      }
      if (cb) {
        return cb(null, process(matchingKey));
      } else {
        return process(matchingKey);
      }
    })
    .catch(function(e) {
      if (cb) {
        cb(e);
      } else {
        throw e;
      }
    });
}
