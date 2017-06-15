# Change Log

## [v1.1.0](https://github.com/auth0/idtoken-verifier/tree/v1.1.0) (2017-06-15)
[Full Changelog](https://github.com/auth0/idtoken-verifier/compare/v1.0.2...v1.1.0)

**Changed**
- Replace iat check with nbf check. [\#7](https://github.com/auth0/idtoken-verifier/pull/7) ([nicosabena](https://github.com/nicosabena))

## [v1.0.2](https://github.com/auth0/auth0.js/tree/v1.0.2) (2017-05-08)
[Full Changelog](https://github.com/auth0/auth0.js/compare/v1.0.1...v1.0.2)

**Fixed**
- FIX decode base64 string with special characters. [\#6](https://github.com/auth0/idtoken-verifier/pull/6) ([dctoon](https://github.com/dctoon))

## [v1.0.1](https://github.com/auth0/auth0.js/tree/v1.0.1) (2017-05-08)
[Full Changelog](https://github.com/auth0/auth0.js/compare/v1.0.0...v1.0.1)

**Fixed**
- Handle JSON.parse errors during decode [\#3](https://github.com/auth0/idtoken-verifier/pull/3) ([rolodato](https://github.com/rolodato))

## [v1.0.0](https://github.com/auth0/idtoken-verifier/tree/v1.0.0) (2016-12-30)
[Full Changelog](https://github.com/auth0/idtoken-verifier/tree/v1.0.0)

A lightweight library to decode and verify RS JWT meant for the browser.

### Usage

```js
var IdTokenVerifier = require('idtoken-verifier');

var verifier = new IdTokenVerifier({
        issuer: 'https://my.auth0.com/',
        audience: 'gYSNlU4YC4V1YPdqq8zPQcup6rJw1Mbt'
    });

verifier.verify(id_token, nonce, function(error, payload) {
    ...
});

var decoded = verifier.decode(id_token);
```
