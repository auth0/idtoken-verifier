# Change Log

## [v2.1.0](https://github.com/auth0/idtoken-verifier/tree/v2.1.0) (2020-09-11)

[Full Changelog](https://github.com/auth0/idtoken-verifier/compare/v2.1.0...v2.1.0)

**Changed**

- Asynchronous JWKS cache [\#107](https://github.com/auth0/idtoken-verifier/pull/107) ([ItalyPaleAle](https://github.com/ItalyPaleAle))
- Migrate to NPM package lock over Yarn, and update dependencies [\#114](https://github.com/auth0/idtoken-verifier/pull/114) ([stevehobbsdev](https://github.com/stevehobbsdev))

**Security**

- Bump bl from 3.0.0 to 3.0.1 [\#111](https://github.com/auth0/idtoken-verifier/pull/111) ([dependabot[bot]](https://github.com/apps/dependabot))
- Bump codecov from 3.6.5 to 3.7.1 [\#109](https://github.com/auth0/idtoken-verifier/pull/109) ([dependabot-preview[bot]](https://github.com/apps/dependabot-preview))
- Bump lodash from 4.17.15 to 4.17.19 [\#108](https://github.com/auth0/idtoken-verifier/pull/108) ([dependabot[bot]](https://github.com/apps/dependabot))
- Bump handlebars from 4.5.3 to 4.7.6 [\#106](https://github.com/auth0/idtoken-verifier/pull/106) ([dependabot-preview[bot]](https://github.com/apps/dependabot-preview))

## [v2.0.3](https://github.com/auth0/idtoken-verifier/tree/v2.0.3) (2020-04-23)

[Full Changelog](https://github.com/auth0/idtoken-verifier/compare/v2.0.2...v2.0.3)

**Fixed**

- Fixed bug with keys not first in keybag [\#101](https://github.com/auth0/idtoken-verifier/pull/101) ([ItalyPaleAle](https://github.com/ItalyPaleAle))

## [v2.0.2](https://github.com/auth0/idtoken-verifier/tree/v2.0.2) (2020-02-20)

[Full Changelog](https://github.com/auth0/idtoken-verifier/compare/v2.0.1...v2.0.2)

**Security**

- [Snyk] Security upgrade crypto-js from 3.1.9-1 to 3.2.1 [\#98](https://github.com/auth0/idtoken-verifier/pull/98) ([crew-security](https://github.com/crew-security))

## [v2.0.1](https://github.com/auth0/idtoken-verifier/tree/v2.0.1) (2020-01-10)

[Full Changelog](https://github.com/auth0/idtoken-verifier/compare/v2.0.0...v2.0.1)

**Removed**

- [SDK-1266] Removed iat future value check [\#95](https://github.com/auth0/idtoken-verifier/pull/95) ([stevehobbsdev](https://github.com/stevehobbsdev))

## [v2.0.0](https://github.com/auth0/idtoken-verifier/tree/v2.0.0) (2019-12-06)

[Full Changelog](https://github.com/auth0/idtoken-verifier/compare/v1.5.1...v2.0.0)

This new major version introduces more validation checks on ID tokens for [OIDC conformance](https://openid.net/specs/openid-connect-core-1_0-final.html#IDTokenValidation) and as such **could introduce a breaking change** if you are already validating tokens that are not OIDC conformant.

In addition, methods that were marked as deprecated in [v1.5.0](https://github.com/auth0/idtoken-verifier/releases/v1.5.0) have now been removed. From here, always use the `verify` method to validate ID tokens.

**Changed**

- Added build step into the versioning process (to be done before release) [\#93](https://github.com/auth0/idtoken-verifier/pull/93) ([stevehobbsdev](https://github.com/stevehobbsdev))
- Updated dependencies [\#92](https://github.com/auth0/idtoken-verifier/pull/92) ([stevehobbsdev](https://github.com/stevehobbsdev))

**Removed**

- Removed deprecated methods + tests [\#90](https://github.com/auth0/idtoken-verifier/pull/90) ([stevehobbsdev](https://github.com/stevehobbsdev))

**Security**

- [SDK-974] Improved OIDC compliance [\#89](https://github.com/auth0/idtoken-verifier/pull/89) ([stevehobbsdev](https://github.com/stevehobbsdev))
- Bump tough-cookie from 2.3.2 to 2.3.4 [\#88](https://github.com/auth0/idtoken-verifier/pull/88) ([dependabot[bot]](https://github.com/apps/dependabot))
- Bump stringstream from 0.0.5 to 0.0.6 [\#87](https://github.com/auth0/idtoken-verifier/pull/87) ([dependabot[bot]](https://github.com/apps/dependabot))
- Bump extend from 3.0.1 to 3.0.2 [\#86](https://github.com/auth0/idtoken-verifier/pull/86) ([dependabot[bot]](https://github.com/apps/dependabot))
- Bump sshpk from 1.13.0 to 1.16.1 [\#85](https://github.com/auth0/idtoken-verifier/pull/85) ([dependabot[bot]](https://github.com/apps/dependabot))
- Bump lodash.merge from 4.6.1 to 4.6.2 [\#84](https://github.com/auth0/idtoken-verifier/pull/84) ([dependabot[bot]](https://github.com/apps/dependabot))

## [v1.5.1](https://github.com/auth0/idtoken-verifier/tree/v1.5.1) (2019-12-06)

[Full Changelog](https://github.com/auth0/idtoken-verifier/compare/v1.5.0...v1.5.1)

Re-release to correct build directory error

## [v1.5.0](https://github.com/auth0/idtoken-verifier/tree/v1.5.0) (2019-12-05)

[Full Changelog](https://github.com/auth0/idtoken-verifier/compare/v1.4.1...v1.5.0)

**Added**

- [SDK-1166] Replaced promise-polyfill with es6-promise, applied globally [\#78](https://github.com/auth0/idtoken-verifier/pull/78) ([stevehobbsdev](https://github.com/stevehobbsdev))

## [v1.4.1](https://github.com/auth0/idtoken-verifier/tree/v1.4.1) (2019-07-09)

[Full Changelog](https://github.com/auth0/idtoken-verifier/compare/v1.4.0...v1.4.1)

**Fixed**

- Use unfetch without requiring window at load time [\#42](https://github.com/auth0/idtoken-verifier/pull/42) ([luisrudge](https://github.com/luisrudge))

## [v1.4.0](https://github.com/auth0/idtoken-verifier/tree/v1.4.0) (2019-06-18)

[Full Changelog](https://github.com/auth0/idtoken-verifier/compare/v1.3.0...v1.4.0)

**Fixed**

- Validate claims after verifying the signature of the token [\#39](https://github.com/auth0/idtoken-verifier/pull/39) ([luisrudge](https://github.com/luisrudge))

## [v1.3.0](https://github.com/auth0/idtoken-verifier/tree/v1.3.0) (2019-06-05)

[Full Changelog](https://github.com/auth0/idtoken-verifier/compare/v1.2.0...v1.3.0)

**Changed**

- Increase leeway limit to 300s [\#31](https://github.com/auth0/idtoken-verifier/pull/31) ([luisrudge](https://github.com/luisrudge))
- Replace superagent with unfetch [\#27](https://github.com/auth0/idtoken-verifier/pull/27) ([luisrudge](https://github.com/luisrudge))

## [v1.2.0](https://github.com/auth0/idtoken-verifier/tree/v1.2.0) (2018-03-21)

[Full Changelog](https://github.com/auth0/idtoken-verifier/compare/v1.1.2...v1.2.0)

**Added**

- Add option to set the endpoint to fetch the jwks.json file [\#19](https://github.com/auth0/idtoken-verifier/pull/19) ([luisrudge](https://github.com/luisrudge))
- Adding access_token validation method `validateAccessToken` [\#17](https://github.com/auth0/idtoken-verifier/pull/17) ([luisrudge](https://github.com/luisrudge))

## [v1.1.2](https://github.com/auth0/idtoken-verifier/tree/v1.1.2) (2018-03-01)

[Full Changelog](https://github.com/auth0/idtoken-verifier/compare/v1.1.1...v1.1.2)

**Fixed**

- Fixing issue with IdTokenVerifier.getRsaVerifier [\#14](https://github.com/auth0/idtoken-verifier/pull/14) ([dfung](https://github.com/dfung))

- Use base64-js methods instead of browser globals atob and btoa [\#15](https://github.com/auth0/idtoken-verifier/pull/15) ([maxbeatty](https://github.com/maxbeatty))

## [v1.1.1](https://github.com/auth0/idtoken-verifier/tree/v1.1.1) (2018-01-15)

[Full Changelog](https://github.com/auth0/idtoken-verifier/compare/v1.1.0...v1.1.1)

**Changed**

- Upgrade superagent version [\#10](https://github.com/auth0/idtoken-verifier/pull/10) ([luisrudge](https://github.com/luisrudge))

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
