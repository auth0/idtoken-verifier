![idtoken-verifier](https://cdn.auth0.com/website/sdks/banners/idtoken-verifier-banner.png)

A lightweight library to decode and verify RSA ID tokens meant for the browser.

[![Build Status][circleci-image]][circleci-url]
[![NPM version][npm-image]][npm-url]
[![Coverage][codecov-image]][codecov-url]
[![License][license-image]][license-url]
[![Downloads][downloads-image]][downloads-url]

:books: [Documentation](#documentation) - :rocket: [Getting Started](#getting-started) - :computer: [API Reference](#api-reference) - :speech_balloon: [Feedback](#feedback)

## Documentation

- [API Reference](https://auth0.github.io/idtoken-verifier)
- [Docs Site](https://auth0.com/docs) - explore our Docs site and learn more about Auth0

## Getting Started

### Installation

Using [npm](https://npmjs.org/) in your project directory run the following command:

```
npm install idtoken-verifier
```

### Verify an ID token

Import the library, create an instance of `IdTokenVerifier` and call the `verify` method to verify an ID token:

```js
import IdTokenVerifier from 'idtoken-verifier';

const verifier = new IdTokenVerifier({
  issuer: 'https://my.auth0.com/',
  audience: 'gYSNlU4YC4V1YPdqq8zPQcup6rJw1Mbt'
});

verifier.verify(id_token, nonce, (error, payload) => {
  if (error) {
    // handle the error
    return;
  }

  // do something with `payload`
});
```

## API Reference

- [IdTokenVerifier constructor](https://auth0.github.io/idtoken-verifier/IdTokenVerifier.html)
- [verify](https://auth0.github.io/idtoken-verifier/global.html#verify)
- [decode](https://auth0.github.io/idtoken-verifier/global.html#decode)
- [validateAccessToken](https://auth0.github.io/idtoken-verifier/global.html#validateAccessToken)

## Feedback

### Contributing

We appreciate feedback and contribution to this repo! Before you get started, please see the following:

- [Auth0's general contribution guidelines](https://github.com/auth0/open-source-template/blob/master/GENERAL-CONTRIBUTING.md)
- [Auth0's code of conduct guidelines](https://github.com/auth0/open-source-template/blob/master/CODE-OF-CONDUCT.md)
- [The contribution guide](https://github.com/auth0/open-source-template/blob/master/GENERAL-CONTRIBUTING.md)

### Raise an issue

To provide feedback or report a bug, please [raise an issue on our issue tracker](https://github.com/auth0/idtoken-verifier/issues).

### Vulnerability Reporting

Please do not report security vulnerabilities on the public GitHub issue tracker. The [Responsible Disclosure Program](https://auth0.com/whitehat) details the procedure for disclosing security issues.

## What is Auth0?

<p align="center">
  <picture>
    <source media="(prefers-color-scheme: dark)" srcset="https://cdn.auth0.com/website/sdks/logos/auth0_dark_mode.png" width="150">
    <source media="(prefers-color-scheme: light)" srcset="https://cdn.auth0.com/website/sdks/logos/auth0_light_mode.png" width="150">
    <img alt="Auth0 Logo" src="https://cdn.auth0.com/website/sdks/logos/auth0_light_mode.png" width="150">
  </picture>
</p>
<p align="center">
  Auth0 is an easy to implement, adaptable authentication and authorization platform. To learn more checkout <a href="https://auth0.com/why-auth0">Why Auth0?</a>
</p>
<p align="center">
  This project is licensed under the Apache 2.0 license. See the <a href="./LICENSE"> LICENSE</a> file for more info.
</p>


<!-- Vaaaaarrrrsss -->

[npm-image]: https://img.shields.io/npm/v/idtoken-verifier.svg?style=flat-square
[npm-url]: https://npmjs.org/package/idtoken-verifier
[circleci-image]: http://img.shields.io/circleci/project/github/auth0/idtoken-verifier.svg?branch=master&style=flat-square
[circleci-url]: https://circleci.com/gh/auth0/idtoken-verifier
[codecov-image]: https://img.shields.io/codecov/c/github/auth0/idtoken-verifier.svg?style=flat-square
[codecov-url]: https://codecov.io/github/auth0/idtoken-verifier?branch=master
[license-image]: http://img.shields.io/npm/l/idtoken-verifier.svg?style=flat-square
[license-url]: #license
[downloads-image]: http://img.shields.io/npm/dm/idtoken-verifier.svg?style=flat-square
[downloads-url]: https://npmjs.org/package/idtoken-verifier
