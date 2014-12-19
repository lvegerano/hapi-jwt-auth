### hapi-jwt-auth
[![Build Status](https://travis-ci.org/lvegerano/hapi-jwt-auth.svg?branch=master)]
(https://travis-ci.org/lvegerano/hapi-jwt-auth)

[![Coverage Status](https://coveralls.io/repos/lvegerano/hapi-jwt-auth/badge.png)](https://coveralls.io/r/lvegerano/hapi-jwt-auth)

#### Installation

> npm install hapi-jwt-auth --save

#### About plugin

JSON Web Token (JWT) authentication plugin for [HapiJS](https://github.com/spumko/hapi)

Inspired by [hapi-auth-jsonwebtoken by boketto](https://github.com/boketto/hapi-auth-jsonwebtoken), modified to to expose
 additional [node-jsonwebtoken](https://github.com/auth0/node-jsonwebtoken) methods for convienience.

#### Usage

This plugin will validate a signed token in the bearer header.

### Setup
You will have to register the plugin with your server object, then create a new [server auth strategy]
(http://hapijs.com/api#serverauthstrategyname-scheme-mode-options). Validation will occur only on routes that require
authorization.

### Options

The `jwt` scheme takes the following options:

- `key`(required) - The private key the token was signed.
- `validate`(optional) - Addiotional validation/user lookup,
    signature `function(token, decoded, callback)`
    - `token` - the verified signed token.
    - `decoded` - the decoded signed token.
    - `callback` - a callback function with signature `function(err, isValid, credentials)`
        - `err` - an internal error.
        - `isValid`(boolean) - whether the token was valid or not.
        - `credentials` - a credentials object passed back to the application in `request.auth.credentials`
