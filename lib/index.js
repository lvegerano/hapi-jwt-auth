const jwt = require('jsonwebtoken');
const Hoek = require('hoek');
const Boom = require('boom');

const internals = {};
internals.key = null;

internals.decode = (token) => {
  Hoek.assert(token, 'Missing token to decode');
  return jwt.decode(token);
};

internals.sign = (payload, secretOrPrivateKey, options) => {
  let settings = {};
  settings.expiresIn = 60;
  settings = Hoek.applyToDefaults(settings, options);

  Hoek.assert(payload, 'Missing payload');
  Hoek.assert(secretOrPrivateKey, 'Missing secret or private key');

  internals.key = secretOrPrivateKey;

  return jwt.sign(payload, internals.key, settings);
};

internals.implementation = (server, options) => {
  let settings = {};
  settings = Hoek.applyToDefaults(settings, options) || {};
  //validate
  if (settings.hasOwnProperty('validate')) {
    Hoek.assert(
      typeof settings.validate === 'function',
      'options.validateFunction must be a valid function'
    );
  }

  Hoek.assert(internals.key, 'Missing privateKey');

  return {
    authenticate(request, reply) {
      const authorization = request.raw.req.headers.authorization;
      if (!authorization) {
        return reply(Boom.unauthorized(null, 'Bearer'));
      }

      const parts = authorization.split(/\s+/);

      if (parts[0].toLowerCase() !== 'bearer') {
        return reply(Boom.unauthorized('Bad HTTP authentication header', 'Bearer'));
      }
      if (parts.length !== 2) {
        return reply(Boom.unauthorized('Bad HTTP authentication header format', 'Bearer'));
      }

      const token = parts[1];

      jwt.verify(token, internals.key, options, (err, decoded) => {
        if (err && err.message === 'jwt expired') {
          return reply(Boom.unauthorized('Token expired', 'Bearer'));
        } else if (err) {
          return reply(Boom.unauthorized('Bad authentication token', 'Bearer'));
        }

        if (!settings.validate) {
          return reply.continue({credentials: decoded});
        }

        settings.validate(token, decoded, (err, isValid, credentials) => {
          credentials = credentials || null;

          if (err) {
            return reply(Boom.badImplementation('Validation error', err), null);
          }

          if (!isValid) {
            return reply(Boom.unauthorized('Invalid token', 'Bearer'), null);
          }

          if (!credentials || typeof credentials !== 'object') {
            return reply(
              Boom.badImplementation('Bad credentials object received for jwt auth validation'),
              {log: {tags: 'credentials'}}
            );
          }
          // Authenticated
          return reply.continue({credentials: credentials});
        });
      });
    }
  };
};

exports.register = (server, options, next) => {
  server.auth.scheme('jwt', internals.implementation);
  server.method('sign', internals.sign, { callback: false });
  server.method('decode', internals.decode, { callback: false });
  next();
};

exports.register.attributes = {
  pkg: require('../package.json')
};

exports.sign = (...args) => {
  console.log('hapi-jwt-auth: exports.sign will be deprecated pleas uses server.methods.sign instead');
  return internals.sign(...args);
};

exports.decode = (...args) => {
  console.log('hapi-jwt-auth: exports.decode will be deprecated pleas uses server.methods.decode instead');
  return internals.decode(...args);
};
