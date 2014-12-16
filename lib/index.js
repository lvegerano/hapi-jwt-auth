var jwt = require('jsonwebtoken');
var Hoek = require('hoek');
var Boom = require('boom');

var internals = {};
internals.key = null;

exports.register = function(server, options, next) {
    server.auth.scheme('jwt', internals.implementation);
    next();
};

exports.register.attributes = {
    pkg: require('../package.json')
};

exports.sign = function(payload, secretOrPrivateKey, options) {
    var settings = {};
    settings.expiresInMinutes = 60;
    settings = Hoek.applyToDefaults(settings, options);

    Hoek.assert(payload, 'Missing payload');
    Hoek.assert(secretOrPrivateKey, 'Missing secret or private key');

    internals.key = secretOrPrivateKey;

    return jwt.sign(payload, internals.key, settings);
};

exports.decode = function(token) {
    Hoek.assert(token, 'Missing token to decode');
    return jwt.decode(token);
};

internals.implementation = function(server, options) {
    var settings = {};
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
        authenticate: function(request, reply) {
            var authorization  = request.raw.req.headers.authorization;
            if (!authorization) {
                return reply(Boom.unauthorized(null, 'Bearer'));
            }

            var parts = authorization.split(/\s+/);

            if (parts[0].toLowerCase() !== 'bearer') {
                return reply(Boom.unauthorized('Bad HTTP authentication header', 'Bearer'));
            }
            if (parts.length !== 2) {
                return reply(Boom.unauthorized('Bad HTTP authentication header format', 'Bearer'));
            }

            var token = parts[1];

            jwt.verify(token, internals.key, options, function(err, decoded) {
                if (err && err.message === 'jwt expired') {
                    return reply(Boom.unauthorized('Token expired', 'Bearer'));
                } else if (err) {
                    return reply(Boom.unauthorized('Bad authentication token', 'Bearer'));
                }
                if (!settings.validate) {
                    return reply.continue({ credentials: decoded });
                }

                settings.validate(token, decoded, function(err, isValid, credentials) {
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
                            { log: { tags: 'credentials' } }
                        );
                    }
                    // Authenticated
                    return reply.continue({ credentials: credentials });
                });
            });
        }
    };
};
