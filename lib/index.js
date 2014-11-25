var jwt = require('jsonwebtoken');
var Hoek = require('hoek');
var Boom = require('boom');

var internals = {};

exports.register = function(plugin, options, next) {
    plugin.auth.scheme('jwt', internals.implementation);
    next();
};

exports.register.attributes = {
    pkg: require('../package.json')
};

exports.key = '';

exports.sign = function(payload, secretOrPrivateKey, options) {
    var settings = {};
    settings.expiresInMinutes = 60;
    settings = Hoek.applyToDefaults(settings, options);

    Hoek.assert(payload, 'Missing payload');
    Hoek.assert(exports.key || secretOrPrivateKey, 'Missing secret or private key');

    exports.key = exports.key || secretOrPrivateKey;

    return jwt.sign(payload, exports.key, settings);
};

exports.decode = function(token) {
    Hoek.assert(token, 'Missin token to decode');
    return jwt.decode(token);
};

internals.implementation = function(server, options) {
    var settings = {};
    settings = Hoek.applyToDefaults(settings, options) || {};
    //validate
    if (settings.hasOwnProperty('validateFunc')) {
        Hoek.assert(
            typeof settings.validateFunc === 'function',
            'options.validateFunction must be a valid function in jwt scheme'
        );
    }

    Hoek.assert(settings.key, 'Missing privateKey');

    return {
        authenticate: function(request, reply) {
            var req = request.raw.req;
            var authorization  = req.headers.authorization;
            if (!authorization) {
                return reply(Boom.unauthorized(null, 'Bearer'));
            }

            var parts = authorization.split(/\s+/);
            if (parts[0] && parts[0].toLowerCase() !== 'bearer') {
                return reply(Boom.unauthorized('Bad HTTP authentication header', 'Bearer'));
            }
            if (parts.length !== 2) {
                return reply(Boom.unauthorized('Bad HTTP authentication header format', 'Bearer'));
            }

            var token = parts[1];

            jwt.verify(token, settings.key, options, function(err, decoded) {
                if (err && err.message === 'jwt expired') {
                    return reply(Boom.unauthorized('Token expired', 'Bearer'));
                } else if (err) {
                    return reply(Boom.unauthorized('Bad authentication token', 'Bearer'));
                }
                if (!settings.validateFunc) {
                    return reply(null, { credentials: decoded });
                }

                settings.validateFunc(token, decoded, function(err, isValid, credentials) {
                    credentials = credentials || null;

                    if (err) {
                        return reply(err, { credentials: credentials, log: { tags: ['auth', 'jwt'], data: err } });
                    }

                    if (!isValid) {
                        return reply(Boom.unauthorized('Invalid token', 'Bearer'), { credentials: credentials });
                    }

                    if (!credentials || typeof credentials !== 'object') {
                        return reply(
                            Boom.badImplementation('Bad credentials object received for jwt auth validation'),
                            { log: { tags: 'credentials' } }
                        );
                    }
                    // Authenticated
                    return reply(null, { credentials: credentials });
                });
            });
        }
    };
};
