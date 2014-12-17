var Lab = require('lab');
var Hapi = require('hapi');
var Code = require('code');
var Boom = require('boom');
var jwt = require('../');

// test shortcuts
var lab = exports.lab = Lab.script();
var expect = Code.expect;
var before = lab.before;
var describe = lab.describe;
var it = lab.it;

var privateKey = 'kljdf[4aoinfl!$!#$v3413$#234knd*()*skladjsfp86$%54andkjvyasd';

describe('hapi-jwt', function() {
    var token = jwt.sign({ foo: 'bar'}, privateKey);
    //partial test token
    it('should return a string', function(done) {
        expect(token).to.be.a.string();
        done();
    });
});

describe('hapi-jwt', function() {
    var token = jwt.sign({ foo: 'bar'}, privateKey);
    var decoded = jwt.decode(token);
    //partial test token
    it('should return an object', function(done) {
        expect(decoded).to.be.an.object();
        done();
    });
});

describe('hapi-jwt', function() {
    var header = function(username, options) {
        options = options || {};
        return 'Bearer ' + jwt.sign({ username: username }, privateKey, options);
    };

    var validateUser = function(token, decoded, callback) {
        var username = decoded.username;
        switch (username) {
            case 'luis':
                return callback(null, true, { user: 'luis', scope: ['x'] });
            case 'invalid':
                return callback(null, false, { user: 'invalid' });
            case 'badCredentials':
                return callback(null, true, false);
            case 'errValidate':
                return callback('this err from validate', null, null);
            default:
                return callback(Boom.badImplementation());
        }
    };

    var handler = function(request, reply) {
        return reply('ok');
    };

    var server = new Hapi.Server({ debug: false });
    server.connection();
    before(function(done) {
        server.register(require('../'), function(err) {
            expect(err).to.not.exist();
            server.auth.strategy('token', 'jwt', 'required', { validate: validateUser });
            server.route([
                {
                    method: 'POST',
                    path: '/base',
                    handler: handler,
                    config: {
                        auth: 'token'
                    }
                }
            ]);
            done();
        });
    });

    it('should reply on successful token verification', function(done) {
        var request = {
            method: 'POST',
            url: '/base',
            headers: {
                authorization: header('luis')
            }
        };
        server.inject(request, function(res) {
            expect(res.result).to.exist();
            expect(res.result).to.equal('ok');
            done();
        });
    });

    it('should return a 401 code when using wrong scheme' , function(done) {
        var request = {
            method: 'POST',
            url: '/base',
            headers: {
                authorization: 'Boom bro'
            }
        };
        server.inject(request, function(res) {
            expect(res.result).to.exist();
            expect(res.result.message).to.equals('Bad HTTP authentication header');
            expect(res.result.statusCode).to.equal(401);
            done();
        });
    });

    it('should return a 401 code when missing authentication header' , function(done) {
        var request = {
            method: 'POST',
            url: '/base',
            headers: {}
        };
        server.inject(request, function(res) {
            expect(res.result).to.exist();
            expect(res.result.statusCode).to.equal(401);
            expect(res.result.message).to.equal('Missing authentication');
            done();
        });
    });

    it('should return a 401 code using empty header' , function(done) {
        var request = {
            method: 'POST',
            url: '/base',
            headers: {
                authorization: ' '
            }
        };
        server.inject(request, function(res) {
            expect(res.result).to.exist();
            expect(res.result.message).to.be.equal('Bad HTTP authentication header');
            expect(res.result.statusCode).to.equal(401);
            done();
        });
    });

    it('should return a 401 code using wrong header format' , function(done) {
        var request = {
            method: 'POST',
            url: '/base',
            headers: {
                authorization: header('luis') + ' cool bro'
            }
        };
        server.inject(request, function(res) {
            expect(res.result).to.exist();
            expect(res.result.message).to.be.equal('Bad HTTP authentication header format');
            expect(res.result.statusCode).to.equal(401);
            done();
        });
    });

    it('should return a 401 code using expired token' , function(done) {
        var request = {
            method: 'POST',
            url: '/base',
            headers: {
                authorization: header('luis', { expiresInMinutes: -1 })
            }
        };
        server.inject(request, function(res) {
            expect(res.result).to.exist();
            expect(res.result.message).to.be.equal('Token expired');
            expect(res.result.statusCode).to.equal(401);
            done();
        });
    });

    it('should return a 401 code using bad token' , function(done) {
        var request = {
            method: 'POST',
            url: '/base',
            headers: {
                authorization: header('luis') + 'X'
            }
        };
        server.inject(request, function(res) {
            expect(res.result).to.exist();
            expect(res.result.message).to.be.equal('Bad authentication token');
            expect(res.result.statusCode).to.equal(401);
            done();
        });
    });

    it('should return a 401 code on invalidated user', function(done) {
        var request = {
            method: 'POST',
            url: '/base',
            headers: {
                authorization: header('invalid')
            }
        };
        server.inject(request, function(res) {
            expect(res.result).to.exist();
            expect(res.result.message).to.equal('Invalid token');
            expect(res.result.statusCode).to.equal(401);
            done();
        });
    });

    it('should return decoded token if no validate function', function(done) {
        var handler = function (request, reply) {
            expect(request.auth.isAuthenticated).to.equal(true);
            expect(request.auth.credentials).to.exist();
            reply('ok');
        };
        var server = new Hapi.Server({ debug: false });
        server.connection();
        server.register(require('../'), function(err) {
            expect(err).to.not.exist();
            server.auth.strategy('token', 'jwt', 'required');
            server.route({
                    method: 'POST',
                    path: '/base',
                    config: {
                        handler: handler,
                        auth: 'token'
                    }
                }
            );
        });
        var request = {
            method: 'POST',
            url: '/base',
            headers: {
                authorization: header('luis')
            }
        };
        server.inject(request, function(res) {
            expect(res.result).to.exist();
            expect(res.result).to.equals('ok');
            done();
        });
    });

    it('should return a 500 code when validate function returns bad credentials', function(done) {
        var request = {
            method: 'POST',
            url: '/base',
            headers: {
                authorization: header('badCredentials')
            }
        };
        server.inject(request, function(res) {
            expect(res.result).to.exist();
            expect(res.result.statusCode).to.equal(500);
            done();
        });
    });

    it('should return a error on internal error', function(done) {
        var request = {
            method: 'POST',
            url: '/base',
            headers: {
                authorization: header('error')
            }
        };
        server.inject(request, function(res) {
            expect(res.result).to.exist();
            expect(res.result.statusCode).to.equal(500);
            done();
        });
    });

});

