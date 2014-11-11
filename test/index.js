var Lab = require('lab');
var Hapi = require('hapi');
var Hoek = require('hoek');
var Code = require('code');
var jwt = require('../');

var internals = {};

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
        }
    };

    var handler = function(req, rep) {
        rep('ok');
    };

    var server = new Hapi.Server({ debug: false });
    before(function(done) {
        server.pack.register(require('../'), function(err) {
            expect(err).to.not.exist();
            server.auth.strategy('token', 'jwt', 'required', { validateFunc: validateUser });
            server.route([
                {
                    method: 'POST',
                    path: '/base',
                    config: {
                        handler: handler,
                        auth: 'token'
                    }
                }
            ]);
            done();
        });
    });

    it('should return a reply on successful token verification', function(done) {
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

    it('should return a 401 code when using a bad scheme' , function(done) {
        var request = {
            method: 'POST',
            url: '/base',
            header: {
                authorization: 'Something crazy'
            }
        };
        server.inject(request, function(res) {
            expect(res.result).to.exist();
            expect(res.statusCode).to.be.a.number();
            expect(res.statusCode).to.equal(401);
            done();
        });
    });
});

