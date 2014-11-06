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

describe('JWT', function() {
    var token = jwt.sign({ foo: 'bar'}, privateKey);
    //partial test token
    it('should return a string', function(done) {
        expect(token).to.be.a.string();
        done();
    });
});

describe('JWT', function() {
    var token = jwt.sign({ foo: 'bar'}, privateKey);
    var decoded = jwt.decode(token);
    //partial test token
    it('should return an object', function(done) {
        expect(decoded).to.be.an.object();
        done();
    });
});

