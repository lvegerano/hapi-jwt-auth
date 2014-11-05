var Lab = require('lab');
var Hapi = require('hapi');
var Hoek = require('hoek');
var Code = require('code');

var internals = {};

var expect = Lab.expect;
var before = Lab.before;
var describe = Lab.experiment;
var it = Lab.test;

var server = new Hapi.Server();
before(function(done) {
    server.pack.register(require('../'), function(err) {
        expect(err).to.not.exist;
        server.auth.strategy()

    });
});