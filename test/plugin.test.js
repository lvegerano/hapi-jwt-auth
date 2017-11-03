const Lab = require('lab');
const Hapi = require('hapi');
const Boom = require('boom');
const jwt = require('../');
const Hoek = require('hoek');

const lab = exports.lab = Lab.script();

const privateKey = 'kljdf[4aoinfl!$!#$v3413$#234knd*()*skladjsfp86$%54andkjvyasd';

const {
  test,
  suite,
  experiment,
  expect,
  beforeEach,
  before,
} = lab;

const header = (username, options) => {
  options = options || {};
  return `Bearer ${jwt.sign({ username }, privateKey, options)}`;
};

const validateUser = (token, decoded, callback) => {
  const username = decoded.username;
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

const handler = (request, reply) => {
  return reply('ok');
};

const getRequest = (headerType) => {
  return {
    method: 'POST',
    url: '/base',
    headers: {
      authorization: header(headerType),
    },
  };
};

experiment('hapi-jwt', () => {

  suite('jwt functions', () => {

    const token = jwt.sign({foo: 'bar'}, privateKey);

    test('it returns signed token', (done) => {
      expect(token).to.be.a.string();
      done();
    });

    test('it decodes a token', (done) => {
      const decoded = jwt.decode(token);
      expect(decoded).to.be.an.object();
      expect(decoded.iat).to.exists();
      done();
    });
  });

  suite('authentication', () => {

    let server;

    beforeEach((done) => {
      server = new Hapi.Server({ debug: false });
      server.connection();
      server.register(require('../'), (err) => {
        Hoek.assert(!err);
        server.auth.strategy('token', 'jwt', 'required', { validate: validateUser });
        server.route({
          method: 'POST',
          path: '/base',
          handler,
          config: {
            auth: 'token',
          },
        });
        done();
      });
    });

    test('replies on sucessful token verification', (done) => {
      server.inject(getRequest('luis'), (res) => {
        expect(res.result).to.exists();
        expect(res.result).to.equal('ok');
        done();
      });
    });

    test('returns a 401 when using a bad header', (done) => {
      const request = getRequest();
      request.headers.authorization = 'Booooyakasha!!!';
      server.inject(request, (res) => {
        expect(res.result).to.exists();
        expect(res.result.message).to.equals('Bad HTTP authentication header');
        expect(res.result.statusCode).to.equal(401);
        done();
      });
    });

    test('returns a 401 when missing auth header', (done) => {
      const request = getRequest();
      request.headers = {};

      server.inject(request, (res) => {
        expect(res.result).to.exist();
        expect(res.result.statusCode).to.equal(401);
        expect(res.result.message).to.equal('Missing authentication');
        done();
      });
    });

    test('returns a 401 when auth header is empty', (done) => {
      const request = getRequest();
      request.headers.authorization = ' ';

      server.inject(request, (res) => {
        expect(res.result).to.exist();
        expect(res.result.message).to.be.equal('Bad HTTP authentication header');
        expect(res.result.statusCode).to.equal(401);
        done();
      });
    });

    test('returns a 401 when using bad header format', (done) => {
      const request = getRequest();
      request.headers.authorization += ' cool story bro';

      server.inject(request, (res) => {
        expect(res.result).to.exist();
        expect(res.result.statusCode).to.equal(401);
        expect(res.result.message).to.be.equal('Bad HTTP authentication header format');
        done();
      });
    });

    test('should return a 401 when token is expired', (done) => {
      const request = getRequest();
      request.headers.authorization = header('luis', {expiresIn: -1});

      server.inject(request, (res) => {
        expect(res.result).to.exist();
        expect(res.result.message).to.be.equal('Token expired');
        expect(res.result.statusCode).to.equal(401);
        done();
      });
    });

    test('returns a 401 when using a bad token', (done) => {
      const request = getRequest();
      request.headers.authorization += 'X';

      server.inject(request, (res) => {
        expect(res.result).to.exist();
        expect(res.result.message).to.be.equal('Bad authentication token');
        expect(res.result.statusCode).to.equal(401);
        done();
      });
    });

    test('returns a 401 with an invalid user', (done) => {
      server.inject(getRequest('invalid'), (res) => {
        expect(res.result).to.exist();
        expect(res.result.message).to.equal('Invalid token');
        expect(res.result.statusCode).to.equal(401);
        done();
      });
    });

    test('returns a decoded token if no validate function', (done) => {
      server = new Hapi.Server();
      server.connection();
      server.register(require('../'), (err) => {
        Hoek.assert(!err);
        server.auth.strategy('token', 'jwt', 'required');
        server.route({
          method: 'POST',
          path: '/base',
          config: {
            handler,
            auth: 'token',
          }
        });
        server.inject(getRequest('luis'), function (res) {
          expect(res.result, 'Has a result').to.exist();
          expect(res.result, 'Responded Ok').to.equals('ok');
          done();
        })
      });
    });

    test('returns a 500 code when the validate function returns a bad credential', (done) => {
      server.inject(getRequest('badCredentials'), (res) => {
        expect(res.result).to.exist();
        expect(res.result.statusCode).to.equal(500);
        done();
      });
    });

    test('returns error on an internal error', (done) => {
      server.inject(getRequest('error'), function (res) {
        expect(res.result).to.exist();
        expect(res.result.statusCode).to.equal(500);
        done();
      });
    });
  });
});
