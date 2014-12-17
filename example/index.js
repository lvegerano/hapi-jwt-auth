var Hapi = require('hapi'),
    jwt = require('../'),
    server = new Hapi.Server();

server.connection({ port: 8080 });

var privateKey = 'supersecretkey';

var accounts = {
    222: {
        id: 222,
        user: 'Jon',
        fullname: 'Jon Doe'
    }
};

var token = jwt.sign({ accountId: 222 }, privateKey);

console.log('');
console.log('Use to test token authentication');
console.log('curl --header "Authorization: Bearer ' + token + '" http://localhost:8080/withtoken');
console.log('');
console.log('Use to test without token authentication');
console.log('curl http://localhost:8080/notoken');

var validate = function (token, decoded, callback) {
    if (decoded) {
        console.log(decoded.accountId.toString());
    }

    var account = accounts[decoded.accountId];

    if (!account) {
        return callback(null, false);
    }

    return callback(null, true, account);
};

server.register(jwt, function (err) {
    if (err) {
        return console.error(err);
    }
    server.auth.strategy('token','jwt', { key:privateKey, validate:validate });

    server.route({
        method: 'GET',
        path: '/withtoken',
        config: {
            auth: 'token',
            handler: function (request, reply) {
                reply({
                    message: 'JSON response from auth required route',
                    credentials: request.auth.credentials
                });
            }
        }
    });

    server.route({
        method: 'GET',
        path: '/notoken',
        config: {
            auth: false,
            handler: function (request, reply) {
                reply({
                    message: 'JSON response from no auth route',
                    credentials: request.auth.credentials
                });
            }
        }
    });
});

server.start();