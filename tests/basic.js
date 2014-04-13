var mongoose = require('mongoose');
var Schema = mongoose.Schema;
var BadRequestError = require('../lib/badrequesterror');
var Strategy = require('../lib/strategy');
var assert = require('assert');
var expect = require('chai').expect;
var mongotest = require('./mongotest');
var plugin = require('../models/account').Plugin;

var setPasswordAndAuthenticate = function (user, passwordToSet, passwordToAuthenticate, cb) {
    user.setPassword(passwordToSet, function (err) {
        if (err) {
            return cb(err);
        }

        user.authenticate(passwordToAuthenticate, cb);
    });
};

var accountSchema = new Schema();
accountSchema.plugin(plugin);
var Account =  mongoose.model('Account', accountSchema);

describe('passport-mongoose-jwt', function () {
    describe('#token-plugin()', function () {
        it('should add "token" field to model', function () {
            var account = new Account({ token: 'token' });

            assert.equal('token', account.token);
        });

        it('should add "resetToken" field to model', function () {
            var account = new Account({ resetToken: 'resetToken' });

            assert.equal('resetToken', account.resetToken);
        });

        it('should create a decodeable token', function(done){
            var token = Account.generateToken({username:"username",test:"test"}, 0);
            Account.decodeToken(token, function(err, decoded){
                assert.equal("username", decoded.username);
                assert.equal("test", decoded.test);
                done();
            });
        });
    });

    describe('static #authenticate()', function () {
        beforeEach(mongotest.prepareDb('mongodb://localhost/passportmongoosejwttests'));
        afterEach(mongotest.disconnect());

        it('should yield false with message option for authenticate', function (done) {
            this.timeout(5000); // Five seconds - mongo db access needed

            Account.authenticate()('user', 'password', function (err, result, options) {
                assert.ifError(err);
                assert.ok(result === false);
                assert.ok(options.message);

                done();
            });
        });

        it('should authenticate existing user with matching password', function (done) {
            this.timeout(5000); // Five seconds - mongo db access needed

            var user = new Account({username: 'user'});
            user.setPassword('password', function (err) {
                assert.ifError(err);

                user.save(function (err) {
                    assert.ifError(err);

                    Account.authenticate()('user', 'password', function (err, result) {
                        assert.ifError(err);

                        assert.ok(result instanceof Account);
                        assert.equal(user.username, result.username);
                        assert.equal(user.salt, result.salt);
                        assert.equal(user.hash, result.hash);

                        done();
                    });
                });
            });
        });

        it('should authenticate and create token for user', function (done) {
            this.timeout(5000); // Five seconds - mongo db access needed
            var user = new Account({username: 'user'});
            user.setPassword('password', function (err) {
                assert.ifError(err);

                user.save(function (err) {
                    assert.ifError(err);

                    Account.authenticate()('user', 'password', function (err, result) {
                        Account.createToken(result.username, {test:"testmessage"}, 5000, function(err, token){
                            assert.ok(token != undefined);
                            Account.decodeToken(token, function(err, decoded){
                                assert.equal("testmessage", decoded.test);
                                done();
                            });
                        });
                    });
                });
            });
        });

        it('should authenticate and decode fail on expired token for user', function (done) {
            this.timeout(5000); // Five seconds - mongo db access needed
            var user = new Account({username: 'user'});
            user.setPassword('password', function (err) {
                assert.ifError(err);

                user.save(function (err) {
                    assert.ifError(err);

                    Account.authenticate()('user', 'password', function (err, result) {
                        Account.createToken(result.username, {test:"testmessage"}, 0.001, function(err, token){
                            assert.ok(token != undefined);
                            Account.decodeToken(token, function(err, decoded, msg){
                                assert.ok(msg != undefined);
                                assert.ok(decoded === undefined);
                                done();
                            });
                        });
                    });
                });
            });
        });

        it('should authenticate, create token and then auth on token', function (done) {
            this.timeout(10000); // Five seconds - mongo db access needed
            var user = new Account({username: 'user'});
            user.setPassword('password', function (err) {
                assert.ifError(err);

                user.save(function (err) {
                    assert.ifError(err);

                    Account.authenticate()('user', 'password', function (err, result) {
                        Account.createToken(result.username, {username:result.username}, 5000, function(err, token){
                            assert.ok(token != undefined);
                            Account.tokenAuthenticate(token, function(err, user){
                                assert.ifError(err);
                                assert.ok(user instanceof Account);
                                assert.equal("user", user.username);
                                done();
                            });
                        });
                    });
                });
            });
        });

        it('should authenticate, create token and then fail on token revoke', function (done) {
            this.timeout(10000); // Five seconds - mongo db access needed
            var user = new Account({username: 'user'});
            user.setPassword('password', function (err) {
                assert.ifError(err);

                user.save(function (err) {
                    assert.ifError(err);

                    Account.authenticate()('user', 'password', function (err, result) {
                        Account.createToken(result.username, {username:result.username}, 5000, function(err, token){
                            assert.ok(token != undefined);
                            Account.invalidateToken(result.username, function(err, msg) {
								assert.ifError(err);
                                Account.tokenAuthenticate(token, function (err, puser, msg) {
									assert.ifError(err);
                                    assert.ok(msg != null);
                                    assert.ok(puser == null);
                                    done();
                                });
                            });
                        });
                    });
                });
            });
        });

        it('should authenticate, create token and then fail on token expiration', function (done) {
            this.timeout(10000); // Five seconds - mongo db access needed
            var user = new Account({username: 'user'});
            user.setPassword('password', function (err) {
                assert.ifError(err);

                user.save(function (err) {
                    assert.ifError(err);

                    Account.authenticate()('user', 'password', function (err, result) {
                        Account.createToken(result.username, {username:result.username}, 0.0001, function(err, token){
                            assert.ok(token != undefined);
                                Account.tokenAuthenticate(token, function (err, user, msg) {
                                    assert.ok(msg != undefined);
                                    assert.ok(user == null);
                                    done();
                                });
                        });
                    });
                });
            });
        });
    });
});