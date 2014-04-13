var mongoose = require('mongoose'),
    token = require('./token')
    Schema = mongoose.Schema,
    Strategy = require('../lib/strategy'),
    BadRequestError = require('../lib/badrequesterror'),
    extend = require('util')._extend,
    passportLocalMongoose = require('passport-local-mongoose');


	
var accountPlugin = function(schema, options){
	schema.plugin(passportLocalMongoose);
	schema.plugin(token);
	
	schema.methods.toResponse = function(){
		var toRet = extend({}, this._doc);
		delete toRet.salt;
		delete toRet.hash;
		delete toRet.token;
		delete toRet.resetToken;
		return toRet;
	}

	schema.statics.createToken = function(username, profile, expiration, cb) {
		var self = this;
		this.findOne({username: username}, function(err, usr) {
			if(err || !usr) {
				cb(err, null);
			}
			else {
				//Create a token and add to user and save
				usr.token = self.generateToken(profile, expiration);
				usr.save(function (err, usr) {
					if (err) {
						cb(err, null);
					} else {
						cb(false, usr.token);
					}
				});
			}
		});
	};

	schema.statics.createResetToken = function(username, expiration, cb) {
		var self = this;
		this.findOne({username: username}, function(err, usr) {
			if(err || !usr) {
				cb(err, null);
			}
			else {
				//Create a token and add to user and save
				usr.resetToken = Token.generateToken(username, expiration);
				usr.save(function (err, usr) {
					if (err) {
						cb(err, null);
					} else {
						cb(false, usr.resetToken);
					}
				});
			}
		});
	};

    schema.statics.authenticate_jwt = function(options){
        options = options || {};
        var self = this;
        return function(token, verified){
            if (!token) {
                return cb(null, false, new BadRequestError(options.badRequestMessage || 'Missing credentials'));
            }
            return self.tokenAuthenticate(token, verified);
        }
    }


	schema.statics.tokenAuthenticate = function(token, callback){
		var self = this;
		return self.decodeToken(token, function(err, user, message){

			if(err){
				return callback(err); //this error will occur if there is an internal token error
			}
			
			if(message){
				return callback(null, null, message); //this error will occur if token can't be decoded
			}

            self.findOne({username: user.username}, function (err, user) {
				if (err) {
					return callback(err); //this error will occur on backend error
				}

				if (!user) {
					return callback(null, null,  {message: 'User does not exist.'}); //this error will occur if user can't be found
				}

				if (user.token == undefined || user.token == null || user.token != token) {
					return callback(null, null, {message: 'Token does not exist or does not match. Request a new token.'});
				}
				return callback(null, user);
			});
		});
	}

	schema.statics.invalidateToken = function(username, cb) {
		var self = this;
		self.findOne({username: username}, function(err, usr) {
			if(err || !usr) {
				cb(err, null);
			}
			else {
				usr.token = null;
				usr.save(function (err, usr) {
					if (err) {
						cb(err, null);
					} else {
						cb(false, 'removed');
					}
				});
			}
		});
	};

    schema.statics.createJwtStrategy = function(options) {
        return new Strategy(options, this.authenticate_jwt(options));
    };
}
	

module.exports.Plugin = accountPlugin;

