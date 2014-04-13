var mongoose = require('mongoose'),
    Schema = mongoose.Schema,
    jwt = require('jsonwebtoken'),
    tokenSecret = 'put-a-$Ecr3t-h3re';

module.exports = exports = function tokenPlugin (schema, options) {
    schema.add({ token: String, resetToken: String });

    //https://github.com/auth0/node-jsonwebtoken
    schema.statics.generateToken = function(profile, expiration){
        return jwt.sign(profile, tokenSecret, { expiresInMinutes: expiration });
    }
    schema.statics.decodeToken = function(token, callback){
        jwt.verify(token, tokenSecret, function(err, decoded) {
            callback(err, decoded);
        });
    }

}
