var passport = require('passport')
    , util = require('util')
    , BadRequestError = require('./badrequesterror');


function Strategy(options, verify){
    if (typeof options == 'function') {
        verify = options;
        options = {};
    }
    options = options || {};
    this._tokenHeader    = options.tokenHeader ? options.tokenHeader.toLowerCase()    : 'x-token';
    this._tokenField    = options.tokenField ? options.tokenField.toLowerCase()    : 'token';
    this._tokenQuery    = options.tokenQuery ? options.tokenQuery.toLowerCase()    : this._tokenField;
    this.name = 'jwt';

    passport.Strategy.call(this);
    this._verify = verify;
    this._passReqToCallback = options.passReqToCallback;
}

util.inherits(Strategy, passport.Strategy);



Strategy.prototype.authenticate = function(req, options) {
	options = options || {};
    var self = this;
    var token    = req.headers[this._tokenHeader] || lookup(req.body, this._tokenField) || lookup(req.query, this._tokenQuery);
    if (!token) {
        return this.fail(new BadRequestError(options.badRequestMessage || 'Missing credentials'));
    }

    function verified(err, user, info) {
        if (err) { return self.error(err); }
        if (!user) { return self.fail(info); }
        self.success(user, info);
    }

    if (self._passReqToCallback) {
        this._verify(req, token, verified);
    } else {
        this._verify(token, verified);
    }

    function lookup(obj, field) {
        if (!obj) { return null; }
        var chain = field.split(']').join('').split('[');
        for (var i = 0, len = chain.length; i < len; i++) {
            var prop = obj[chain[i]];
            if (typeof(prop) === 'undefined') { return null; }
            if (typeof(prop) !== 'object') { return prop; }
            obj = prop;
        }
        return null;
    }
}

module.exports = Strategy;