/** User profile API */

"use strict";

var $Q = require('q');
var NoPg = require('nor-nopg');
var strip = require('nor-nopg').strip;
var debug = require('nor-debug');
//var is = require('nor-is');
var HTTPError = require('nor-express').HTTPError;
var ref = require('nor-ref');
var crypt = require('crypt3');
var helpers = require('nor-api-helpers');

/** Returns nor-express based profile resource */
module.exports = function profile_builder(opts) {
	opts = opts || {};

	opts.user_type = opts.user_type || 'User';
	opts.path = opts.path || 'api/profile';
	opts.messages = opts.messages || {};
	opts.messages.success = opts.messages.success || 'Your email address has been verified successfully.';
	opts.messages.fail = opts.messages.fail || 'Your email address validation failed. Please request validation again.';

	opts.changeable_fields = opts.changeable_fields || ['password', 'password2'];

	debug.assert(opts.pg).is('string');
	debug.assert(opts.path).is('string');
	debug.assert(opts.user_type).is('string');
	debug.assert(opts.smtp).is('object');
	debug.assert(opts.mailer).is('object');
	debug.assert(opts.verification_message).is('function');
	debug.assert(opts.messages).is('object');
	debug.assert(opts.messages.success).is('string');
	debug.assert(opts.messages.fail).is('string');
	debug.assert(opts.changeable_fields).is('array');

	if(!opts.view) {
		opts.view = {
			'element': function(req/*, res*/) {
				return function(user) {
					user = strip(req.user).specials().unset('password').unset('orig').get();
					user.$id = req.user.$id;
					user.$created = req.user.$created;
					user.$type = req.user.$type;
					user.validity = {
						'status': !!( req.user.email_valid ),
						'email_sent': !!( req.user.email_validation_hash ),
						'$ref': ref(req, opts.path + '/validity')
					};
					user.$ref = ref(req, opts.path);
					return user;
				};
			}
		};
	}


	var routes = {};

	/** Returns connected user data */
	routes.GET = function(req, res) {
		if(!req.user) { throw new HTTPError(401); }
		debug.assert(req.user).is('object');
		return opts.view.element(req, res, {
			'elementPath': 'api/profile'
		})(req.user);
	};

	/** Changes current profile data */
	routes.POST = function api_profile_post(req, res) {
		//debug.log('req.user = ', req.user);
		if(!req.user) { throw new HTTPError(500); }
		debug.assert(req.user).is('object');
		debug.assert(req.user.$id).is('string');
		debug.assert(req.body).is('object');
		//debug.log('req.body = ', req.body);
		var data = helpers.parse_body_params(req, opts.changeable_fields);
		if(data.password) {
			if(data.password !== data.password2) {
				throw new TypeError("Passwords do not match");
			}
			data.password = crypt(data.password, crypt.createSalt('md5'));
		}
		if(data.password2) {
			delete data.password2;
		}
		return $Q(NoPg.start(opts.pg).search(opts.user_type)({'$id': req.user.$id}).then(function(db) {
			var users = db.fetch();
			debug.assert(users).is('object').instanceOf(Array);
			var user = users.shift();
			debug.assert(user).is('object');
			//debug.log("user = ", user);
			return db.update(user, data ).commit();
		}).then(function() {
			res.redirect(303, ref(req, opts.path) );
		}));
	};

	/** Validity support */
	routes.validity = require('./validity.js')({
		'pg': opts.pg,
		'smtp': opts.smtp,
		'mailer': opts.mailer,
		'verification_message': opts.verification_message,
		'user_type': opts.user_type,
		'path': opts.path + '/validity',
		'messages': opts.messages
	});

	// Returns the resource
	return routes;
}; // End of profile_builder

/* EOF */
