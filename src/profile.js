/** User profile API */

"use strict";

var $Q = require('q');
var NoPg = require('nor-nopg');
var strip = require('nor-nopg').strip;
var debug = require('nor-debug');
var is = require('nor-is');
var HTTPError = require('nor-express').HTTPError;
var ref = require('nor-ref');
var crypt = require('crypt3');
var helpers = require('nor-api-helpers');

/** Returns nor-express based profile resource */
var profile_builder = module.exports = function profile_builder(opts) {
	opts = opts || {};

	opts.user_type = opts.user_type || 'User';
	opts.path = opts.path || 'api/profile';
	opts.messages = opts.messages || {};
	opts.messages.success = opts.messages.success || 'Your email address has been verified successfully.';
	opts.messages.fail = opts.messages.fail || 'Your email address validation failed. Please request validation again.';

	debug.assert(opts.pg).is('string');
	debug.assert(opts.path).is('string');
	debug.assert(opts.user_type).is('string');
	debug.assert(opts.smtp).is('object');
	debug.assert(opts.mailer).is('object');
	debug.assert(opts.verification_message).is('function');
	debug.assert(opts.messages).is('object');
	debug.assert(opts.messages.success).is('string');
	debug.assert(opts.messages.fail).is('string');

	var routes = {};

/** Returns connected user data */
routes.GET = function(req, res) {
	if(!req.user) { throw new HTTPError(401); }
	debug.assert(req.user).is('object');
	var user = strip(req.user).specials().unset('password').unset('orig').get();
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

/** Changes current profile data */
routes.POST = function api_profile_post(req, res) {
	//debug.log('req.user = ', req.user);
	if(!req.user) { throw new HTTPError(500); }
	debug.assert(req.user).is('object');
	debug.assert(req.user.$id).is('string');
	debug.assert(req.body).is('object');
	//debug.log('req.body = ', req.body);
	var data = helpers.parse_body_params(req, ['password', 'password2']);
	if(data.password) {
		if(data.password !== data.password2) {
			throw new TypeError("Passwords do not match");
		}
		data.password = crypt(data.password, crypt.createSalt('md5'));
	}
	return $Q(NoPg.start(opts.pg).search(opts.user_type)({'$id': req.user.$id}).then(function(db) {
		var users = db.fetch();
		debug.assert(users).is('object').instanceOf(Array);
		var user = users.shift();
		debug.assert(user).is('object');
		//debug.log("user = ", user);
		return db.update(user, {"password": data.password} ).commit();
	}).then(function() {
		res.redirect(303, ref(req, opts.path) );
	}));
};

/** Validity support */

routes.validity = {};

/** */
routes.validity.GET = function(req, res) {
	if(!req.user) { throw new HTTPError(500); }
	return {
		'status': !!( req.user.email_valid ),
		'email_sent': !!( req.user.email_validation_hash ),
		'description': 'When you POST here, an email is sent to validate your email address.'
	};
};

/** */
routes.validity.POST = function(req, res) {
	if(!req.user) { throw new HTTPError(500); }

	var secret_uuid = require('node-uuid').v4();
	var crypted_secret_uuid = crypt(secret_uuid, crypt.createSalt('md5'));
	var secret_url = ref(req, opts.path + '/validity/verify', req.user.$id, secret_uuid);

	return $Q(NoPg.start(opts.pg).searchSingle(opts.user_type)({'$id': req.user.$id}).then(function(db) {
		var user = db.fetch();
		return db.update(user, {
			'email_validation_hash': crypted_secret_uuid
		}).commit();
	}).then(function() {

		var msg = opts.verification_message({
			'user': req.user,
			'secret_uuid': secret_uuid,
			'secret_url': secret_url
		});

		if(is.array(msg.body)) {
			msg.body = msg.body.join('\n');
		}

		// Ignore @example.com emails
		if(req.user.email.substr(req.user.email.indexOf('@')) === '@example.com') {
			return;
		}

		// We intenttionally handle the promise here and not chain it with the request since this action might take more time than HTTP request has.
		opts.mailer.send({
			from: opts.smtp.from || 'app@example.com',
			to: req.user.email,
			subject: msg.subject,
			body: msg.body
		}).fail(function(err) {
			debug.error('Sending email to ' + req.user.email + ' failed:', err);
		}).done();

	}).then(function() {
		res.redirect(303, ref(req, opts.path + '/validity') );
	}));
};

routes.validity.verify = {};
routes.validity.verify[':uuid'] = {};
routes.validity.verify[':uuid'][':uuid2'] = {};

/** Add a message
 * @fixme This code should be from session.js somehow
 */
function create_message(req, data) {
	debug.assert(data).is('object');
	if(!is.uuid(data.$id)) {
		data.$id = require('node-uuid').v4();
	}
	req.session.client.messages[data.$id] = data;
}

/** */
routes.validity.verify[':uuid'][':uuid2'].GET = function(req, res) {
	debug.assert(req.params).is('object');
	debug.assert(req.params.uuid).is('uuid');
	debug.assert(req.params.uuid2).is('uuid');
	debug.assert(req.session).is('object');

	if(!req.session.client) {
		req.session.client = {};
	}

	if( (!is.obj(req.session.client.messages)) || is.array(req.session.client.messages) ) {
		req.session.client.messages = {};
	}

	var user_uuid = req.params.uuid;
	var secret_uuid = req.params.uuid2;

	return $Q(NoPg.start(opts.pg).searchSingle(opts.user_type)({'$id': user_uuid}).then(function(db) {
		var user = db.fetch();
		debug.assert(user.email_validation_hash).is('string');

		var crypted_secret_uuid = crypt(secret_uuid, user.email_validation_hash);
		if(user.email_validation_hash !== crypted_secret_uuid) {
			throw new HTTPError(403, "Forbidden");
		}

		return db.update(user, {
			'email_valid': true,
			'email_validation_hash': ''
		}).commit().then(function() {
			create_message(req, {
				'type': 'info',
				'message': opts.messages.success
			});
		}).fail(function(err) {
			debug.error(err);
			create_message(req, {
				'type': 'error',
				'message': opts.messages.fail
			});
			return db.rollback();
		});
		
	}).then(function() {
		res.redirect(303, ref(req, '/') );
	}));
};

	// Returns the resource
	return routes;
}; // End of profile_builder

/* EOF */
