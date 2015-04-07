/** User profile API */

"use strict";

var _Q = require('q');
var nopg = require('nor-nopg');
var debug = require('nor-debug');
var is = require('nor-is');
var HTTPError = require('nor-express').HTTPError;
var ref = require('nor-ref');
var crypt = require('crypt3');
var FUNCTION = require('nor-function');
var NR = require('nor-newrelic');

function ref_req_path (path, req/*, res*/) {
	return ref(req, path);
}

function verify_path_ref(path, req, res, secret_uuid) {
	return ref(req, path, secret_uuid);
}

function get_user(req/*, res*/) {
	if(!req.user) { return; }
	return req.user;
}

/** Returns nor-express based profile resource */
module.exports = function validity_builder(opts) {
	opts = opts || {};

	opts.user_type = opts.user_type || 'User';

	// The path where to redirect if user verifies successfully
	opts.success_redirect_target = opts.hasOwnProperty('success_redirect_target') ? opts.success_redirect_target : '/';

	if(is.undef(opts.path)) {
		opts.path = 'api/profile/validity';
	}

	if(is.string(opts.path)) {
		opts.path = FUNCTION(ref_req_path).curry(opts.path);
	}

	if(is.undef(opts.verify_path)) {
		opts.verify_path = 'api/profile/validity/verify';
	}

	if(is.string(opts.verify_path)) {
		opts.verify_path = FUNCTION(verify_path_ref).curry(opts.verify_path);
	}

	opts.messages = opts.messages || {};
	opts.messages.success = opts.messages.success || 'Your email address has been verified successfully.';
	opts.messages.fail = opts.messages.fail || 'Your email address validation failed. Please request validation again.';
	opts.messages.login_first = opts.messages.login_first || 'You must login first';

	if(!is.defined(opts.get_user)) {
		opts.get_user = get_user;
	}

	debug.assert(opts.pg).is('string');
	debug.assert(opts.path).is('function');
	debug.assert(opts.user_type).is('string');
	debug.assert(opts.smtp).is('object');
	debug.assert(opts.mailer).is('object');
	debug.assert(opts.verification_message).is('defined');
	debug.assert(opts.messages).is('object');
	debug.assert(opts.messages.success).is('string');
	debug.assert(opts.messages.fail).is('string');
	debug.assert(opts.get_user).is('function');

	/** Validity support */
	var routes = {};

	/** */
	routes.GET = function validity_get(req, res) {
		return _Q.fcall(function validity_get_() {
			return opts.get_user(req, res);
		}).then(function validity_get_2(user) {
			if(is.undef(user)) { throw new HTTPError(401); }
			if(is.obj(user) && is.uuid(user.$id)) {
				return user.$id;
			}
			if(is.uuid(user)) {
				return user;
			}
			throw new TypeError("Invalid params");
		}).then(function validity_get_3(uuid) {
			return _Q(nopg.start(opts.pg).searchSingle(opts.user_type)({'$id': uuid}).commit().then(function(db) {
				return db.fetch();
			}));
		}).then(function validity_get_4(user) {
			return {
				'status': !!( user.email_valid ),
				'email_sent': !!( user.email_validation_hash ),
				'description': 'When you POST here, an email is sent to validate your email address.',
				'verify': {'$ref': ref(req, 'api/profile/validity/verify/:uuid')}
			};
		});
	};

	/** */
	routes.POST = function validity_post(req, res) {
		return _Q.fcall(function validity_post_() {
			return opts.get_user(req, res);
		}).then(function validity_post_2(user) {
			if(is.undef(user)) { throw new HTTPError(401); }
			if(is.obj(user) && is.uuid(user.$id)) {
				return user.$id;
			}
			if(is.uuid(user)) {
				return user;
			}
			throw new TypeError("Invalid params");
		}).then(function validity_post_3(user_uuid) {

			var secret_uuid = require('node-uuid').v4();
			var crypted_secret_uuid = crypt(secret_uuid, crypt.createSalt('md5'));
			var secret_url = opts.verify_path(req, res, secret_uuid);

			return _Q(nopg.start(opts.pg).searchSingle(opts.user_type)({'$id': user_uuid}).then(function(db) {
				var user = db.fetch();
				return db.update(user, {
					'email_validation_hash': crypted_secret_uuid
				}).commit().then(function validity_post_fetch_user() {
					return user;
				});
			}).then(function validity_post_4(user) {

				// Ignore @example.com emails
				if(user.email.substr(user.email.indexOf('@')) === '@example.com') {
					return;
				}

				var msg_params = {
					'name': user && user.name || undefined,
					'email': user && user.email || undefined,
					'user': user,
					'secret_uuid': secret_uuid,
					'secret_url': secret_url,
					'site_url': ref(req, '/')
				};

				return _Q.fcall(function validity_post_5() {
					if(!is.func(opts.verification_message)) {
						return opts.verification_message;
					}
					return opts.verification_message(msg_params, req, res);
				}).then(function validity_post_6(msg) {
					if(is.array(msg.body)) {
						msg.body = msg.body.join('\n');
					}

					debug.assert(msg).is('object');
					debug.assert(msg.subject).is('string');
					debug.assert(msg.body).is('string');

					// Convert parameters
					msg.subject = msg.subject.replace(/%{([^}]+)}/g, function validity_post_subject_replace(m, key) {
						return msg_params[key];
					});

					msg.body = msg.body.replace(/%{([^}]+)}/g, function validity_post_body_replace(m, key) {
						return msg_params[key];
					});

					/* We intentionally handle the promise here (with optional NewRelic support)
					 * and not chain it with the request since this action might take more time
					 * than the HTTP request has time to wait.
					 */

					NR.wtfcall("/mailer/sending/validity-email", function validity_post_nr_wtfcall_() {
						var from = opts.smtp.from || 'no-reply@example.com';
						debug.log('Sending email to ', user.email, ' (with from:', from, ')');
						return opts.mailer.send({
							from: from,
							to: user.email,
							subject: msg.subject,
							body: msg.body
						}).fail(function validity_post_nr_wtfcall_failed(err) {
							debug.error('Sending email to ' + user.email + ' failed:', err);
							return _Q.reject(err);
						});
					});
				});

			}).then(function validity_post_redirect() {
				res.redirect(303, opts.path(req, res) );
			}));
		});
	};

	routes.verify = {};
	routes.verify[':uuid'] = {};

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
	routes.verify[':uuid'].GET = function validity_verify_uuid_get(req, res) {
		return _Q.fcall(function() {
			return opts.get_user(req, res);
		}).then(function(req_user) {
			if(!req_user) { throw new HTTPError(401, ''+opts.messages.login_first); }
			var user_uuid = is.uuid(req_user) ? req_user : ( is.obj(req_user) && is.uuid(req_user.$id) ? req_user.$id : undefined );

			debug.assert(req.params).is('object');
			debug.assert(req.params.uuid).is('uuid');
			debug.assert(req.session).is('object');

			if(!req.session.client) {
				req.session.client = {};
			}

			if( (!is.obj(req.session.client.messages)) || is.array(req.session.client.messages) ) {
				req.session.client.messages = {};
			}

			var secret_uuid = req.params.uuid;

			return _Q(nopg.start(opts.pg).searchSingle(opts.user_type)({'$id': user_uuid}).then(function(db) {
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

			}).then(function validity_verify_redirect() {
				if(!opts.success_redirect_target) {
					return {'ok': true};
				}
				res.redirect(303, ref(req, opts.success_redirect_target) );
			}));
		});
	};

	// Returns the resource
	return routes;
}; // End of validity_builder

/* EOF */
