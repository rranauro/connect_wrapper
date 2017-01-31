/*jslint newcap: false, node: true, vars: true, white: true, nomen: true  */
/*global _: true, Basepath: true, Boxspring: true, start: true, toJSON: true, getRow: true, send: true */

"use strict";

// We need to keep this "server-side" file independet of frontend side
// maybe pre-processing this file with grunt
var config = require('../frontend/config.js');

var MongoClient = require('mongodb').MongoClient;

// this is the configuration relative to localhost:3000
var dbengine = config.getEnvConf('database');
var dbconfig =  config.getEnvConf('dbconfig')[dbengine];

var _ = require('underscore')._

// test if we are running as a Node.js process
, isNode = (typeof process !== 'undefined' && process.argv) ? true : false
, uuid = require('node-uuid').v1
, async = require('async');

_.mixin( require('base-utils') );


var mapRoles = function(roles) {
	return _.map(roles || [], function(role) {
		return role.role;
	});
};

var connectUrl = function(req) {	 
	return _.template(dbconfig.url)(_.defaults({
		user: req && req.session && req.session.userName && encodeURIComponent(req.session.userName),
		pwd: req && req.session && req.session.passWord
	}, dbconfig));
}

exports.authenticate = function(req, res, callback) {
	var user
	, password;

	if (req.method === 'POST') {
		user = req.body.name;
		password = req.body.password;
	} else {
		user = req.session.userName;
		password = req.session.passWord;
	}

	if (!user || !password) {
		return callback(null, {
				"userCtx": {
					"db": '',
					"name": '',
					"roles": []
				}
			});
	}

	// mongodb://<dbuser>:<dbpassword>@ds123849-a0.mlab.com:23849,ds123849-a1.mlab.com:23849/<dbname>?replicaSet=rs-ds123849
	return MongoClient.connect(connectUrl({session:{userName: user,passWord: password}}), function(err, db) {
		
		if (req.method === 'GET') {
			
			if (req.session.authenticated) {

				return db.collection('users').find({user: user}, function(e, doc) {
					req.session.roles = mapRoles( doc.roles );
					// We can have different instances of Basepath attached to the same db hosted separately
					// _.first( doc.roles ) && _.first( doc.roles ).db;
					req.session.db = dbconfig.name;
					res.status(err || !doc ? 404 : 200).json({
						ok: !err,
						userCtx: err || !doc
							? {
								"db": "",
								"name": "",
								"roles": []
							}
							: {
								"db": req.session.db,
								"name": user,
								"roles": req.session.roles
							}
						});
						db.close();
					});				
			}
			
			return res.status( 403 ).json({ok: false, error: 'forbidden', reason: 'unauthorized'});
		}

		if (!err) {
			req.session.authenticated = true;
			req.session.userName = user;
			req.session.passWord = password;
			db.close();
		} else {
			req.session.authenticated = false;
			req.session.userName = null;
			req.session.passWord = null;
			req.session.db = '';
			req.session.roles = [];
		}

		callback(err, {
			"userCtx": {
				"db": '',
				"name": '',
				"roles": []
			}
		});
	});
};

exports.logout = function(req, res, callback) {

	if (!req.session.authenticated || !req.session.userName || !req.session.passWord) {
		return res.status( 200 ).json({ok: false});
	}

	return MongoClient.connect(connectUrl(req), function(err, db) {
		if (err) {
			throw new Error('mongodb failed to connect.');
		}

		return db.logout(function(err, result) {
			req.session.authenticated = false;
			req.session.userName = null;
			req.session.passWord = null;
			req.session.roles = null;
			req.session.db = null;
			res.status( err && 500 || 200 ).json({ok: !err});
			db.close();
		});
	});
};

var checkId = function(doc) {
	if (!doc.hasOwnProperty('_id')) {
		doc._id = uuid();
	}
	return doc;
}
, checkIds = function(docs) {
	return _.map(docs, checkId);
};

var findOneAndUpdate = function(db, collectionName, doc, callback) {
	
	// Get the collectionName collection
	db.collection( collectionName ).findOneAndUpdate({_id: doc.id}, {$set: _.omit(doc, 'id')}, {
			upsert: true,
			returnOriginal: false }, function() {
				callback.apply(null, arguments);
				db.close()
			});
};

exports.updateDoc = function(req, res) {
	return function(collectionName, doc, callback) {
		callback = callback || function(err, result) {
			exports.sendHeader(req, res, { "Content-Type" : "application/json" });
			exports.sendData(req, res)(err, err || {ok: true});
		};


		if (isNode) {

			if (!_.isString(collectionName)) {
				collectionName = 'notype';
			}

			// Connection URL
			// Use connect method to connect to the Server
			return MongoClient.connect(connectUrl(req), function(err, db) {
				if (err) {
					throw new Error('mongodb failed to connect.');
				}

				if (req.method === 'POST') {
					return db.collection( collectionName ).insertOne(checkId(doc), function() {
						callback.apply(null, arguments);
						db.close()
					});
				}
				
				findOneAndUpdate(db, collectionName, doc, callback);
			});
		}

		// if we're CouchDB, return the doc in the first index and the response object in the second;
		return [ doc, {
			'headers' : {
				'Content-Type' : 'application/json'
			},
			'body' : JSON.stringify({ok: true})
		} ];
	};

};

var insertMany = function(collectionName, docs, callback) {
	MongoClient.connect(connectUrl(), function(err, db) {
		if (err) {
			throw new Error('mongodb failed to connect.');
		}

		db.collection( collectionName ).insertMany(checkIds(docs), null, function(err, response) {
			db.close();
			callback(err, err ? response : response.result);
		});
	});
};

exports.bulkDocs = function(req, res) {
	return function(collectionName, docs) {
		var now = Date.now();

		if (!_.isString(collectionName)) {
			collectionName = 'missing-or-invalid-collection';
		}

		// Connection URL
		// Use connect method to connect to the Server
		if (!docs.length) {
			if (_.isFunction(res)) {
				return res(null, {ok: false, message: 'nothing to save.'})
			}
			return res.status(200).json({ok: false, message: 'nothing to save.'})
		}

		// check for bulk delete
		if (_.first(_.filter(docs, function(doc) { return doc._deleted; }))) {

			return MongoClient.connect(connectUrl(req), function(err, db) {

				if (err) {
					throw new Error('mongodb failed to connect.');
				}

				// delete the requested documents one at a time;
				return async.eachLimit(docs, 1, function(item, callback) {
					db.collection( collectionName ).deleteOne({_id: item._id}, null, callback);
				}, function(err) {
					if (_.isFunction(res)) {
						return res(err, {ok: !err, deleted: docs.length});
					}
					res.status( err ? 500 : 200).json(err, {ok: !err, deleted: docs.length});
					db.close();
				});
			});
		}

		// insert all the docs
		insertMany(collectionName, docs, function(err, response) {
			if (_.isFunction(res)) {
				return res(err, {ok: !err, saved: docs.length, elapsed: (Date.now()-now)/1000})
			}
			exports.sendHeader(req, res, { "Content-Type" : "application/json" });
			exports.sendData(req, res)(err, {ok: !err, saved: docs.length, elapsed: (Date.now()-now)/1000});
		});
	}
};

exports.sendHeader = function(req, res, header) {
	if (isNode) {
		return res.set( header );
	}

	start({"headers": _.reduce(header, function(result, value, key) {
		if (_.isObject(value)) {
			result[key] = JSON.stringify(value);
		}
		return result;
	}, header)});
};

exports.sendData = function(req, res) {
	return function(err, data) {
		if (isNode) {
			return res.status(err ? 500 : 200 ).json( err ? {ok: false, error: err.name, reason: err.message} : data );
		}
		send( JSON.stringify( data ) );
	};
};

exports.sendDoc = function(req, res) {
	return function(err, doc) {
		if (isNode) {
			exports.sendHeader(req, res, { "Content-Type" : "application/json" });
			return exports.sendData(req, res)(err, doc);
		}

		return {
			'headers' : { "Content-Type" : "application/json" },
			'body' : _.isString( doc ) ? doc : JSON.stringify( doc )
		};
	};
};

exports.getData = function(collectionName, select, options, callback) {
	var docs = []
	, row
	, matcher = function(doc) {

		if (!_.keys(select).length) {
			return true;
		}

		if (!doc) {
			return true;
		}

		// always true when select is null or {}; if ANY key/val does not match, it does not match
		return !_.first(_.filter(_.keys(select), function(key) {
			return this[key] !== doc[key];
		}, select));
	};
	

	// getData as argument to async method;
	if (_.isObject(collectionName)) {
		options = collectionName.options || {};
		callback = select;
		select = collectionName.select;
		collectionName = collectionName.collection;
	}

	if (_.isFunction(options)) {
		callback = options;
		options = {};
	} else {
		options = options || {};
	}

	// Connection URL
	// Use connect method to connect to the Server
	return MongoClient.connect(connectUrl(), function(err, db) {
		if (err) {
			throw new Error('mongodb failed to connect.');
		}

		// Get the collectionName collection
		// Find some documents
		return 	db.collection( collectionName )
			.find( select )
			.sort( options.sort || {})
			.project( options.project || {})
			.toArray(function(err, docs) {
				callback(err, docs);
				db.close();
			});
		});
};

exports.getPage = function(collection, select, query, callback) {
	var page = parseInt( (query && query.page), 10 ) || 0
	, pageSize = query && query.hasOwnProperty('page') ? (parseInt(query.pageSize, 10) || 10) : undefined;

	exports.getData(collection, select, function(err, docs) {
		var last_page;
		if (!err && pageSize) {
			last_page = (docs.length <= (page*pageSize)+pageSize);
			docs = docs.slice((page*pageSize), (page*pageSize)+pageSize);
		}
		callback(err, docs, {
			page: page,
			pageSize: pageSize,
			last_page: last_page,
			total_rows: docs.length,
			total_pages: Math.ceil(docs.length / pageSize)
		});
	});
};

// Role definitions:
/*


Mongo:

{
  role: "<name>",
  privileges: [
     { resource: { <resource> }, actions: [ "<action>", ... ] },
     ...
  ],
  roles: [
     { role: "<role>", db: "<database>" } | "<role>",
      ...
  ]
}

Couch:
{
    "admins": {
        "names": [
            "Bob"
        ],
        "roles": []
    },
    "members": {
        "names": [
            "Mike",
            "Alice"
        ],
        "roles": []
    }
}
*/

var mongoSecurityRoles = function(name) {
	return([
		{
			role: "admin",
			db: name,
			roles: [],
			privileges: []
		},
		{
			role: "pa",
			db: name,
			roles: [],
			privileges: []
		},
		{
			role: "md",
			db: name,
			roles: [],
			privileges: []
		}
	]);
};

exports.initDb = function(req, res) {
	
	if (dbengine === 'mongo') {
		
		// be certain there are no existing users;
		return getUser(req, res)(null, function(err, users) {
			if (!err && users.length) {
				console.log('Database exists.')
//				return res.status( 412 ).json({error: 'precondition failed', reason: 'already initialized'});
			}
			
			if (err) {
				return res.status( 500 ).json( {error: 'failed', reason: err.message} );
			}
			

			MongoClient.connect(connectUrl(), function(err, db) {
				if (err) {
					return res.status( 500 ).json( {error: 'failed', reason: err.message} );
				}
				db.addUser('ron@ranauro.net', '1Basepath', {roles: ["admin"]}, function(err, result) {
					if (err) {
						return res.status( 500 ).json( {error: 'failed', reason: err.message} );
					}
					res.status( 200 ).json( {ok: true} );
					db.close();
				});
			});
		});
	}
	res.status(500).json({error: 'forbidden', reason: 'not_implemented'});
};


exports.addUser = function(req, res) {
	return function(username, password, roles) {
		var data = _.pick(req.body || {}, 'first_name', 'last_name', 'user')
		, db = req.session && req.session.db || dbconfig && dbconfig.name || 'basepath_dev';
		
		try {
			roles = _.isString(roles) ? JSON.parse(roles || '[]') : roles;
		} catch(e) {
			roles = ["pa"];
		}

		roles = _.reduce(roles || [], function(result, role) {
			if (_.contains(['md','pa', 'admin'], role.toLowerCase())) {
				result.push( {role: role.toLowerCase(), db: db} );
			}
			return result;
		}, []);

		roles = roles.length ? roles : [{role: "pa", db: db}];

		MongoClient.connect(connectUrl(), function(err, db) {

		  // Add the new user to the admin database
			console.log('roles', roles);
			
			db.addUser(username, password, {roles: roles, customData: data || {}}, function(err, result) {
				res
					.status(err ? 500 : 200)
					.json({ok: !err, roles: mapRoles(roles) || [], error: err && err.name, reason: err && err.message});
	      	db.close();
		  });
		});
	};
};

var getUser = function(req) {
	return function(user, callback) {
		
		// if we're querying from a user who is not Admin, limit output to only that user
		if (!user && req.session && req.session.roles && req.session.roles.indexOf('admin') === -1) {
			user = req.session.userName;
		}

		
		return MongoClient.connect(connectUrl(req), function(err, db) {
			
			if (err) {
				return callback({error: 'server_error', reason: 'connection failed'});
			}

		
			db.collection('users').find().toArray(function(err, docs) {
				
				// unless request is 'admin', only return the users own doc;
				var selected = _.reduce(docs, function(result, doc) {
					
					// extend the customData 
					doc = _.extend(doc, _.omit(doc.customData, 'roles', 'user'));
					if (user) {
						if (doc.user === user) {
							result.push( doc );
						}
					} else {
						result.push( doc );
					}
					return result;
				}, []);
			
				// for each doc, map over array of "roles" objects and return a simple array of rolws
				callback( err, _.map(selected, function(doc) {
					doc.roles = mapRoles( doc.roles );
					return doc;
				}) );
				db.close();
			});
		});
	}
};

exports.dropUser = function(req, res, callback) {

	return MongoClient.connect(connectUrl(), function(err, db) {
		db.removeUser(req.body.user || req.query.user, null, function(err, result) {
			if (_.isFunction(callback)) {
				callback.apply(null, arguments);
			} else {
				res.status(err ? 500 : 201).json(err ? {error: err.name, reason: err.message} : {ok: true});
			}
			db.close();
		});
	});
};

exports.updatePassword = function(req, res) {
	
	// get the user document
	return getUser(req, res)(req.body.user, function(err, docs) {
		var doc = _.first(docs);
	
		// drop the user
		exports.dropUser(req, res, function(err, result) {
			if (err) {
				return res.status( 500 ).json({error: err.name, reason: err.message});
			}
		
			// add roles, first_name, last_name to req.body
			req.body = _.defaults( req.body || {}, doc );
			
			// update the session password
			req.session.passWord = req.body.password;
			
		
			// add back the user with the new password;
			exports.addUser(req, res)(req.body.user, req.body.password, req.body.roles);
		})
	})
};

exports.updateUser = function(req, res) {
	var newRoles = _.map(req.body.roles || [], function(role) { return({role: role, db: req.session && req.session.db}) });
		
	if (req.session.roles.indexOf('admin') !== -1 || req.session.userName === req.body.user) {
		return getUser(req, res)(req.body.user, function(err, doc) {
			doc = doc[0];
			doc.id = doc._id;
			doc.customData = _.omit(req.body, 'password', 'roles', 'user');
			doc.roles = newRoles;
			
			return exports.dropUser(req, res, function(err, result) {
				if (err) {
					res.status( 500 ).json({error: 'server_error', reason: 'unable to remove user'});
				}
<<<<<<< HEAD
		
				db.collection('users').find().toArray(function(err, docs) {
					findOneAndUpdate(db, 'users', doc, function(err, result) {
						res.status(err ? 500 : 201).json({ok: true});
						db.close();
					});								
				});
=======
				exports.addUser(req, res)(req.body.user, req.body.password, newRoles);
>>>>>>> label
			});
		});
	} 
	res.status( 403 ).json({error: 'forbidden', reason: 'unauthorized'});
};

exports.allUsers = function(req, res) {
	return getUser(req, res)(null, function(err, docs) {
		res.status(err ? 500 : 200).json( err ? {error: 'failed', reason: err.message} : docs );
	});
};




