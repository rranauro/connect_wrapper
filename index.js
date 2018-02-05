/*jslint newcap: false, node: true, vars: true, white: true, nomen: true  */
/*global _: true, Basepath: true, Boxspring: true, start: true, toJSON: true, getRow: true, send: true */

"use strict";
var _ = require('underscore')._
var MongoClient = require('mongodb').MongoClient;
var assert = require('assert');
var pool = {};
var uuidV1 = require('uuid').v1;
var async = require('async');

var ConnectWrapper = function(auth, uri_template, collection_prefix) {
	this._arguments = arguments;
	auth = auth ? auth.split(' ') : '';   
    var plain_auth = new Buffer(auth[1], 'base64'); 			// create a buffer and tell it the data coming in is base64
    
	plain_auth = plain_auth.toString().split(':');        	// read it back out as a string
	this.url = _.template(uri_template)({
		username: plain_auth[0],
		password: plain_auth[1]
	});
	this._username = this.url;
	if (pool[this._username]) {
		if (Date.now() - pool[this._username].now < 600000) {
			this._db = pool[this._username].db;
		} else if (pool[this._username]) {
			pool[this._username].db && pool[this._username].db.close();
			delete pool[this._username];
		}
	}
	
	// allow multiple logical databases within 1 physical;
	this._collection_prefix = collection_prefix ? collection_prefix + ':' : '';
	
	// this.url = MONGO_URI
	return this;
};

ConnectWrapper.prototype.noPrefix = function() {
	return new ConnectWrapper( this._arguments[0], this._arguments[1] );
};

ConnectWrapper.prototype.auth = function(req, res, next) {
	var self = this;
	

	if (!this._db) {
		MongoClient.connect( this.url, function(err, db) {
			if (err) {
				return next(err);
			}
			self._db = db;
			pool[self._username] = {now: Date.now(), db: db};
			next();
		});
	} else {
		process.nextTick( function() { next(); });
	}
	return this;
};

ConnectWrapper.prototype.createUser = function(req, res, next) {
	var password = require('password-hash-and-salt');
	var self = this;
	
	// hash the password and store it in the "users" collection
	password( req.body.password ).hash(function(err, salted) {
		if (err) {
			return res.status( 400 ).json({error: err, message: err});
		}
		self.create( 'users' )({body: {_id: req.body.name || req.body.user, hash: salted, roles: req.body.roles, customData: req.body.customData}}, res, next);
	});
};

ConnectWrapper.prototype.updatePassword = function(req, res, next) {
	var password = require('password-hash-and-salt');
	var self = this;
	
	password( req.body.password ).hash(function(err, salted) {
		if (err) {
			return res.status( 400 ).json({error: err, message: err});
		}
		req.body.hash = salted;
		self.update( 'users' )({params: {id: req.params.id}, body: req.body}, res, next);		
	});
};

ConnectWrapper.prototype.authenticateUser = function(req, res, next) {
	var password = require('password-hash-and-salt');
	var self = this;
	
	this.read( 'users' )({params:{id: req.params.id}}, res, function(err, doc) {
		if (err) return res.status( 404 ).json({error: err.name, message: err.message});
		if (!doc) return res.status( 404 ).json({error: 'error', message: 'not_found'});
		
		// Verifying a hash 
	    password(req.session.passWord || req.body.password).verifyAgainst(doc.hash, function(err, verified) {
			if (err) return res.status( 403 ).json({error: err, message: err});
			if (_.isFunction(next)) {
				return next(!verified, doc);
			}
			res.status( !verified ? 403 : 200 ).json(!verified ? {error: 'forbidden', message:'authentication_failed'} : {ok:true});
	    });
	});
};

ConnectWrapper.prototype.create = function( collection ) {
	collection = this._collection_prefix + collection;
	return _.bind(function(req, res, next) {	
		var self = this;
		var options;
		
		// We don't want to rely Mong's OID
		if (_.isArray(req.body)) {
			req.body = req.body.map(function(doc) {
				if (!doc._id) {
					doc._id = uuidV1();
				}
				return doc;
			});
			options = _.defaults(req.options || {}, {ordered: false});
		} else if (!req.body._id) {
			req.body._id = uuidV1();
			options = {};
		}
		
		try {
			
			if (_.isArray(req.body)) {
				
				// copy docs 1000 at a time
				async.eachLimit(_.range(0, req.body.length, 10000), 1, function(start, go) {
					console.log('[create] info:', collection, start, req.body.length);
					self._db.collection( collection ).insertMany(req.body.slice(start, start+10000), options, go);
				}, next);
				
			} else {

				// don't quit on duplicate _id errors
				this._db.collection( collection ).insertOne( req.body, options, function(e,r) {
					if (e) return next(null, {error: e.name, reason: e.message});
					next.apply(null, arguments);
				});	
			}
		
		} catch(e) {
			next(null, {error: e.name, reason: e.message});
		}
		
	}, this);
};

ConnectWrapper.prototype.update = function( collection ) {
	collection = this._collection_prefix + collection;
	return _.bind(function(req, res, next) {
		var data;
		var select = {_id: req.params && req.params.id};
		
		if (!req.params.id) {
			select = req.body.select;
			data = req.body.data;
		} else if (_.keys(req.query || {}).length){
			data = req.query;
		} else {
			data = req.body;
		}
		this._db.collection( collection ).updateOne( select, {$set: data || {}}, next);

	}, this);
};

ConnectWrapper.prototype.count = function(collection) {
	collection = this._collection_prefix + collection;
	return _.bind(function(req, res, next) {

		this._db.collection( collection )
			.find( req.query || {})
			.project( {_id: 1} )
			.toArray( function(err, results) {
				next(null, results.length);
			});
	}, this);
}

ConnectWrapper.prototype.collection = function( collection ) {
	collection = this._collection_prefix + collection;
	return this._db.collection( collection );
};

ConnectWrapper.prototype.all_ids = function( collection ) {
	collection = this._collection_prefix + collection;
	return _.bind(function(req, res, next) {
		this._db.collection(collection)
		.find(req.query || {})
		.project({_id:1})
		.toArray(function(err, results) {
			next(err, results.map(function(doc) { return doc._id; }));
		})
	}, this);
};

ConnectWrapper.prototype.bulkSave = function(collection) {
	let _all_ids = this.all_ids( collection );
	let _read = this.read( collection );
	let _collection = collection;
	
	collection = this._collection_prefix + collection;
	return _.bind(function(req, res, next) {
		let size = req.query.size || 1000;
		
		_all_ids({}, null, function(err, ids) {
			if (err) return next(err);
			
			// copy docs 1000 at a time
			async.eachLimit(_.range(0, ids.length, size), 1, function(start, next) {
				_read({query:{_id:{$in: ids.slice(start, start+size)}}}, null, 
				function(err, docs) {
					console.log('[bulkSave] info:', _collection, start, ids.length);
					req.query.target.create(_collection)({body: docs}, null, next);
				});
			}, next);
		});
		
	}, this);
};

ConnectWrapper.prototype.read = function( collection ) {
	collection = this._collection_prefix + collection;
	return _.bind(function(req, res, next) {
		
		var query
		, limit = (req.query && req.query.limit) || 0
		, page = req.query && req.query.page
		, pageSize = req.query && req.query.pageSize
		, $project = req.$project || {}
		
		if (req.params && req.params.id) {
			return this._db.collection( collection ).findOne( {_id: req.params.id}, next )
		} 
		
		if ((req.method || 'GET').toUpperCase() === 'GET') {
			query = req.query;
		} else {
			query = req.body;
		}
		
		if (limit) {
			limit = parseInt( query.limit, 10);	
			delete query.limit;		
		}
		
		if (page && pageSize) {
			page = parseInt(page, 10);
			pageSize = parseInt(pageSize, 10);
			if (typeof page !== 'number' || typeof pageSize !== 'number') page = undefined;
		}
		this._db.collection( collection )
			.find( query || {}).limit( limit )
			.project( $project )
			.toArray( function(err, results) {
				if (err) return next(err, results);
				if (page && pageSize) {
					return next(null, results.slice(page, (page * pageSize) + pageSize));
				} 
				next(null, results);
			});
	}, this);
};

ConnectWrapper.prototype.readAll = function( collection ) {
	collection = this._collection_prefix + collection;
	return _.bind(function(req, res, next) {
		this._db.collection( collection ).findOne( req.query, next );
	}, this);
};

ConnectWrapper.prototype.deleteOne = function( collection ) {
	collection = this._collection_prefix + collection;
	return _.bind(function(req, res, next) {
		if (req.params && req.params.id) {
			return this._db.collection( collection ).deleteOne( {_id: req.params.id}, next )
		}
		return this._db.collection( collection ).deleteOne( req.query || {}, next )
	}, this);
};

ConnectWrapper.prototype.drop = function( collection ) {
	collection = this._collection_prefix + collection;
	return _.bind(function(req, res, next) {
		this._db.collection( collection ).drop( function() { next.apply(null, arguments); } );
	}, this);
};

ConnectWrapper.prototype.view = function( collection ) {
	collection = this._collection_prefix + collection;
	return _.bind(function(req, res, next) {		
		this._db.collection( collection ).createIndex(req.body, next );
	}, this);
};

var connectWrapper = function(auth, URI, prefix) {
        return new ConnectWrapper(auth, URI, prefix);
};

exports.connectWrapper = connectWrapper;
