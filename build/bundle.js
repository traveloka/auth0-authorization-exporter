module.exports =
/******/ (function(modules) { // webpackBootstrap
/******/ 	// The module cache
/******/ 	var installedModules = {};

/******/ 	// The require function
/******/ 	function __webpack_require__(moduleId) {

/******/ 		// Check if module is in cache
/******/ 		if(installedModules[moduleId])
/******/ 			return installedModules[moduleId].exports;

/******/ 		// Create a new module (and put it into the cache)
/******/ 		var module = installedModules[moduleId] = {
/******/ 			exports: {},
/******/ 			id: moduleId,
/******/ 			loaded: false
/******/ 		};

/******/ 		// Execute the module function
/******/ 		modules[moduleId].call(module.exports, module, module.exports, __webpack_require__);

/******/ 		// Flag the module as loaded
/******/ 		module.loaded = true;

/******/ 		// Return the exports of the module
/******/ 		return module.exports;
/******/ 	}


/******/ 	// expose the modules object (__webpack_modules__)
/******/ 	__webpack_require__.m = modules;

/******/ 	// expose the module cache
/******/ 	__webpack_require__.c = installedModules;

/******/ 	// __webpack_public_path__
/******/ 	__webpack_require__.p = "/build/";

/******/ 	// Load entry module and return exports
/******/ 	return __webpack_require__(0);
/******/ })
/************************************************************************/
/******/ ([
/* 0 */
/***/ (function(module, exports, __webpack_require__) {

	'use strict';

	var async = __webpack_require__(1);
	var express = __webpack_require__(2);
	var Webtask = __webpack_require__(3);
	var app = express();
	var Request = __webpack_require__(13);
	var memoizer = __webpack_require__(14);
	var AWS = __webpack_require__(15);
	var metadata = __webpack_require__(16);

	function s3Exporter(req, res) {
	    "use strict";

	    var ctx = req.webtaskContext;

	    var required_settings = ['AUTH0_DOMAIN', 'AUTH0_CLIENT_ID', 'AUTH0_CLIENT_SECRET', 'AWS_REGION', 'AWS_ACCESS_KEY', 'AWS_SECRET_KEY', 'S3_BUCKET', 'S3_FILE_NAME'];
	    var missing_settings = required_settings.filter(function (setting) {
	        return !ctx.data[setting];
	    });
	    if (missing_settings.length) {
	        return res.status(400).send({ message: 'Missing settings: ' + missing_settings.join(', ') });
	    }

	    var excludedClients = [];
	    if (ctx.data.EXCLUDED_CLIENTS) {
	        excludedClients = ctx.data.EXCLUDED_CLIENTS.split(",");
	    }

	    async.waterfall([
	    // get all users 
	    function (callback) {
	        var allUser = function allUser(context) {
	            getAllUsers(req.webtaskContext.data.AUTH0_DOMAIN, req.access_token, 0, 100, [], function (err, users) {
	                if (err) {
	                    console.log('Error ' + err);
	                    res.sendStatus(500);
	                }

	                console.log('No of user ' + users.length);
	                var clientUserPermissionMapper = {};
	                users.forEach(function (user) {
	                    if (user.app_metadata && user.app_metadata.authorization) {
	                        //console.log('App metadata authorisation is ' + JSON.stringify(user.app_metadata.authorization));
	                        user.app_metadata.authorization.forEach(function (userPermission) {
	                            if (userPermission.permissions && userPermission.permissions.length > 0) {
	                                var clientUserPermissionContent = clientUserPermissionMapper[userPermission.clientID] || {};
	                                clientUserPermissionContent.client_id = userPermission.clientID;
	                                var userPermissionList = clientUserPermissionContent.user_permissions || [];
	                                userPermissionList.push({ username: user.email, permissions: userPermission.permissions });
	                                clientUserPermissionContent.user_permissions = userPermissionList;
	                                clientUserPermissionMapper[userPermission.clientID] = clientUserPermissionContent;
	                            }
	                        });
	                    }
	                });

	                var result = [];
	                for (var key in clientUserPermissionMapper) {
	                    if (clientUserPermissionMapper.hasOwnProperty(key)) {
	                        result.push(clientUserPermissionMapper[key]);
	                    }
	                }
	                context.user_permissions = result;

	                return callback(null, context);
	            });
	        };
	        allUser({});
	    },
	    // send user permissions to s3
	    function (context, callback) {
	        console.log('User permissions is ' + JSON.stringify(context.user_permissions));
	        if (context.user_permissions && context.user_permissions.length > 0) {
	            var s3 = new AWS.S3({
	                region: req.webtaskContext.data.AWS_REGION,
	                accessKeyId: req.webtaskContext.data.AWS_ACCESS_KEY,
	                secretAccessKey: req.webtaskContext.data.AWS_SECRET_KEY
	            });
	            var maxAge = 60 * 60 * 24 * 365;
	            var cacheControl = 'public, max-age=' + maxAge;
	            var awsConfig = {
	                Bucket: req.webtaskContext.data.S3_BUCKET,
	                ACL: 'private',
	                CacheControl: cacheControl,
	                Key: req.webtaskContext.data.S3_FILE_NAME,
	                Body: JSON.stringify(context.user_permissions)
	            };

	            s3.putObject(awsConfig, function (err, data) {
	                if (err) throw err;
	                callback(null, context);
	            });
	        } else {
	            callback(null, context);
	        }
	    }], function (err, context) {
	        if (err) {
	            console.log('Job failed.');
	            res.status(500).send({
	                error: err
	            });
	        }

	        console.log('Job complete.');
	        res.sendStatus(200);
	    });
	}

	function getAllUsers(domain, token, page, pageSize, users, callback) {
	    getUsers(domain, token, page, pageSize).then(function (result) {
	        if (result.length === pageSize) {
	            getAllUsers(domain, token, page + 1, pageSize, users.concat(result), callback);
	        } else {
	            callback(null, users);
	        }
	    }).catch(function (error) {
	        console.log('Error ' + error);
	        callback(null);
	    });
	}

	function getUsers(domain, token, page, pageSize) {
	    return new Promise(function (resolve, reject) {
	        var url = 'https://' + domain + '/api/v2/users';
	        Request({
	            method: 'GET',
	            url: url,
	            json: true,
	            qs: {
	                fields: 'name,email,user_id,app_metadata',
	                page: page,
	                per_page: pageSize,
	                q: 'email:@traveloka.com',
	                search_engine: 'v2'
	            },
	            headers: {
	                Authorization: 'Bearer ' + token,
	                Accept: 'application/json'
	            }
	        }, function (err, res, body) {
	            if (err) {
	                reject(Error(err));
	            } else {
	                resolve(body);
	            }
	        });
	    });
	}

	var getTokenCached = memoizer({
	    load: function load(apiUrl, audience, clientId, clientSecret, cb) {
	        Request({
	            method: 'POST',
	            url: apiUrl,
	            json: true,
	            body: {
	                audience: audience,
	                grant_type: 'client_credentials',
	                client_id: clientId,
	                client_secret: clientSecret
	            }
	        }, function (err, res, body) {
	            if (err) {
	                cb(null, err);
	            } else {
	                cb(body.access_token);
	            }
	        });
	    },
	    hash: function hash(apiUrl) {
	        return apiUrl;
	    },
	    max: 100,
	    maxAge: 1000 * 60 * 60
	});

	app.use(function (req, res, next) {
	    var apiUrl = 'https://' + req.webtaskContext.data.AUTH0_DOMAIN + '/oauth/token';
	    var audience = 'https://' + req.webtaskContext.data.AUTH0_DOMAIN + '/api/v2/';
	    var clientId = req.webtaskContext.data.AUTH0_CLIENT_ID;
	    var clientSecret = req.webtaskContext.data.AUTH0_CLIENT_SECRET;

	    getTokenCached(apiUrl, audience, clientId, clientSecret, function (access_token, err) {
	        if (err) {
	            console.log('Error getting access_token with url ' + apiUrl + '  and domain ' + req.webtaskContext.data.AUTH0_DOMAIN, err);
	            return next(err);
	        }

	        req.access_token = access_token;
	        next();
	    });
	});

	app.get('/', s3Exporter);

	app.get('/meta', function (req, res) {
	    res.status(200).send(metadata);
	});

	module.exports = Webtask.fromExpress(app);

/***/ }),
/* 1 */
/***/ (function(module, exports) {

	module.exports = require("async");

/***/ }),
/* 2 */
/***/ (function(module, exports) {

	module.exports = require("express");

/***/ }),
/* 3 */
/***/ (function(module, exports, __webpack_require__) {

	exports.auth0 = __webpack_require__(4);
	exports.fromConnect = exports.fromExpress = fromConnect;
	exports.fromHapi = fromHapi;
	exports.fromServer = exports.fromRestify = fromServer;

	// API functions

	function addAuth0(func) {
	    func.auth0 = function (options) {
	        return exports.auth0(func, options);
	    }

	    return func;
	}

	function fromConnect (connectFn) {
	    return addAuth0(function (context, req, res) {
	        var normalizeRouteRx = createRouteNormalizationRx(req.x_wt.jtn);

	        req.originalUrl = req.url;
	        req.url = req.url.replace(normalizeRouteRx, '/');
	        req.webtaskContext = attachStorageHelpers(context);

	        return connectFn(req, res);
	    });
	}

	function fromHapi(server) {
	    var webtaskContext;

	    server.ext('onRequest', function (request, response) {
	        var normalizeRouteRx = createRouteNormalizationRx(request.x_wt.jtn);

	        request.setUrl(request.url.replace(normalizeRouteRx, '/'));
	        request.webtaskContext = webtaskContext;
	    });

	    return addAuth0(function (context, req, res) {
	        var dispatchFn = server._dispatch();

	        webtaskContext = attachStorageHelpers(context);

	        dispatchFn(req, res);
	    });
	}

	function fromServer(httpServer) {
	    return addAuth0(function (context, req, res) {
	        var normalizeRouteRx = createRouteNormalizationRx(req.x_wt.jtn);

	        req.originalUrl = req.url;
	        req.url = req.url.replace(normalizeRouteRx, '/');
	        req.webtaskContext = attachStorageHelpers(context);

	        return httpServer.emit('request', req, res);
	    });
	}


	// Helper functions

	function createRouteNormalizationRx(jtn) {
	    var normalizeRouteBase = '^\/api\/run\/[^\/]+\/';
	    var normalizeNamedRoute = '(?:[^\/\?#]*\/?)?';

	    return new RegExp(
	        normalizeRouteBase + (
	        jtn
	            ?   normalizeNamedRoute
	            :   ''
	    ));
	}

	function attachStorageHelpers(context) {
	    context.read = context.secrets.EXT_STORAGE_URL
	        ?   readFromPath
	        :   readNotAvailable;
	    context.write = context.secrets.EXT_STORAGE_URL
	        ?   writeToPath
	        :   writeNotAvailable;

	    return context;


	    function readNotAvailable(path, options, cb) {
	        var Boom = __webpack_require__(12);

	        if (typeof options === 'function') {
	            cb = options;
	            options = {};
	        }

	        cb(Boom.preconditionFailed('Storage is not available in this context'));
	    }

	    function readFromPath(path, options, cb) {
	        var Boom = __webpack_require__(12);
	        var Request = __webpack_require__(13);

	        if (typeof options === 'function') {
	            cb = options;
	            options = {};
	        }

	        Request({
	            uri: context.secrets.EXT_STORAGE_URL,
	            method: 'GET',
	            headers: options.headers || {},
	            qs: { path: path },
	            json: true,
	        }, function (err, res, body) {
	            if (err) return cb(Boom.wrap(err, 502));
	            if (res.statusCode === 404 && Object.hasOwnProperty.call(options, 'defaultValue')) return cb(null, options.defaultValue);
	            if (res.statusCode >= 400) return cb(Boom.create(res.statusCode, body && body.message));

	            cb(null, body);
	        });
	    }

	    function writeNotAvailable(path, data, options, cb) {
	        var Boom = __webpack_require__(12);

	        if (typeof options === 'function') {
	            cb = options;
	            options = {};
	        }

	        cb(Boom.preconditionFailed('Storage is not available in this context'));
	    }

	    function writeToPath(path, data, options, cb) {
	        var Boom = __webpack_require__(12);
	        var Request = __webpack_require__(13);

	        if (typeof options === 'function') {
	            cb = options;
	            options = {};
	        }

	        Request({
	            uri: context.secrets.EXT_STORAGE_URL,
	            method: 'PUT',
	            headers: options.headers || {},
	            qs: { path: path },
	            body: data,
	        }, function (err, res, body) {
	            if (err) return cb(Boom.wrap(err, 502));
	            if (res.statusCode >= 400) return cb(Boom.create(res.statusCode, body && body.message));

	            cb(null);
	        });
	    }
	}


/***/ }),
/* 4 */
/***/ (function(module, exports, __webpack_require__) {

	var url = __webpack_require__(5);
	var error = __webpack_require__(6);
	var handleAppEndpoint = __webpack_require__(7);
	var handleLogin = __webpack_require__(9);
	var handleCallback = __webpack_require__(10);

	module.exports = function (webtask, options) {
	    if (typeof webtask !== 'function' || webtask.length !== 3) {
	        throw new Error('The auth0() function can only be called on webtask functions with the (ctx, req, res) signature.');
	    }
	    if (!options) {
	        options = {};
	    }
	    if (typeof options !== 'object') {
	        throw new Error('The options parameter must be an object.');
	    }
	    if (options.scope && typeof options.scope !== 'string') {
	        throw new Error('The scope option, if specified, must be a string.');
	    }
	    if (options.authorized && ['string','function'].indexOf(typeof options.authorized) < 0 && !Array.isArray(options.authorized)) {
	        throw new Error('The authorized option, if specified, must be a string or array of strings with e-mail or domain names, or a function that accepts (ctx, req) and returns boolean.');
	    }
	    if (options.exclude && ['string','function'].indexOf(typeof options.exclude) < 0 && !Array.isArray(options.exclude)) {
	        throw new Error('The exclude option, if specified, must be a string or array of strings with URL paths that do not require authentication, or a function that accepts (ctx, req, appPath) and returns boolean.');
	    }
	    if (options.clientId && typeof options.clientId !== 'function') {
	        throw new Error('The clientId option, if specified, must be a function that accepts (ctx, req) and returns an Auth0 Client ID.');
	    }
	    if (options.clientSecret && typeof options.clientSecret !== 'function') {
	        throw new Error('The clientSecret option, if specified, must be a function that accepts (ctx, req) and returns an Auth0 Client Secret.');
	    }
	    if (options.domain && typeof options.domain !== 'function') {
	        throw new Error('The domain option, if specified, must be a function that accepts (ctx, req) and returns an Auth0 Domain.');
	    }
	    if (options.webtaskSecret && typeof options.webtaskSecret !== 'function') {
	        throw new Error('The webtaskSecret option, if specified, must be a function that accepts (ctx, req) and returns a key to be used to sign issued JWT tokens.');
	    }
	    if (options.getApiKey && typeof options.getApiKey !== 'function') {
	        throw new Error('The getApiKey option, if specified, must be a function that accepts (ctx, req) and returns an apiKey associated with the request.');
	    }
	    if (options.loginSuccess && typeof options.loginSuccess !== 'function') {
	        throw new Error('The loginSuccess option, if specified, must be a function that accepts (ctx, req, res, baseUrl) and generates a response.');
	    }
	    if (options.loginError && typeof options.loginError !== 'function') {
	        throw new Error('The loginError option, if specified, must be a function that accepts (error, ctx, req, res, baseUrl) and generates a response.');
	    }

	    options.clientId = options.clientId || function (ctx, req) {
	        return ctx.secrets.AUTH0_CLIENT_ID;
	    };
	    options.clientSecret = options.clientSecret || function (ctx, req) {
	        return ctx.secrets.AUTH0_CLIENT_SECRET;
	    };
	    options.domain = options.domain || function (ctx, req) {
	        return ctx.secrets.AUTH0_DOMAIN;
	    };
	    options.webtaskSecret = options.webtaskSecret || function (ctx, req) {
	        // By default we don't expect developers to specify WEBTASK_SECRET when
	        // creating authenticated webtasks. In this case we will use webtask token
	        // itself as a JWT signing key. The webtask token of a named webtask is secret
	        // and it contains enough entropy (jti, iat, ca) to pass
	        // for a symmetric key. Using webtask token ensures that the JWT signing secret 
	        // remains constant for the lifetime of the webtask; however regenerating 
	        // the webtask will invalidate previously issued JWTs. 
	        return ctx.secrets.WEBTASK_SECRET || req.x_wt.token;
	    };
	    options.getApiKey = options.getApiKey || function (ctx, req) {
	        if (req.headers.authorization && req.headers.authorization.split(' ')[0] === 'Bearer') {
	            return req.headers.authorization.split(' ')[1];
	        } else if (req.query && req.query.apiKey) {
	            return req.query.apiKey;
	        }
	        return null;
	    };
	    options.loginSuccess = options.loginSuccess || function (ctx, req, res, baseUrl) {
	        res.writeHead(302, { Location: baseUrl + '?apiKey=' + ctx.apiKey });
	        return res.end();
	    };
	    options.loginError = options.loginError || function (error, ctx, req, res, baseUrl) {
	        if (req.method === 'GET') {
	            if (error.redirect) {
	                res.writeHead(302, { Location: error.redirect });
	                return res.end(JSON.stringify(error));
	            }
	            res.writeHead(error.code || 401, { 
	                'Content-Type': 'text/html', 
	                'Cache-Control': 'no-cache' 
	            });
	            return res.end(getNotAuthorizedHtml(baseUrl + '/login'));
	        }
	        else {
	            // Reject all other requests
	            return error(error, res);
	        }            
	    };
	    if (typeof options.authorized === 'string') {
	        options.authorized = [ options.authorized ];
	    }
	    if (Array.isArray(options.authorized)) {
	        var authorized = [];
	        options.authorized.forEach(function (a) {
	            authorized.push(a.toLowerCase());
	        });
	        options.authorized = function (ctx, res) {
	            if (ctx.user.email_verified) {
	                for (var i = 0; i < authorized.length; i++) {
	                    var email = ctx.user.email.toLowerCase();
	                    if (email === authorized[i] || authorized[i][0] === '@' && email.indexOf(authorized[i]) > 1) {
	                        return true;
	                    }
	                }
	            }
	            return false;
	        }
	    }
	    if (typeof options.exclude === 'string') {
	        options.exclude = [ options.exclude ];
	    }
	    if (Array.isArray(options.exclude)) {
	        var exclude = options.exclude;
	        options.exclude = function (ctx, res, appPath) {
	            return exclude.indexOf(appPath) > -1;
	        }
	    }

	    return createAuthenticatedWebtask(webtask, options);
	};

	function createAuthenticatedWebtask(webtask, options) {

	    // Inject middleware into the HTTP pipeline before the webtask handler
	    // to implement authentication endpoints and perform authentication 
	    // and authorization.

	    return function (ctx, req, res) {
	        if (!req.x_wt.jtn || !req.x_wt.container) {
	            return error({
	                code: 400,
	                message: 'Auth0 authentication can only be used with named webtasks.'
	            }, res);
	        }

	        var routingInfo = getRoutingInfo(req);
	        if (!routingInfo) {
	            return error({
	                code: 400,
	                message: 'Error processing request URL path.'
	            }, res);
	        }
	        switch (req.method === 'GET' && routingInfo.appPath) {
	            case '/login': handleLogin(options, ctx, req, res, routingInfo); break;
	            case '/callback': handleCallback(options, ctx, req, res, routingInfo); break;
	            default: handleAppEndpoint(webtask, options, ctx, req, res, routingInfo); break;
	        };
	        return;
	    };
	}

	function getRoutingInfo(req) {
	    var routingInfo = url.parse(req.url, true);
	    var segments = routingInfo.pathname.split('/');
	    if (segments[1] === 'api' && segments[2] === 'run' && segments[3] === req.x_wt.container && segments[4] === req.x_wt.jtn) {
	        // Shared domain case: /api/run/{container}/{jtn}
	        routingInfo.basePath = segments.splice(0, 5).join('/');
	    }
	    else if (segments[1] === req.x_wt.container && segments[2] === req.x_wt.jtn) {
	        // Custom domain case: /{container}/{jtn}
	        routingInfo.basePath = segments.splice(0, 3).join('/');
	    }
	    else {
	        return null;
	    }
	    routingInfo.appPath = '/' + segments.join('/');
	    routingInfo.baseUrl = [
	        req.headers['x-forwarded-proto'] || 'https',
	        '://',
	        req.headers.host,
	        routingInfo.basePath
	    ].join('');
	    return routingInfo;
	}

	var notAuthorizedTemplate = function () {/*
	<!DOCTYPE html5>
	<html>
	  <head>
	    <meta charset="utf-8"/>
	    <meta http-equiv="X-UA-Compatible" content="IE=edge"/>
	    <meta name="viewport" content="width=device-width, initial-scale=1"/>
	    <link href="https://cdn.auth0.com/styleguide/latest/index.css" rel="stylesheet" />
	    <title>Access denied</title>
	  </head>
	  <body>
	    <div class="container">
	      <div class="row text-center">
	        <h1><a href="https://auth0.com" title="Go to Auth0!"><img src="https://cdn.auth0.com/styleguide/1.0.0/img/badge.svg" alt="Auth0 badge" /></a></h1>
	        <h1>Not authorized</h1>
	        <p><a href="##">Try again</a></p>
	      </div>
	    </div>
	  </body>
	</html>
	*/}.toString().match(/[^]*\/\*([^]*)\*\/\s*\}$/)[1];

	function getNotAuthorizedHtml(loginUrl) {
	    return notAuthorizedTemplate.replace('##', loginUrl);
	}


/***/ }),
/* 5 */
/***/ (function(module, exports) {

	module.exports = require("url");

/***/ }),
/* 6 */
/***/ (function(module, exports) {

	module.exports = function (err, res) {
	    res.writeHead(err.code || 500, { 
	        'Content-Type': 'application/json',
	        'Cache-Control': 'no-cache'
	    });
	    res.end(JSON.stringify(err));
	};


/***/ }),
/* 7 */
/***/ (function(module, exports, __webpack_require__) {

	var error = __webpack_require__(6);

	module.exports = function (webtask, options, ctx, req, res, routingInfo) {
	    return options.exclude && options.exclude(ctx, req, routingInfo.appPath)
	        ? run()
	        : authenticate();

	    function authenticate() {
	        var apiKey = options.getApiKey(ctx, req);
	        if (!apiKey) {
	            return options.loginError({
	                code: 401,
	                message: 'Unauthorized.',
	                error: 'Missing apiKey.',
	                redirect: routingInfo.baseUrl + '/login'
	            }, ctx, req, res, routingInfo.baseUrl);
	        }

	        // Authenticate

	        var secret = options.webtaskSecret(ctx, req);
	        if (!secret) {
	            return error({
	                code: 400,
	                message: 'The webtask secret must be provided to allow for validating apiKeys.'
	            }, res);
	        }

	        try {
	            ctx.user = req.user = __webpack_require__(8).verify(apiKey, secret);
	        }
	        catch (e) {
	            return options.loginError({
	                code: 401,
	                message: 'Unauthorized.',
	                error: e.message
	            }, ctx, req, res, routingInfo.baseUrl);       
	        }

	        ctx.apiKey = apiKey;

	        // Authorize

	        if  (options.authorized && !options.authorized(ctx, req)) {
	            return options.loginError({
	                code: 403,
	                message: 'Forbidden.'
	            }, ctx, req, res, routingInfo.baseUrl);        
	        }

	        return run();
	    }

	    function run() {
	        // Route request to webtask code
	        return webtask(ctx, req, res);
	    }
	};


/***/ }),
/* 8 */
/***/ (function(module, exports) {

	module.exports = require("jsonwebtoken");

/***/ }),
/* 9 */
/***/ (function(module, exports, __webpack_require__) {

	var error = __webpack_require__(6);

	module.exports = function(options, ctx, req, res, routingInfo) {
	    var authParams = {
	        clientId: options.clientId(ctx, req),
	        domain: options.domain(ctx, req)
	    };
	    var count = !!authParams.clientId + !!authParams.domain;
	    var scope = 'openid name email email_verified ' + (options.scope || '');
	    if (count ===  0) {
	        // TODO, tjanczuk, support the shared Auth0 application case
	        return error({
	            code: 501,
	            message: 'Not implemented.'
	        }, res);
	        // Neither client id or domain are specified; use shared Auth0 settings
	        // var authUrl = 'https://auth0.auth0.com/i/oauth2/authorize'
	        //     + '?response_type=code'
	        //     + '&audience=https://auth0.auth0.com/userinfo'
	        //     + '&scope=' + encodeURIComponent(scope)
	        //     + '&client_id=' + encodeURIComponent(routingInfo.baseUrl)
	        //     + '&redirect_uri=' + encodeURIComponent(routingInfo.baseUrl + '/callback');
	        // res.writeHead(302, { Location: authUrl });
	        // return res.end();
	    }
	    else if (count === 2) {
	        // Use custom Auth0 account
	        var authUrl = 'https://' + authParams.domain + '/authorize' 
	            + '?response_type=code'
	            + '&scope=' + encodeURIComponent(scope)
	            + '&client_id=' + encodeURIComponent(authParams.clientId)
	            + '&redirect_uri=' + encodeURIComponent(routingInfo.baseUrl + '/callback');
	        res.writeHead(302, { Location: authUrl });
	        return res.end();
	    }
	    else {
	        return error({
	            code: 400,
	            message: 'Both or neither Auth0 Client ID and Auth0 domain must be specified.'
	        }, res);
	    }
	};


/***/ }),
/* 10 */
/***/ (function(module, exports, __webpack_require__) {

	var error = __webpack_require__(6);

	module.exports = function (options, ctx, req, res, routingInfo) {
	    if (!ctx.query.code) {
	        return options.loginError({
	            code: 401,
	            message: 'Authentication error.',
	            callbackQuery: ctx.query
	        }, ctx, req, res, routingInfo.baseUrl);
	    }

	    var authParams = {
	        clientId: options.clientId(ctx, req),
	        domain: options.domain(ctx, req),
	        clientSecret: options.clientSecret(ctx, req)
	    };
	    var count = !!authParams.clientId + !!authParams.domain + !!authParams.clientSecret;
	    if (count !== 3) {
	        return error({
	            code: 400,
	            message: 'Auth0 Client ID, Client Secret, and Auth0 Domain must be specified.'
	        }, res);
	    }

	    return __webpack_require__(11)
	        .post('https://' + authParams.domain + '/oauth/token')
	        .type('form')
	        .send({
	            client_id: authParams.clientId,
	            client_secret: authParams.clientSecret,
	            redirect_uri: routingInfo.baseUrl + '/callback',
	            code: ctx.query.code,
	            grant_type: 'authorization_code'
	        })
	        .timeout(15000)
	        .end(function (err, ares) {
	            if (err || !ares.ok) {
	                return options.loginError({
	                    code: 502,
	                    message: 'OAuth code exchange completed with error.',
	                    error: err && err.message,
	                    auth0Status: ares && ares.status,
	                    auth0Response: ares && (ares.body || ares.text)
	                }, ctx, req, res, routingInfo.baseUrl);
	            }

	            return issueApiKey(ares.body.id_token);
	        });

	    function issueApiKey(id_token) {
	        var jwt = __webpack_require__(8);
	        var claims;
	        try {
	            claims = jwt.decode(id_token);
	        }
	        catch (e) {
	            return options.loginError({
	                code: 502,
	                message: 'Cannot parse id_token returned from Auth0.',
	                id_token: id_token,
	                error: e.message
	            }, ctx, req, res, routingInfo.baseUrl);
	        }

	        // Issue apiKey by re-signing the id_token claims 
	        // with configured secret (webtask token by default).

	        var secret = options.webtaskSecret(ctx, req);
	        if (!secret) {
	            return error({
	                code: 400,
	                message: 'The webtask secret must be be provided to allow for issuing apiKeys.'
	            }, res);
	        }

	        claims.iss = routingInfo.baseUrl;
	        req.user = ctx.user = claims;
	        ctx.apiKey = jwt.sign(claims, secret);

	        // Perform post-login action (redirect to /?apiKey=... by default)
	        return options.loginSuccess(ctx, req, res, routingInfo.baseUrl);
	    }
	};


/***/ }),
/* 11 */
/***/ (function(module, exports) {

	module.exports = require("superagent");

/***/ }),
/* 12 */
/***/ (function(module, exports) {

	module.exports = require("boom");

/***/ }),
/* 13 */
/***/ (function(module, exports) {

	module.exports = require("request");

/***/ }),
/* 14 */
/***/ (function(module, exports) {

	module.exports = require("lru-memoizer");

/***/ }),
/* 15 */
/***/ (function(module, exports) {

	module.exports = require("aws-sdk");

/***/ }),
/* 16 */
/***/ (function(module, exports) {

	module.exports = {
		"title": "Export Auth0 Authorisation to S3",
		"name": "export-auth0-authorisation-to-s3",
		"version": "1.2.0",
		"author": "traveloka",
		"description": "This extension will take Auth0 authorisation defined in authorisation extension and export them to S3",
		"type": "cron",
		"repository": "https://github.com/traveloka/auth0-authorization-exporter",
		"keywords": [
			"auth0",
			"extension"
		],
		"schedule": "0 */10 * * * *",
		"auth0": {
			"scopes": "read:users"
		},
		"secrets": {
			"AWS_REGION": {
				"description": "AWS Region",
				"required": true
			},
			"AWS_ACCESS_KEY": {
				"description": "AWS Access Key",
				"required": true
			},
			"AWS_SECRET_KEY": {
				"description": "AWS Secret Key",
				"required": true
			},
			"S3_BUCKET": {
				"description": "S3 Bucket Name",
				"required": true
			},
			"S3_FILE_NAME": {
				"description": "S3 File Name",
				"required": true
			}
		}
	};

/***/ })
/******/ ]);