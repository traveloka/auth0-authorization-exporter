const async = require('async');
const express = require('express');
const Webtask = require('webtask-tools');
const app = express();
const Request = require('request');
const memoizer = require('lru-memoizer');
const AWS = require('aws-sdk');
const metadata = require('./webtask.json');

function s3Exporter(req, res) {
    "use strict";
    let ctx = req.webtaskContext;

    let required_settings = ['AUTH0_DOMAIN', 'AUTH0_CLIENT_ID', 'AUTH0_CLIENT_SECRET','AWS_REGION','AWS_ACCESS_KEY','AWS_SECRET_KEY','S3_BUCKET','S3_FILE_NAME'];
    let missing_settings = required_settings.filter((setting) => !ctx.data[setting]);
    if (missing_settings.length) {
        return res.status(400).send({ message: 'Missing settings: ' + missing_settings.join(', ') });
    }

    let excludedClients = [];
    if (ctx.data.EXCLUDED_CLIENTS) {
        excludedClients = ctx.data.EXCLUDED_CLIENTS.split(",");
    }


    async.waterfall([   
        // get all users 
        (callback) => {
            const allUser = (context) => {  
                getAllUsers(req.webtaskContext.data.AUTH0_DOMAIN, req.access_token, 0, 100, [], (err, users) => {
                    if (err) {
                        console.log('Error ' + err);
                        res.sendStatus(500);
                    }

                    console.log('No of user ' + users.length);
                    let clientUserPermissionMapper = {};
                    users.forEach(user => {
                        if (user.app_metadata && user.app_metadata.authorization) {
                            //console.log('App metadata authorisation is ' + JSON.stringify(user.app_metadata.authorization));
                            user.app_metadata.authorization.forEach(userPermission => {
                                if (userPermission.permissions && userPermission.permissions.length > 0) {
                                    let clientUserPermissionContent = clientUserPermissionMapper[userPermission.clientID] || {};
                                    clientUserPermissionContent.client_id = userPermission.clientID;
                                    let userPermissionList = clientUserPermissionContent.user_permissions || []; 
                                    userPermissionList.push({username: user.email, permissions: userPermission.permissions});
                                    clientUserPermissionContent.user_permissions = userPermissionList;
                                    clientUserPermissionMapper[userPermission.clientID] = clientUserPermissionContent;
                                }
                            });
                        }
                    });

                    let result = [];
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
        (context, callback) => {
            console.log('User permissions is ' + JSON.stringify(context.user_permissions));
            if (context.user_permissions && context.user_permissions.length > 0) {
                const s3 = new AWS.S3({
                region: req.webtaskContext.data.AWS_REGION,
                accessKeyId: req.webtaskContext.data.AWS_ACCESS_KEY,
                secretAccessKey: req.webtaskContext.data.AWS_SECRET_KEY
                });
                const maxAge = 60 * 60 * 24 * 365;
                const cacheControl = `public, max-age=${maxAge}`;
                const awsConfig = {
                Bucket: req.webtaskContext.data.S3_BUCKET,
                ACL: 'private',
                CacheControl: cacheControl,
                Key: req.webtaskContext.data.S3_FILE_NAME,
                Body: JSON.stringify(context.user_permissions)
                };
                
                s3.putObject(awsConfig, (err, data) => {
                if (err) throw err;
                callback(null, context);
                });
            } else {
                callback(null, context);  
            } 
        }
    ],  function (err, context) {
          if (err) {
              console.log('Job failed.');
              res.status(500).send({
                  error: err
              });
          }

          console.log('Job complete.');
          res.sendStatus(200);
        }
    );
}

function getAllUsers(domain, token, page,  pageSize, users, callback) {
    getUsers(domain, token, page, pageSize)
        .then(result => {
            if (result.length === pageSize) {
                getAllUsers(domain, token, page + 1, pageSize, users.concat(result), callback);
            } else {
                callback(null, users);
            } 
        })
        .catch(error => {
            console.log('Error ' + error);
            callback(null);
        });
}

function getUsers(domain, token, page, pageSize) {
    return new Promise((resolve, reject) => {
        var url = `https://${domain}/api/v2/users`;
        Request({
            method: 'GET',
            url: url,
            json: true,
            qs: {
                fields: 'name,email,user_id,app_metadata',
                page: page,
                per_page: pageSize,
                q: 'email:@traveloka.com',
                search_engine: 'v2',
            },
            headers: {
                Authorization: `Bearer ${token}`,
                Accept: 'application/json'
            }
        }, (err, res, body) => {
            if (err) {
                reject(Error(err));
            } else {
                resolve(body);
            }
        });
    });
}

const getTokenCached = memoizer({
    load: (apiUrl, audience, clientId, clientSecret, cb) => {
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
        }, (err, res, body) => {
        if (err) {
            cb(null, err);
        } else {
            cb(body.access_token);
        }
        });
    },
    hash: (apiUrl) => apiUrl,
    max: 100,
    maxAge: 1000 * 60 * 60
});

app.use(function (req, res, next) {
    var apiUrl            = `https://${req.webtaskContext.data.AUTH0_DOMAIN}/oauth/token`;
    var audience          = `https://${req.webtaskContext.data.AUTH0_DOMAIN}/api/v2/`;
    var clientId          = req.webtaskContext.data.AUTH0_CLIENT_ID;
    var clientSecret      = req.webtaskContext.data.AUTH0_CLIENT_SECRET;
    
    getTokenCached(apiUrl, audience, clientId, clientSecret, function (access_token, err) {
        if (err) {
            console.log(`Error getting access_token with url ${apiUrl}  and domain ${req.webtaskContext.data.AUTH0_DOMAIN}` , err);
            return next(err);
        }

        req.access_token = access_token;
        next();
    });
});

app.get('/', s3Exporter);

app.get('/meta', function(req, res) {
  res.status(200).send(metadata);
});

module.exports = Webtask.fromExpress(app);