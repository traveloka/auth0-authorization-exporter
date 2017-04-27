const async = require('async');
const express = require('express');
const Webtask = require('webtask-tools');
const app = express();
const Request = require('request');
const memoizer = require('lru-memoizer');
const AWS = require('aws-sdk');     

function s3Exporter(req, res) {
  "use strict";
  let ctx = req.webtaskContext;

  let required_settings = ['AUTH0_DOMAIN', 'AUTH0_CLIENT_ID', 'AUTH0_CLIENT_SECRET','AUTHORISATION_EXTENSION_API_URL','AWS_REGION','AWS_ACCESS_KEY','AWS_SECRET_KEY','S3_BUCKET','S3_FILE_NAME'];
  let missing_settings = required_settings.filter((setting) => !ctx.data[setting]);
  if (missing_settings.length) {
    return res.status(400).send({ message: 'Missing settings: ' + missing_settings.join(', ') });
  }

  let excludedClients = [];
  if (ctx.data.EXCLUDED_CLIENTS) {
    excludedClients = ctx.data.EXCLUDED_CLIENTS.split(",");
  }
  
  async.waterfall([
    // get all available clients      
    (callback) => {
      const getClients = (context) => {
          context.clients = [];
          getClientsFromAuth0(req.webtaskContext.data.AUTH0_DOMAIN, req.access_token, (clients, err) => {
              if (err) {
                console.log('Error getting clients from Auth0', err);
                return callback(err);
              }
              if (clients && clients.length) {
                  clients
                    .filter(client => excludedClients.indexOf(client.client_id) < 0)
                    .forEach((client) => context.clients.push(client));
              }

              console.log(`Total clients: ${context.clients.length}.`);
              return callback(null, context);
          });
      };

      getClients({});
    },
    // get all users
    (context, callback) => {
        const getUsers = (context) => {
            context.users = [];
            getUsersFromAuth0(req.webtaskContext.data.AUTH0_DOMAIN, req.access_token, (users, err) => {
                if (err) {
                    console.log('Error getting users from auth0', err);
                    return callback(err);
                }

                if (users && users.length) {
                    users.forEach((user) => context.users.push(user));
                }

                console.log(`Total user is ${context.users.length}`);
                return callback(null, context);
            });    
        }
        
        if (context.clients.length > 0) {        
          getUsers(context);
        } else {
          callback(null, context);
        }
    },
    // get user permission for every client
    (context, callback) => {
        var userPermissions = [];
        var allPromises = [];
        if (context.clients && context.users) {
          for (let i = 0; i < context.clients.length; i++) {
            for (let j = 0; j < context.users.length; j++) {
                allPromises.push(getUserPolicy(
                  req.webtaskContext.data.AUTHORISATION_EXTENSION_API_URL, 
                  context.users[j].user_id, 
                  context.users[j].email, 
                  context.clients[i].client_id, 
                  req.extension_access_token));
            }
          }
        }

        if (allPromises.length > 0) {
          Promise.all(allPromises)
            .then(values => { 
              let mapper  = {};
              values
                .filter(element => element.permissions.length > 0)
                .forEach(function(element) {
                  let content = mapper[element.client_id];
                  if (content) {
                    content.user_permissions.push({username: element.email, permissions: element.permissions});
                    mapper[element.client_id] = content;
                  } else {
                    content = {};
                    content.client_id = element.client_id;
                    content.user_permissions = [];
                    content.user_permissions.push({username: element.email, permissions: element.permissions});
                    mapper[element.client_id] = content;
                  }
              });
              
              let result = [];
              for (var key in mapper) {
                if (mapper.hasOwnProperty(key)) {
                  result.push(mapper[key]);
                }
              }

              context.user_permissions = result;
              callback(null, context);
            }).catch(reason => { 
              console.log(reason)
              callback(reason, context);
            });       
        }  else {
          callback(null, context);
        }       
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
          ACL: 'public-read',
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
  ], function (err, context) {
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

function getClientsFromAuth0(domain, token, cb) {
  var url = `${domain}/api/v2/clients`;

  Request({
    method: 'GET',
    url: url,
    json: true,
    headers: {
      Authorization: `Bearer ${token}`,
      Accept: 'application/json'
    },
    qs: {
      fields: 'client_id'
    }
  }, (err, res, body) => {
    if (err) {
      console.log('Error getting clients', err);
      cb(null, err);
    } else {
      cb(body);
    }
  });
}

function getUsersFromAuth0(domain, token, cb) {
  var url = `${domain}/api/v2/users`;

  Request({
    method: 'GET',
    url: url,
    json: true,
    qs: {
        fields: 'name,email,user_id',
        q: 'email:@traveloka.com',
        search_engine: 'v2'
    },
    headers: {
      Authorization: `Bearer ${token}`,
      Accept: 'application/json'
    }
  }, (err, res, body) => {
    if (err) {
      console.log('Error getting users', err);
      cb(null, err);
    } else {
      cb(body);
    }
  });
}

function getUserPolicy(domain, user_id, email, client_id, token) {
    return new Promise(function(resolve, reject) {
      var url = `${domain}/users/${user_id}/policy/${client_id}`;
      Request({
          method: 'POST',
          url: url,
          json: true,
          headers: {
              Authorization: `Bearer ${token}`,
              Accept: 'application/json'    
          },
          body: {
              connectionName: "Y"
          }
      }, (err, res, body) => {
          if (err) {
              console.log('Error getting user policy', err);
              reject(Error(err));
          } else {
              var userPermission = {};
              userPermission.client_id = client_id;
              userPermission.email = email;
              userPermission.permissions = body.permissions;
              resolve(userPermission);
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

const getExtensionTokenCached = memoizer({
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
    var apiUrl            = `${req.webtaskContext.data.AUTH0_DOMAIN}/oauth/token`;
    var audience          = `${req.webtaskContext.data.AUTH0_DOMAIN}/api/v2/`;
    var extensionAudience = 'urn:auth0-authz-api'
    var clientId          = req.webtaskContext.data.AUTH0_CLIENT_ID;
    var clientSecret      = req.webtaskContext.data.AUTH0_CLIENT_SECRET;

    getTokenCached(apiUrl, audience, clientId, clientSecret, function (access_token, err) {
        if (err) {
            console.log('Error getting access_token', err);
            return next(err);
        }

        req.access_token = access_token;
        next();
    });

    getExtensionTokenCached(apiUrl, extensionAudience, clientId, clientSecret, function (access_token, err) {
        if (err) {
            console.log('Error getting extension access_token', err);
            return next(err);
        }

        req.extension_access_token = access_token;
        // not sure this has to be remarked
        //next();
    });
});

app.post('/', s3Exporter);

module.exports = Webtask.fromExpress(app);