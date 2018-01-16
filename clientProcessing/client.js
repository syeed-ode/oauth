var express = require("express");
var request = require("sync-request");
var url = require("url");
var qs = require("qs");
var querystring = require('querystring');
var cons = require('consolidate');
var randomstring = require("randomstring");
var __ = require('underscore');
__.string = require('underscore.string');

var app = express();

app.engine('html', cons.underscore);
app.set('view engine', 'html');
app.set('views', 'files/client');

// authorization server information
var authServer = {
	authorizationEndpoint: 'http://localhost:9001/authorize',
	tokenEndpoint: 'http://localhost:9001/token'
};

// client information


/*
 * Add the client information in here
 */
var client = {
	"client_id": "af7d2b88-ae7f-496b-9b27-334160bd3e7c",
	"client_secret": "oauth-client-secret-1",
	"redirect_uris": ["http://localhost:9000/callback"]
};

var protectedResource = 'http://localhost:9002/resource';

var state = null;

var access_token = null;
var scope = null;

app.get('/', function (req, res) {
	res.render('index', {access_token: access_token, scope: scope});
});

app.get('/authorize', processAuthGrantCodeRequest);

app.get('/callback', utilizeAuthCodeToRequestToken);

app.get('/fetch_resource', requestResourceWithToken);

function processAuthGrantCodeRequest(req, res){

	state = randomstring.generate();

    var authGrantCodeUrl = buildUrl(authServer.authorizationEndpoint, {
    	  response_type: 'code'
		, client_id: client.client_id
		, redirect_uri: client.redirect_uris[0]
        , state: state
	});

    res.redirect(authGrantCodeUrl);
}

var buildUrl = function(base, options, hash) {
	var newUrl = url.parse(base, true);
	delete newUrl.search;
	if (!newUrl.query) {
		newUrl.query = {};
	}
	__.each(options, function(value, key, list) {
		newUrl.query[key] = value;
	});
	if (hash) {
		newUrl.hash = hash;
	}
	
	return url.format(newUrl);
};

function utilizeAuthCodeToRequestToken(req, res){

    // Authorization Grant Code from
	// Authorization Server
	var code = req.query.code;

	if(req.query.state != state) {
		res.render('error', {error: "State value didn't match"});
		return;
	}

    var tokenRequestHeaders = {
    	  'Content-Type' : 'application/x-www-form-urlencoded'
		, 'Authorization': 'Basic ' + encodeClientCredentials(
			client.client_id, client.client_secret)
	};

    var tokenRequestForm = qs.stringify({
		  grant_type: 'authorization_code'
		, code: code // Authorization Grant Code
		, redirect_uri: client.redirect_uris[0]
	});

    var getTokenResponse = request('POST', authServer.tokenEndpoint, {
     	  headers: tokenRequestHeaders
		, body: tokenRequestForm
	});

    var tokenReaponseBody = JSON.parse(getTokenResponse.getBody());
    access_token = tokenReaponseBody.access_token;

    res.render('index', {access_token: access_token, scope: scope});
}

var encodeClientCredentials = function(clientId, clientSecret) {
	return new Buffer(querystring.escape(clientId) + ':' + querystring.escape(clientSecret)).toString('base64');
};


function requestResourceWithToken(req, res) {

    if(!access_token) {
    	res.render('error', {error: 'Missing access token.'});
    	return;
	}

	var headers = {
    	'Authorization': 'Bearer ' + access_token
	};

    var resource = request('POST', protectedResource, {
    	headers: headers
	});

    if(resource.statusCode >=200 && resource.statusCode < 300) {
    	var resourceBody = JSON.parse(resource.getBody());

    	res.render('data', {resource: resourceBody});
    	return;
	} else {
    	res.render('error', {error: 'Server returned response code: ' + resource.statusCode});
        return;
    }
}

app.use('/', express.static('files/client'));

var server = app.listen(9000, 'localhost', function () {
  var host = server.address().address;
  var port = server.address().port;
  console.log('OAuth Client is listening at http://%s:%s', host, port);
});
 
