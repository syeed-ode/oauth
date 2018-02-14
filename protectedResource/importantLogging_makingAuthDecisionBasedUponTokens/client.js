var express = require("express");
var bodyParser = require('body-parser');
var request = require("sync-request");
var url = require("url");
var qs = require("qs");
var querystring = require('querystring');
var cons = require('consolidate');
var randomstring = require("randomstring");

var app = express();

app.use(bodyParser.json());
app.use(bodyParser.urlencoded({ extended: true }));

app.engine('html', cons.underscore);
app.set('view engine', 'html');
app.set('views', 'files/client');

// authorization server information
var authServer = {
	authorizationEndpoint: 'http://localhost:9001/authorize',
	tokenEndpoint: 'http://localhost:9001/token',
	revocationEndpoint: 'http://localhost:9001/revoke',
	registrationEndpoint: 'http://localhost:9001/register',
	userInfoEndpoint: 'http://localhost:9001/userinfo'
};

// client information

var client = {
	"client_id": "oauth-client-1",
	"client_secret": "oauth-client-secret-1",
	"redirect_uris": ["http://localhost:9000/callback"],
	"scope": "read write delete"
};

var wordApi = 'http://localhost:9002/words';

var state = null;

var access_token = null;
var refresh_token = null;
var scope = null;

app.get('/', function (req, res) {
	res.render('index', {access_token: access_token, refresh_token: refresh_token, scope: scope});
});

app.get('/authorize', function(req, res){

	console.log("Entering /authorize endpoint from client's " +
		"index.html anchor href=/authorize.")
	access_token = null;
	refresh_token = null;
	scope = null;
	state = randomstring.generate();
	
	var authorizeUrl = url.parse(authServer.authorizationEndpoint, true);
	delete authorizeUrl.search; // this is to get around odd behavior in the node URL library
	authorizeUrl.query.response_type = 'code';
	console.log("Now setting the response_type to code " +
		"[authorizeUrl.query.response_type = 'code';]. " +
		"This is the equivalent of springs constructor " +
		"'public AuthorizationCodeResourceDetails() {this.setGrantType(\"authorization_code\");}'. " +
		"It informs the authorizationServer that this response " +
		"requires an authorization_code that the client may " +
		"user to once again call the authorizationServer to " +
		"receive a token for it.\nAlso sending authorization " +
		"server a list of scopes the client want to have " +
		"access to.");
	authorizeUrl.query.scope = client.scope;
	authorizeUrl.query.client_id = client.client_id;
	authorizeUrl.query.redirect_uri = client.redirect_uris[0];
	authorizeUrl.query.state = state;
	
	console.log("redirect", url.format(authorizeUrl));
    console.log("Using client's front channel communication to redirect to the " +
		"authorizationServers redirect url %s. Front channel " +
		"comms means that browser is not involved in the " +
		"conversation at all. Just redirect the URI\n\n"
		, url.format(authorizeUrl));
	res.redirect(url.format(authorizeUrl));
});

app.get("/callback", function(req, res){

    console.log('Entered in client with /callback endpoint just called.');

	if (req.query.error) {
		// it's an error response, act accordingly
		res.render('error', {error: req.query.error});
		return;
	}
	
	var resState = req.query.state;
	if (resState == state) {
		console.log('State value matches: expected %s got %s', state, resState);
	} else {
		console.log('State DOES NOT MATCH: expected %s got %s', state, resState);
		res.render('error', {error: 'State value did not match'});
		return;
	}

	var code = req.query.code;

	var form_data = qs.stringify({
				grant_type: 'authorization_code',
				code: code,
				redirect_uri: client.redirect_uri
			});
	var headers = {
		'Content-Type': 'application/x-www-form-urlencoded',
		'Authorization': 'Basic ' + new Buffer(querystring.escape(client.client_id) + ':' + querystring.escape(client.client_secret)).toString('base64')
	};

	var tokRes = request('POST', authServer.tokenEndpoint, 
		{	
			body: form_data,
			headers: headers
		}
	);

	console.log('Requesting access token for code %s',code);
	
	if (tokRes.statusCode >= 200 && tokRes.statusCode < 300) {
		var body = JSON.parse(tokRes.getBody());
	
		access_token = body.access_token;
		console.log('Got access token: %s', access_token);
		if (body.refresh_token) {
			refresh_token = body.refresh_token;
			console.log('Got refresh token: %s', refresh_token);
		}
		
		scope = body.scope;
		console.log('Got scope: %s', scope);

        console.log('Now calling client\'s index.html with token: %s, ' +
			'and scope: [%s]\n\n', access_token, scope);
		res.render('index', {access_token: access_token, refresh_token: refresh_token, scope: scope});
	} else {
		res.render('error', {error: 'Unable to fetch access token, server ' +
		'response: ' + tokRes.statusCode})
	}
});

app.get('/words', function (req, res) {
	console.log("Entered in /words endpoint called by client's index.html.");
    console.log("Now rending clients words.html.");
	res.render('words', {words: '', timestamp: 0, result: 'noget'});
	return;
});

app.get('/get_words', function (req, res) {

    console.log("Entered in /get_words endpoint called by client's words.html. It was an anchor with 'href=\"/get_words\"");
	var headers = {
		'Authorization': 'Bearer ' + access_token,
		'Content-Type': 'application/x-www-form-urlencoded'
	};

    console.log("Calling %s GET api in the protectedResource...", wordApi);
	var resource = request('GET', wordApi,
		{headers: headers}
	);
    console.log("Got back: \n%s\n, as a JSON body from protectedResource for " +
		"calling %s GET api.", resource.getBody()
		, wordApi);

	if (resource.statusCode >= 200 && resource.statusCode < 300) {
		var body = JSON.parse(resource.getBody());
        console.log("Rending words.html within client passing " +
			"words: %s, and timestamp: %s, and get: %s"
			, body.words, body.timestamp, 'get');
		res.render('words', {words: body.words, timestamp: body.timestamp, result: 'get'});
		return;
	} else {
        console.log("Rending  words.html within client passing words " +
            "%s, and timestamp: %s, and get: %s"
            , '', 0, 'noget');
		res.render('words', {words: '', timestamp: 0, result: 'noget'});
		return;
	}
	
	
	
});

app.get('/add_word', function (req, res) {
	console.log("Entering /add_word GET on client called from " +
		"client's word.html " +
		"form,action=/add_word,method=GET form. Received a " +
		"form body query string of 'word' with a value of: %s. " +
		"This was populated as: %s. It was assigned as: %s. And " +
		"it was utilized as: %s."
		, qs.stringify({word: req.query.word})
		, "qs.stringify({word: req.query.word})"
		, "form_body = qs.stringify({word: req.query.word})"
		, "{headers: headers, body: form_body}");
	var headers = {
		'Authorization': 'Bearer ' + access_token,
		'Content-Type': 'application/x-www-form-urlencoded'
	};
	
	var form_body = qs.stringify({word: req.query.word});

    console.log("Calling %s POST api with a form_body: %s, and " +
		"headers: \n%s\n, in the protectedResource..."
		, wordApi, form_body, JSON.stringify(headers));
    var resource = request('POST', wordApi,
		{headers: headers, body: form_body}
	);
	
	if (resource.statusCode >= 200 && resource.statusCode < 300) {
		res.render('words', {words: '', timestamp: 0, result: 'add'});
		return;
	} else {
		res.render('words', {words: '', timestamp: 0, result: 'noadd'});
		return;
	}
	

});

app.get('/delete_word', function (req, res) {

    console.log("Entering /delete_word GET on client called from " +
        "client's word.html " +
        "anchor href=/delete_word<>DELETE the last word</>. " +
		"Received a form body query string of 'word' with a " +
		"value of: %s. This was populated as: %s"
        , qs.stringify({word: req.query.word})
        , "qs.stringify({word: req.query.word})");
	var headers = {
		'Authorization': 'Bearer ' + access_token,
		'Content-Type': 'application/x-www-form-urlencoded'
	};

    console.log("Calling %s DELETE api with headers: %s, in the " +
		"protectedResource..."
        , wordApi, headers);
	var resource = request('DELETE', wordApi,
		{headers: headers}
	);
	
	if (resource.statusCode >= 200 && resource.statusCode < 300) {
		res.render('words', {words: '', timestamp: 0, result: 'rm'});
		return;
	} else {
		res.render('words', {words: '', timestamp: 0, result: 'norm'});
		return;
	}
	
	
});


app.use('/', express.static('files/client'));

var server = app.listen(9000, 'localhost', function () {
  var host = server.address().address;
  var port = server.address().port;
  console.log('OAuth Client is listening at http://%s:%s', host, port);
});
 
