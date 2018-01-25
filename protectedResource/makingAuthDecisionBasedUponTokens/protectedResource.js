var express = require("express");
var bodyParser = require('body-parser');
var cons = require('consolidate');
var nosql = require('nosql').load('database.nosql');
var _ = require('underscore');
var cors = require('cors');

var app = express();

app.use(bodyParser.urlencoded({ extended: true })); // support form-encoded bodies (for bearer tokens)

app.engine('html', cons.underscore);
app.set('view engine', 'html');
app.set('views', 'files/protectedResource');
app.set('json spaces', 4);

app.use('/', express.static('files/protectedResource'));
app.use(cors());

var resource = {
	"name": "Protected Resource",
	"description": "This data has been protected by OAuth 2.0"
};

/** ch-4-ex-2 */
// The third parameter, next, is a function that lets us chain together multiple
// functions to serve a single request, allowing us to add this token scanning
// functionality into other handlers throughout our application.
var getAccessToken = function(req, res, next) {
    var inToken = null;
    var auth = req.header('authorization');

    // The OAuth Bearer Token Usage specification1 defines three different methods
    // for passing bearer tokens to the protected resource: the HTTP Authorization
    // header, inside a form-encoded POST body, and as a query parameter.

    // Checking the Authorization header
    if(auth && (auth.toLowerCase().indexOf('bearer') == 0)) {
        inToken = auth.slice('bearer '.length);
    }
    // Handle tokens passed as form-encoded parameters in the body. This method
    // isn't ecommended by the OAuth specification because it artificially limits
    // the input of the API to a form-encoded set of values. This could prevent
    // a client application from being able to send the token along with the
    // input.
    //
    // The Authorization header is preferred.
    else if(req.body && req.body.access_token) {
        inToken = req.body.access_token;
    }

    // Finally, we’ll handle the token being passed as a query parameter. This
    // method is recommended by OAuth only as a last resort. With this method
    // the access token has a higher probability of being inadvertently logged
    // in server access logs or accidentally leaked through referrer headers,
    // both of which replicate the URL in full.
    //
    // However, there are situations where a client can’t access the Authorization
    // headers directly (due to platform or library access restrictions) and can’t
    // use a form-encoded body parameter (such as with HTTP GET).
    else if (req.query && req.query.access_token) {
        inToken = req.query.access_token;
    }

    // The first function passed in checks the value of the stored access tokens
    // against the input token that we pulled off the wire.
    nosql.one(function(token) {
        // If it finds a match, it returns the token and the searching algorithm
        // stops.
        if (token.access_token == inToken) {
            return token;
        }
        // The second function is called when either a match is found or the database
        // is exhausted, whichever comes first. If we do find a token in the store, it
        // will be passed in the 'token' argument.
    }, function(err, token) {
        // If we are unable to find a token with the input value, this argument will
        // be null.
        if (token) {
            console.log("We found a matching token: %s", inToken);
        } else {
            console.log('No matching token was found.');
        }
        // Whatever we find, we attach it to the access_token member of the req
        // object and call the next function.
        req.access_token = token;
        // The 'req' object is automatically passed to the next part of the process
        // handler.
        next();
        return;
    });
};

var requireAccessToken = function(req, res, next) {

    // If the token was found, this will contain the token object from the database.
    // If the token was not found, this will contain null. We can branch our code
    // accordingly.
    if(req.access_token) {
        console.log('Finished checking parsing tokens, and ' +
            'checking their existence. Now calling this ' +
            'function: $s', next);
        next();
    } else {
        res.status(401).end();
    }
};


app.options('/resource', cors(), getAccessToken, requireAccessToken);


app.get("/resource", cors(), getAccessToken, requireAccessToken);

/*
 * Add the getAccessToken function to this handler
 */
app.post("/resource", cors(), getAccessToken, requireAccessToken);

var savedWords = [];

app.get('/words', getAccessToken, requireAccessToken, function(req, res) {
    console.log("Entering /words GET api called from client. " +
        "Got a scope of: [%s]", req.access_token.scope);
    if(_.contains(req.access_token.scope, 'read')) {
        console.log("Scope contained READ value");
        console.log("Now sending savedWords back to client " +
            "with: %s", savedWords.join(' '));
        res.json({words: savedWords.join(' '), timeStamp: Date.now()});
    } else {
        console.log("Now sending 403 forbidden back to client " +
            "no read scope");
        res.set('WWW-Authenticate'
            , 'Bearer realm=localost:9002, error="inssufficent_scope", scope="read"');
        res.status(403);
    }
});

app.post("/words", getAccessToken, requireAccessToken, function (req, res) {
    console.log("Entering /words POST api called from client's /add_word GET api. Got a scope " +
        "of %s", req.access_token.scope);
    if(_.contains(req.access_token.scope, 'write')) {
        console.log("Scope contained WRITE value");
        console.log("Checking for the presence of: %s, to " +
            "store in saveWords array"
            , "req.body.word");
        if(req.body.word) {
            savedWords.push(req.body.word);
            console.log("Saving word: %s to savedWords: %s"
                , req.body.word
                , savedWords.join(' '));
        }
        res.status(201).end();
    } else {
        res.set(('WWW-Authenticate'
            , 'Bearer realm=localost:9002, error="inssufficent_scope", scope="write"'));
        res.status(403);
    }
});

app.delete('/words', getAccessToken, requireAccessToken, function(req, res) {
    console.log("Entering /words DELETE api called from " +
        "client's /delete_word GET api route as a request. " +
        "Got a scope of: [%s]", req.access_token.scope);
    if(_.contains(req.access_token.scope, 'delete')) {
        console.log("Trying to remove the last item in this " +
            "list: [%s]", savedWords.join(', '));
        savedWords.pop();
        console.log("Now our current list is: [%s]"
            , savedWords.join(', '));
        res.status(204).end();
    } else {
        res.set(('WWW-Authenticate'
            , 'Bearer realm=localost:9002, error="inssufficent_scope", scope="delete"'));
        res.status(403);
    }
});

var server = app.listen(9002, 'localhost', function () {
  var host = server.address().address;
  var port = server.address().port;

  console.log('OAuth Resource Server is listening at http://%s:%s', host, port);
});
 
