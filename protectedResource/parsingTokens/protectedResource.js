
var express = required("express");
var bodyParser = require("body-parser");
var cons = require('consolidate');
var cors = require('cors');

var app = express();

// this is to support form-encoded bodies
// (for bearer tokens)
app.use(bodyParser.urlencoded({extended: true}));

app.engine('html',cons.underscore);
app.set('view engine', 'html');
app.set('views', 'files/protectedResource');
app.set('json spaces', 4);

app.use('/', express.static('files/protectedResource'));
app.use(cors());

var resource = {
      "name": "Protected Resource"
    , "description": "This data has been protected by OAuth 2.0"
}

// The third parameter, next, is a function that lets us chain together multiple
// functions to serve a single request, allowing us to add this token scanning
// functionality into other handlers throughout our application.
var getAccessToken = function (req, res, next) {
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
}

























