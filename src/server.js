const bodyParser = require('body-parser');
const cookieParser = require('cookie-parser');
const crypto = require('crypto');
const express = require('express');
const handlebars = require('express-handlebars');
const path = require('path');
const jwt = require('jsonwebtoken');
const request = require('request-promise');

// loading env vars from .env file
require('dotenv').config();

const nonceCookie = 'auth0rization-nonce';
let oidcProviderInfo;

const app = express();

app.use(bodyParser.urlencoded());
app.use(cookieParser(crypto.randomBytes(16).toString('hex')));
app.engine('handlebars', handlebars());
app.set('view engine', 'handlebars');
app.set('views', path.join(__dirname, 'views'));

app.get('/', (req, res) => {
  res.render('index');
});

app.get('/login', (req, res) => {
  // create the authorization request
  const authorizationEndpoint = oidcProviderInfo['authorization_endpoint'];
  const responseType = 'id_token';
  const scope = 'openid';
  const clientID = process.env.CLIENT_ID;
  const redirectUri = 'http://localhost:3000/callback';
  const responseMode = 'form_post';
  const nonce = crypto.randomBytes(16).toString('hex');

  // define a signed cookie containing the nonce value
  let options = {
    maxAge: 1000 * 60 * 15,
    httpOnly: true, // The cookie only accessible by the web server
    signed: true // Indicates if the cookie should be signed
  };

  // add cookie to the response and issue a 302 redirecting user
  res
    .cookie(nonceCookie, nonce, options)
    .redirect(
      authorizationEndpoint +
      '?response_mode=' + responseMode +
      '&response_type=' + responseType +
      '&scope=' + scope +
      '&client_id=' + clientID +
      '&redirect_uri='+ redirectUri +
      '&nonce='+ nonce
  );
});

app.post('/callback', async (req, res) => {
  // take nonce from cookie
  const nonce = req.signedCookies[nonceCookie];

  // take id token posted by the user
  const {id_token} = req.body;

  // decode the id token
  const decodedToken = jwt.decode(id_token);

  // check audience, nonce, and expiration time
  const {nonce: decodedNonce, aud: audience, exp: expirationDate, iss: issuer} = decodedToken;
  const currentTime = Math.floor(Date.now() / 1000);
  const expectedAudience = process.env.CLIENT_ID;
  if (audience !== expectedAudience || decodedNonce !== nonce || expirationDate < currentTime || issuer !== oidcProviderInfo['issuer']) {
    // send an unauthorized http status
    return res.status(401).send();
  }

  // send the decoded version of the id token
  res.redirect(`https://jwt.io/#debugger-io?token=${id_token}`);
});

request(`${process.env.OIDC_PROVIDER}/.well-known/openid-configuration`).then((res) => {
  oidcProviderInfo = JSON.parse(res);
  app.listen(3000, () => {
    console.log(`Server running on http://localhost:3000`);
  });
}).catch((error) => {
  console.error(error);
  console.error(`Unable to read discover OpenID Connect endpoints for ${process.env.OIDC_PROVIDER}`);
  process.exit(1);
});
