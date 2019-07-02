const bodyParser = require('body-parser');
const cookieParser = require('cookie-parser');
const crypto = require('crypto');
const express = require('express');
const handlebars = require('express-handlebars');
const path = require('path');
const request = require('request-promise');

// loading env vars from .env file
require('dotenv').config();

const nonceCookieName = 'auth0rization-nonce';

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
  const authorizationEndpoint = `${process.env.OIDC_PROVIDER}/authorize`;
  const responseType = 'id_token';
  const scope = 'openid';
  const clientID = 'cSZ566Xw5yOZYs0bcebqKnXwKnfFHtVS';
  const redirectUri = 'http://localhost:3000/callback';
  const responseMode = 'form_post';
  const nonce = crypto.randomBytes(16).toString('hex');

  let options = {
    maxAge: 1000 * 60 * 15,
    httpOnly: true, // The cookie only accessible by the web server
    signed: true // Indicates if the cookie should be signed
  };

  // Set cookie
  res
    .cookie(nonceCookieName, nonce, options)
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
  const nonceCookie = req.signedCookies[nonceCookieName];
  const {id_token} = req.body;
  res.send({
    nonceCookie,
    id_token
  });
});

app.listen(3000, () => {
  console.log(`Server running on http://localhost:3000`);
});
