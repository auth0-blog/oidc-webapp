const express = require('express');
const handlebars = require('express-handlebars');
const path = require('path');
const request = require('request-promise');

// loading env vars from .env file
require('dotenv').config();

const app = express();

app.engine('handlebars', handlebars());
app.set('view engine', 'handlebars');
app.set('views', path.join(__dirname, 'views'));

app.get('/', (req, res) => {
  res.render('index');
});

app.get('/login', (req, res) => {
  const authorizationEndpoint = `${process.env.OIDC_PROVIDER}/authorize`;
  const responseType = 'code';
  const scope = 'openid';
  const clientID = 'cSZ566Xw5yOZYs0bcebqKnXwKnfFHtVS';
  const redirectUri = 'http://localhost:3000/callback';
  res.redirect(
    `${authorizationEndpoint}?response_type=${responseType}&scope=${scope}&client_id=${clientID}&redirect_uri=${redirectUri}`
  );
});

app.get('/callback', async (req, res) => {
  const {code} = req.query;
  const tokenEndpoint = 'https://oidc-handbook.auth0.com/oauth/token';

  const tokenExchangeOptions = {
    method: 'POST',
    uri: tokenEndpoint,
    form: {
      grant_type: 'authorization_code',
      code: code,
      client_id: 'cSZ566Xw5yOZYs0bcebqKnXwKnfFHtVS',
      client_secret: 'XkJuIyK8GYZT9NTy5nOEPsEsaA-Xxs3V2C8TM4rJFc72haPmq_cwDDZXe5brmlKS',
      redirect_uri: 'http://localhost:3000'
    },
  };

  try {
    const response = await request(tokenExchangeOptions);
    const responseObject = JSON.parse(response);
    res.send(responseObject);
  } catch (error) {
    console.log(error);
    res.status(500).send(error);
  }
});

app.listen(3000, () => {
  console.log(`Server running on http://localhost:3000`);
});
