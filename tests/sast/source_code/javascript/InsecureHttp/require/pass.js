const axios = require('axios');

import qs from 'qs';
const data = { 'bar': 123 };
const options = {
  method: 'GET',
  headers: { 'content-type': 'application/x-www-form-urlencoded' },
  data: qs.stringify(data),
  url: "https://google.com"
};
axios(options);