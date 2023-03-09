const axios = require('axios');

import qs from 'qs';
const data = { 'bar': 123 };
axios({
  method: 'GET',
  headers: { 'content-type': 'application/x-www-form-urlencoded' },
  data: qs.stringify(data),
  url: "http://google.com"
});