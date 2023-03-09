import axios from 'axios';

import qs from 'qs';
const data = { 'bar': 123 };
const options = {
  method: 'GET',
  headers: { 'content-type': 'application/x-www-form-urlencoded' },
  data: qs.stringify(data),
  url: "http://google.com"
};
axios(options);