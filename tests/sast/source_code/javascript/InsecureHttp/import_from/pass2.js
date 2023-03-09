import axios from 'axios';

import qs from 'qs';
const data = { 'bar': 123 };

axios({
  method: 'POST',
  headers: { 'content-type': 'application/x-www-form-urlencoded' },
  data: qs.stringify(data),
  url: "https://google.com"
});