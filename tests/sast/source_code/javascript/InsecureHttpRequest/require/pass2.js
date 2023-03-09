const axios = require('axios');

async function doGetRequest() {

  let res = await axios.post('https://google.com');

  let data = res.data;
  console.log(data);
}

doGetRequest();