import axios from 'axios';

async function doGetRequest() {

  let res = await axios.get('http://google.com');

  let data = res.data;
  console.log(data);
}

doGetRequest();