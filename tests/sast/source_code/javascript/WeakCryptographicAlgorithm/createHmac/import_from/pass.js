import crypto from 'node:crypto';

import {
  createReadStream,
} from 'node:fs';
import { argv } from 'node:process';
const filename = argv[2];

const hmac = crypto.createHmac('sha256', 'a secret');

const input = createReadStream(filename);
input.on('readable', () => {
  // Only one element is going to be produced by the
  // hash stream.
  const data = input.read();
  if (data)
    hmac.update(data);
  else {
    console.log(`${hmac.digest('hex')} ${filename}`);
  }
});