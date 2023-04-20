import Client from './client.js'
import * as crypto from './crypto/index.js'
import axios from './axios.js'
import { setLogger } from './logger.js'

/** Directory URLs */
const directory = {
  buypass: {
    staging: 'https://api.test4.buypass.no/acme/directory',
    production: 'https://api.buypass.com/acme/directory'
  },
  letsencrypt: {
    staging: 'https://acme-staging-v02.api.letsencrypt.org/directory',
    production: 'https://acme-v02.api.letsencrypt.org/directory'
  },
  zerossl: {
    production: 'https://acme.zerossl.com/v2/DV90'
  }
}

export {
  Client,
  crypto,
  axios,
  setLogger,
  directory
}
