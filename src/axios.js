/**
 * Axios instance
 */

import axios from 'axios';
import adapter from 'axios/lib/adapters/http.js';

const pkg = { name: 'acme-client', version: '4.0.0' }


/**
 * Instance
 */

const instance = axios.create();

/* Default User-Agent */
instance.defaults.headers.common['User-Agent'] = `node-${pkg.name}/${pkg.version}`;

/* Default ACME settings */
instance.defaults.acmeSettings = {
    httpChallengePort: 80,
    bypassCustomDnsResolver: false
};


/**
 * Explicitly set Node as default HTTP adapter
 *
 * https://github.com/axios/axios/issues/1180
 * https://stackoverflow.com/questions/42677387
 */

instance.defaults.adapter = adapter;


/**
 * Export instance
 */

export default instance;
