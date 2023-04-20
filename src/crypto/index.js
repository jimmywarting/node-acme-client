import { Buffer } from 'node:buffer'
import nodeCrypto from 'node:crypto'
import jsrsasign from 'jsrsasign'
import { createWorker } from 'await-sync'


const c = new TextEncoder(); const U = Uint8Array; const A = ArrayBuffer,
d = new TextDecoder()

/** @param {string} str */
const toBytes = str => U.from(atob(str), c => c.charCodeAt(0))
/** @param {Uint8Array} u8 */
const toBase64 = u8 => btoa([...u8].map(c => String.fromCharCode(c)).join(''))
/** Convert anything to Uint8Array without a copy */
const toUint8 = x => x instanceof A ? new U(x) : A.isView(x) ? x instanceof U && x.constructor.name === U.name ? x : new U(x.buffer, x.byteOffset, x.byteLength) : c.encode(x)

const awaitSync = createWorker()

const { crypto } = globalThis

/** @param {string | Uint8Array} pem */
function decodePem (pem) {
  if (pem instanceof Uint8Array) {
    pem = new TextDecoder().decode(pem)
  }

  const [header, ...lines] = pem.trim().split('\n')
  lines.pop()
  const type = header.replaceAll('-', '').replace('BEGIN ', '')
  const base64 = lines.join('')

  return {
    type,
    pem,
    key: toBytes(base64),
    key64: base64,
  }
}

const forgeObjectFromPem = awaitSync(async input => {
  let result
  [ 'PRIVATE KEY', 'RSA PUBLIC KEY', 'PUBLIC KEY' ]
  if (input.key) {
    switch (input.type) {
      case 'PUBLIC KEY': {
        // result = await crypto.subtle.importKey('spki', input.key, { name: 'ECDSA', namedCurve: 'P-256' }, true, ['verify'])
        break
      }
      case 'PRIVATE KEY': {
        // TODO
        break
      }
      case 'RSA PUBLIC KEY': {
        // TODO
        break
      }
      default:
        console.log(`Unsupported key type: ${input.type}`)
    }
  }

  return new Uint8Array(2).fill(2)
})

/**
 * Determine key type and info by attempting to derive public key
 *
 * @param {Buffer} keyPem PEM encoded private or public key
 * @returns {object}
 */
function getKeyInfo (keyPem) {
  forgeObjectFromPem(decodePem(keyPem))
  const result = {
    isRSA: false,
    isECDSA: false,
    signatureAlgorithm: null,
    publicKey: nodeCrypto.createPublicKey(keyPem)
  }

  if (result.publicKey.asymmetricKeyType === 'rsa') {
    result.isRSA = true
    result.signatureAlgorithm = 'SHA256withRSA'
  } else if (result.publicKey.asymmetricKeyType === 'ec') {
    result.isECDSA = true
    result.signatureAlgorithm = 'SHA256withECDSA'
  } else {
    throw new Error('Unable to parse key information, unknown format')
  }

  return result
}

/**
 * Convert a buffer to a PEM encoded string
 *
 * @param {ArrayBuffer} buffer
 * @param {string} label
 */
function bufferToPem (buffer, label) {
  const base64 = toBase64(toUint8(buffer))

  const lines = base64.match(/.{1,64}/g)
  const head = `-----BEGIN ${label}-----\n`
  const mid = lines ? `${lines.join('\n')}\n` : `${base64}\n`
  const foot = `-----END ${label}-----\n`

  return head + mid + foot
}

/**
 * Generate a private RSA key
 *
 * @example Generate private RSA key
 * ```js
 * const privateKey = await acme.crypto.createPrivateRsaKey()
 * ```
 *
 * @example Private RSA key with modulus size 4096
 * ```js
 * const privateKey = await acme.crypto.createPrivateRsaKey(4096)
 * ```
 * @param {number} [modulusLength=2048] Size of the keys modulus in bits
 * @returns {Promise<Buffer>} PEM encoded private RSA key
 */
async function createPrivateRsaKey (modulusLength = 2048) {
  const algorithm = {
    name: 'RSA-OAEP',
    modulusLength,
    publicExponent: new Uint8Array([1, 0, 1]),
    hash: { name: 'SHA-256' }
  }

  const keys = await crypto.subtle.generateKey(
    algorithm,
    true, // extractable
    ['encrypt', 'decrypt'] // key usages
  )

  const privateKey = await crypto.subtle.exportKey(
    'pkcs8',
    keys.privateKey
  )

  const pemPrivateKey = bufferToPem(privateKey, 'PRIVATE KEY')

  return Buffer.from(pemPrivateKey)
}

/**
 * Generate a private ECDSA key
 *
 * @param {string} [namedCurve] ECDSA curve name (P-256, P-384 or P-521), default `P-256`
 * @returns {Promise<Buffer>} PEM encoded private ECDSA key
 *
 * @example Generate private ECDSA key
 * ```js
 * const privateKey = await acme.crypto.createPrivateEcdsaKey();
 * ```
 *
 * @example Private ECDSA key using P-384 curve
 * ```js
 * const privateKey = await acme.crypto.createPrivateEcdsaKey('P-384');
 * ```
 */

async function createPrivateEcdsaKey (namedCurve = 'P-256') {
  const algorithm = {
    name: 'ECDSA',
    namedCurve
  }

  const keys = await crypto.subtle.generateKey(
    algorithm,
    true, // extractable
    ['sign', 'verify'] // key usages
  )

  const privateKey = await crypto.subtle.exportKey(
    'pkcs8',
    keys.privateKey
  )
  console.log(privateKey)
  const pemPrivateKey = bufferToPem(privateKey, 'PRIVATE KEY')

  return Buffer.from(pemPrivateKey)
}

/**
 * Get a public key derived from a RSA or ECDSA key
 *
 * @param {buffer|string} keyPem PEM encoded private or public key
 * @returns PEM encoded public key
 *
 * @example Get public key
 * ```js
 * const publicKey = acme.crypto.getPublicKey(privateKey);
 * ```
 */

const getPublicKey = (keyPem) => {
  const info = getKeyInfo(keyPem)

  const publicKey = info.publicKey.export({
    type: info.isECDSA ? 'spki' : 'pkcs1',
    format: 'pem'
  })

  return Buffer.from(publicKey)
}

/**
 * Get a JSON Web Key derived from a RSA or ECDSA key
 *
 * https://datatracker.ietf.org/doc/html/rfc7517
 *
 * @param {Buffer} keyPem PEM encoded private or public key
 * @returns {object} JSON Web Key
 *
 * @example Get JWK
 * ```js
 * const jwk = acme.crypto.getJwk(privateKey);
 * ```
 */
function getJwk (keyPem) {
  const jwk = nodeCrypto.createPublicKey(keyPem).export({
    format: 'jwk'
  })

  /* Sort keys */
  const result = Object.keys(jwk).sort().reduce((result, k) => {
    result[k] = jwk[k]
    return result
  }, {})

  return result
}

/**
 * Fix missing support for NIST curve names in jsrsasign
 *
 * @private
 * @param {string} crv NIST curve name
 * @returns {string} SECG curve name
 */

function convertNistCurveNameToSecg (nistName) {
  switch (nistName) {
    case 'P-256':
      return 'secp256r1'
    case 'P-384':
      return 'secp384r1'
    case 'P-521':
      return 'secp521r1'
    default:
      return nistName
  }
}

/**
 * Split chain of PEM encoded objects from string into array
 *
 * @param {buffer|string} chainPem PEM encoded object chain
 * @returns {array} Array of PEM objects including headers
 */

function splitPemChain (chainPem) {
  if (Buffer.isBuffer(chainPem)) {
    chainPem = chainPem.toString()
  }

  return chainPem
  /* Split chain into chunks, starting at every header */
    .split(/\s*(?=-----BEGIN [A-Z0-9- ]+-----\r?\n?)/g)
  /* Match header, PEM body and footer */
    .map((pem) => pem.match(/\s*-----BEGIN ([A-Z0-9- ]+)-----\r?\n?([\S\s]+)\r?\n?-----END \1-----/))
  /* Filter out non-matches or empty bodies */
    .filter((pem) => pem && pem[2] && pem[2].replace(/[\r\n]+/g, '').trim())
  /* Decode to hex, and back to PEM for formatting etc */
    .map(([pem, header]) => jsrsasign.hextopem(jsrsasign.pemtohex(pem, header), header))
}

/**
 * Parse body of PEM encoded object and return a Base64URL string
 * If multiple objects are chained, the first body will be returned
 *
 * @param {buffer|string} pem PEM encoded chain or object
 * @returns {string} Base64URL-encoded body
 */

const getPemBodyAsB64u = (pem) => {
  const chain = splitPemChain(pem)

  if (!chain.length) {
    throw new Error('Unable to parse PEM body from string')
  }

  /* First object, hex and back to b64 without new lines */
  return jsrsasign.hextob64u(jsrsasign.pemtohex(chain[0]))
}

/**
 * Parse common name from a subject object
 *
 * @private
 * @param {object} subj Subject returned from jsrsasign
 * @returns {string} Common name value
 */

function parseCommonName (subj) {
  const subjectArr = (subj && subj.array) ? subj.array : []
  const cnArr = subjectArr.find((s) => (s[0] && s[0].type && s[0].value && (s[0].type === 'CN')))
  return (cnArr && cnArr.length && cnArr[0].value) ? cnArr[0].value : null
}

/**
 * Parse domains from a certificate or CSR
 *
 * @private
 * @param {object} params Certificate or CSR params returned from jsrsasign
 * @returns {object} {commonName, altNames}
 */

function parseDomains (params) {
  const commonName = parseCommonName(params.subject)
  const extensionArr = (params.ext || params.extreq || [])
  let altNames = []

  if (extensionArr && extensionArr.length) {
    const altNameExt = extensionArr.find((e) => (e.extname && (e.extname === 'subjectAltName')))
    const altNameArr = (altNameExt && altNameExt.array && altNameExt.array.length) ? altNameExt.array : []
    altNames = altNameArr.map((a) => Object.values(a)[0] || null).filter((a) => a)
  }

  return {
    commonName,
    altNames
  }
}

/**
 * Read domains from a Certificate Signing Request
 *
 * @param {buffer|string} csrPem PEM encoded Certificate Signing Request
 * @returns {object} {commonName, altNames}
 *
 * @example Read Certificate Signing Request domains
 * ```js
 * const { commonName, altNames } = acme.crypto.readCsrDomains(certificateRequest);
 *
 * console.log(`Common name: ${commonName}`);
 * console.log(`Alt names: ${altNames.join(', ')}`);
 * ```
 */

const readCsrDomains = (csrPem) => {
  if (Buffer.isBuffer(csrPem)) {
    csrPem = csrPem.toString()
  }

  /* Parse CSR */
  const params = jsrsasign.KJUR.asn1.csr.CSRUtil.getParam(csrPem)
  return parseDomains(params)
}

/**
 * Read information from a certificate
 * If multiple certificates are chained, the first will be read
 *
 * @param {buffer|string} certPem PEM encoded certificate or chain
 * @returns {object} Certificate info
 *
 * @example Read certificate information
 * ```js
 * const info = acme.crypto.readCertificateInfo(certificate);
 * const { commonName, altNames } = info.domains;
 *
 * console.log(`Not after: ${info.notAfter}`);
 * console.log(`Not before: ${info.notBefore}`);
 *
 * console.log(`Common name: ${commonName}`);
 * console.log(`Alt names: ${altNames.join(', ')}`);
 * ```
 */

const readCertificateInfo = (certPem) => {
  const chain = splitPemChain(certPem)

  if (!chain.length) {
    throw new Error('Unable to parse PEM body from string')
  }

  /* Parse certificate */
  const obj = new jsrsasign.X509()
  obj.readCertPEM(chain[0])
  const params = obj.getParam()

  return {
    issuer: {
      commonName: parseCommonName(params.issuer)
    },
    domains: parseDomains(params),
    notBefore: jsrsasign.zulutodate(params.notbefore),
    notAfter: jsrsasign.zulutodate(params.notafter)
  }
}

/**
 * Determine ASN.1 character string type for CSR subject field
 *
 * https://tools.ietf.org/html/rfc5280
 * https://github.com/kjur/jsrsasign/blob/2613c64559768b91dde9793dfa318feacb7c3b8a/src/x509-1.1.js#L2404-L2412
 * https://github.com/kjur/jsrsasign/blob/2613c64559768b91dde9793dfa318feacb7c3b8a/src/asn1x509-1.0.js#L3526-L3535
 *
 * @private
 * @param {string} field CSR subject field
 * @returns {string} ASN.1 jsrsasign character string type
 */

function getCsrAsn1CharStringType (field) {
  switch (field) {
    case 'C':
      return 'prn'
    case 'E':
      return 'ia5'
    default:
      return 'utf8'
  }
}

/**
 * Create array of subject fields for a Certificate Signing Request
 *
 * @private
 * @param {object} input Key-value of subject fields
 * @returns {object[]} Certificate Signing Request subject array
 */

function createCsrSubject (input) {
  return Object.entries(input).reduce((result, [type, value]) => {
    if (value) {
      const ds = getCsrAsn1CharStringType(type)
      result.push([{ type, value, ds }])
    }

    return result
  }, [])
}

// IPv4 Segment
const v4Seg = '(?:[0-9]|[1-9][0-9]|1[0-9][0-9]|2[0-4][0-9]|25[0-5])';
const v4Str = `(${v4Seg}[.]){3}${v4Seg}`;
const IPv4Reg = new RegExp(`^${v4Str}$`);

// IPv6 Segment
const v6Seg = '(?:[0-9a-fA-F]{1,4})';
const IPv6Reg = new RegExp('^(' +
  `(?:${v6Seg}:){7}(?:${v6Seg}|:)|` +
  `(?:${v6Seg}:){6}(?:${v4Str}|:${v6Seg}|:)|` +
  `(?:${v6Seg}:){5}(?::${v4Str}|(:${v6Seg}){1,2}|:)|` +
  `(?:${v6Seg}:){4}(?:(:${v6Seg}){0,1}:${v4Str}|(:${v6Seg}){1,3}|:)|` +
  `(?:${v6Seg}:){3}(?:(:${v6Seg}){0,2}:${v4Str}|(:${v6Seg}){1,4}|:)|` +
  `(?:${v6Seg}:){2}(?:(:${v6Seg}){0,3}:${v4Str}|(:${v6Seg}){1,5}|:)|` +
  `(?:${v6Seg}:){1}(?:(:${v6Seg}){0,4}:${v4Str}|(:${v6Seg}){1,6}|:)|` +
  `(?::((?::${v6Seg}){0,5}:${v4Str}|(?::${v6Seg}){1,7}|:))` +
')(%[0-9a-zA-Z-.:]{1,})?$');

/**
 * Create array of alt names for Certificate Signing Requests
 *
 * https://github.com/kjur/jsrsasign/blob/3edc0070846922daea98d9588978e91d855577ec/src/x509-1.1.js#L1355-L1410
 *
 * @private
 * @param {string[]} altNames Array of alt names
 * @returns {object[]} Certificate Signing Request alt names array
 */

function formatCsrAltNames (altNames) {
  return altNames.map((value) => {
    const key = IPv4Reg.test(value) || IPv6Reg.test(value) ? 'ip' : 'dns'
    return { [key]: value }
  })
}

/**
 * Create a Certificate Signing Request
 *
 * @param {object} data
 * @param {number} [data.keySize] Size of newly created RSA private key modulus in bits, default: `2048`
 * @param {string} [data.commonName] FQDN of your server
 * @param {array} [data.altNames] SAN (Subject Alternative Names), default: `[]`
 * @param {string} [data.country] 2 letter country code
 * @param {string} [data.state] State or province
 * @param {string} [data.locality] City
 * @param {string} [data.organization] Organization name
 * @param {string} [data.organizationUnit] Organizational unit name
 * @param {string} [data.emailAddress] Email address
 * @param {string} [keyPem] PEM encoded CSR private key
 * @returns {Promise<buffer[]>} [privateKey, certificateSigningRequest]
 *
 * @example Create a Certificate Signing Request
 * ```js
 * const [certificateKey, certificateRequest] = await acme.crypto.createCsr({
 *     commonName: 'test.example.com'
 * });
 * ```
 *
 * @example Certificate Signing Request with both common and alternative names
 * ```js
 * const [certificateKey, certificateRequest] = await acme.crypto.createCsr({
 *     keySize: 4096,
 *     commonName: 'test.example.com',
 *     altNames: ['foo.example.com', 'bar.example.com']
 * });
 * ```
 *
 * @example Certificate Signing Request with additional information
 * ```js
 * const [certificateKey, certificateRequest] = await acme.crypto.createCsr({
 *     commonName: 'test.example.com',
 *     country: 'US',
 *     state: 'California',
 *     locality: 'Los Angeles',
 *     organization: 'The Company Inc.',
 *     organizationUnit: 'IT Department',
 *     emailAddress: 'contact@example.com'
 * });
 * ```
 *
 * @example Certificate Signing Request with ECDSA private key
 * ```js
 * const certificateKey = await acme.crypto.createPrivateEcdsaKey();
 *
 * const [, certificateRequest] = await acme.crypto.createCsr({
 *     commonName: 'test.example.com'
 * }, certificateKey);
 */

const createCsr = async (data, keyPem) => {
  if (!keyPem) {
    keyPem = await createPrivateRsaKey(data.keySize)
  } else if (!Buffer.isBuffer(keyPem)) {
    keyPem = Buffer.from(keyPem)
  }

  if (typeof data.altNames === 'undefined') {
    data.altNames = []
  }

  /* Get key info and JWK */
  const info = getKeyInfo(keyPem)
  const jwk = await getJwk(keyPem)
  const extensionRequests = []

  /* Missing support for NIST curve names in jsrsasign - https://github.com/kjur/jsrsasign/blob/master/src/asn1x509-1.0.js#L4388-L4393 */
  if (jwk.crv && (jwk.kty === 'EC')) {
    jwk.crv = convertNistCurveNameToSecg(jwk.crv)
  }

  /* Ensure subject common name is present in SAN - https://cabforum.org/wp-content/uploads/BRv1.2.3.pdf */
  if (data.commonName && !data.altNames.includes(data.commonName)) {
    data.altNames.unshift(data.commonName)
  }

  /* Subject */
  const subject = createCsrSubject({
    CN: data.commonName,
    C: data.country,
    ST: data.state,
    L: data.locality,
    O: data.organization,
    OU: data.organizationUnit,
    E: data.emailAddress
  })

  /* SAN extension */
  if (data.altNames.length) {
    extensionRequests.push({
      extname: 'subjectAltName',
      array: formatCsrAltNames(data.altNames)
    })
  }

  /* Create CSR */
  const csr = new jsrsasign.KJUR.asn1.csr.CertificationRequest({
    subject: { array: subject },
    sigalg: info.signatureAlgorithm,
    sbjprvkey: keyPem.toString(),
    sbjpubkey: jwk,
    extreq: extensionRequests
  })

  /* Sign CSR, get PEM */
  csr.sign()
  const pem = csr.getPEM()

  /* Done */
  return [keyPem, Buffer.from(pem)]
}

export {
  createPrivateRsaKey,
  createPrivateEcdsaKey,
  getPublicKey,
  getJwk,
  getPemBodyAsB64u,
  splitPemChain,
  readCertificateInfo,
  createCsr,
  readCsrDomains,
  createPrivateRsaKey as createPrivateKey
}
