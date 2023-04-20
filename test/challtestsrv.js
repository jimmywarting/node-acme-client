/**
 * Pebble Challenge Test Server integration
 */

import { assert } from 'chai'
import axios from './../src/axios.js'

const apiBaseUrl = process.env.ACME_CHALLTESTSRV_URL || null

/**
 * Send request
 */

async function request (apiPath, data = {}) {
  if (!apiBaseUrl) {
    throw new Error('No Pebble Challenge Test Server URL found')
  }

  await axios.request({
    url: `${apiBaseUrl}/${apiPath}`,
    method: 'post',
    data
  })

  return true
}

/**
 * State
 */

const isEnabled = () => !!apiBaseUrl

/**
 * DNS
 */

const addDnsARecord = async (host, addresses) => request('add-a', { host, addresses })
const setDnsCnameRecord = async (host, target) => request('set-cname', { host, target })

/**
 * Challenge response
 */

async function addHttp01ChallengeResponse (token, content) {
  return request('add-http01', { token, content })
}

async function addDns01ChallengeResponse (host, value) {
  return request('set-txt', { host, value })
}

/**
 * Challenge response mock functions
 */

async function assertHttpChallengeCreateFn (authz, challenge, keyAuthorization) {
  assert.strictEqual(challenge.type, 'http-01')
  return addHttp01ChallengeResponse(challenge.token, keyAuthorization)
}

async function assertDnsChallengeCreateFn (authz, challenge, keyAuthorization) {
  assert.strictEqual(challenge.type, 'dns-01')
  return addDns01ChallengeResponse(`_acme-challenge.${authz.identifier.value}.`, keyAuthorization)
}

async function challengeCreateFn (authz, challenge, keyAuthorization) {
  if (challenge.type === 'http-01') {
    return assertHttpChallengeCreateFn(authz, challenge, keyAuthorization)
  }

  if (challenge.type === 'dns-01') {
    return assertDnsChallengeCreateFn(authz, challenge, keyAuthorization)
  }

  throw new Error(`Unsupported challenge type ${challenge.type}`)
}

const challengeRemoveFn = async () => true
const challengeNoopFn = async () => true
const challengeThrowFn = async () => { throw new Error('oops') }

export {
  isEnabled,
  addDnsARecord,
  setDnsCnameRecord,
  addHttp01ChallengeResponse,
  addDns01ChallengeResponse,
  challengeRemoveFn,
  challengeNoopFn,
  challengeThrowFn,
  assertHttpChallengeCreateFn,
  assertDnsChallengeCreateFn,
  challengeCreateFn
}
