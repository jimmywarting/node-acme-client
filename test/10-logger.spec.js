/**
 * Logger tests
 */

import { assert } from 'chai'
import * as logger from './../src/logger.js'

describe('logger', () => {
  let lastLogMessage = null

  function customLoggerFn (msg) {
    lastLogMessage = msg
  }

  /**
     * Logger
     */

  it('should log without custom logger', () => {
    logger.log('something')
    assert.isNull(lastLogMessage)
  })

  it('should log with custom logger', () => {
    logger.setLogger(customLoggerFn);

    ['abc123', 'def456', 'ghi789'].forEach((m) => {
      logger.log(m)
      assert.strictEqual(lastLogMessage, m)
    })
  })
})
