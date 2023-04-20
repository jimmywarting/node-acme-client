let logger = () => {}

/**
 * Set logger function
 *
 * @param {() => void} fn Logger function
 */
export const setLogger = (fn) => logger = fn

/**
 * Log message
 *
 * @param {string} msg
 */

export const log = msg => logger(msg)
