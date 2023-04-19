let logger = () => {};


/**
 * Set logger function
 *
 * @param {() => void} fn Logger function
 */
exports.setLogger = (fn) => {
    logger = fn
}


/**
 * Log message
 *
 * @param {string} msg
 */

exports.log = msg => logger(msg)
