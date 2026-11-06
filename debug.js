'use strict';
const util = require('util');
let enabled = false;
function enable() { enabled = true; }
function log(fmt, ...args) { if (enabled) console.error('[DEBUG] ' + util.format(fmt, ...args)); }
module.exports = { enable, log };
