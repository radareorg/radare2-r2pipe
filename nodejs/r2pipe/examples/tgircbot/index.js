'use strict';

const OPT = require('optimist').argv;
require('./irc').bind(require('./tg')).start(OPT);
