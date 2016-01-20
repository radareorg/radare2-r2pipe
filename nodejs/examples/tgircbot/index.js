'use strict';

var OPT = require('optimist').argv;

const p0 = require('./irc').start(OPT);
p0.bot = require('./tg')(p0);