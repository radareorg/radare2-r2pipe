'use strict';

const OPT = require('optimist').argv;
const pipe = {
  irc: require('./irc'),
  tg: require('./tg')
};

pipe.irc.start(OPT, (irc, channel) => {
  pipe.tg.ircProxy(irc, channel, function(bot, chatid) {
    pipe.irc.telegramLink(bot, chatid);
  });
});