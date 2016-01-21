'use strict';

const TelegramBot = require('node-telegram-bot-api');
var gChatId = null;

module.exports.getChannel = function() {
  return gChatId;
}

module.exports.ircProxy = function(irc, ircChannel, channelCallback) {
  const token = slurp('TOKEN', true);

  function slurp(file, assert) {
    try {
      return ('' + require('fs').readFileSync(file)).trim();
    } catch (e) {
      if (!assert) {
        return null;
      }
      console.error(e.message);
      process.exit(1);
    }
  }

  /* Telegram Bot Side */

  // Setup polling way
  var bot = new TelegramBot(token, {
    polling: true
  });
  bot.onText(/(.*)/, function(msg, match) {
    console.log('bridge', msg);
  });

  bot.on('message', function(msg) {
    var chatId = msg.chat.id;
    if (!gChatId && chatId) {
      gChatId = chatId;
      if (channelCallback) {
        channelCallback(bot, gChatId);
      }
    }
    console.log(gChatId, chatId);
    //bot.sendMessage(chatId, 'hello world');
    try {
      var name = msg.chat.username || msg.chat.first_name;
      if (!name) {
        name = msg.from.username || msg.from.first_name;
      }
    } catch (e) {
      if (!name) {
        name = msg.from.username || msg.from.first_name;
      }
      console.log(e);
    }
    console.log(msg);
    var lines = msg.text.replace('@r2tgircBot', '').split("\n");
    var count = 10;
    console.log("SENDING MESSAGE!", irc);
    for (var line of lines) {
      console.log("SENDING LINE!", line);
      const msgline = '<' + name + '> ' + line.trim();
      if (count-- < 1) {
        irc.privmsg(ircChannel, '<' + name + '> ...');
        break;
      }
      if (irc === null) {
        console.error("irc instance not yet defined");
      } else {
        irc.privmsg(ircChannel, msgline);
      }
    }
    //  var photo = 'cats.png';
    // bot.sendPhoto(chatId, photo, {caption: 'Lovely kittens'});
  });
  return bot;
};