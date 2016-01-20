'use strict';

const TelegramBot = require('node-telegram-bot-api');

module.exports = function(irc) {
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

  var gChatId = null;

  bot.on('message', function(msg) {
    var chatId = msg.chat.id;
    if (!gChatId && chatId) {
      gChatId = chatId;
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
    var msgline = '<' + name + '> ' + msg.text.replace('@r2tgircBot', '').trim();
    irc.privmsg(channel, msgline);
    //  var photo = 'cats.png';
    // bot.sendPhoto(chatId, photo, {caption: 'Lovely kittens'});
  });
  return bot;
};
