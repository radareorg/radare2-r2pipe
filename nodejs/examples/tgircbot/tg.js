'use strict';

const TelegramBot = require('node-telegram-bot-api');
var gChatId = null;
var bot = null;

module.exports.bridgeMessage = function(name, text) {
  if (gChatId !== null) {
    bot.sendMessage(gChatId, '<' + name + '> ' + text);
  } else {
    console.error("Global chat_id not yet known");
  }
}

module.exports.launch = function(endpoint) {
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
  bot = new TelegramBot(token, {
    polling: true
  });
  bot.onText(/(.*)/, function(msg, match) {
    console.log('bridge', msg);
  });

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
    endpoint.bridgeMessage(name, msg.text);
    // bot.sendPhoto(chatId, 'cats.png', {caption: 'Lovely kittens'});
  });
  return bot;
};
