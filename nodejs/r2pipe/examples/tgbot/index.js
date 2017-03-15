'use strict';

/* nodejs r2 telegram bot */

var qs = require('querystring');
var https = require('https');
var r2p = require('r2pipe');
var fs = require('fs');

const config = {
  target: 'http://cloud.rada.re/cmd/',
  anycmd: true,
  markdown: true,
  token: ''
};

/* required to run the bot */
var TOKEN = slurp('TOKEN', true);
/* required for the admin */
var OWNER = slurp('OWNER', false);

function slurp (file, assert) {
  try {
    return ('' + fs.readFileSync(file)).trim();
  } catch (e) {
    if (!assert) {
      return null;
    }
    console.error(e.message);
    process.exit(1);
  }
}

var TGAPIURL = 'https://api.telegram.org/';

function TelegramBot (apiurl, cb) {
  var bot = {
    query: function (q, args, cb) {
      var postData = qs.stringify(args);
      // console.log (postData);
      var options = {
        method: 'POST',
        hostname: 'api.telegram.org',
        port: 443,
        path: '/' + TOKEN + '/' + q,
        headers: {
          'Content-Type': 'application/x-www-form-urlencoded',
          'Content-Length': postData.length
        }
      };
      var req = https.request(options, function (res) {
        var data = '';
        res.on('data', function (chunk) {
          data += chunk;
        });
        res.on('end', function () {
          // console.log(data);
          try {
            cb(JSON.parse(data));
          } catch (e) {
            console.log(e, data);
            cb(null);
          }
        });
      });
      req.on('error', function (e) {
        console.log('problem with request: ' + e.message);
      });
      req.write(postData);
      req.end();
    }
  };

  bot.query('getMe', {}, function (data) {
    cb(bot, data);
  });
}

function filtercmd (x) {
  for (const token of ';|') {
    const pos = x.indexOf(token);
    if (pos !== -1) x = x.substring(0, pos);
  }
  return x;
}

function filterMarkdown (x) {
  if (!config.markdown) {
    return x;
  }
  x = x.replace(/`/g, '\'');
/*
 x = x.replace('[', '#');
 x = x.replace(']', '#');
 // x = x.replace('(', '#');
 // x = x.replace(')', '#');
 x = x.replace('_', '-');
 x = x.replace('=', '-');
 x = x.replace(';', '-');
 x = x.replace('*', '#');
 x = x.replace('.', '#');
 x = x.replace('---', '111');
*/
  var lines = x.split('\n');
      // trim all lines, some markdown parsers fail to decode
  lines = lines.map((a) => { return a.trim(); });
  x = lines.join('\n');
  return '`' + x + '`';
}

function launchTelegramBot (r2) {
  (function SetupR2 (r2) {
    r2.cmd('e scr.color=false');
    r2.cmd('e scr.html=false');
    r2.cmd('e cfg.sandbox=true');
  })(r2);
  TelegramBot(TGAPIURL, function (bot, msg) {
    function sendMessage (from, chat, text) {
      function sendChunk (txt) {
        var args = {
          'chat_id': from.id,
          'text': txt
        };
        if (chat) {
          args['chat_id'] = chat.id;
        }
        if (config.markdown === true) {
          args['parse_mode'] = 'Markdown';
          args.text = filterMarkdown(args.text);
        }
        bot.query('sendMessage', args, function (data) {
          if (!data) {
            sendMessage(from, chat, 'error');
          }
          // done
        });
      }
      while (text.length > 4095) {
        var txt = text.substring(0, 4095);
        text = text.substring(4095);
        sendChunk(txt);
      }
      sendChunk(text);
    }

    function onMessage (from, chat, text) {
      function replyCommand (err, txt) {
        if (err) {
          throw err;
        }
        sendMessage(from, chat, txt);
      }
      function replyMessage (txt) {
        sendMessage(from, chat, txt);
      }
      console.log(text);
      if (text.substring(0, 7) === '@r2bot ') {
        text = text.substring(7);
      }
      text = text.trim();
      console.log('<' + from.first_name + '>', text);
      var owned = false;
      if (OWNER && from.username === OWNER) {
        owned = true;
        switch (text) {
          case 'help':
            replyMessage('Commands are: start stop update');
            break;
          case 'hi':
            replyMessage('My lord');
            break;
          default:
            owned = false;
            break;
        }
      }
      if (owned) {
      /* do nothing here */
      } else if (text.indexOf('http://') !== -1 || text.indexOf('https://') !== -1) {
        replyMessage('@' + from.first_name + ' too old!');
      } else {
        if (text.indexOf('/dis') === 0) {
          let arch = 0;
          if (text.length > 4) {
            text = text.substring(4).trim();
          }
          const off = text.indexOf('@');
          let addr = '';
          if (off !== -1) {
            addr = text.substring(off);
            text = text.substring(0, off);
          }
          let words = text.split(' ');
          let idx = 0;
          if (words[0] === '/dis') {
            replyMessage('Usage: /dis [-arch:bits] [hexpairs] [@ addr]');
          } else {
            if (words[0] && words[0][0] === '-') {
              arch = words[0].substring(1);
              idx = 1;
            }
            var bytes = words.slice(idx).join('');
            var cmd = 'pad ' + bytes;
            if (arch) {
              cmd += '@a:' + arch;
            }
            if (addr) {
              cmd += addr;
            }
            console.log('[r2cmd]', cmd);
            r2.cmd(filtercmd(cmd), replyCommand);
          }
          return;
        } else if (text.substring(0, 3) === '/r2') {
          let sp = text.indexOf(' ');
          if (sp !== -1) {
            text = text.substring(sp).trim();
            r2.cmd(filtercmd(text), replyCommand);
          }
          return;
        } else if (text.indexOf('/cmd') === 0) {
          if (text.length > 4) {
            text = text.substring(5).trim();
            r2.cmd(filtercmd(text), replyCommand);
          }
          return;
        } else if (text.indexOf('/asm') === 0) {
          let arch = 0;
          if (text.length > 4) {
            text = text.substring(5).trim();
          }
          let off = text.indexOf('@');
          let addr = '';
          if (off !== -1) {
            addr = text.substring(off);
            text = text.substring(0, off);
          }
          let words = text.split(' ');
          let idx = 0;
          if (words[0] === '/asm') {
            replyMessage('Usage: /asm [-arch:bits] [instruction] [@ addr]');
          } else {
            if (words[0] && words[0][0] === '-') {
              arch = words[0].substring(1);
              idx = 1;
            }
            let bytes = words.slice(idx).join(' ');
            let text = 'pa ' + bytes;
            if (arch) {
              text += '@a:' + arch;
            }
            if (addr) {
              text += addr;
            }
            console.log('===========> ' + text);
            r2.cmd(filtercmd(text), replyCommand);
          }
          return;
        }
        switch (text) {
          case '/r2':
            replyMessage('Usage: /r2 [r2command]');
            break;
          case '/cmd':
            replyMessage('Usage: /cmd [r2command]');
            break;
          case '/asm':
            replyMessage('Usage: /asm [-arch] [-bits] [instruction]');
            break;
          case '/dis':
            replyMessage('Usage: /dis [-arch] [-bits] [hexpairs]');
            break;
          case '/list':
            r2.cmd('e asm.arch=?~[2]', function (data) {
              replyMessage(data.replace(/\n/g, ' '));
            });
            break;
          case '/start':
            replyMessage(
              'I am a random radare2 shell.\n' +
              "Type '?' to get a quick help for all the commands.\n" +
              'See http://www.radare.org for more details.\n --@pancake');
            break;
          case '/help':
            sendMessage(from, chat,
              'r2bot accepts r2 commands and /start /help /list /asm /dis');
            break;
          default:
            if (config.anycmd) {
              r2.cmd(text, function (data) {
                // console.log (data);
                sendMessage(from, chat, data);
              });
            } else {
              sendMessage(from, chat, 'Arbitrary r2 command execution disabled');
            }
        }
      }
    }
    console.log('Logged in', msg);
    var lastUpdateId = 0;
    function queryUpdates () {
      var args = {};
      if (lastUpdateId) {
        args.offset = lastUpdateId;
      }
      bot.query('getUpdates', args, function (data) {
        if (data && data.ok) {
          // console.log(data);
          for (var i in data.result) {
            var item = data.result[i];
            lastUpdateId = item.update_id + 1;
            console.log('updates', i, item.update_id, item.message);
            var msg = item.message;
            onMessage(msg.from, msg.chat, msg.text);
          }
        } else {
          console.error('not ok');
        }
      });
    }
    setInterval(queryUpdates, 1000);
  });
}

(x => {
  return (x.indexOf('http') === 0) ? r2p.connect : r2p.launch;
})(config.target)(config.target, launchTelegramBot);
