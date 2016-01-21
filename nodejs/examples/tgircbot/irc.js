'use strict';

/* IRC */
const IRC = require('irc.js');
var irc = null;
var bot = null;
var gChatId = null;
var channel = null;

module.exports.telegramLink = function(b, c) {
  bot = b;
  gChatId = c;
}

module.exports.start = function(OPT, connectCallback) {
  /* config */
  var nick = OPT.nick || 'r2tg';
  channel = OPT.channel || '#radare';
  var host = OPT.host || 'irc.freenode.net';
  var port = OPT.port || 6667;
  var owner = OPT.owner || 'pancake';
  var file = OPT.file || '/bin/ls';
  var limit = OPT.limit || 10;

  const msgtimeout = 1000;
  const Chi = '\x1b[32m';
  const Cend = '\x1b[0m';
  const print = console.log;

  function finalize() {
    //if (irc) irc.privmsg (channel, "byebye");
    print('^C :D');
    process.exit(0);
  }
  if (channel[0] != '#') {
    channel = '#' + channel;
  }

  if (OPT.help || OPT.h) {
    print('r2irc.js [--ssl] [--host host] [--port port] [--file program]');
    print('         [--nick nick] [--channel chan] [--owner nick] [--limit num]');
    process.exit(0);
  }

  if (OPT.ssl) {
    const sslport = 9000 + (100 * Math.random());
    const cmd = 'socat TCP4-LISTEN:' + sslport + ' OPENSSL:' + host + ':' + port + ',verify=0';
    //print ("SPAWN ("+cmd+")")
    require('child_process')
      .spawn('/bin/sh', ['-c', cmd], {
        stdio: 'pipe'
      })
      .on('exit', function() {
        print('socat closed');
      });
    host = '127.0.0.1';
    port = sslport;
  }

  process.on('SIGINT', finalize);
  process.on('SIGTERM', finalize);

  /* r2 stuff */
  print(Chi, '[=>] Initializing r2 core...', Cend);

  function startIrcBot(cb) {
    print(Chi, '[=>] Connecting to irc ', Cend);
    print(Chi, '     HOST: ', host, ':', port, Cend);
    print(Chi, '     NICK: ', nick, ' ', channel, Cend);

    irc = new IRC(host, port);

    irc.on('disconnected', function(data) {
      print('Cannot connect');
    });

    irc.on('raw', function(data) {
      print('raw', data);
    });
    irc.on('connected', function(s) {
      irc.nick(nick);
      irc.join(channel, function(x) {
        irc.privmsg(channel, 'hi');
        if (connectCallback) {
          connectCallback(irc, channel);
        }
      });
      print('connected');
    });

    if (typeof String.prototype.startsWith != 'function') {
      String.prototype.startsWith = function(str) {
        return this.slice(0, str.length) == str;
      };
    }

    irc.on('privmsg', function(from, to, msg) {
      function tailRun(o) {
        if (o != null && o != '') {
          if (o.split('\n').length < limit) {
            (function() {
              var a = o.split(o.indexOf('\r') != -1 ?
                '\r' : '\n');
              var timedmsg = function(x) {
                irc.privmsg(to, a[0]);
                a = a.slice(1);
                if (a.length > 0) {
                  setTimeout(timedmsg, msgtimeout);
                }
              };
              setTimeout(timedmsg, msgtimeout);
            })();
          } else {
            irc.privmsg(to, 'Output limited to ' + limit + ' lines');
          }
        }
      }
      print('<' + from + '> to ' + to + ' ' + msg);
      if (bot !== null && gChatId) {
        // console.log('CHATID', gChatId);
        const msgline = to + ' <' + from + '> ' + msg;
        bot.sendMessage(gChatId, msgline);
      } else {
        console.error("BOT IS NOT YET DEFINED");
        irc.privmsg (channel, 'Bridge not initialized yet, message not forwarded.');
      }
    });

    irc.connect(nick, 'radare-telegram-irc-bridge');
  }
  startIrcBot();
  return irc;
};
