#!/usr/bin/node
/* r2.js irc bot -- author: pancake(nopcode.org) */

var OPT = require('optimist').argv;
var IRC = require('irc.js');
var r2p = require('r2pipe');
var irc;

/* config */
var nick = OPT.nick || 'r2bot';
var channel = OPT.channel || '#radare';
var host = OPT.host || 'irc.freenode.net';
var port = OPT.port || 6667;
var owner = OPT.owner || 'pancake';
var file = OPT.file || '/bin/ls';
var limit = OPT.limit || 10;

const msgtimeout = 1000;
const Chi = '\x1b[32m';
const Cend = '\x1b[0m';
const print = console.log;

function finalize () {
  if (irc) irc.privmsg(channel, 'byebye');
  print('^C :D');
  process.exit(0);
}
if (channel[0] !== '#') {
  channel = '#' + channel;
}

if (OPT.help || OPT.h) {
  print('r2irc.js [--ssl] [--host host] [--port port] [--file program]');
  print('         [--nick nick] [--channel chan] [--owner nick] [--limit num]');
  process.exit(0);
}

if (OPT.ssl) {
  var sslport = 9000 + (100 * Math.random());
  var cmd = 'socat TCP4-LISTEN:' + sslport + ' OPENSSL:' + host + ':' + port + ',verify=0';
  // print ("SPAWN ("+cmd+")")
  require('child_process')
  .spawn('/bin/sh', ['-c', cmd], { stdio: 'pipe' })
  .on('exit', function () { print('socat closed'); });
  host = '127.0.0.1';
  port = sslport;
}

process.on('SIGINT', finalize);
process.on('SIGTERM', finalize);

// setTimeout (goirc, 3000);

function startsWith (str) {
  return this.slice(0, str.length) === str;
}

/* r2 stuff */
print(Chi, '[=>] Initializing r2 core...', Cend);
r2p.launch(file, startIrcBot);

function startIrcBot (err, r2) {
  if (err) {
    console.error(err);
    return;
  }
  r2.cmd('e cfg.sandbox=true');
  r2.cmd('e scr.color=false');
  r2.cmd('e scr.interactive=false');

  print(Chi, '[=>] Connecting to irc ', Cend);
  print(Chi, '     HOST: ', host, ':', port, Cend);
  print(Chi, '     NICK: ', nick, ' ', channel, Cend);

  irc = new IRC(host, port);

  irc.on('disconnected', function (data) {
    print('Cannot connect');
  });

  irc.on('raw', function (data) {
    print(data);
  });
  irc.on('connected', function (s) {
    irc.nick(nick);
    irc.join(channel, function (x) {
      irc.privmsg(channel, 'hi');
    });
    print('connected');
  });

  irc.on('privmsg', function (from, to, msg) {
    function tailRun (o) {
      if (o !== null && o !== '') {
        if (o.split('\n').length < limit) {
          (function () {
            var a = o.split(o.indexOf('\r') !== -1
? '\r' : '\n');
            var timedmsg = function (x) {
              irc.privmsg(to, a[0]);
              a = a.slice(1);
              if (a.length > 0) { setTimeout(timedmsg, msgtimeout); }
            };
            setTimeout(timedmsg, msgtimeout);
          })();
        } else irc.privmsg(to, 'Output limited to ' + limit + ' lines');
      }
    }
    print('<' + from + '> to ' + to + ': ' + msg);
    if (to[0] !== '#' && from === owner) {
      if (startsWith('nick ').bind(msg)) {
        irc.nick(msg.slice(5));
      } else if (startsWith('join ').bind(msg)) {
        irc.join(msg.slice(5));
      } else if (startsWith('part ').bind(msg)) {
        irc.part(msg.slice(5));
      } else {
        irc.privmsg(channel, msg);
      }
    } else {
      switch (to) {
        case channel:
        default:
          if (!startsWith('!').bind(msg)) {
            return;
          }
          var o = '';
          msg = msg.substring(1);
          // msg = msg.replace (/>/g, "");
          // msg = msg.replace (/|/g, "");
          // msg = msg.replace (/!/g, "");
          // msg = msg.replace (/`/g, "");
          msg = msg.replace(/\t/g, '   ');
          msg = msg.trim();
          var cmds = msg.split(';');
          for (var i in cmds) {
            msg = cmds[i];
            msg = msg.replace(/^ */, '');
            if (startsWith('q').bind(msg)) {
              o = 'not now';
            } else if (startsWith('o').bind(msg) && msg.length > 1) {
              o = 'no open allowed';
            } else if (startsWith('V').bind(msg)) {
              o = 'i cant do visuals on irc :(';
            } else if (startsWith('ag').bind(msg)) {
              o = 'graphs cant be seen here.';
            } else {
              o = '';
              r2.cmd(msg, (err, o) => {
                if (err) {
                  throw err;
                }
                print('=', msg);
                print(o);
                tailRun(o);
              });
            }
            if (o) {
              print('=', msg);
              print(o);
            }
          }
          tailRun(o);
          break;
      }
    }
  });

  irc.connect(nick, 'http://www.radare.org/', 'r2bot');
}
