'use strict';

const os = require('os');
const fs = require('fs');
const net = require('net');
const http = require('http');
const sync = require('./sync.js');
const util = require('./util');
const proc = require('child_process');

var IN, OUT, R2PIPE_PATH;

try {
  IN = parseInt(process.env.R2PIPE_IN);
  OUT = parseInt(process.env.R2PIPE_OUT);
  R2PIPE_PATH = process.env.R2PIPE_PATH;
} catch (e) {
  /* do nothing */
}

/*
 * CMD handlers for different connection methods
 */
function syscmd (command, childOpts, cb) {
  let childOpt = {
    maxBuffer: 1024 * 1024 * 2 // 2MB as limit by default
  };
  switch (typeof childOpts) {
    case 'object':
      childOpt = childOpts;
      break;
    case 'function':
      cb = childOpts;
      break;
  }
  if (typeof cb !== 'function') {
    cb = function () {};
  }
  var callback = function (err, stdout, stderr) {
    cb(err, stdout);
  };
  if (typeof command === 'string') {
    proc.exec(command, childOpt, callback);
  } else if (typeof command === 'object' && command.length > 0) {
    proc.execFile(command[0], command.slice(1), childOpt, callback);
  } else {
    cb(new Error('r2pipe.js: Invalid command type in syscmd'));
  }
}

/* Run system cmd and return JSON output */
function syscmdj (command, cb2) {
  if (typeof cb2 !== 'function') {
    cb2 = function () {};
  }
  parseJSON(syscmd, command, cb2);
}

function remoteCmd (port, cmd, cb) {
  try {
    let msg = '';
    const client = new net.Socket();
    client.connect(port, 'localhost', function () {});
    client.write(cmd + '\n');
    client.on('data', function (data) {
      msg += data;
    });
    // Add a 'close' event handler for the client socket
    client.on('close', function () {
      if (typeof cb === 'function') {
        cb(msg);
      }
    });
  } catch (e) {
    console.error(e);
  }
}

function httpCmd (uri, cmd, cb) {
  let text = '';
  const req = http.get(uri + cmd, function (res) {
    res.on('data', function (res) {
      text += res;
    });
  }).on('error', function (err) {
    cb(err);
  });
  req.on('close', function (e) {
    cb(null, text);
  });
}

function pipeCmd (proc, cmd, cb) {
  this.pipeQueue.push({
    cmd: cmd,
    cb: cb,
    result: '',
    error: null
  });
  if (this.pipeQueue.length === 1) {
    proc.stdin.write(cmd + '\n');
  }
}

function pipeCmdOutput (proc, data, cb) {
  var len = data.length;

  if (this.pipeQueue.length < 1) {
    return cb(new Error('r2pipe error: No pending commands for incomming data'));
  }

  if (data[len - 1] !== 0x00) {
    this.pipeQueue[0].result += data.toString();
    return this.pipeQueue[0].result;
  }

  while (data[len - 1] == 0x00) {
    len--;
  }

  this.pipeQueue[0].result += data.slice(0, len).toString();
  this.pipeQueue[0].cb(this.pipeQueue[0].error, this.pipeQueue[0].result);
  this.pipeQueue.splice(0, 1);

  if (this.pipeQueue.length > 0) {
    try {
      proc.stdin.write(this.pipeQueue[0].cmd + '\n');
    } catch (e) {
      return cb(e);
    }
  }
}

function parseJSON (func, cmd, callback) {
  func(cmd, function (error, res) {
    if (error) {
      return callback(error);
    }
    res = res.replace(/\u0000$/, '').trim();
    if (res === '') {
      res = '{}';
    }
    try {
      callback(null, r2node.jsonParse(res));
    } catch (e) {
      e.res = res;
      e.cmd = cmd;
      callback(e);
    }
  });
}

/*
 * r2pipe main
 */

function r2bind (ls, cb, r2cmd) {
  let running = false;
  let errmsg = '';
  const r2 = {
    pipeQueue: [],

    getBuffer: function (addr, size, cb) {
      let dataBuffer = Buffer.from([]);
      const server = net.createServer(client => {
        client.on('data', data => {
          dataBuffer = Buffer.concat([dataBuffer, data]);
        });
        client.on('end', _ => {
          cb(null, dataBuffer);
          client.destroy();
          server.close();
        });
        client.on('error', err => {
          cb(err);
        });
      });
      server.listen(0, _ => {
        const port = server.address().port;
        const command = 'wts 127.0.0.1:' + port + ' ' + size + '@ ' + addr;
        r2.cmd(command);
      });
    },

    /* Run cmd and return plaintext output */
    cmd: function (s, cb2) {
      if (typeof cb2 !== 'function') {
        cb2 = function () {console.error('lost promise');};
      }
      try {
        s = util.cleanCmd(s);
        switch (typeof r2cmd) {
          case 'string':
            pipeCmd.bind(r2)(ls, s, cb2);
            break;
          case 'function':
            r2cmd(ls.cmdparm, s, cb2);
            break;
        }
      } catch (e) {
        cb2(e);
      }
    },

    /* Run cmd and return JSON output */
    cmdj: function (s, cb2) {
      if (typeof cb2 !== 'function') {
        cb2 = function () {};
      }
      try {
        s = util.cleanCmd(s);
        parseJSON(r2.cmd, s, cb2);
      } catch (e) {
        cb2(e);
      }
    },

    /* Run system cmd */
    syscmd: syscmd,
    syscmdj: syscmdj,

    /* Quit CMD */
    quit: function (callback) {
      if (typeof ls.stdin === 'object' && typeof ls.stdin.end === 'function') {
        ls.stdin.end(); // i think this can be removed
      }
      ls.kill('SIGINT');
      if (typeof callback === 'function') {
        callback();
      }
    }
  };

  /* handle SDTERR message */
  if (ls.stderr !== null) {
    ls.stderr.on('data', function (data) {
      /* Set as running for connect & launch methods */
      if (typeof errmsg === 'string') {
        errmsg += data.toString();
        if (errmsg.length > 1024 * 32) {
          errmsg = null;
        }
      }
      if (!running && (typeof r2cmd !== 'string')) {
        running = true;
        if (typeof cb === 'function') {
          cb(null, r2);
        } else {
          throw new Error('Callback in .cmd() is not a function');
        }
      }
    });
  }

  /* handle STDOUT nessages */
  if (ls.stdout !== null) {
    ls.stdout.on('data', data => {
      /* Set as running for pipe method */
      if (running) {
        if (typeof r2cmd === 'string') {
          pipeCmdOutput.bind(r2)(ls, data, cb);
        }
      } else {
        running = true;
        cb(null, r2);
      }
    });
  } else {
    cb(null, r2); // Callback for connect
  }

  /* Proccess event handling only for methods using childs */
  if (typeof ls.on === 'function') {
    ls.on('error', function (err) {
      running = false;
      console.log(err);
    });

    ls.on('close', function (code, signal) {
      running = false;
      let error = errmsg ? errmsg : '';
      if (signal) {
        cb(new Error('Child received signal ' + signal + '\n' + error));
      } else if (code && r2cmd.toString().indexOf('httpCmd') === -1) {
        cb(new Error('Cannot spawn children with code ' + code + '\n' + error));
      }
    });
  }

  /* lpipe (rlangpipe) is ready from the start and does not
   * require to wait for any input from stdin or stdout */
  if (!running && (r2cmd === 'lpipe')) {
    running = true;
    cb(null, r2);
  }
}

function isPath (text) {
  return (text && (text[0] === '.' || text[0] === '/' || fs.existsSync(text)));
}

function isAvailable () {
  return !isNaN(IN);
}

const r2node = {
  r2bin: 'radare2',
  options: [],
  jsonParse: JSON.parse,
  isAvailable: isAvailable,
  syscmd: syscmd,
  syscmdj: syscmdj,
  open: function () {
    // XXX shrink this spaguetti somehow
    const modes = [
      function (me, arg) { // 0 args
        return me.lpipeSync();
      },
      function (me, arg) { // 1 arg
        if (typeof (arg[0]) === 'function') {
          return me.lpipe(arg[0]);
        }
        if (isPath(arg[0])) {
          return me.pipeSync(arg[0]);
        }
        return me.lpipe(arg[0]);
      },
      function (me, arg) { // 2 args
        if (!arg[0]) {
          const cb = arg[1];
          return me.lpipe(cb);
          // throw new Error('Invalid path');
        } else if (isPath(arg[0])) {
          me.pipe(arg[0], arg[1]);
        } else if (arg[0].startsWith('http://')) {
          me.connect(arg[0], arg[1]);
        } else if (arg[0].startsWith('io://')) {
          me.connect(arg[0], arg[1]);
        } else {
          me.pipe(arg[0], arg[1]);
          // throw new Error('Unknown URI');
        }
      },
      function (me, arg) { // 3 args
        if (!arg[0]) {
          throw new Error('Invalid path');
        }
        if (isPath(arg[0])) {
          me.pipe(arg[0], arg[1], arg[2]);
        } else if (arg[0].startsWith('http://')) {
          me.connect(arg[0], arg[1], arg[2]);
        } else if (arg[0].startsWith('io://')) {
          me.connect(arg[0], arg[1], arg[2]);
        } else {
          me.pipe(arg[0], arg[1], arg[2]);
          // throw new Error('Unknown URI');
        }
      }
    ];
    if (arguments.length < modes.length) {
      return modes[arguments.length](this, arguments);
    }
    throw new Error('Invalid parameters' + arguments.length);
  },
  openSync: function () {
    const args = [...arguments].filter(x => x !== undefined);
    let msg;
    switch (args.length) {
      case 0:
        return this.lpipeSync();
      case 1:
        if (isPath(args[0])) {
          return this.pipeSync(arguments[0]);
        } else if (args.indexOf('http://') === 0) {
          msg = 'httpsync not supported';
        } else if (args.indexOf('io://') === 0) {
          msg = 'iosync not supported';
        } else {
          msg = 'Unknown uri';
        }
        break;
      default:
        msg = 'Invalid parameters';
    }
    if (typeof msg !== 'undefined') {
      throw new Error(msg);
    }
  },

  openBuffer: function (buf, cb) {
    const server = net.createServer(client => {
      client.write(buf, null, _ => {
        client.destroy();
        server.close();
      });
    });
    server.listen(0, _ => {
      const port = server.address().port;
      this.pipe('tcp://127.0.0.1:' + port, cb);
    });
  },

  connect: function (uri, cb) {
    var ls = {
      cmdparm: uri,
      stderr: null,
      stdout: null,
      kill: function () {}
    };
    r2bind(ls, cb, httpCmd);
  },

  /* TCP connection */
  launch: function (file, opts, cb) {
    if (typeof opts === 'function') {
      cb = opts;
      opts = this.options;
    }
    const port = (4000 + (Math.random() * 4000)) | 0;
    const ls = proc.spawn(this.r2bin, ['-qc.:' + port].concat(...opts).concat(file));
    ls.cmdparm = port;
    r2bind(ls, cb, remoteCmd);
  },

  /* spawn + raw fd pipe (faster method) */
  pipe: function (file, opts, cb) {
    if (typeof opts === 'function') {
      cb = opts;
      opts = this.options;
    }
    if (!opts) {
      opts = this.options;
    }
    const args = ['-q0'].concat(opts).concat(file);
    const ls = proc.spawn(this.r2bin, args);
    r2bind(ls, cb, 'pipe');
  },

  lpipe: function (cb) {
    let ls;

    if (os.platform() === 'win32') {
      const client = net.connect('\\\\.\\pipe\\' + R2PIPE_PATH);
      ls = {
        stdin: client,
        stdout: client,
        stderr: null,
        kill: function () {
          ls.stdin.destroy();
          ls.stdout.destroy();
          process.exit(0);
        }
      };
    } else {
      /* OS: linux/sunos/osx */
      if (!IN || !OUT) {
        throw new Error('This script needs to run from radare2 with r2pipe://');
      }
      ls = {
        stdin: fs.createWriteStream(null, {
          fd: OUT
        }),
        stdout: fs.createReadStream(null, {
          fd: IN
        }),
        stderr: null,
        kill: function () {
          process.exit(0);
        }
      };
    }

    r2bind(ls, cb, 'lpipe');
  },

  pipeSync: function (file, opts) {
    throw new Error('ERROR: sync r2pipe apis have been deprecated');
  },

  lpipeSync: function () {
    if (!IN || !OUT) {
      throw new Error('This script needs to run from radare2 with r2pipe://');
    }
    var ls = {
      syncStdin: OUT,
      syncStdout: IN,
      stderr: null,
      kill: function () {
        process.exit(0);
      }
    };

    return sync.r2bind(ls, 'lpipe');
  },

  listen: function (file, cb) {
    // TODO
  },

  ioplugin: function (cb) {
    const nfdIn = +process.env.R2PIPE_IN;
    const nfdOut = +process.env.R2PIPE_OUT;

    if (!nfdIn || !nfdOut) {
      throw new Error('This script needs to run from radare2 with r2pipe://');
    }

    const fdIn = fs.createReadStream(null, {
      fd: nfdIn
    });
    const fdOut = fs.createWriteStream(null, {
      fd: nfdOut
    });

    console.error('[+] Running r2pipe io');

    fdIn.on('end', function () {
      console.error('[-] r2pipe-io is over');
    });
    /* send initial byte to initialize the r2pipe stream */
    /* this thing can change in the future. and should be */
    /* enforced to bring better errors to the user */
    fdOut.write('\x00\x00');
    function send (obj) {
      // console.error ("Send Object To R2",obj);
      fdOut.write(JSON.stringify(obj || {}) + '\x00');
    }

    fdIn.on('data', function (data) {
      const trimmedData = data.slice(0, -1).toString().trim();
      if (cb) {
        cb({ 'send': send }, r2node.jsonParse(trimmedData));
      }
    });
  }
};

module.exports = r2node;
