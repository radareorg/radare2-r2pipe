'use strict';

const os = require('os');
const fs = require('fs');
const net = require('net');
const http = require('http');
const sync = require('./sync.js');
const util = require('./util');
const proc = require('child_process');
const promise = require('./promise.js');
const pipeQueue = [];

var IN, OUT, R2PIPE_PATH;

try {
  IN = parseInt(process.env.R2PIPE_IN);
  OUT = parseInt(process.env.R2PIPE_OUT);
  R2PIPE_PATH = process.env.R2PIPE_PATH;
} catch (e) {
  /* do nothing */
}

function mergeArrays (a, b) {
  let c = a.concat(b);
  return c.filter((i, p) => {
    return c.indexOf(i) === p;
  });
}

/*
 * CMD handlers for different connection methods
 */
function syscmd (command, childOpts, cb) {
  const childopt = {};
  switch (typeof childOpts) {
    case 'object':
      childopt = childOpts;
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
    proc.exec(command, childopt, callback);
  } else if (typeof command === 'object' && command.length > 0) {
    proc.execFile(command[0], command.slice(1), childopt, callback);
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
  }).on('error', function (res) {
    cb(new Error('http ' + res.statusCode));
  });
  req.on('close', function (e) {
    cb(null, text);
  });
}

function pipeCmd (proc, cmd, cb) {
  pipeQueue.push({
    cmd: cmd,
    cb: cb,
    result: '',
    error: false
  });
  if (pipeQueue.length === 1) {
    proc.stdin.write(cmd + '\n');
  }
}

function pipeCmdOutput (proc, data, cb) {
  var len = data.length;
  var response;

  if (pipeQueue.length < 1) {
    return cb(new Error('r2pipe error: No pending commands for incomming data'));
  }

  if (data[len - 1] !== 0x00) {
    return pipeQueue[0].result += data.toString();
  }

  pipeQueue[0].result += data.toString().substr(0, len - 1);
  pipeQueue[0].cb(pipeQueue[0].error, pipeQueue[0].result);
  pipeQueue.splice(0, 1);

  if (pipeQueue.length > 0) {
    proc.stdin.write(pipeQueue[0].cmd + '\n');
  }
}

function parseJSON (func, cmd, callback) {
  func(cmd, function (error, res) {
    if (error) {
      return callback(error);
    }
    try {
      callback(null, JSON.parse(res));
    } catch (e) {
      callback(e);
    } finally {
    }
  });
}

/*
 * r2pipe main
 */

function r2bind (ls, cb, r2cmd) {
  var running = false;

  const r2 = {

    /* Run cmd and return plaintext output */
    cmd: function (s, cb2) {
      s = util.cleanCmd(s);
      if (typeof cb2 !== 'function') {
        cb2 = function () {};
      }
      if (typeof r2cmd === 'string') {
        pipeCmd(ls, s, cb2);
      } else if (typeof r2cmd === 'function') {
        r2cmd(ls.cmdparm, s, cb2);
      }
    },

    /* Run cmd and return JSON output */
    cmdj: function (s, cb2) {
      s = util.cleanCmd(s);
      if (typeof cb2 !== 'function') {
        cb2 = function () {};
      }
      parseJSON(r2.cmd, s, cb2);
    },

    /* Run system cmd */
    syscmd: syscmd,
    syscmdj: syscmdj,

    /* Quit CMD */
    quit: function () {
      if (ls.stdin && ls.stdin.end) {
        ls.stdin.end();
      }
      ls.kill('SIGINT');
    },

    /* Custom promises */
    promise: function (func, cmd, callback) {
      return new promise.Promise(func, cmd, callback);
    }
  };

  /* handle SDTERR message */
  if (ls.stderr !== null) {
    ls.stderr.on('data', function (data) {
      /* Set as running for connect & launch methods */
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
    ls.stdout.on('data', function (data) {
      /* Set as running for pipe method */
      if (running) {
        if (typeof r2cmd === 'string') {
          pipeCmdOutput(ls, data, cb);
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
    ls.on('error', function (code) {
      running = false;
      console.log('ERROR');
    });

    ls.on('close', function (code) {
      running = false;
      if (code && r2cmd.toString().indexOf('httpCmd') === -1) {
        console.log('r2pipe: child process exited with code ' + code);
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

function ispath (text) {
  return (text[0] === '.' || text[0] === '/' || fs.existsSync(text));
}

const r2node = {
  r2bin: 'radare2',
  options: [],
  syscmd: syscmd,
  syscmdj: syscmdj,
  open: function () {
    const modes = [
      function (me, arg) {
        return me.lpipeSync();
      },
      function (me, arg) {
        if (ispath(arg[0])) {
          return me.pipeSync(arg[0]);
        }
        return me.lpipe(arg[0]);
      },
      function (me, arg) {
        if (ispath(arg[0])) {
          me.pipe(arg[0], arg[1]);
        } else if (arg[0].startsWith('http://')) {
          me.connect(arg[0], arg[1]);
        } else if (arg[0].startsWith('io://')) {
          me.connect(arg[0], arg[1]);
        } else {
          throw new Error('Unknown URI');
        }
      }
    ];
    if (arguments.length < modes.length) {
      return modes[arguments.length](this, arguments);
    } else {
      throw new Error('Invalid parameters');
    }
  },
  openSync: function () {
    let msg;
    switch (arguments.length) {
      case 0:
        return this.lpipeSync();
      case 1:
        if (ispath(arguments[0])) {
          return this.pipeSync(arguments[0]);
        } else if (arguments.indexOf('http://') === 0) {
          msg = 'httpsync not supported';
        } else if (arguments.indexOf('io://') === 0) {
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
    var port = (4000 + (Math.random() * 4000)) | 0;
    var ls = proc.spawn(this.r2bin, ['-qc.:' + port].concat(opts).concat(file));
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
    var ls;

    if (os.platform() === 'win32') {
      const client = net.connect('\\\\.\\pipe\\' + R2PIPE_PATH);
      ls = {
        stdin: client,
        stdout: client,
        stderr: null,
        kill: function () {
          process.exit(0);
        }
      };
    } else {
      /* OS: linux/sunos/osx */
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
    var pipe, syspipe;
    try {
      syspipe = require('syspipe');
      pipe = syspipe.pipe();
    } catch (e) {
      throw new Error('ERROR: Cannot find "syspipe" npm module');
    }
    if (typeof opts !== 'object') {
      opts = this.options;
    }
    var procOptions = {
      stdio: ['pipe', pipe.write, 'ignore']
    };
    var ls = proc.spawn(this.r2bin,
      ['-q0'].concat(opts).concat(file), procOptions);

    ls.syncStdin = ls.stdin['_handle'].fd;
    ls.syncStdout = pipe.read;

    return sync.r2bind(ls, 'pipe');
  },

  lpipeSync: function () {
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
    var fs = require('fs');
    var nfd_in = +process.env.R2PIPE_IN;
    var nfd_out = +process.env.R2PIPE_OUT;

    if (!nfd_in || !nfd_out) {
      throw new Error('This script needs to run from radare2 with r2pipe://');
    }

    var fd_in = fs.createReadStream(null, {
      fd: nfd_in
    });
    var fd_out = fs.createWriteStream(null, {
      fd: nfd_out
    });

    console.error('[+] Running r2pipe io');

    fd_in.on('end', function () {
      console.error('[-] r2pipe-io is over');
    });
    /* send initial byte to initialize the r2pipe stream */
    /* this thing can change in the future. and should be */
    /* enforced to bring better errors to the user */
//    fd_out.write('\x00');
    function send (obj) {
      // console.error ("Send Object To R2",obj);
      fd_out.write(JSON.stringify(obj || {}) + '\x00');
    }

    fd_in.on('data', function (data) {
      var trimmedData = data.slice(0, -1).toString().trim();
      var obj_in = JSON.parse(trimmedData);
      if (cb) {
        var me = {
          'send': send
        };
        cb(me, obj_in);
      }
    });
  }
};

module.exports = r2node;
