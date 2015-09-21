var fs = require('fs');
var net = require('net');
var http = require('http');
var sync = require('./sync.js');
var proc = require('child_process');
var promise = require('./promise.js');

var pipeQueue = [];


var IN = parseInt(process.env.R2PIPE_IN);
var OUT = parseInt(process.env.R2PIPE_OUT);


/*
 * CMD handlers for different connection methods
 */

function remoteCmd(port, cmd, cb) {
  var msg = "";
  try {
    var client = new net.Socket();
    client.connect(port, "localhost", function() {});
    client.write (cmd + "\n");
    client.on('data', function(data) {
      msg += data;
    });

    // Add a 'close' event handler for the client socket
    client.on('close', function() {
      if (cb) {
        cb (msg);
      }
    });
  } catch ( e ) {
    console.error (e);
  }
}

function httpCmd(uri, cmd, cb) {
  var text = "";
  var req = http.get(uri + cmd, function(res) {
    res.on("data", function(res) {
      text += res;
    });
  }).on ("error", function(res) {
    console.log("Got response: " + res.statusCode);
  });
  req.on('close', function(e) {
    cb (text);
  });
}


function pipeCmd(proc, cmd, cb) {
  pipeQueue.push({
    cmd: cmd,
    cb: cb,
    result: '',
    error: false
  });
  if (pipeQueue.length === 1) {
    proc.stdin.write(cmd + "\n");
  }
}


function pipeCmdOutput(proc, data) {
  var len = data.length;
  var response;

  if (pipeQueue.length < 1) {
    console.error("r2pipe error: No pending commands for incomming data");
    return;
  }

  if (data[len - 1] !== 0x00) {
    pipeQueue[0].result += data.toString();
    return;
  }

  pipeQueue[0].result += data.toString().substr(0, len - 1);

  response = (pipeQueue[0].error) ? null : pipeQueue[0].result;

  pipeQueue[0].cb(response);
  pipeQueue.splice(0, 1);

  if (pipeQueue.length > 0) {
    proc.stdin.write(pipeQueue[0].cmd + "\n");
  }
}


function parseJSON(func, cmd, callback) {
  func(cmd, function(res) {
    var result;
    if (res === null) {
      callback(null);
      return;
    }

    try {
      result = JSON.parse(res);
    } catch ( e ) {
      result = null;
    } finally {
      callback(result);
    }
  });
}




/*
 * r2pipe main
 */

function r2bind(ls, cb, r2cmd) {
  var running = false;

  var r2 = {

    /* Run cmd and return plaintext output */
    cmd: function(s, cb2) {
      if (typeof cb2 !== 'function') {
        cb2 = function() {};
      }
      if (typeof r2cmd === 'string') {
        pipeCmd(ls, s, cb2);
      } else if (typeof r2cmd === 'function') {
        r2cmd (ls.cmdparm, s, cb2);
      }
    },

    /* Run cmd and return JSON output */
    cmdj: function(s, cb2) {
      if (typeof cb2 !== 'function') {
        cb2 = function() {};
      }
      parseJSON(r2.cmd, s, cb2);
    },

    /* Run system cmd */
    syscmd: function(command, cb2) {
      if (typeof cb2 !== 'function') {
        cb2 = function() {};
      }
      var child = proc.exec(command, function(err, stdout, stderr) {
        if (err) {
          cb2 (null);
        } else {
          cb2 (stdout);
        }
      });
    },

    /* Run system cmd and return JSON output */
    syscmdj: function(command, cb2) {
      if (typeof cb2 !== 'function') {
        cb2 = function() {};
      }
      parseJSON(r2.syscmd, command, cb2);
    },

    /* Quit CMD */
    quit: function() {
      if (ls.stdin && ls.stdin.end)
        ls.stdin.end();
      ls.kill ('SIGINT');
    },

    /* Custom promises */
    promise: function(func, cmd, callback) {
      return new promise.Promise(func, cmd, callback);
    }
  };


  /* handle SDTERR message */
  if (ls.stderr !== null) {
    ls.stderr.on('data', function(data) {

      /* Set as running for connect & launch methods */
      if (!running && (typeof r2cmd !== 'string')) {
        running = true;
        cb(r2);
      }
    });
  }


  /* handle STDOUT nessages */
  ls.stdout.on('data', function(data) {

    /* Set as running for pipe method */
    if (!running) {
      running = true;
      cb (r2);
    } else if (running && (typeof r2cmd === 'string')) {
      pipeCmdOutput (ls, data);
    }
  });


  /* Proccess event handling only for methods using childs */
  if (typeof ls.on === 'function') {
    ls.on('error', function(code) {
      running = false;
      console.log('ERROR');
    });

    ls.on('close', function(code) {
      running = false;
      if (code !== 0) {
        console.log('r2pipe: child process exited with code ' + code);
      }
    });
  }

  /* rlangpipe is ready from the start and does not
   * require to wait for any input from stdin or stdout */
  if (!running && (r2cmd === 'rlangpipe')) {
    running = true;
    cb(r2);
  }
}

function ispath(text) {
  return (text[0] == '.' || text[0] == '/');
}

var r2node = {

  open: function() {
    const arg = arguments;
    switch (arg.length) {
    case 1:
      this.rlangpipe (arg[0]);
      break;
    case 2:
      if (ispath (arg[0])) {
        this.pipe(arg[0], arg[1]);
      } else if (arg.indexOf('http://')==0) {
        this.connect(arg[0], arg[1]);
      } else if (arg.indexOf('io://')==0) {
        this.connect(arg[0], arg[1]);
      } else {
        throw "Unknown uri";
      }
      break;
    default:
      throw "Invalid parameters";
    }
  },

  openSync: function() {
    const arg = arguments;
    switch (arg.length) {
    case 0:
      return this.lpipeSync();
    case 1:
      if (ispath(arg[0])) {
        return this.pipeSync (arg[0]);
      } else if (arg.indexOf('http://')==0) {
        throw "httpsync not supported";
      } else if (arg.indexOf('io://')==0) {
        throw "iosync not supported";
      } else {
        throw "Unknown uri";
      }
      break;
    default:
      throw "Invalid parameters";
    }
  },

  connect: function(uri, cb) {
    var ls = proc.spawn('r2', ["-qc.:" + uri]);
    ls.cmdparm = uri;
    r2bind (ls, cb, httpCmd);
  },

  launch: function(file, cb) {
    var port = (4000 + (Math.random() * 4000)) | 0;
    var ls = proc.spawn('r2', ["-qc.:" + port, file]);
    ls.cmdparm = port;
    r2bind (ls, cb, remoteCmd);
  },

  pipe: function(file, cb) {
    var ls = proc.spawn('r2', ["-q0", file]);
    r2bind (ls, cb, 'pipe');
  },

  rlangpipe: function(cb) {
    var ls = {
      stdin: fs.createWriteStream (null, {
        fd: OUT
      }),
      stdout: fs.createReadStream (null, {
        fd: IN
      }),
      stderr: null,
      kill: function() {
        process.exit(0);
      }
    };
    r2bind (ls, cb, 'rlangpipe');
  },

  lpipe: function(cb) {
    this.rlangpipe(cb);
  },

  pipeSync: function(file) {
    var pipe, syspipe;
    try {
      syspipe = require('syspipe');
      pipe = syspipe.pipe();
    } catch (e) {
      throw 'ERROR: pipeSync() is not available in this system';
    }

    var options = { stdio: ['pipe', pipe.write, 'ignore'] };
    var ls = proc.spawn('r2', ["-q0", file], options);

    ls.syncStdin = ls.stdin['_handle'].fd;
    ls.syncStdout = pipe.read;

    return sync.r2bind(ls, 'pipe');
  },

  lpipeSync: function() {
    var ls = {
      syncStdin: OUT,
      syncStdout: IN,
      stderr: null,
      kill: function() {
        process.exit(0);
      }
    };

    return sync.r2bind(ls, 'lpipe');
  },

  listen: function(file, cb) {
    // TODO
  },

  ioplugin: function(cb) {
    var fs = require ('fs');
    var nfd_in = +process.env.R2PIPE_IN;
    var nfd_out = +process.env.R2PIPE_OUT;

    if (!nfd_in || !nfd_out) {
      throw "This script needs to run from radare2 with r2pipe://";
    }

    var fd_in = fs.createReadStream(null, {
      fd: nfd_in
    });
    var fd_out = fs.createWriteStream(null, {
      fd: nfd_out
    });

    console.log ("[+] Running r2pipe io");

    fd_in.on('end', function() {
      console.log ("[-] r2pipe-io is over");
    });
    function send(obj) {
      //console.log ("Send Object To R2",obj);
      fd_out.write (JSON.stringify (obj || {}) + "\x00");
    }

    fd_in.on('data', function(data) {
      data = data.slice (0, -1);
      var obj_in = JSON.parse (data);
      if (cb) {
        var me = {
          'send': send
        };
        cb (me, obj_in);
      }
    });
  }
};

module.exports = r2node;
