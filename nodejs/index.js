var fs = require('fs');
var net = require('net');
var http = require('http');
var proc = require('child_process');

var pipeQueue = [];



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


function syscmd(cmd, callback) {

}




/*
 * r2pipe main
 */

function r2bind(ls, cb, r2cmd) {
  var running = false;

  var r2 = {

    /* Run cmd and return plaintext output */
    cmd: function(s, cb2) {
      if (typeof r2cmd === 'string') {
        pipeCmd(ls, s, cb2);
      } else if (typeof r2cmd === 'function') {
        r2cmd (ls.cmdparm, s, cb2);
      }
    },

    /* Run cmd and return JSON output */
    cmdj: function (s, cb2) {
      r2.cmd(s, function (res) {
        if (res === null) {
          cb2(null);
          return;
        }

        try {
          cb2(JSON.parse(res));
        } catch (e) {
          cb2(null);
        }
      });
    },

    /* Run system cmd */
    syscmd: function (command, cb2) {
      var child = proc.exec(command, function(err, stdout, stderr) {
        if (err)
          cb2 (null);
        else
          cb2 (stdout);
      });
    },

    /* Run system cmd and return JSON output */
    syscmdj: function (command, cb2) {
      r2.syscmd(command, function (res) {
        if (res === null) {
          cb2(null);
          return;
        }

        try {
          cb2(JSON.parse(res));
        } catch (e) {
          cb2(null);
        }
      });
    },

    /* Quit CMD */
    quit: function() {
      ls.stdin.end();
      ls.kill ('SIGINT');
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
      if (code != 0) {
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


var r2node = {

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
    var IN = +process.env.R2PIPE_IN;
    var OUT = +process.env.R2PIPE_OUT;

    var ls = {
      stdin: fs.createWriteStream (null, {fd: OUT}),
      stdout: fs.createReadStream (null, {fd: IN}),
      stderr: null,
      kill: function () {
        process.exit(0);
        process.kill(process.pid, 'SIGKILL');
      }
    };

    r2bind (ls, cb, 'rlangpipe');
  },

  listen: function(file, cb) {
    // TODO
  }
};

module.exports = r2node;
