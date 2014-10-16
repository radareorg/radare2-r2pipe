var net = require('net');
var http = require('http');
var proc = require('child_process');

var pipeQueue = [];

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



function r2bind(file, cb, r2cmd) {
  var port = (file.indexOf("http") != -1) ? file
  : (4000 + (Math.random() * 4000)) | 0; // TODO must be random
  if (r2cmd !== null) {
    /* TODO :implement local http API 
    	// Http
      var ls = proc.spawn('r2', ["-qe","http.port="+port, "-c=h", file]);
    */
    var ls = proc.spawn('r2', ["-qc.:" + port, file]);
  } else {
    var ls = proc.spawn('r2', ["-q0", file]);
  }
  var running = false;

  var r2 = {
    /* Run cmd and return plaintext output */
    cmd: function(s, cb2) {
      if (r2cmd === null) {
        pipeCmd(ls, s, cb2);
      } else {
        r2cmd (port, s, cb2);
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

    /* Quit CMD */
    quit: function() {
      ls.stdin.end();
      ls.kill ('SIGINT');
    }
  };


  /* SDTERR message */
  ls.stderr.on('data', function(data) {
    // TODO find a good way to handle stderr messages

    //console.log('stderr: ' + data);
    if (!running && r2cmd) {
      running = true;
      cb(r2);
    }
  });

  /* STDOUT nessages */
  ls.stdout.on('data', function(data) {
    //console.log('stdout: ' + data);
    if (!running) {
      running = true;
      cb (r2);
    } else if (running && !r2cmd) {
      pipeCmdOutput (ls, data);
    } else {
      console.log ("r2pipe: wtf");
    }
  });

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


var r2node = {
  // TODO
  // - listen()
  // - rap()
  connect: function(uri, cb) {
    r2bind (uri, cb, httpCmd);
  },
  launch: function(file, cb) {
    r2bind (file, cb, remoteCmd);
  },
  pipe: function(file, cb) {
    r2bind (file, cb, null);
  },
  listen: function(file, cb) {
    // TODO
  }
}

module.exports = r2node;
