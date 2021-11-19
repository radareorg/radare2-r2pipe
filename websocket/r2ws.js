var queue = [];

var ws = null;
var r2ws = {};

r2ws.quit = function r2ws_quit (cb) {
  ws.close();
  return cb();
};

r2ws.cmd = function r2ws_cmd (cmd, cb) {
  if (ws === null) {
    console.error('not connected');
    return;
  }
  queue.push(cb);
  ws.send(cmd);
};

r2ws.open = function r2ws_open (addr, file, cb) {
  ws = new WebSocket(addr);
  ws.onmessage = function (event) {
    first = queue[0];
    queue = queue.slice(1);
    if (first) {
      first(event.data);
    }
  };
  ws.onopen = function (event) {
    r2ws.cmd('o ' + file);
    if (cb) {
      cb(null, r2ws);
    }
  };
  return {
    ws: ws,
    cmd: r2ws.cmd,
    quit: r2ws.quit
  };
};

r2ws.open('ws://127.0.0.1:5678', '/bin/ls', function (err, r2) {
  r2.cmd('x', console.log);
});
