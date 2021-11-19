/* radare2 Copyleft 2013-2021 pancake */

var r2 = {};

// TODO: avoid globals
var backward = false;
var next_curoff = 0;
var next_lastoff = 0;
var prev_curoff = 0;
var prev_lastoff = 0;
var hascmd = false;
var r2_root = self.location.pathname.split('/').slice(0, -2).join('/');

// Valid options: sync, async or sasync
// r2.asyncMode = 'sasync';
r2.asyncMode = 'sync';

r2.err = null; // callback to be executed when connection fails

r2.root = r2_root;

// async helper
function asyncLoop (iterations, func, callback) {
  var index = 0;
  var done = false;
  var loop = {
    next: function () {
      if (done) {
        return;
      }

      if (index < iterations) {
        index++;
        func(loop);
      } else {
        done = true;
        callback();
      }
    },

    iteration: function () {
      return index - 1;
    },

    break: function () {
      done = true;
      callback();
    }
  };
  loop.next();
  return loop;
}

if (typeof (module) !== 'undefined') {
  module.exports = function (r) {
    if (typeof (r) === 'function') {
      hascmd = r;
    } else {
      hascmd = r.cmd;
    }
    return r2;
  };
}

r2.project_name = '';

r2.plugin = function () {
  console.error('r2.plugin is not available in this environment');
};
try {
  if (r2plugin) {
    r2.plugin = r2plugin;
  }
} catch (e) {}

r2.root = r2_root; // prefix path

/* helpers */
function dump (obj) {
  var x = '';
  for (var a in obj) {
    x += a + '\n';
  }
  if (typeof ('alert') !== 'undefined') {
    alert(x);
  } else {
    console.log(x);
  }
}



function objtostr (obj) {
  var str = '';
  for (var a in obj) {
    str += a + ': ' + obj[a] + ',\n';
  }
  return str;
}

var ajax_in_process = false;

function Ajax (method, uri, body, fn, err) {
  if (typeof (XMLHttpRequest) === 'undefined') {
    return false;
  }
  if (r2.asyncMode == 'fake') {
    if (fn) {
      fn('{}');
    }
    return true;
  }
  if (r2.asyncMode == 'sasync') {
    console.log('async waiting');
    if (ajax_in_process) {
      setTimeout(function () {
        Ajax(method, uri, body, fn);
      }, 100);
      return false;
    }
  }

  var x = undefined;
    var x = new XMLHttpRequest();
  if (!x) {
    return false;
  }
  ajax_in_process = true;
  if (r2.asyncMode == 'sync') {
    x.open(method, uri, false);
  } else {
    x.open(method, uri, true);
  }
  x.setRequestHeader('Accept', 'text/plain');
  // x.setRequestHeader ('Accept', 'text/html');
  x.setRequestHeader('Content-Type', 'application/x-ww-form-urlencoded; charset=UTF-8');
  x.onreadystatechange = function () {
    ajax_in_process = false;
    if (x.status == 200) {
      if (x.readyState < 4) {
        // wait until request is complete
        return;
      }
      if (fn) {
        fn(x.responseText);
      } else {
        console.error('missing ajax callback');
      }
    } else {
      (err || r2.err)('connection refused');
      console.error('ajax ' + x.status);
    }
  };

  try {
    x.send(body);
  } catch (e) {
    if (e.name == 'NetworkError') {
      (err || r2.err)('connection error');
    }
  }

  return true;
}

r2.cmds = function (cmds, cb) {
  if (cmds.length == 0) return;
  var cmd = cmds[0];
  cmds = cmds.splice(1);
  function lala () {
    if (cmd == undefined || cmds.length == 0) {
      return;
    }
    cmd = cmds[0];
    cmds = cmds.splice(1);
    r2.cmd(cmd, lala);
    if (cb) {
      cb();
    }
  }
  r2.cmd(cmd, lala);
};

function _internal_cmd (c, cb, err) {
  if (typeof (r2cmd) !== 'undefined') {
    hascmd = r2cmd;
  }
  if (hascmd) {
    // TODO: use setTimeout for async?
    if (typeof (r2plugin) !== 'undefined') {
      // duktape
      return cb(r2cmd(c));
    } else {
      // node
      return hascmd(c, cb);
    }
  } else {
    Ajax('GET', r2.root + '/cmd/' + encodeURI(c), '', function (x) {
      if (cb) {
        cb(x);
      }
    }, err);
  }
}

r2.cmd = function (c, cb, err) {
  if (Array.isArray(c)) {
    var res = [];
    var idx = 0;
    asyncLoop(c.length, function (loop) {
      _internal_cmd(c[idx], function (result) {
        idx = loop.iteration();
        res[idx] = result.replace(/\n$/, '');
        idx++;
        loop.next();
      }, err);
    }, function () {
      // all iterations done
      cb(res);
    });
  } else {
    _internal_cmd(c, cb, err);
  }
};

r2.cmdj = function (c, cb) {
  r2.cmd(c, function (x) {
    try {
      cb(JSON.parse(x));
    } catch (e) {
      cb(null);
    }
  });
};

r2.alive = function (cb) {
  r2.cmd('b', function (o) {
    var ret = false;
    if (o && o.length() > 0) {
      ret = true;
    }
    if (cb) {
      cb(o);
    }
  });
};

r2.filter_asm = function (x, display) {
  var curoff = backward ? prev_curoff : next_curoff;

  var lastoff = backward ? prev_lastoff : next_lastoff;

  var lines = x.split(/\n/g);
  r2.cmd('s', function (x) {
    curoff = x;
  });
  for (var i = lines.length - 1; i > 0; i--) {
    var a = lines[i].match(/0x([a-fA-F0-9]+)/);
    if (a && a.length > 0) {
      lastoff = a[0].replace(/:/g, '');
      break;
    }
  }
  if (display == 'afl') {
    // hasmore (false);
    var z = '';
    for (var i = 0; i < lines.length; i++) {
      var row = lines[i].replace(/\ +/g, ' ').split(/ /g);
      z += row[0] + '  ' + row[3] + '\n';
    }
    x = z;
  } else if (display[0] == 'f') {
    // hasmore (false);
    if (display[1] == 's') {
      var z = '';
      for (var i = 0; i < lines.length; i++) {
        var row = lines[i].replace(/\ +/g, ' ').split(/ /g);
        var mark = row[1] == '*' ? '*' : ' ';
        var space = row[2] ? row[2] : row[1];
        if (!space) continue;
        z += row[0] + ' ' + mark + ' <a href="javascript:runcmd(\'fs ' +
				space + '\')">' + space + '</a>\n';
      }
      x = z;
    } else {
    }
  } else if (display[0] == 'i') {
    // hasmore (false);
    if (display[1]) {
      var z = '';
      for (var i = 0; i < lines.length; i++) {
        var elems = lines[i].split(/ /g);
        var name = '';
        var addr = '';
        for (var j = 0; j < elems.length; j++) {
          var kv = elems[j].split(/=/);
          if (kv[0] == 'addr') {
            addr = kv[1];
          }
          if (kv[0] == 'name') {
            name = kv[1];
          }
          if (kv[0] == 'string') {
            name = kv[1];
          }
        }
        z += addr + '  ' + name + '\n';
      }
      x = z;
    }
  } // else hasmore (true);

  function haveDisasm (x) {
    if (x[0] == 'p' && x[1] == 'd') return true;
    if (x.indexOf(';pd') != -1) return true;
    return false;
  }
  if (haveDisasm(display)) {
    //	x = x.replace(/function:/g, '<span style=color:green>function:</span>');
    /*
		x = x.replace(/;(\s+)/g, ';');
		x = x.replace(/;(.*)/g, '// <span style=\'color:#209020\'>$1</span>');
		x = x.replace(/(bl|goto|call)/g, '<b style=\'color:green\'>call</b>');
		x = x.replace(/(jmp|bne|beq|js|jnz|jae|jge|jbe|jg|je|jl|jz|jb|ja|jne)/g, '<b style=\'color:green\'>$1</b>');
		x = x.replace(/(dword|qword|word|byte|movzx|movsxd|cmovz|mov\ |lea\ )/g, '<b style=\'color:#1070d0\'>$1</b>');
		x = x.replace(/(hlt|leave|iretd|retn|ret)/g, '<b style=\'color:red\'>$1</b>');
		x = x.replace(/(add|sbb|sub|mul|div|shl|shr|and|not|xor|inc|dec|sar|sal)/g, '<b style=\'color:#d06010\'>$1</b>');
		x = x.replace(/(push|pop)/g, '<b style=\'color:#40a010\'>$1</b>');
		x = x.replace(/(test|cmp)/g, '<b style=\'color:#c04080\'>$1</b>');
		x = x.replace(/(outsd|out|string|invalid|int |int3|trap|main|in)/g, '<b style=\'color:red\'>$1</b>');
		x = x.replace(/nop/g, '<b style=\'color:blue\'>nop</b>');
*/
    x = x.replace(/(reloc|class|method|var|sym|fcn|str|imp|loc)\.([^:<(\\\/ \|\])\->]+)/g, '<a href=\'javascript:r2ui.seek("$1.$2")\'>$1.$2</a>');
  }
  x = x.replace(/0x([a-zA-Z0-9]+)/g, '<a href=\'javascript:r2ui.seek("0x$1")\'>0x$1</a>');
  // registers
  if (backward) {
    prev_curoff = curoff;
    prev_lastoff = lastoff;
  } else {
    next_curoff = curoff;
    next_lastoff = lastoff;
    if (!prev_curoff) {
      prev_curoff = next_curoff;
    }
  }
  return x;
};
