import * as proc from "child_process";
import { R2PipeBase } from "./base.js";

export class R2PipeSpawn extends R2PipeBase {
  private filePath: string;
  private r2Path: string;
  private r2cb: any;

  constructor(filePath: string, r2path: string = "radare2") {
    super();
    this.filePath = filePath;
    // this.r2Path = "/usr/local/bin/radare2";
    this.r2Path = r2path;
    this.pipeSpawn(this.filePath, []);
  }
  async cmd(command: string): Promise<string> {
    return new Promise((resolve, reject) => {
      this.r2cb.cmd(command, (error, res) => {
        if (error) {
          reject(error);
        } else {
          resolve(res);
        }
      });
    });
    //return this.httpCmd(this.filePath, command);
  }
  async quit(): Promise<boolean> {
    this.r2cb.quit();
    return true;
  }
  private pipeSpawn(filePath: string, opts: any) {
    const args = ['-q0'].concat(opts).concat(filePath);
    const child = proc.spawn(this.r2Path, args);
    this.r2cb = r2bind(child, () => { }, 'pipe');
  }
}

function pipeCmd(proc, cmd, cb) {
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

function pipeCmdOutput(proc, data, cb) {
  let len = data.length;

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

function r2bind(child, cb, r2cmd) {
  let running = false;
  let errmsg = '';
  const r2 = {
    pipeQueue: [],
    call: (s, cb2) => {
      this.cmd("'" + s, cb2);
    },
    callj: (s, cb2) => {
      this.cmd("'" + s, cb2);
    },
    callAt: (s, addr, cb2) => {
      // addr must be a NativePointer not a number
      this.cmd("'0x" + Number(addr).toString(16) + "'" + s, cb2);
    },
    cmdAt: function (s, addr, cb2) {
      // addr must be a NativePointer not a number
      this.cmd(s + "@0x" + Number(addr).toString(16), cb2);
    },
    /* Run cmd and return plaintext output */
    cmd: function (s, cb2) {
      pipeCmd.bind(r2)(child, s, cb2);
      // s = util.cleanCmd(s);
      // r2cmd(child.cmdparm, s, cb2);
    },


    /* Quit CMD */
    quit: function (callback) {
      if (typeof child.stdin === 'object' && typeof child.stdin.end === 'function') {
        child.stdin.end(); // i think this can be removed
      }
      child.kill('SIGINT');
      if (typeof callback === 'function') {
        callback();
      }
    }
  };

  /* handle SDTERR message */
  if (child.stderr !== null) {
    child.stderr.on('data', function (data) {
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
  if (child.stdout !== null) {
    child.stdout.on('data', data => {
      /* Set as running for pipe method */
      if (running) {
        if (typeof r2cmd === 'string') {
          pipeCmdOutput.bind(r2)(child, data, cb);
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
  if (typeof child.on === 'function') {
    child.on('error', function (err) {
      running = false;
      console.log(err);
    });

    child.on('close', function (code, signal) {
      running = false;
      const error = errmsg ? errmsg : '';
      if (signal) {
        cb(new Error('Child received signal ' + signal + '\n' + error));
      } else {
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
  return r2;
}
