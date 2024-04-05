import * as proc from "child_process";
import { R2PipeBase } from "./base.js";

/**
 * Provides an interface to run commands on an spawned instance of the radare2.
 *
 * The `R2PipeSpawn` class extends the `R2PipeBase` class and provides a way to
 * spawn a new radare2 process and interact with it through a pipe-based
 * interface.
 *
 * The constructor takes the path to the file to be analyzed and an optional
 * path to the radare2 executable. The `cmd` method can be used to execute
 * radare2 commands and retrieve the output. The `quit` method can be used to
 * terminate the radare2 process.
 */
export class R2PipeSpawn extends R2PipeBase {
  /**
    * The path to the file loaded by the spawned r2 instance
    */
  private filePath: string;

  /**
   * The path to the `radare2` executable
   */
  private r2Path: string;
  private r2cb: any;

  constructor(filePath: string, r2path: string = "radare2") {
    super();
    this.filePath = filePath;
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
  }

  async quit(): Promise<boolean> {
    this.r2cb.quit();
    return true;
  }

  private pipeSpawn(filePath: string, opts: any) {
    const args = ['-q0'].concat(opts).concat(filePath);
    const child = proc.spawn(this.r2Path, args);
    this.r2cb = r2bind(child, () => { console.log("nothing"); }, 'pipe');
    // this.r2cb = r2bind(child, () => { }, 'pipe');
  }
}

function pipeCmdOutput(r2, proc, data) {
  r2.running = true;
  let len = data.length;

  if (r2.pipeQueue.length < 1) {
    return new Error('r2pipe error: No pending commands for incomming data');
  }

  if (data.length > 1 && data[0] === 0x00) {
    data = data.slice(1);
  }
  if (data[len - 1] !== 0x00) {
    r2.pipeQueue[0].result += data.toString();
    data = "";
  //  return;
    /// return r2.pipeQueue[0].result;
  }

  while (data[len - 1] == 0x00) {
    len--;
  }
  if (len == 0) {
    r2.running = false;
    return;
  }

  r2.pipeQueue[0].result += data.slice(0, len).toString();
  r2.pipeQueue[0].cb(r2.pipeQueue[0].error, r2.pipeQueue[0].result);
  r2.pipeQueue.splice(0, 1);

  if (r2.pipeQueue.length > 0) {
    try {
      proc.stdin.write(r2.pipeQueue[0].cmd + '\n');
    } catch (e) {
      r2.pipeQueue[0].cb(e, null);
    }
  }
  r2.running = false;
}

function r2bind(child, cb, r2cmd) {
  let errmsg = '';
  const r2 = {
    running: false,
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
    cmd: (command, commandCallback) => {
      // s = util.cleanCmd(s);
      r2.pipeQueue.push({
        cmd: command,
        cb: commandCallback,
        result: '',
        error: null
      });
      if (r2.pipeQueue.length === 1) {
        child.stdin.write(command + '\n');
      }
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
      if (!r2.running && (typeof r2cmd !== 'string')) {
        r2.running = true;
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
      if (r2.running) {
        console.error("race");
      }
      pipeCmdOutput(r2, child, data);
      /*
        // console.log("received data: " + data);
        // Set as running for pipe method
        if (running) {
          console.log("RUNING");
          if (typeof r2cmd === 'string') {
            pipeCmdOutput.bind(r2)(child, data, cb);
          }
        } else {
          console.log("not RUNING");
          running = true;
          cb(null, r2);
        }
       */
    });
  } else {
    cb(null, r2); // Callback for connect
  }

  /* Proccess event handling only for methods using childs */
  if (typeof child.on === 'function') {
    child.on('error', function (err) {
      r2.running = false;
      console.log(err);
    });

    child.on('close', function (code, signal) {
      r2.running = false;
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
  if (!r2.running && (r2cmd === 'lpipe')) {
    r2.running = true;
    cb(null, r2);
  }
  return r2;
}
