import * as http from "http";
import * as proc from "child_process";

export abstract class R2PipeBase implements R2PipeCmdInterface {
  abstract cmd(command: string): Promise<string>;
  abstract quit(): Promise<boolean>;

  async cmdj(command: string): Promise<any> {
    const output = await this.cmd(command);
    try {
      return JSON.parse(output);
    } catch (e) {
      throw new Error("Failed to parse JSON output from radare2 command.");
    }
  }
}

export interface R2PipeCmdInterface {
  /**
   * Executes a radare2 command and returns the output as a string.
   * @param command The radare2 command to execute.
   * @returns A promise that resolves with the command output as a string.
   */
  cmd(command: string): Promise<string>;

  /**
   * Executes a radare2 command that expects a JSON response.
   * @param command The radare2 command to execute.
   * @returns A promise that resolves with the parsed JSON output.
   */
  cmdj(command: string): Promise<any>;

  /**
   * Quits and destroys the given instance
   * @returns async nothing
   */
  quit(): Promise<boolean>;
}

export class R2PipeHttp extends R2PipeBase {
  private baseUrl: string;

  constructor(url: string) {
    super();
    this.baseUrl = url;
  }
  async cmd(command: string): Promise<string> {
    return this.httpCmd(this.baseUrl, command);
  }
  async quit(): Promise<boolean> {
    // nothing
    return true;
  }
  /////////////////////////
  private async httpCmd(uri: string, cmd: string): Promise<string> {
    return new Promise((resolve, reject) => {
      const url = `${uri}/cmd/${cmd}`;
      // console.error("==> " + url);
      http.get(url, (res: any) => {
        if (res.statusCode !== 200) {
          reject(new Error(`Request Failed. Status Code: ${res.statusCode}`));
          res.resume(); // Consume response data to free up memory
          return;
        }
        res.setEncoding('utf8');
        let rawData = '';
        res.on('data', (chunk: string) => { rawData += chunk; });
        res.on('end', () => {
          resolve(rawData);
        });
      }).on('error', (e: any) => {
        reject(new Error(`Error making HTTP request: ${e.message}`));
      });
    });
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
function r2bind(ls, cb, r2cmd) {
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
    plugin: function (s, cb2) {
      //throw new Exception("not implemented");
    },
    unload: function (s, cb2) {
      // throw new Exception("not implemented");
    },
    log: function (msg) {
      console.log(msg);
    },
    /* Run cmd and return plaintext output */
    cmd: function (s, cb2) {
      try {
        //  s = util.cleanCmd(s);
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

    /*
        // Run cmd and return JSON output
        cmdj: function (s, cb2) {
          if (typeof cb2 !== 'function') {
            cb2 = function () {};
          }
          try {
            s = util.cleanCmd(s);
            arseJSON(r2.cmd, s, cb2);
          } catch (e) {
            cb2(e);
          }
        },
    */
    /* Run system cmd */
    //syscmd: syscmd,
    //syscmdj: syscmdj,

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
  return r2;
}

export class R2PipeLocal extends R2PipeBase {
  private IN: number;
  private OUT: number;
  private R2PIPE_PATH: string;

  constructor(filePath: string) {
    super();
    this.OUT = parseInt(process.env.R2PIPE_OUT);
    this.IN = parseInt(process.env.R2PIPE_IN);
    this.R2PIPE_PATH = process.env.R2PIPE_PATH;
    /*
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
      // OS: linux/sunos/osx
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
    */
  }

  async cmd(command: string): Promise<string> {
    return "TODO";
  }
  async quit(): Promise<boolean> {
    // nothing
    return true;
  }
}

export class R2PipeSpawn extends R2PipeBase {
  private filePath: string;
  private r2Path: string;
  private r2cb: any;

  constructor(filePath: string) {
    super();
    this.filePath = filePath;
    // this.r2Path = "/usr/local/bin/radare2";
    this.r2Path = "radare2";
    this.pipeSpawn(this.filePath, []);
  }
  async cmd(command: string): Promise<string> {
    return new Promise((resolve, reject) => {
      this.r2cb.cmd(command, (error, res) => {
        resolve(res);
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
    const ls = proc.spawn(this.r2Path, args);
    this.r2cb = r2bind(ls, () => { }, 'pipe');
  }
}

// Function to create an instance of R2Pipe
export function open(filePath: string): R2PipeCmdInterface {
  if (filePath.startsWith("http://")) {
    return new R2PipeHttp(filePath);
  }
  return new R2PipeSpawn(filePath);
}
