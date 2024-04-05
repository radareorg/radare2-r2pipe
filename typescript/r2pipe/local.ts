import { R2PipeBase } from "./base.js";
import { R2PipeQueue } from "./queue.js";
import * as fs from "fs";
import * as os from "os";
import * as net from "net";

export class R2PipeLocal extends R2PipeBase {
  private stream: R2PipeQueue;

  constructor() {
    super();
    if (os.platform() === 'win32') {
      const R2PIPE_PATH = process.env.R2PIPE_PATH;
      const client = net.connect('\\\\.\\pipe\\' + R2PIPE_PATH) as any;
      // TODO: we just need the read and write methods, but net.Socket doesnt have path or close()
      this.stream = new R2PipeQueue(client, client);
    } else {
      const envIn = process.env.R2PIPE_IN;
      const envOut = process.env.R2PIPE_OUT;
      if (!envIn || !envOut) {
        throw new Error('This script must be executed from r2 -c "#!pipe node foo.js"');
      }
      const IN = parseInt(envIn);
      const OUT = parseInt(envOut);
      if (!IN || !OUT) {
        throw new Error('This script must be executed from r2 -c "#!pipe node foo.js"');
      }
      const input = fs.createWriteStream(null, { fd: OUT });
      const output = fs.createReadStream(null, { fd: IN });
      this.stream = new R2PipeQueue(input, output);
    }
  }

/**
 * Executes a command in the radare2 pipe and returns the output as a Promise.
 *
 * @param command - The command to execute in the radare2 pipe.
 * @returns A Promise that resolves with the output of the command, or rejects with an error.
 */
  async cmd(command: string): Promise<string> {
    return new Promise((resolve, reject) => {
      this.stream.cmd(command, (error, res) => {
        if (error) {
          reject(error);
        } else {
          resolve(res);
        }
      });
    });
  }

  async quit(): Promise<boolean> {
    this.stream.dispose();
    this.stream = null;
    process.kill(process.pid, 'SIGINT');
    return true;
  }
}

