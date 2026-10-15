import { R2PipeBase } from "./base.js";
import { R2PipeQueue } from "./queue.js";
import * as os from "os";
import * as net from "net";

export class R2PipeLocal extends R2PipeBase {
  private readonly stream: R2PipeQueue;

  constructor() {
    super();
    if (os.platform() === 'win32') {
      const pipePath = process.env.R2PIPE_PATH;
      if (!pipePath) {
        throw new Error('R2PIPE_PATH must specify the radare2 named pipe');
      }
      const client = net.connect(pipePath);
      this.stream = new R2PipeQueue(client, client);
    } else {
      const envIn = process.env.R2PIPE_IN;
      const envOut = process.env.R2PIPE_OUT;
      if (!envIn || !envOut || !/^\d+$/.test(envIn) || !/^\d+$/.test(envOut)) {
        throw new Error('This script must be executed from r2 -c "#!pipe node foo.js"');
      }
      const IN = Number(envIn);
      const OUT = Number(envOut);
      if (!Number.isSafeInteger(IN) || !Number.isSafeInteger(OUT)) {
        throw new Error('This script must be executed from r2 -c "#!pipe node foo.js"');
      }
      // Pipe sockets use cancellable, nonblocking I/O. A ReadStream can leave
      // a blocking filesystem read alive after quit(), keeping Node running.
      const input = new net.Socket({ fd: OUT, readable: false, writable: true });
      const output = new net.Socket({ fd: IN, readable: true, writable: false });
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
    return true;
  }
}

