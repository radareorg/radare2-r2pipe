import * as proc from "child_process";
import { R2PipeBase } from "./base.js";
import { R2PipeQueue } from "./queue.js";

/** Runs commands on a spawned radare2 process. */
export class R2PipeSpawn extends R2PipeBase {
  private readonly child: proc.ChildProcessWithoutNullStreams;
  private readonly queue: R2PipeQueue;
  private closed = false;

  constructor(filePath: string, r2path: string = "radare2") {
    super();
    this.child = proc.spawn(r2path, ["-q0", filePath]);
    this.queue = new R2PipeQueue(this.child.stdin, this.child.stdout, true);
    // Diagnostics must be consumed even when the caller only reads stdout.
    this.child.stderr.resume();
    this.child.stderr.on("error", (error: Error) => this.queue.fail(error));
    this.child.on("error", (error: Error) => this.queue.fail(error));
    this.child.on("close", (code, signal) => {
      const reason = signal ? `signal ${signal}` : `code ${code}`;
      this.queue.fail(new Error(`radare2 exited with ${reason}`));
    });
  }

  async cmd(command: string): Promise<string> {
    return new Promise((resolve, reject) => {
      this.queue.cmd(command, (error, result) => {
        if (error) {
          reject(error);
        } else {
          resolve(result);
        }
      });
    });
  }

  async quit(): Promise<boolean> {
    if (!this.closed) {
      this.closed = true;
      this.queue.dispose();
      this.child.kill("SIGINT");
    }
    return true;
  }
}
