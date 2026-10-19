import * as proc from "child_process";
import { R2PipeBase } from "./base.js";
import { R2PipeQueue } from "./queue.js";

/** Runs commands on a spawned radare2 process. */
export class R2PipeSpawn extends R2PipeBase {
  private readonly child: proc.ChildProcessWithoutNullStreams;
  private readonly queue: R2PipeQueue;
  private closed = false;
  private quitting?: Promise<boolean>;

  constructor(filePath: string, r2path: string = "radare2") {
    super();
    this.child = proc.spawn(r2path, ["-q0", filePath]);
    this.queue = new R2PipeQueue(this.child.stdin, this.child.stdout, true);
    // Diagnostics must be consumed even when the caller only reads stdout.
    this.child.stderr.resume();
    this.child.stderr.on("error", (error: Error) => this.queue.fail(error));
    this.child.on("error", (error: Error) => this.queue.fail(error));
    this.child.on("close", (code, signal) => {
      this.closed = true;
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

  quit(timeoutMs: number = 5000): Promise<boolean> {
    if (!Number.isInteger(timeoutMs) || timeoutMs < 0 || timeoutMs > 0x7fffffff) {
      return Promise.reject(new RangeError("Shutdown timeout must be an integer from 0 to 2147483647 ms"));
    }
    if (this.closed) {
      return Promise.resolve(true);
    }
    if (this.quitting) {
      return this.quitting;
    }
    this.quitting = new Promise<boolean>((resolve, reject) => {
      let settled = false;
      const finish = (error?: Error) => {
        if (settled) return;
        settled = true;
        clearTimeout(timer);
        this.child.off("close", onClose);
        this.child.off("error", onError);
        if (error) reject(error);
        else resolve(true);
      };
      const onClose = () => finish();
      const onError = (error: Error) => {
        // A failed spawn has no child to signal; its close event still settles
        // the streams. A failed signal must remain visible and retryable.
        if (this.child.pid !== undefined) finish(error);
      };
      const signalChild = (signal: NodeJS.Signals) => {
        try {
          if (!this.child.kill(signal)) {
            finish(new Error(`Could not send ${signal} to radare2; quit() may be retried`));
          }
        } catch (error: unknown) {
          finish(error instanceof Error ? error : new Error("Could not stop radare2", { cause: error }));
        }
      };
      let timer = setTimeout(() => {
        if (this.child.pid === undefined || this.child.exitCode !== null || this.child.signalCode !== null) {
          finish(new Error("radare2 stdio did not close before the shutdown deadline; quit() may be retried"));
          return;
        }
        // Retain the same child handle and wait for closure after escalation.
        timer = setTimeout(() => finish(new Error(
          "radare2 did not close within 5000 ms after SIGKILL; quit() may be retried"
        )), 5000);
        signalChild("SIGKILL");
      }, timeoutMs);
      this.child.once("close", onClose);
      this.child.once("error", onError);
      try {
        this.queue.dispose();
        // An exited child may still have open stdio. Wait for close without
        // sending a signal to a process whose execution has already ended.
        if (!this.closed && this.child.pid !== undefined && this.child.exitCode === null && this.child.signalCode === null) {
          signalChild("SIGINT");
        }
      } catch (error: unknown) {
        finish(error instanceof Error ? error : new Error("Could not stop radare2", { cause: error }));
      }
    }).finally(() => {
      this.quitting = undefined;
    });
    return this.quitting;
  }
}
