import { Readable, Writable } from "stream";

type R2PipeCallback = (error: Error | null, result: string) => void;

interface R2PipeQueueItem {
  command: string;
  chunks: Buffer[];
  callback: R2PipeCallback;
}

/** Serializes commands and frames their NUL-terminated responses. */
export class R2PipeQueue {
  private pending: (R2PipeQueueItem | undefined)[] = [];
  private head = 0;
  private inFlight = false;
  private failure?: Error;

  constructor(
    private readonly input: Writable,
    private readonly output: Readable,
    private startup = false
  ) {
    output.on("data", (data: Buffer) => this.onData(data));
    input.on("error", (error: Error) => this.fail(error));
    output.on("error", (error: Error) => this.fail(error));
    input.on("close", () => this.fail(new Error("r2pipe input closed")));
    output.on("end", () => this.fail(new Error("r2pipe output ended")));
    output.on("close", () => this.fail(new Error("r2pipe output closed")));
    if (input.destroyed || output.destroyed) {
      this.fail(new Error("r2pipe stream is already closed"));
    }
  }

  dispose(): void {
    this.fail(new Error("r2pipe connection is closed"));
  }

  /** Reject outstanding and future commands after a terminal transport error. */
  fail(error: Error): void {
    if (this.failure) {
      return;
    }
    this.failure = error;
    const pending = this.pending.slice(this.head);
    this.pending = [];
    this.head = 0;
    this.inFlight = false;
    this.input.destroy();
    this.output.destroy();
    for (const item of pending) {
      item?.callback(error, "");
    }
  }

  cmd(command: string, callback: R2PipeCallback): void {
    if (this.failure) {
      callback(this.failure, "");
      return;
    }
    this.pending.push({ command, callback, chunks: [] });
    this.dispatch();
  }

  onData(data: Buffer): void {
    if (this.failure) {
      return;
    }
    let offset = 0;
    if (this.startup) {
      const end = data.indexOf(0);
      if (end < 0) {
        return;
      }
      this.startup = false;
      offset = end + 1;
    }
    while (offset < data.length) {
      const item = this.pending[this.head];
      if (!item) {
        this.fail(new Error("r2pipe received output without a pending command"));
        return;
      }
      const end = data.indexOf(0, offset);
      if (end < 0) {
        item.chunks.push(data.subarray(offset));
        return;
      }
      if (end > offset) {
        item.chunks.push(data.subarray(offset, end));
      }
      // Decode once per response so UTF-8 characters may span stream reads.
      const result = Buffer.concat(item.chunks).toString("utf8");
      this.pending[this.head] = undefined;
      this.head++;
      this.inFlight = false;
      if (this.head === this.pending.length) {
        this.pending = [];
        this.head = 0;
      } else if (this.head >= 1024 && this.head * 2 >= this.pending.length) {
        this.pending = this.pending.slice(this.head);
        this.head = 0;
      }
      item.callback(null, result);
      this.dispatch();
      if (this.failure) {
        return;
      }
      offset = end + 1;
    }
  }

  private dispatch(): void {
    const item = this.pending[this.head];
    if (this.failure || this.inFlight || !item) {
      return;
    }
    this.inFlight = true;
    try {
      this.input.write(item.command + "\n", (error?: Error | null) => {
        if (error) {
          this.fail(error);
        }
      });
    } catch (error: unknown) {
      this.fail(error instanceof Error ? error : new Error(String(error)));
    }
  }
}
