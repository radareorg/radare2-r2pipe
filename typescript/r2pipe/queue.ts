import * as fs from "fs";

interface R2PipeQueueItem {
  cmd: string;
  result: string;
  cb: any;
  error: any;
}

export class R2PipeQueue {
  private pipeQueue: R2PipeQueueItem[];
  private output: fs.ReadStream;
  private input: fs.WriteStream;

  constructor(input:fs.WriteStream, output:fs.ReadStream) {
    this.pipeQueue = [];
    this.input = input;
    this.output = output;
    this.output.on('data', (data: Buffer) => {
      this.onData(data);
    });
  }
  dispose(): void {
    this.input.destroy();
    this.output.destroy();
  }
  cmd(cmd: string, cb: Function) {
    this.pipeQueue.push({
      cmd: cmd,
      cb: cb,
      result: '',
      error: null
    });
    if (this.pipeQueue.length === 1) {
      this.input.write(cmd + '\n');
    }
  }
  onData(data: Buffer) {
    let len = data.length;
    if (this.pipeQueue.length < 1) {
      return new Error('r2pipe error: No pending commands for incomming data');
    }

    const pq0 = this.pipeQueue[0];
    if (len > 0 && data[len - 1] !== 0x00) {
      pq0.result += data.toString();
      return pq0.result;
    }

    while (len > 0 && data[len - 1] == 0x00) {
      len--;
    }

    pq0.result += data.slice(0, len).toString();
    pq0.cb(pq0.error, pq0.result);
    this.pipeQueue.splice(0, 1);

    if (this.pipeQueue.length > 0) {
      try {
        this.input.write(this.pipeQueue[0].cmd + '\n');
      } catch (e) {
        console.error(e);
      }
    }
  }
}


