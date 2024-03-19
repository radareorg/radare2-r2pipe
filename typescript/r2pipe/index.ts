
import {R2PipeBase, R2PipeCmdInterface} from "./base.js";
import {R2PipeHttp} from "./http.js";
import {R2PipeSpawn} from "./spawn.js";



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


// Function to create an instance of R2Pipe
export function open(filePath: string): R2PipeCmdInterface {
  if (filePath.startsWith("http://")) {
    return new R2PipeHttp(filePath);
  }
  return new R2PipeSpawn(filePath);
}
