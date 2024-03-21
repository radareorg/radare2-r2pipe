import {R2PipeCmdInterface} from "./base.js";
import {R2PipeHttp} from "./http.js";
import {R2PipeSpawn} from "./spawn.js";
import {R2PipeLocal} from "./local.js";


// Function to create an instance of R2Pipe
export function open(filePath: string = ""): R2PipeCmdInterface {
  if (filePath === "") {
    return new R2PipeLocal();
  }
  if (filePath.startsWith("http://")) {
    return new R2PipeHttp(filePath);
  }
  return new R2PipeSpawn(filePath);
}
