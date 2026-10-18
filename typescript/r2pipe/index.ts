import {R2PipeBase, R2PipeCmdInterface, R2PipeOptions} from "./base.js";
import {R2PipeHttp} from "./http.js";
import {R2PipeSpawn} from "./spawn.js";
import {R2PipeLocal} from "./local.js";
import {R2PipeWasm} from "./wasm.js";
export type { R2PipeCmdInterface, R2PipeOptions, R2PipeWasmOptions } from "./base.js";
export type { JsonParser } from "./json.js";
export { parseJson, parseAddress } from "./json.js";

// Function to create an instance of R2Pipe
export function open(filePath: string = "", options: R2PipeOptions = {}): R2PipeCmdInterface {
  let pipe: R2PipeBase;
  if (options.wasm !== undefined) {
    pipe = new R2PipeWasm(filePath, options.wasm);
  } else if (filePath === "") {
    pipe = new R2PipeLocal();
  } else if (filePath.startsWith("http://")) {
    pipe = new R2PipeHttp(filePath);
  } else {
    pipe = new R2PipeSpawn(filePath);
  }
  if (options.jsonParser !== undefined) {
    pipe.jsonParser = options.jsonParser;
  }
  return pipe;
}
