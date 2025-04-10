// tsc test-http.ts
// node --insecure-http-parser test-http.js

import * as r2pipe from "./dist/index.js";
import { R2PipeCmdInterface } from "./dist/base.js";
// import * as r2pipe from "r2pipe-ts";

const R2_SERVER_URL = process.env.R2_SERVER_URL || "http://127.0.0.1:9090";

async function main(): Promise<string> {
  console.log("Hello R2Pipe for TypeScript");
  let r2: R2PipeCmdInterface | null = null;
  
  try {
    r2 = await r2pipe.open(R2_SERVER_URL);
    const res: string = await r2.cmd("?E Hello TypeScript");
    console.log(res);
    return "Done";
  } catch (error) {
    if (error instanceof Error) {
      console.error(`Error connecting to radare2 server at ${R2_SERVER_URL}:`, error.message);
    } else {
      console.error("Unknown error occurred:", error);
    }
    throw error;
  } finally {
    if (r2) {
      await r2.quit();
    }
  }
}

main().catch(console.error);
