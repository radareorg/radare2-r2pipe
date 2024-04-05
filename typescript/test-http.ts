// tsc test-http.ts
// node --insecure-http-parser test-http.js

import * as r2pipe from "./dist/index.js";
// import * as r2pipe from "r2pipe-ts";

async function main() : Promise<string> {
  console.log("Hello R2Pipe for TypeScript");
  const r2 = await r2pipe.open("http://127.0.0.1:9090");
  const res = await r2.cmd("?E Hello TypeScript");
  console.log(res);
  await r2.quit();
  return "Done";
}

main().then(console.log).catch(console.error);
