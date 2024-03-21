import * as r2pipe from "./dist/index.js";
// import * as r2pipe from "r2pipe-ts";

async function main() {
  console.log("Hello R2Pipe for TypeScript");
  const r2 = await r2pipe.open();
  const res = await r2.cmd("?E Hello TypeScript");
  console.log(res);
  const r2s = await r2.cmd("?E Hello World");
  console.log(r2s);
  await r2.quit();
}

main().then((x)=>{}).catch(console.error);

