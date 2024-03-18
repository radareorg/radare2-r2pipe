import * as r2pipe from "./r2pipe/index.js";
// import * as r2pipe from "r2pipe-ts";

async function main() {
	console.log("Hello R2Pipe for TypeScript");
	// const r2 = await r2pipe.open("http://127.0.0.1:9090");
	const r2 = await r2pipe.open("/bin/ls");
	const res = await r2.cmd("pd");
	console.log(res);
	await r2.quit();
}

main().then((x)=>{}).catch(console.error);
