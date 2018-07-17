"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
const __1 = require("..");
const util_1 = require("util");
async function main() {
    const r2 = await __1.R2Pipe.open("/bin/ls");
    try {
        const res = await r2.cmd("?E Hello World");
        console.log(res);
        const info = await r2.cmdj("ij");
        console.error(util_1.inspect(info.core, { depth: null, colors: true }));
    }
    finally {
        r2.quit();
    }
}
main().catch(err => { console.error(err); });
