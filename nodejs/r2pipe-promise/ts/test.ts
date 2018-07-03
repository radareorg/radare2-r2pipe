import { R2Pipe } from "..";
import { inspect } from "util";

async function main(): Promise<void> {
    const r2 = await R2Pipe.open("/bin/ls");
    try {
        const res = await r2.cmd("?E Hello World")
        console.log(res);
        const info = await r2.cmdj("ij");
        console.error(inspect(info.core, { depth: null, colors: true} ))
    } finally {
        r2.quit();
    }
}

main().catch(err => { console.error(err); });
