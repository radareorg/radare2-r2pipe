// const r2pipe = r2pipe.open('/bin/ls')

export class R2Pipe {
	cmd(string): string;
	cmdj(string): any;
}

export default class r2pipe {
	static open(): R2Pipe;
}
// export default r2pipe;

/*
export const options: any[];
export const r2bin: string;
export function connect(uri: any, cb: any): void;

export function ioplugin(cb: any): void;

export function jsonParse(p0: any, p1: any): any;

export function launch(file: any, opts: any, cb: any): void;

export function listen(file: any, cb: any): void;

export function lpipe(cb: any): void;

export function lpipeSync(): any;

export function open(...args: any[]): any;

export function openBuffer(buf: any, cb: any): void;

export function openSync(...args: any[]): any;

export function pipe(file: any, opts: any, cb: any): void;

export function pipeSync(file: any, opts: any): any;

export function syscmd(command: any, childOpts: any, cb: any): void;

export function syscmdj(command: any, cb2: any): void;

*/
