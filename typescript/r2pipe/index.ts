module r2pipe {
export class R2Pipe {
	constructor() {
	}
	cmd(s: string) : string{
		return "win";
	}
}

export function open() {
	return new R2Pipe();
}
}
