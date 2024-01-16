
export declare class R2Pipe {
  static open(target: string, options?: string[]): R2Pipe;
  cmd(command: string): Promise<string>;
  cmdj(command: string): Promise<CommandResponse>;
  cmdAt(command: string, addr: number): Promise<CommandResponse>;
  call(command: string): Promise<string>;
  callj(command: string): Promise<CommandResponse>;
  callAt(command: string, addr: number): Promise<CommandResponse>;
  plugin(string, string): boolean;
  unload(string, string): boolean;
  log(string);
  quit(): Promise<void>;
}

export declare interface CommandResponse {
  [key: string]: any;
}
