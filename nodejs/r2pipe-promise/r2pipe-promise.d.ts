
export declare class R2Pipe {
  static open(target: string, options?: string[]): R2Pipe;
  cmd(command: string): Promise<string>;
  cmdj(command: string): Promise<CommandResponse>;
  quit(): Promise<void>;
}

export declare interface CommandResponse {
  [key: string]: any;
}