import { JsonParser, parseJson } from "./json.js";

export interface R2PipeOptions {
  /** Defaults to preserving unsafe integer literals as bigint. */
  jsonParser?: JsonParser;
}

export abstract class R2PipeBase implements R2PipeCmdInterface {
  jsonParser: JsonParser = parseJson;

  abstract cmd(command: string): Promise<string>;
  abstract quit(): Promise<boolean>;

  async cmdj<T = unknown>(command: string): Promise<T> {
    const output = await this.cmd(command);
    try {
      return this.jsonParser(output) as T;
    } catch (e) {
      throw new Error("Failed to parse JSON output from radare2 command.", { cause: e });
    }
  }
}

export interface R2PipeCmdInterface {
  /**
   * Executes a radare2 command and returns the output as a string.
   * @param command The radare2 command to execute.
   * @returns A promise that resolves with the command output as a string.
   */
  cmd(command: string): Promise<string>;

  /**
   * Executes a radare2 command that expects a JSON response.
   * @param command The radare2 command to execute.
   * @returns A promise that resolves with the parsed JSON output.
   */
  cmdj<T = unknown>(command: string): Promise<T>;

  /**
   * Quits and destroys the given instance
   * @returns async nothing
   */
  quit(): Promise<boolean>;
}

