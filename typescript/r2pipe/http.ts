import * as http from "http";
import { R2PipeBase } from "./base.js";

/**
 * Extends the `R2PipeBase` class to provide an HTTP-based implementation of the r2pipe protocol.
 */
export class R2PipeHttp extends R2PipeBase {
  private baseUrl: string;

  /**
   * Initializes a new instance of the `R2PipeHttp` class with the specified base URL.
   * @param url - The base URL for the HTTP-based r2pipe protocol. f.ex: `http://host:port`
   */
  constructor(baseUrl: string) {
    super();
    this.baseUrl = baseUrl.replace(/\/+$/, "");
  }

  /**
   * Executes the given r2 command and returns the response as a string.
   * @param command - The r2 command to execute.
   * @returns The response from the r2 command as a string.
   */
  async cmd(command: string): Promise<string> {
    return this.httpCmd(this.baseUrl, command);
  }

  /**
  * Closes the connection to the r2 process and returns a boolean indicating whether the operation was successful.
  * @returns `true` if the connection was closed successfully, `false` otherwise.
  */
  async quit(): Promise<boolean> {
    // do nothing
    return true;
  }

  private async httpCmd(uri: string, cmd: string): Promise<string> {
    return new Promise((resolve, reject) => {
      const url = new URL(uri);
      // Pass path separately so URL normalization cannot remove commands such as '..'.
      const path = `${url.pathname.replace(/\/+$/, "")}/cmd/${encodeURIComponent(cmd)}${url.search}`;
      http.get(url, { path }, (res: http.IncomingMessage) => {
        res.on('error', reject);
        res.on('aborted', () => reject(new Error('HTTP response was aborted.')));
        res.on('close', () => {
          if (!res.complete) {
            reject(new Error('HTTP response closed before completion.'));
          }
        });
        if (res.statusCode !== 200) {
          reject(new Error(`Request Failed. Status Code: ${res.statusCode}`));
          res.resume(); // Consume response data to free up memory
          return;
        }
        res.setEncoding('utf8');
        const chunks: string[] = [];
        res.on('data', (chunk: string) => { chunks.push(chunk); });
        res.on('end', () => {
          if (res.complete) {
            resolve(chunks.join(''));
          } else {
            reject(new Error('HTTP response ended before completion.'));
          }
        });
      }).on('error', (e: Error) => {
        reject(new Error(`Error making HTTP request: ${e.message}`));
      });
    });
  }
}

