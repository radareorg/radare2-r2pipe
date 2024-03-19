import * as http from "http";
import {R2PipeBase, R2PipeCmdInterface} from "./base.js";

export class R2PipeHttp extends R2PipeBase {
  private baseUrl: string;

  constructor(url: string) {
    super();
    this.baseUrl = url;
  }
  async cmd(command: string): Promise<string> {
    return this.httpCmd(this.baseUrl, command);
  }
  async quit(): Promise<boolean> {
    // nothing
    return true;
  }
  /////////////////////////
  private async httpCmd(uri: string, cmd: string): Promise<string> {
    return new Promise((resolve, reject) => {
      const url = `${uri}/cmd/${cmd}`;
      // console.error("==> " + url);
      http.get(url, (res: any) => {
        if (res.statusCode !== 200) {
          reject(new Error(`Request Failed. Status Code: ${res.statusCode}`));
          res.resume(); // Consume response data to free up memory
          return;
        }
        res.setEncoding('utf8');
        let rawData = '';
        res.on('data', (chunk: string) => { rawData += chunk; });
        res.on('end', () => {
          resolve(rawData);
        });
      }).on('error', (e: any) => {
        reject(new Error(`Error making HTTP request: ${e.message}`));
      });
    });
  }
}

