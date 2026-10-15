const assert = require("node:assert/strict");
const http = require("node:http");
const { test } = require("node:test");
const { R2PipeHttp } = require("./dist/http.js");

test("HTTP preserves literal commands and r2pipe2 JSON containing URL characters", async () => {
  const paths = [];
  const server = http.createServer((request, response) => {
    response.setHeader("Content-Type", "text/plain; charset=utf-8");
    response.setHeader("X-Content-Type-Options", "nosniff");
    paths.push(request.url);
    try {
      response.end(decodeURIComponent(request.url.slice("/cmd/".length)));
    } catch (error) {
      response.writeHead(400);
      response.end(error.message);
    }
  });
  await new Promise((resolve, reject) => {
    server.once("error", reject);
    server.listen(0, "127.0.0.1", resolve);
  });
  const client = new R2PipeHttp(`http://127.0.0.1:${server.address().port}`);
  try {
    const commands = [
      "?e before # after",
      "?e spaces + & % ? / café",
      JSON.stringify({ cmd: '?e "quotes" # café', json: false, trim: false }),
    ];
    for (const command of commands) {
      assert.equal(await client.cmd(command), command);
      assert.equal(paths.at(-1), `/cmd/${encodeURIComponent(command)}`);
    }
  } finally {
    await client.quit();
    server.closeAllConnections();
    await new Promise((resolve, reject) => server.close((error) => error ? reject(error) : resolve()));
  }
});
