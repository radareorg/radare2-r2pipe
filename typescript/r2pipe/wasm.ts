import { R2PipeBase, type R2PipeWasmOptions } from "./base.js";

// Local structural types keep WASM optional without requiring DOM types in Node projects.
interface R2WasmExports {
  memory: { buffer: ArrayBuffer };
  malloc(size: number): number;
  free(pointer: number): void;
  r_core_new(): number;
  r_core_free(core: number): void;
  r_core_cmd_str(core: number, command: number): number;
  r_core_file_open(core: number, path: number, permissions: number, address: bigint): number;
  r_core_bin_load(core: number, path: number, address: bigint): number;
}

interface WasmRuntime {
  instantiate(bytes: Uint8Array, imports: object): Promise<{
    instance: { exports: Record<string, unknown> };
  }>;
}

/** Drives a separate radare2 core through the exports of a WASI reactor. */
export class R2PipeWasm extends R2PipeBase {
  private exports?: R2WasmExports;
  private core = 0;
  private pending: Promise<void> = Promise.resolve();
  private initialization?: Promise<void>;
  private quitting?: Promise<boolean>;
  private closed = false;
  private readonly options: R2PipeWasmOptions;

  constructor(private readonly filePath: string, options: R2PipeWasmOptions) {
    super();
    if (!options?.path) {
      throw new Error("The WASM backend requires a path to a wasi-api radare2.wasm file");
    }
    this.options = { ...options, preopens: { ...options.preopens } };
  }

  cmd(command: string): Promise<string> {
    if (this.closed) {
      return Promise.reject(new Error("r2pipe connection is closed"));
    }
    const result = this.pending.then(async () => {
      this.initialization ??= this.initialize();
      await this.initialization;
      return this.execute(command);
    });
    this.pending = result.then(() => {}, () => {});
    return result;
  }

  quit(): Promise<boolean> {
    this.closed = true;
    this.quitting ??= this.pending.then(() => {
      try {
        if (this.core) {
          this.exports!.r_core_free(this.core);
        }
      } finally {
        this.core = 0;
        this.exports = undefined;
        this.initialization = undefined;
      }
      return true;
    });
    return this.quitting;
  }

  private async initialize(): Promise<void> {
    const wasm = (globalThis as typeof globalThis & { WebAssembly?: WasmRuntime }).WebAssembly;
    if (!wasm || typeof wasm.instantiate !== "function") {
      throw new Error("The WASM backend requires WebAssembly support in this runtime");
    }
    const { readFile } = await import("node:fs/promises");
    const bytes = await readFile(this.options.path);
    // Loading the package and using other backends never loads node:wasi.
    const { WASI } = await import("node:wasi");
    const wasi = new WASI({
      version: "preview1",
      args: ["radare2"],
      env: {},
      preopens: this.options.preopens,
      returnOnExit: true,
    });
    const { instance } = await wasm.instantiate(bytes, wasi.getImportObject());
    const exports = instance.exports;
    for (const name of ["malloc", "free", "r_core_new", "r_core_free", "r_core_cmd_str",
      "r_core_file_open", "r_core_bin_load"]) {
      if (typeof exports[name] !== "function") {
        throw new Error(`Missing WASM export ${name}; use a wasi-api build of radare2`);
      }
    }
    if (!(exports.memory as R2WasmExports["memory"])?.buffer) {
      throw new Error("Missing WASM memory export; use a wasi-api build of radare2");
    }
    wasi.initialize(instance);
    this.exports = exports as unknown as R2WasmExports;
    try {
      this.core = this.exports.r_core_new();
      if (!this.core) {
        throw new Error("Failed to allocate a radare2 WASM core");
      }
      this.execute("e scr.color=0");
      if (this.filePath) {
        const path = this.allocate(this.filePath);
        try {
          if (!this.exports.r_core_file_open(this.core, path, 4, 0n)) {
            throw new Error(`Cannot open ${this.filePath} in WASM; host files require an explicit preopens mapping`);
          }
          // UT64_MAX selects the binary's preferred base address.
          this.exports.r_core_bin_load(this.core, path, 0xffffffffffffffffn);
        } finally {
          this.exports.free(path);
        }
      }
    } catch (error) {
      if (this.core) {
        this.exports.r_core_free(this.core);
      }
      this.core = 0;
      this.exports = undefined;
      throw error;
    }
  }

  private allocate(text: string): number {
    if (text.includes("\0")) {
      throw new Error("WASM strings cannot contain NUL characters");
    }
    const bytes = new TextEncoder().encode(text + "\0");
    const pointer = this.exports!.malloc(bytes.length) >>> 0;
    if (!pointer) {
      throw new Error("Failed to allocate a radare2 WASM string");
    }
    // malloc and commands can grow memory, so never cache a view across calls.
    new Uint8Array(this.exports!.memory.buffer).set(bytes, pointer);
    return pointer;
  }

  private execute(command: string): string {
    const exports = this.exports!;
    const input = this.allocate(command);
    let output = 0;
    try {
      output = exports.r_core_cmd_str(this.core, input) >>> 0;
      if (!output) {
        throw new Error("radare2 WASM command returned a null string");
      }
      const memory = new Uint8Array(exports.memory.buffer);
      const end = memory.indexOf(0, output);
      if (end < 0) {
        throw new Error("radare2 WASM command returned an unterminated string");
      }
      return new TextDecoder().decode(memory.subarray(output, end));
    } finally {
      if (output) {
        exports.free(output);
      }
      exports.free(input);
    }
  }
}
