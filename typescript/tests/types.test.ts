import { open, parseJson, type JsonParser, type R2PipeCmdInterface, type R2PipeOptions } from "..";

const parser: JsonParser = JSON.parse;
const options: R2PipeOptions = { jsonParser: parser };
const pipe: R2PipeCmdInterface = open("http://localhost:9090", options);
const result: Promise<{ offset: number | bigint }> = pipe.cmdj<{ offset: number | bigint }>("ij");
const unknownResult: Promise<unknown> = pipe.cmdj("ij");
const defaultResult = pipe.cmdj("ij");
// @ts-expect-error The default result must be narrowed before reading properties.
const objectResult: Promise<object> = defaultResult;
const primitive: Promise<null> = pipe.cmdj<null>("ij");
const parsed: unknown = parseJson("18446744073709551615");
void [result, unknownResult, objectResult, primitive, parsed];
