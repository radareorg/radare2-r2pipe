/* A tiny API reactor for offline transport tests, with no libc or WASI SDK.
 * Rebuild: clang --target=wasm32 -Oz -nostdlib -fno-builtin \
 *   -Wl,--no-entry -Wl,--export-all -o wasm-api.wasm wasm-api.c
 */
static unsigned char heap[65536];
static unsigned int used;
static unsigned int allocations;
static unsigned int frees;
static unsigned int cores_freed;
static unsigned int cores_created;

void *malloc(unsigned long size) {
  if (size > sizeof(heap) - used) return 0;
  void *result = heap + used;
  used += size;
  allocations++;
  return result;
}

void free(void *pointer) {
  if (pointer) frees++;
}

unsigned int r_core_new(void) {
  cores_created++;
  return 42;
}

void r_core_free(unsigned int core) {
  if (core == 42) cores_freed++;
}

char *r_core_cmd_str(unsigned int core, const char *command) {
  if (core != 42 || command[0] == '!') return 0;
  if (command[0] == 'g') __builtin_wasm_memory_grow(0, 1);
  const char *text = command[0] == 'j' ? "{\"offset\":18446744073709551615}" : command;
  unsigned int size = 0;
  while (text[size]) size++;
  char *output = malloc(size + 1);
  if (!output) return 0;
  for (unsigned int i = 0; i <= size; i++) output[i] = text[i];
  return output;
}

unsigned int r_core_file_open(unsigned int core, const char *path, int permissions, unsigned long long address) {
  (void)permissions;
  (void)address;
  return core == 42 && path[0] != '!';
}

unsigned int r_core_bin_load(unsigned int core, const char *path, unsigned long long address) {
  (void)core;
  (void)path;
  (void)address;
  return 1;
}

unsigned int allocated_strings(void) { return allocations; }
unsigned int freed_strings(void) { return frees; }
unsigned int freed_cores(void) { return cores_freed; }
unsigned int created_cores(void) { return cores_created; }
