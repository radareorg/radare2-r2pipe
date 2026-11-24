module r2pipe

import dl
import sync

fn C.strnlen(&u8, uint) uint

$if windows {
	fn C.GetModuleHandleW(&u16) voidptr
}

type CoreNew = fn () voidptr
type CoreFree = fn (voidptr)
type CoreCmd = fn (voidptr, &u8) &u8
type CoreFileOpen = fn (voidptr, &u8, i32, u64) voidptr
type CoreBinLoad = fn (voidptr, &u8, u64) bool
type CoreCons = fn (voidptr) voidptr
type ConsEmbedded = fn (voidptr, bool)
type MemFree = fn (voidptr)
type LogFini = fn ()

// Older libr versions and some plugins share process-wide state.
const native_mutex = sync.new_mutex()

struct NativeResult {
	output  string
	failure string
}

struct NativeTransport {
	commands chan string
	replies  chan NativeResult
mut:
	worker thread
}

struct NativeCore {
	library   voidptr
	core      voidptr
	cmd       CoreCmd  @[required]
	free_core CoreFree @[required]
	free_mem  voidptr
	log_fini  voidptr
}

fn new_native(target string, options NativeOptions, limit int) !Transport {
	if options.library.contains_u8(0) {
		return error('r2pipe: library path contains NUL')
	}
	for command in options.before_open {
		if command.contains_u8(0) {
			return error('r2pipe: native startup command contains NUL')
		}
	}
	for command in options.after_open {
		if command.contains_u8(0) {
			return error('r2pipe: native startup command contains NUL')
		}
	}
	commands := chan string{}
	replies := chan NativeResult{}
	mut worker := spawn native_worker(target, options, limit, commands, replies)
	status := <-replies
	if status.failure != '' {
		worker.wait()
		return error(status.failure)
	}
	return &NativeTransport{
		commands: commands
		replies:  replies
		worker:   worker
	}
}

// Keep construction, execution and teardown on one OS thread. Libr uses
// thread-local console and logging state, even though RCore is passed explicitly.
fn native_worker(target string, options NativeOptions, limit int, commands chan string, replies chan NativeResult) {
	native_mutex.lock()
	core := init_native(target, options, limit) or {
		native_mutex.unlock()
		replies <- NativeResult{ failure: err.msg() }
		return
	}
	native_mutex.unlock()
	replies <- NativeResult{}
	for {
		command := <-commands or { break }
		native_mutex.lock()
		output := core.exchange(command, limit) or {
			native_mutex.unlock()
			replies <- NativeResult{ failure: err.msg() }
			continue
		}
		native_mutex.unlock()
		replies <- NativeResult{ output: output }
	}
	native_mutex.lock()
	core.close()
	native_mutex.unlock()
}

fn native_symbol(library voidptr, name string) !voidptr {
	return dl.sym_opt(library, name) or { return error('r2pipe: libr_core is missing ${name}') }
}

fn load_core_library(options NativeOptions) !voidptr {
	flags := dl.rtld_now | if options.global_symbols { dl.rtld_global } else { dl.rtld_local }
	if options.library != '' {
		return dl.open_opt(options.library, flags) or {
			return error('r2pipe: cannot load ${options.library}: ${err}')
		}
	}
	candidates := $if windows {
		['libr_core.dll', 'r_core.dll']
	} $else $if macos {
		['libr_core.dylib', '/opt/homebrew/lib/libr_core.dylib', '/usr/local/lib/libr_core.dylib']
	} $else {
		['libr_core.so', 'libr_core.so.0', '/usr/local/lib/libr_core.so']
	}
	for name in candidates {
		if library := dl.open_opt(name, flags) {
			return library
		}
	}
	return error('r2pipe: cannot load libr_core (tried ${candidates.join(', ')}); set NativeOptions.library')
}

fn native_dependency_symbol(core_library voidptr, symbol string, dependency string) voidptr {
	pointer := dl.sym(core_library, symbol)
	$if windows {
		if isnil(pointer) {
			// GetProcAddress searches a single DLL, unlike dlsym on a dlopen handle.
			// The dependency stays loaded for the lifetime of core_library.
			for name in ['libr_${dependency}.dll', 'r_${dependency}.dll'] {
				handle := C.GetModuleHandleW(name.to_wide())
				if !isnil(handle) {
					return dl.sym(handle, symbol)
				}
			}
		}
	}
	return pointer
}

fn init_native(target string, options NativeOptions, limit int) !NativeCore {
	library := load_core_library(options)!
	mut initialized := false
	defer {
		if !initialized {
			dl.close(library)
		}
	}
	new_core := CoreNew(native_symbol(library, 'r_core_new')!)
	free_core := CoreFree(native_symbol(library, 'r_core_free')!)
	cmd := CoreCmd(native_symbol(library, 'r_core_cmd_str')!)
	free_mem := native_dependency_symbol(library, 'r_mem_free', 'util')
	$if windows {
		// Windows DLLs may use a different C runtime than the caller.
		if isnil(free_mem) {
			return error('r2pipe: libr_core is missing r_mem_free')
		}
	}
	core := new_core()
	if isnil(core) {
		return error('r2pipe: r_core_new failed')
	}
	log_fini := native_dependency_symbol(library, 'r_log_fini', 'util')
	defer {
		if !initialized {
			free_core(core)
			if !isnil(log_fini) {
				LogFini(log_fini)()
			}
		}
	}
	core_cons := dl.sym(library, 'r_core_get_cons')
	embedded := native_dependency_symbol(library, 'r_cons_set_embedded', 'cons')
	if !isnil(core_cons) && !isnil(embedded) {
		ConsEmbedded(embedded)(CoreCons(core_cons)(core), true)
	}
	state := NativeCore{
		library:   library
		core:      core
		cmd:       cmd
		free_core: free_core
		free_mem:  free_mem
		log_fini:  log_fini
	}
	state.exchange('e scr.interactive=false; e scr.color=0', 0)!
	for command in options.before_open {
		state.exchange(command, limit)!
	}
	if target != '' && target != '--' {
		filename := if target == '-' { 'malloc://512' } else { target }
		file_open := CoreFileOpen(native_symbol(library, 'r_core_file_open')!)
		// R_PERM_R = 4 and R_PERM_W = 2 in libr's public ABI.
		permissions := if options.writable { 6 } else { 4 }
		if isnil(file_open(core, filename.str, permissions, options.load_address)) {
			return error('r2pipe: libr_core could not open ${target}')
		}
		if options.load_binary {
			bin_load := CoreBinLoad(native_symbol(library, 'r_core_bin_load')!)
			if !bin_load(core, filename.str, options.base_address) {
				return error('r2pipe: libr_core could not load binary information for ${target}')
			}
		}
	}
	for command in options.after_open {
		state.exchange(command, limit)!
	}
	initialized = true
	return state
}

fn (state &NativeCore) exchange(command string, limit int) !string {
	output := state.cmd(state.core, command.str)
	if isnil(output) {
		return error('r2pipe: r_core_cmd_str failed')
	}
	defer {
		if !isnil(state.free_mem) {
			MemFree(state.free_mem)(output)
		} else {
			C.free(output)
		}
	}
	length := if limit > 0 {
		C.strnlen(output, uint(limit) + 1)
	} else {
		unsafe { C.strlen(output) }
	}
	if limit > 0 && length > uint(limit) {
		return error('r2pipe: response exceeds ${limit} bytes')
	}
	return unsafe { tos(output, int(length)).clone() }
}

fn (state &NativeCore) close() {
	state.free_core(state.core)
	if !isnil(state.log_fini) {
		LogFini(state.log_fini)()
	}
	dl.close(state.library)
}

fn (mut transport NativeTransport) exchange(command string) !string {
	transport.commands <- command
	result := <-transport.replies
	if result.failure != '' {
		return error(result.failure)
	}
	return result.output
}

fn (mut transport NativeTransport) close() {
	transport.commands.close()
	transport.worker.wait()
}
