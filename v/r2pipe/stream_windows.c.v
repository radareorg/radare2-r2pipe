module r2pipe

import time

fn new_spawn(_ string, _ SpawnOptions, _ int) !Transport {
	return error('r2pipe: subprocess transport requires POSIX')
}

fn new_inherited(_ time.Duration, _ int) !Transport {
	return error('r2pipe: inherited descriptor transport requires POSIX')
}
