# r2pipe Python Test Suite

This directory contains a comprehensive test suite for the r2pipe Python library. The tests cover all aspects of the library including synchronous and asynchronous modes, native interface, error handling, and network connectivity.

## Test Files

### Core Tests
- `test_unit.py` - Original unit tests
- `test_integration.py` - Original integration tests
- `test_sync_enhanced.py` - Enhanced tests for synchronous r2pipe mode
- `test_async_enhanced.py` - Tests for asynchronous r2pipe mode
- `test_native_enhanced.py` - Tests for r2pipe native interface
- `test_error_handling.py` - Tests for error handling and edge cases
- `test_network.py` - Tests for HTTP and TCP connections using mock servers

### Support Files
- `mock_r2_server.py` - Mock r2 server for HTTP and TCP testing
- `ls` - Sample binary used for testing
- `race.py` and `race.sh` - Race condition test scripts
- `ccall.py` - Native interface test script

## Running the Tests

### Basic Test Execution

To run all tests:

```bash
cd python
python -m unittest discover test
```

To run a specific test file:

```bash
python -m unittest test.test_sync_enhanced
```

To run a specific test case:

```bash
python -m unittest test.test_sync_enhanced.TestR2PipeSyncEnhanced.test_cmd_basic_commands
```

### Setting Up for Tests

1. Make sure radare2 is installed and in your PATH
2. The tests require Python 3.6 or later
3. For native interface tests, you need the r2 shared library (libr_core)

### Mock Server for Network Tests

The mock server allows testing HTTP and TCP functionality without a real r2 server:

```bash
# Start mock server manually (usually not needed as tests start it)
python test/mock_r2_server.py
```

Options:
- `--http PORT` - HTTP server port (default: 9090)
- `--tcp PORT` - TCP server port (default: 9080)
- `--http-only` - Start only the HTTP server
- `--tcp-only` - Start only the TCP server

## Test Coverage

The test suite covers:

1. **Synchronous Mode**
   - Basic commands execution
   - JSON command parsing
   - Multiple commands
   - Cache functionality
   - File operations
   - Error handling

2. **Asynchronous Mode**
   - Basic async operation
   - Callbacks
   - Concurrent commands
   - Command ordering
   - Connection pooling
   - Context manager

3. **Native Interface**
   - r2lib loading
   - RCore initialization
   - Command execution
   - Memory management
   - ccall:// protocol

4. **Network Functionality**
   - HTTP connections (sync and async)
   - TCP connections (sync and async)
   - Error handling
   - Performance testing

5. **Error Handling & Edge Cases**
   - Nonexistent files
   - Invalid files
   - Command timeout
   - Large commands
   - Process termination
   - Multiple instances

## Contributing to Tests

When adding new tests:

1. Follow the existing test patterns
2. Ensure tests are independent and don't rely on each other
3. Clean up resources in tearDown and tearDownClass methods
4. Use descriptive docstrings explaining what each test does
5. Consider error handling cases for any new features

## Future Test Improvements

Some areas for further test improvements:

1. More comprehensive async command testing
2. Testing with large files/commands to stress-test the library
3. Fork/threading stress tests
4. More r2 commands coverage in mock server
5. Memory leak detection tests
6. Performance benchmarking