TEST_PROJECT=tests/R2Pipe.Tests/R2Pipe.Tests.csproj
DOTNET=dotnet

all: build

restore:
	$(DOTNET) restore $(TEST_PROJECT)

build: restore
	$(DOTNET) build $(TEST_PROJECT) --no-restore -p:UseSharedCompilation=false /nr:false

test: restore
	$(DOTNET) test $(TEST_PROJECT) --no-build --no-restore -p:UseSharedCompilation=false /nr:false

clean:
	$(DOTNET) clean $(TEST_PROJECT)
	rm -rf r2pipe/bin r2pipe/obj tests/R2Pipe.Tests/bin tests/R2Pipe.Tests/obj

.PHONY: all restore build test clean
