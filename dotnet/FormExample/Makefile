all:
	ln -fs ../r2pipe/bin/Release/r2pipe.dll r2pipe.dll
	mcs -pkg:dotnet rasm2net.cs /r:r2pipe.dll
	mono rasm2net.exe
