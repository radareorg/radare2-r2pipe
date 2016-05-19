all: Newtonsoft.Json.dll
	ln -fs ../r2pipe/bin/Release/r2pipe.dll r2pipe.dll
	mcs -pkg:dotnet main.cs /r:r2pipe.dll /r:Newtonsoft.Json.dll
	mono main.exe main.exe

Newtonsoft.Json.dll:
	rm -rf Bin
	wget -c https://github.com/JamesNK/Newtonsoft.Json/releases/download/8.0.3/Json80r3.zip
	unzip Json80r3.zip Bin/Net40/Newtonsoft.Json.dll
	mv Bin/Net40/* .
	rm -rf Json80r3.zip Bin
