R2P_LIB=r2pipe.dll
MCS=mcs
MONO=mono
XBUILD=xbuild /p:Configuration=Release
NUGET=nuget
# See http://sourceforge.net/projects/narrange/files/narrange/NArrange%20Beta%20Version%200.2.9/NArrange-0.2.9-net-2.0.zip/download
NARRANGE_WD=~/Downloads/NArrange/bin
NARRANGE=$(NARRANGE_WD)/narrange-console.exe
MCS_LIB=$(MCS) -optimize -target:library -out:$(R2P_LIB)
MCS_LINK=$(MCS) -optimize -reference:$(R2P_LIB)

ifneq ($(KEYFILE),)
MCS_LIB+=-keyfile:$(KEYFILE)
MCS_LINK+=-keyfile:$(KEYFILE)
endif

all: $(R2P_LIB) examples
	ln -fs r2pipe/bin/Release/r2pipe.dll r2pipe.dll
	ln -fs r2pipe/bin/Debug/r2pipe.dll r2pipeDebug.dll

$(R2P_LIB): 
ifneq ($(KEYFILE),)
	$(XBUILD) /p:SignAssembly=true /p:AssemblyOriginatorKeyFile=$(KEYFILE) r2pipe/r2pipe.csproj
else
	$(XBUILD) r2pipe/r2pipe.csproj
endif

examples:
	$(XBUILD) LocalExample/LocalExample.csproj
	$(XBUILD) HttpExample/HttpExample.csproj

run:
	$(MONO) LocalExample/bin/Release/LocalExample.exe

clean:
	rm -f main.exe http.exe $(R2P_LIB)
	rm -rf r2pipe/obj r2pipe/bin
	rm -rf HttpExample/obj HttpExample/bin
	rm -rf LocalExample/obj LocalExample/bin

nuget:
	$(NUGET) pack r2pipe/r2pipe.csproj.nuspec

indent:
	for a in *.cs ; do $(MONO) $(NARRANGE) $$a ; done

.PHONY: run all clean indent examples $(R2P_LIB)
