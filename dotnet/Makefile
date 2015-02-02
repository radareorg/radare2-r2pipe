R2P_LIB=r2pipe.dll
MCS=mcs
MONO=mono
MCS_LIB=$(MCS) -optimize -target:library -out:$(R2P_LIB)
MCS_LINK=$(MCS) -optimize -reference:$(R2P_LIB)

all: $(R2P_LIB) main.exe http.exe

$(R2P_LIB): r2pipe.cs
	$(MCS_LIB) r2pipe.cs

main.exe: main.cs $(R2P_LIB)
	$(MCS_LINK) main.cs

http.exe: http.cs $(R2P_LIB)
	$(MCS_LINK) http.cs

run:
	$(MONO) main.exe

clean:
	rm -f main.exe http.exe $(R2P_LIB)

.PHONY: run all clean
