JARPATH=$(shell pwd)
include config.mk

all:
	javac $(JAVACFLAGS) org/radare/r2pipe/*.java examples/Test.java
	jar cvf r2pipe.jar org
	$(MAKE) -C jni
	$(MAKE) -C examples

run:
	$(MAKE) -C examples run

clean:
	rm -f *.class org/radare/r2pipe/*.class
	rm -f r2pipe.jar
