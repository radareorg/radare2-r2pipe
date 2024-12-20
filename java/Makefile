JARPATH=$(shell pwd)
JAVASRC=src/main/java/org/radare/r2pipe
JAVAC?=javac
include config.mk

all:
	$(JAVAC) $(JAVACFLAGS) $(JAVASRC)/*.java examples/Test.java
	cd src/main/java && jar cvf ../../../r2pipe.jar org
#	$(MAKE) -C jni
	$(MAKE) -C examples

m mvn maven:
	mvn clean compile
	mvn install

run:
	$(MAKE) -C examples run

clean:
	rm -f *.class org/radare/r2pipe/*.class
	rm -f r2pipe.jar
