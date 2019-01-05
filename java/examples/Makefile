JARPATH=$(shell pwd)/..
include ../config.mk

# used to test that r2pipe.java works without the javax.json apis loaded
JCF+=-classpath $(JARPATH)/r2pipe.jar:$(JARPATH)/examples

all:
	javac $(JAVACFLAGS) TestJNI.java
	javac $(JAVACFLAGS) TestJSON.java 
	javac $(JAVACFLAGS) Test.java 

run:
	java $(JCF) Test
	java $(JAVACFLAGS) TestJSON
	java -Djava.library.path=../jni/ $(JCF) TestJNI
