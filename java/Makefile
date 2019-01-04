all:
	javac -source 1.6 -target 1.6 -classpath . org/radare/r2pipe/*.java examples/Test.java
	jar cvf r2pipe.jar org
	$(MAKE) -C jni
	$(MAKE) -C examples

run:
	$(MAKE) -C examples run

clean:
	rm -f *.class org/radare/r2pipe/*.class
	rm -f r2pipe.jar
