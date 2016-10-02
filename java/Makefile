all:
	javac -source 1.5 -target 1.5 -classpath . org/radare/r2pipe/*.java examples/Test.java
	jar cvf r2pipe.jar org

run:
	cd examples ; java -cp .. Test

clean:
	rm -f *.class org/radare/r2pipe/*.class
	rm -f r2pipe.jar
