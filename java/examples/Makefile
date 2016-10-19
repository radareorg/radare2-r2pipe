all:
	javac TestJNI.java -cp ../r2pipe.jar
	javac Test.java -cp ../r2pipe.jar

run:
	java -cp ../r2pipe.jar:. Test
	java -Djava.library.path=../jni/ -cp ../r2pipe.jar:. TestJNI
