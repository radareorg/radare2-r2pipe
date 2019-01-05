#JAVACFLAGS=-source 1.7 -target 1.7
JAVACFLAGS+=-classpath $(JARPATH)/javax.json-api-1.0.jar:$(JARPATH)/r2pipe.jar:examples:.
JAVACFLAGS+=-classpath $(JARPATH)/javax.json-1.1.jar:$(JARPATH)/javax.json-api-1.0.jar:$(JARPATH)/r2pipe.jar:examples:.
