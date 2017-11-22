all:
	go test
	cd example ; go run example.go

sync:
	rm -rf tmp
	git clone `cat ORIGIN` tmp
	cp -f tmp/*.go .

.PHONY: all sync
