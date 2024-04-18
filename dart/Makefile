all:
	$(MAKE) r2js

r2js:
	dart pub get
	# dart compile js -O4 -o r2pipe.r2.js r2pipe-r2js.dart
	dart compile js -o _r2pipe.r2.js r2pipe-r2js.dart
	(echo 'var self = global;' ; cat _r2pipe.r2.js ) > r2pipe.r2.js ; rm -f _r2pipe.r2.js
	r2 -qi r2pipe.r2.js /bin/ls

ffi:
	dart compile exe r2pipe-ffi.dart
