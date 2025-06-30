
all: qmake build

.PHONY: clean
clean:
	rm -fr build

.PHONY: qmake
qmake: clean
	-mkdir build
	cd build && qmake ../../quissh.pro

.PHONY: build
build:
	cd build && make -j16

.PHONY: run
run:
	../_bin/libssh-example
