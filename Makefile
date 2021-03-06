CFLAGS = -O3 -g -Wall
LDFLAGS = -llzo2

all: testit

testit: testit.o rpmpkg.o rpmidx.o rpmxdb.o

clean:
	rm -f testit.o rpmpkg.o rpmidx.o rpmxdb.o testit

rpmpkg.o: rpmpkg.h
rpmidx.o: rpmpkg.h rpmidx.h
rpmxdb.o: rpmpkg.h rpmxdb.h
testit.o: rpmpkg.h rpmidx.h
