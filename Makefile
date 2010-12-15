CFLAGS=-ggdb -I. -Wall -Werror -Wstrict-prototypes -Wshadow
XML_LIBS=`xml2-config --libs`
XML_FLAGS=`xml2-config --cflags`

all: rgm_flatten

rgm_flatten: reslist.o resrules.o restree.o flatten.o \
	     xmlconf.o
	gcc -o $@ $^ $(XML_LIBS)

%.o: %.c
	gcc -c -o $@ $^ $(CFLAGS) $(XML_FLAGS)

clean:
	rm -f *.o *~ rgm_flatten



