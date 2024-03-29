.POSIX:

CONFIGFILE = config.mk
include $(CONFIGFILE)

OS = linux
# Linux:   linux
# Mac OS:  macos
# Windows: windows
include mk/$(OS).mk


LIB_MAJOR = 1
LIB_MINOR = 0
LIB_VERSION = $(LIB_MAJOR).$(LIB_MINOR)


HDR =\
	libsha1.h\
	common.h

OBJ =\
	algorithm_output_size.o\
	behex_lower.o\
	behex_upper.o\
	digest.o\
	hmac_digest.o\
	hmac_init.o\
	hmac_marshal.o\
	hmac_state_output_size.o\
	hmac_unmarshal.o\
	hmac_update.o\
	init.o\
	marshal.o\
	process.o\
	state_output_size.o\
	sum_fd.o\
	unhex.o\
	unmarshal.o\
	update.o

MAN0 =\
	libsha1.h.0

MAN3 =\
	libsha1_algorithm_output_size.3\
	libsha1_behex_lower.3\
	libsha1_behex_upper.3\
	libsha1_digest.3\
	libsha1_hmac_digest.3\
	libsha1_hmac_init.3\
	libsha1_hmac_marshal.3\
	libsha1_hmac_state_output_size.3\
	libsha1_hmac_unmarshal.3\
	libsha1_hmac_update.3\
	libsha1_init.3\
	libsha1_marshal.3\
	libsha1_state_output_size.3\
	libsha1_sum_fd.3\
	libsha1_unhex.3\
	libsha1_unmarshal.3\
	libsha1_update.3

MAN7 =\
	libsha1.7

LOBJ = $(OBJ:.o=.lo)
SRC = $(OBJ:.o=.c)


all: libsha1.a libsha1.$(LIBEXT) test
$(OBJ): $(HDR)
$(LOBJ): $(HDR)

.c.o:
	$(CC) -c -o $@ $< $(CFLAGS) $(CPPFLAGS)

.c.lo:
	$(CC) -fPIC -c -o $@ $< $(CFLAGS) $(CPPFLAGS)

test: test.o libsha1.a
	$(CC) -o $@ test.o libsha1.a $(LDFLAGS)

libsha1.$(LIBEXT): $(LOBJ)
	$(CC) $(LIBFLAGS) -o $@ $(LOBJ) $(LDFLAGS)

libsha1.a: $(OBJ)
	-rm -f -- $@
	$(AR) rc $@ $(OBJ)
	$(AR) -s $@

check: test
	./test

install: libsha1.a libsha1.$(LIBEXT)
	mkdir -p -- "$(DESTDIR)$(PREFIX)/lib"
	mkdir -p -- "$(DESTDIR)$(PREFIX)/include"
	mkdir -p -- "$(DESTDIR)$(MANPREFIX)/man0"
	mkdir -p -- "$(DESTDIR)$(MANPREFIX)/man3"
	mkdir -p -- "$(DESTDIR)$(MANPREFIX)/man7"
	cp -- libsha1.a "$(DESTDIR)$(PREFIX)/lib"
	cp -- libsha1.$(LIBEXT) "$(DESTDIR)$(PREFIX)/lib/libsha1.$(LIBMINOREXT)"
	$(FIX_INSTALL_NAME) "$(DESTDIR)$(PREFIX)/lib/libsha1.$(LIBMINOREXT)"
	ln -sf -- "libsha1.$(LIBMINOREXT)" "$(DESTDIR)$(PREFIX)/lib/libsha1.$(LIBMAJOREXT)"
	ln -sf -- "libsha1.$(LIBMAJOREXT)" "$(DESTDIR)$(PREFIX)/lib/libsha1.$(LIBEXT)"
	cp -- libsha1.h "$(DESTDIR)$(PREFIX)/include"
	cp -- $(MAN0) "$(DESTDIR)$(MANPREFIX)/man0"
	cp -- $(MAN3) "$(DESTDIR)$(MANPREFIX)/man3"
	cp -- $(MAN7) "$(DESTDIR)$(MANPREFIX)/man7"

uninstall:
	-rm -f -- "$(DESTDIR)$(PREFIX)/lib/libsha1.a"
	-rm -f -- "$(DESTDIR)$(PREFIX)/lib/libsha1.$(LIBEXT)"
	-rm -f -- "$(DESTDIR)$(PREFIX)/lib/libsha1.$(LIBMAJOREXT)"
	-rm -f -- "$(DESTDIR)$(PREFIX)/lib/libsha1.$(LIBMINOREXT)"
	-rm -f -- "$(DESTDIR)$(PREFIX)/include/libsha1.h"
	-cd -- "$(DESTDIR)$(MANPREFIX)/man0" && rm -f -- $(MAN0)
	-cd -- "$(DESTDIR)$(MANPREFIX)/man3" && rm -f -- $(MAN3)
	-cd -- "$(DESTDIR)$(MANPREFIX)/man7" && rm -f -- $(MAN7)

clean:
	-rm -f -- *.o *.lo *.su *.a *.$(LIBEXT) *.gcda *.gcno *.gcov test

.SUFFIXES:
.SUFFIXES: .lo .o .c

.PHONY: all check install uninstall clean
