CROSS_PREFIX :=
CC=$(CROSS_PREFIX)gcc
STRIP=$(CROSS_PREFIX)strip

PREFIX=/usr/local
BINDIR=$(PREFIX)/bin
SRCDIR=src
INCLUDEDIR=include
BUILDDIR=build
SRCS := $(wildcard $(SRCDIR)/*.c)
OBJS := $(patsubst $(SRCDIR)/%.c,$(BUILDDIR)/%.o,$(SRCS))

override CFLAGS+=-std=c99 -I$(INCLUDEDIR) -frandom-seed=fakesip \
	-pedantic -Wall -Wextra -Wdate-time -pthread
override LDFLAGS+=-pthread -lnetfilter_queue -lnfnetlink -lmnl

ifdef VERSION
	override CFLAGS += -DVERSION=\"$(VERSION)\"
endif

FAKESIP=$(BUILDDIR)/fakesip

ifeq ($(STATIC), 1)
	override LDFLAGS += -static
endif

ifeq ($(DEBUG), 1)
	override CFLAGS += -O0 -g3 -fsanitize=address,leak,undefined
	override LDFLAGS += -fsanitize=address,leak,undefined
else
	override CFLAGS += -Os
endif

all: $(FAKESIP)

debug:
	$(MAKE) DEBUG=1

clean:
	$(RM) -r $(BUILDDIR)

$(BUILDDIR):
	mkdir -p $(BUILDDIR)

$(BUILDDIR)/%.d: $(SRCDIR)/%.c | $(BUILDDIR)
	$(CC) $(CFLAGS) -MM -MT $(@:.d=.o) $< -MF $@

$(BUILDDIR)/%.o: $(SRCDIR)/%.c | $(BUILDDIR)
	$(CC) $(CFLAGS) -c $< -o $@

$(FAKESIP): $(OBJS) $(MKS)
	$(CC) $(OBJS) -o $@ $(LDFLAGS)
ifneq ($(DEBUG), 1)
	$(STRIP) $@
endif

install: all
	mkdir -p $(DESTDIR)$(BINDIR)
	install -m 755 $(FAKESIP) $(DESTDIR)$(BINDIR)/fakesip

uninstall:
	$(RM) $(DESTDIR)$(BINDIR)/fakesip

.PHONY: all debug clean install uninstall

ifneq ($(MAKECMDGOALS),clean)
-include $(OBJS:.o=.d)
endif
