CC        ?= cc
CFLAGS    ?= -O2 -Wall -Wextra
PREFIX    ?= /usr/local
BINDIR    ?= $(PREFIX)/bin
DESTDIR   ?=
UDEVDIR   ?= /etc/udev/rules.d
PKG_CONFIG ?= pkg-config
SUDO      := $(shell if [ "`id -u`" = "0" ]; then echo ""; \
                     elif command -v sudo >/dev/null 2>&1; then echo "sudo"; fi)

PROG := stkeytool
SRCS := stmkeytool.c crc16.c hmac_sha1.c
HDRS := crc16.h hmac_sha1.h
RULES_FILE := 70-stm32key.rules
RULES_DEST := 70-stkeytool.rules

# Unity build: stmkeytool.c #includes crc16.c and hmac_sha1.c,
# so only stmkeytool.c goes on the compile/link line.
LIBUSB_CFLAGS := $(shell $(PKG_CONFIG) --cflags libusb-1.0 2>/dev/null)
LIBUSB_LIBS   := $(shell $(PKG_CONFIG) --libs libusb-1.0 2>/dev/null || echo -lusb-1.0)

all: $(PROG)

$(PROG): $(SRCS) $(HDRS)
	$(CC) $(CFLAGS) $(LIBUSB_CFLAGS) -o $@ stmkeytool.c $(LIBUSB_LIBS)

# Install build dependencies (libusb-1.0 headers + pkg-config).
deps:
	@if command -v apt-get >/dev/null 2>&1; then \
		$(SUDO) apt-get install -y libusb-1.0-0-dev pkg-config; \
	elif command -v dnf >/dev/null 2>&1; then \
		$(SUDO) dnf install -y libusb1-devel pkgconf-pkg-config; \
	elif command -v pacman >/dev/null 2>&1; then \
		$(SUDO) pacman -S --noconfirm libusb pkgconf; \
	elif command -v zypper >/dev/null 2>&1; then \
		$(SUDO) zypper --non-interactive install libusb-1_0-devel pkg-config; \
	elif command -v apk >/dev/null 2>&1; then \
		$(SUDO) apk add libusb-dev pkgconf; \
	else \
		echo "unknown package manager: install libusb-1.0 dev files manually"; \
		exit 1; \
	fi

install: $(PROG)
	install -d $(DESTDIR)$(BINDIR)
	install -m 755 $(PROG) $(DESTDIR)$(BINDIR)/$(PROG)
	install -d $(DESTDIR)$(UDEVDIR)
	install -m 644 $(RULES_FILE) $(DESTDIR)$(UDEVDIR)/$(RULES_DEST)
	@if [ -z "$(DESTDIR)" ] && command -v udevadm >/dev/null 2>&1; then \
		udevadm control --reload-rules 2>/dev/null || true; \
		udevadm trigger --subsystem-match=usb 2>/dev/null || true; \
	fi
	@echo "installed $(DESTDIR)$(BINDIR)/$(PROG) and $(DESTDIR)$(UDEVDIR)/$(RULES_DEST)"

uninstall:
	rm -f $(DESTDIR)$(BINDIR)/$(PROG)
	rm -f $(DESTDIR)$(UDEVDIR)/$(RULES_DEST)

clean:
	rm -f $(PROG)

.PHONY: all deps install uninstall clean
