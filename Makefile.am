SUBDIRS = polkitgtkmate src po docs

EXTRA_DIST = \
	autogen.sh		\
	TODO			\
	HACKING

ACLOCAL_AMFLAGS = -I m4 ${ACLOCAL_FLAGS}

DISTCHECK_CONFIGURE_FLAGS = --enable-gtk-doc

clean-local :
	rm -f *~ po/*~
