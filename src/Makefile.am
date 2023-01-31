
FULL_LIBEXECDIR=$(libexecdir)

desktopdir = $(sysconfdir)/xdg/autostart
desktop_in_files = polkit-mate-authentication-agent-1.desktop.in
desktop_DATA = $(desktop_in_files:.desktop.in=.desktop)

polkit-mate-authentication-agent-1.desktop.in : polkit-mate-authentication-agent-1.desktop.in.in Makefile
	$(AM_V_GEN)sed \
		-e "s|\@FULL_LIBEXECDIR\@|$(FULL_LIBEXECDIR)|" \
		$< > $@

$(desktop_DATA): $(desktop_in_files)
	$(AM_V_GEN) $(MSGFMT) --desktop --template $< -d $(top_srcdir)/po -o $@

libexec_PROGRAMS = polkit-mate-authentication-agent-1

polkit_mate_authentication_agent_1_SOURCES = 						\
	polkitmatelistener.h			polkitmatelistener.c			\
	polkitmateauthenticator.h		polkitmateauthenticator.c		\
	polkitmateauthenticationdialog.h	polkitmateauthenticationdialog.c	\
	main.c										\
	$(BUILT_SOURCES)

polkit_mate_authentication_agent_1_CPPFLAGS = 		\
	-I$(top_srcdir)					\
	-DG_LOG_DOMAIN=\"polkit-mate-1\"		\
	-DDATADIR=\""$(pkgdatadir)"\"			\
	-DMATELOCALEDIR=\""$(datadir)/locale"\"	\
	-DPOLKIT_AGENT_I_KNOW_API_IS_SUBJECT_TO_CHANGE	\
	$(AM_CPPFLAGS)

polkit_mate_authentication_agent_1_CFLAGS = 		\
	$(GTK_CFLAGS)					\
	$(GLIB_CFLAGS)					\
	$(POLKIT_AGENT_CFLAGS)				\
	$(POLKIT_GOBJECT_CFLAGS)			\
	$(AYATANA_APPINDICATOR_CFLAGS)			\
	$(UBUNTU_APPINDICATOR_CFLAGS)			\
	$(WARN_CFLAGS)					\
	$(AM_CFLAGS)

polkit_mate_authentication_agent_1_LDFLAGS = 		\
	$(AM_LDFLAGS)

polkit_mate_authentication_agent_1_LDADD = 		\
	$(GTK_LIBS)					\
	$(GLIB_LIBS)					\
	$(POLKIT_AGENT_LIBS)				\
	$(POLKIT_GOBJECT_LIBS)				\
	$(AYATANA_APPINDICATOR_LIBS)			\
	$(UBUNTU_APPINDICATOR_LIBS)			

EXTRA_DIST = \
	polkit-mate-authentication-agent-1.desktop.in \
	polkit-mate-authentication-agent-1.desktop.in.in

clean-local :
	rm -f *~ polkit-mate-authentication-agent-1.desktop polkit-mate-authentication-agent-1.desktop.in

-include $(top_srcdir)/git.mk
