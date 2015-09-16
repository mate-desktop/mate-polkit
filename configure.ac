AC_INIT([polkit-mate],[1.10.2],[http://www.mate-desktop.org/],[mate-polkit])

AM_INIT_AUTOMAKE([1.9 foreign dist-xz no-dist-gzip check-news])

AC_CONFIG_SRCDIR([src])
AC_CONFIG_HEADERS([config.h])
AC_CONFIG_MACRO_DIR([m4])

AM_MAINTAINER_MODE

m4_ifdef([AM_SILENT_RULES], [AM_SILENT_RULES([yes])])

# libtool versioning - this applies to all libraries in this package
#
# See http://sources.redhat.com/autobook/autobook/autobook_91.html#SEC91 for details
#
LT_CURRENT=0
LT_REVISION=0
LT_AGE=0
AC_SUBST(LT_CURRENT)
AC_SUBST(LT_REVISION)
AC_SUBST(LT_AGE)

AC_PROG_CC
AC_HEADER_STDC
AC_PROG_LIBTOOL

GTK_DOC_CHECK([1.3])

#### gcc warning flags

if test "x$GCC" = "xyes"; then
  changequote(,)dnl
  case " $CFLAGS " in
  *[\ \	]-Wall[\ \	]*) ;;
  *) CFLAGS="$CFLAGS -Wall" ;;
  esac

  case " $CFLAGS " in
  *[\ \	]-Wchar-subscripts[\ \	]*) ;;
  *) CFLAGS="$CFLAGS -Wchar-subscripts" ;;
  esac

  case " $CFLAGS " in
  *[\ \	]-Wmissing-declarations[\ \	]*) ;;
  *) CFLAGS="$CFLAGS -Wmissing-declarations" ;;
  esac

  case " $CFLAGS " in
  *[\ \	]-Wnested-externs[\ \	]*) ;;
  *) CFLAGS="$CFLAGS -Wnested-externs" ;;
  esac

  case " $CFLAGS " in
  *[\ \	]-Wpointer-arith[\ \	]*) ;;
  *) CFLAGS="$CFLAGS -Wpointer-arith" ;;
  esac

  case " $CFLAGS " in
  *[\ \	]-Wcast-align[\ \	]*) ;;
  *) CFLAGS="$CFLAGS -Wcast-align" ;;
  esac

  case " $CFLAGS " in
  *[\ \	]-Wsign-compare[\ \	]*) ;;
  *) CFLAGS="$CFLAGS -Wsign-compare" ;;
  esac

  if test "x$enable_ansi" = "xyes"; then
    case " $CFLAGS " in
    *[\ \	]-ansi[\ \	]*) ;;
    *) CFLAGS="$CFLAGS -ansi" ;;
    esac

    case " $CFLAGS " in
    *[\ \	]-D_POSIX_C_SOURCE*) ;;
    *) CFLAGS="$CFLAGS -D_POSIX_C_SOURCE=199309L" ;;
    esac

    case " $CFLAGS " in
    *[\ \	]-D_BSD_SOURCE[\ \	]*) ;;
    *) CFLAGS="$CFLAGS -D_BSD_SOURCE" ;;
    esac

    case " $CFLAGS " in
    *[\ \	]-pedantic[\ \	]*) ;;
    *) CFLAGS="$CFLAGS -pedantic" ;;
    esac
  fi
  if test x$enable_gcov = xyes; then
    case " $CFLAGS " in
    *[\ \	]-fprofile-arcs[\ \	]*) ;;
    *) CFLAGS="$CFLAGS -fprofile-arcs" ;;
    esac
    case " $CFLAGS " in
    *[\ \	]-ftest-coverage[\ \	]*) ;;
    *) CFLAGS="$CFLAGS -ftest-coverage" ;;
    esac

    ## remove optimization
    CFLAGS=`echo "$CFLAGS" | sed -e 's/-O[0-9]*//g'`
  fi
  changequote([,])dnl
else
  if test x$enable_gcov = xyes; then
    AC_MSG_ERROR([--enable-gcov can only be used with gcc])
  fi
fi

# *****
# MATE
# *****

MATE_COMMON_INIT
MATE_DEBUG_CHECK
MATE_COMPILE_WARNINGS([maximum])
MATE_MAINTAINER_MODE_DEFINES

# ***************************
# Check for required packages
# ***************************

GLIB_REQUIRED=2.36.0
POLKIT_AGENT_REQUIRED=0.97
POLKIT_GOBJECT_REQUIRED=0.97
APPINDICATOR_REQUIRED=0.0.13

AC_MSG_CHECKING([which gtk+ version to compile against])
AC_ARG_WITH([gtk],
  [AS_HELP_STRING([--with-gtk=2.0|3.0],[which gtk+ version to compile against (default: 2.0)])],
  [case "$with_gtk" in
     2.0|3.0) ;;
     *) AC_MSG_ERROR([invalid gtk version specified]) ;;
   esac],
  [with_gtk=2.0])
AC_MSG_RESULT([$with_gtk])

case "$with_gtk" in
  2.0) GTK_API_VERSION=2.0
       GTK_REQUIRED=2.24.0
       ;;
  3.0) GTK_API_VERSION=3.0
       GTK_REQUIRED=3.0.0
       ;;
esac
AC_SUBST(GTK_API_VERSION)

PKG_CHECK_MODULES(GLIB, glib-2.0 >= $GLIB_REQUIRED gio-2.0 >= $GLIB_REQUIRED)

PKG_CHECK_MODULES(GTK, gtk+-$GTK_API_VERSION >= $GTK_REQUIRED)
AC_SUBST(GTK_CFLAGS)
AC_SUBST(GTK_LIBS)

PKG_CHECK_MODULES(POLKIT_AGENT, polkit-agent-1 >= $POLKIT_AGENT_REQUIRED)
AC_SUBST(POLKIT_AGENT_CFLAGS)
AC_SUBST(POLKIT_AGENT_LIBS)

PKG_CHECK_MODULES(POLKIT_GOBJECT, polkit-gobject-1 >= $POLKIT_GOBJECT_REQUIRED)
AC_SUBST(POLKIT_GOBJECT_CFLAGS)
AC_SUBST(POLKIT_GOBJECT_LIBS)

AC_ARG_ENABLE([accountsservice],
	      AC_HELP_STRING([--enable-accountsservice], [Enable accountsservice]),,
	      [enable_accountsservice=yes])

AM_CONDITIONAL([HAVE_ACCOUNTSSERVICE], [test "x$enable_accountsservice" = xyes])

# Application indicator
AC_ARG_ENABLE([appindicator],
	      AS_HELP_STRING([--enable-appindicator[=@<:@no/auto/yes@:>@]],[Build support for application indicators]),
	      [enable_appindicator=$enableval],
	      [enable_appindicator="auto"])


if test "x$enable_appindicator" = "xauto"; then
	PKG_CHECK_EXISTS(appindicator-0.1 >= $APPINDICATOR_REQUIRED,
			 [enable_appindicator="yes"],
			 [enable_appindicator="no"])
fi

if test "x$enable_appindicator" = "xyes"; then
	PKG_CHECK_MODULES(APPINDICATOR,
			  [appindicator-0.1 >= $APPINDICATOR_REQUIRED],
			  [AC_DEFINE(HAVE_APPINDICATOR, 1, [Have AppIndicator])])
fi

AM_CONDITIONAL(HAVE_APPINDICATOR, test "x$enable_appindicator" = "xyes")
AC_SUBST(APPINDICATOR_CFLAGS)
AC_SUBST(APPINDICATOR_LIBS)

AC_ARG_ENABLE([examples],
              AC_HELP_STRING([--enable-examples], [Build the example programs]),,
              [enable_examples=yes])

AM_CONDITIONAL(BUILD_EXAMPLES, test "x$enable_examples" = "xyes")

# GObject introspection
#
AC_ARG_ENABLE([introspection],
	AS_HELP_STRING([--enable-introspection], [enable GObject introspection]),
	[], [enable_introspection=yes])
if test "x$enable_introspection" = xyes; then
	PKG_CHECK_MODULES([INTROSPECTION], [gobject-introspection-1.0 >= 0.6.2])
	AC_DEFINE([ENABLE_INTROSPECTION], [1], [enable GObject introspection support])
	AC_SUBST([G_IR_SCANNER], [$($PKG_CONFIG --variable=g_ir_scanner gobject-introspection-1.0)])
	AC_SUBST([G_IR_COMPILER], [$($PKG_CONFIG --variable=g_ir_compiler gobject-introspection-1.0)])
	AC_SUBST([G_IR_GENERATE], [$($PKG_CONFIG --variable=g_ir_generate gobject-introspection-1.0)])
	#AC_SUBST([GIRDIR], [$($PKG_CONFIG --variable=girdir gobject-introspection-1.0)])
	#AC_SUBST([GIRTYPELIBDIR], [$($PKG_CONFIG --variable=typelibdir gobject-introspection-1.0)])
        GIRDIR=${datadir}/gir-1.0
        GIRTYPELIBDIR=${libdir}/girepository-1.0
        AC_SUBST(GIRDIR)
        AC_SUBST(GIRTYPELIBDIR)
fi
AM_CONDITIONAL([ENABLE_INTROSPECTION], [test "x$enable_introspection" = xyes])

# ********************
# Internationalisation
# ********************

IT_PROG_INTLTOOL([0.35.0])

GETTEXT_PACKAGE=mate-polkit
AC_SUBST([GETTEXT_PACKAGE])
AM_GLIB_GNU_GETTEXT
AC_DEFINE_UNQUOTED([GETTEXT_PACKAGE],["$GETTEXT_PACKAGE"],[gettext domain])

# *************************************
# *************************************

AC_SUBST([AM_CPPFLAGS])
AC_SUBST([AM_CFLAGS])
AC_SUBST([AM_CXXFLAGS])
AC_SUBST([AM_LDFLAGS])

AC_CONFIG_FILES([
Makefile
po/Makefile.in
polkitgtkmate/Makefile
polkitgtkmate/polkit-gtk-mate-1.pc
src/Makefile
docs/version.xml
docs/Makefile
])

AC_OUTPUT

echo "
                  polkit-mate $VERSION
                =======================

        prefix:                     ${prefix}
        libdir:                     ${libdir}
        libexecdir:                 ${libexecdir}
        bindir:                     ${bindir}
        sbindir:                    ${sbindir}
        datadir:                    ${datadir}
        sysconfdir:                 ${sysconfdir}
        localstatedir:              ${localstatedir}

        compiler:                   ${CC}
        cflags:                     ${CFLAGS}
        cppflags:                   ${CPPFLAGS}

        Gtk+ version:               ${GTK_API_VERSION}
        Accountsservice:            ${enable_accountsservice}
        Application indciator:      ${enable_appindicator}
        Maintainer mode:            ${USE_MAINTAINER_MODE}
        Building api docs:          ${enable_gtk_doc}
        GObject Introspection:      ${enable_introspection}
"
