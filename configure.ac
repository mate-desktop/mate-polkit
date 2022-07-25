AC_INIT([polkit-mate],[1.26.0],[https://mate-desktop.org/],[mate-polkit])

AM_INIT_AUTOMAKE([1.9 foreign dist-xz no-dist-gzip check-news])

AC_CONFIG_SRCDIR([src])
AC_CONFIG_HEADERS([config.h])
AC_CONFIG_MACRO_DIR([m4])

AM_MAINTAINER_MODE([enable])

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

# *****
# MATE
# *****

MATE_DEBUG_CHECK
MATE_COMPILE_WARNINGS

AC_PROG_CC
AC_HEADER_STDC

# Initialize libtool
LT_PREREQ([2.2.6])
LT_INIT

#### gcc warning flags

if test "x$GCC" = "xyes"; then
  changequote(,)dnl

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

# ***************************
# Check for required packages
# ***************************

GLIB_REQUIRED=2.50.0
GTK_REQUIRED=3.22.0
POLKIT_AGENT_REQUIRED=0.97
POLKIT_GOBJECT_REQUIRED=0.97
APPINDICATOR_REQUIRED=0.0.13

PKG_CHECK_MODULES(GLIB, glib-2.0 >= $GLIB_REQUIRED gio-2.0 >= $GLIB_REQUIRED)

PKG_CHECK_MODULES(GTK, gtk+-3.0 >= $GTK_REQUIRED)
AC_SUBST(GTK_CFLAGS)
AC_SUBST(GTK_LIBS)

PKG_CHECK_MODULES(POLKIT_AGENT, polkit-agent-1 >= $POLKIT_AGENT_REQUIRED)
AC_SUBST(POLKIT_AGENT_CFLAGS)
AC_SUBST(POLKIT_AGENT_LIBS)

PKG_CHECK_MODULES(POLKIT_GOBJECT, polkit-gobject-1 >= $POLKIT_GOBJECT_REQUIRED)
AC_SUBST(POLKIT_GOBJECT_CFLAGS)
AC_SUBST(POLKIT_GOBJECT_LIBS)

AC_ARG_ENABLE([accountsservice],
	      AS_HELP_STRING([--enable-accountsservice], [Enable accountsservice]),,
	      [enable_accountsservice=yes])

AM_CONDITIONAL([HAVE_ACCOUNTSSERVICE], [test "x$enable_accountsservice" = xyes])

# Application indicator
APPINDICATOR_PKG=appindicator3-0.1

AC_ARG_ENABLE([appindicator],
	      AS_HELP_STRING([--enable-appindicator[=@<:@no/auto/yes@:>@]],[Build support for application indicators]),
	      [enable_appindicator=$enableval],
	      [enable_appindicator="auto"])


if test "x$enable_appindicator" = "xauto"; then
	PKG_CHECK_EXISTS($APPINDICATOR_PKG >= $APPINDICATOR_REQUIRED,
			 [enable_appindicator="yes"],
			 [enable_appindicator="no"])
fi

if test "x$enable_appindicator" = "xyes"; then
	PKG_CHECK_MODULES(APPINDICATOR,
			  [$APPINDICATOR_PKG >= $APPINDICATOR_REQUIRED],
			  [AC_DEFINE(HAVE_APPINDICATOR, 1, [Have AppIndicator])])
fi

AM_CONDITIONAL(HAVE_APPINDICATOR, test "x$enable_appindicator" = "xyes")
AC_SUBST(APPINDICATOR_CFLAGS)
AC_SUBST(APPINDICATOR_LIBS)

# ********************
# Internationalisation
# ********************
AM_GNU_GETTEXT_VERSION([0.19.8])
AM_GNU_GETTEXT_REQUIRE_VERSION([0.19.8])
AM_GNU_GETTEXT([external])

GETTEXT_PACKAGE=mate-polkit
AC_SUBST([GETTEXT_PACKAGE])
AC_DEFINE_UNQUOTED([GETTEXT_PACKAGE],["$GETTEXT_PACKAGE"],[gettext domain])

# *************************************
# *************************************

AC_SUBST([AM_CPPFLAGS])
AC_SUBST([AM_CFLAGS])
AC_SUBST([AM_LDFLAGS])

AC_CONFIG_FILES([
Makefile
po/Makefile.in
src/Makefile
])

AC_OUTPUT

echo "
Configure summary:

    ${PACKAGE_STRING}
    `echo $PACKAGE_STRING | sed "s/./=/g"`

    prefix ...................: ${prefix}
    libdir ...................: ${libdir}
    libexecdir ...............: ${libexecdir}
    bindir ...................: ${bindir}
    sbindir ..................: ${sbindir}
    datadir ..................: ${datadir}
    sysconfdir ...............: ${sysconfdir}
    localstatedir ............: ${localstatedir}

    compiler .................: ${CC}
    cflags ...................: ${CFLAGS}
    cppflags .................: ${CPPFLAGS}
    Warning flags ............: ${WARN_CFLAGS}

    Accountsservice ..........: ${enable_accountsservice}
    Application indicator ....: ${enable_appindicator}
    Maintainer mode ..........: ${USE_MAINTAINER_MODE}
"
