PHP_ARG_WITH([oqs],
  [for OQS extension support (path to liboqs prefix)],
  [--with-oqs[=DIR]        Build the OQS extension; DIR is the liboqs prefix])

if test "$PHP_OQS" = "no"; then
  AC_MSG_ERROR([You must provide --with-oqs=<liboqs prefix>])
fi

dnl Default to /usr/local if user passed just --with-oqs
if test "$PHP_OQS" = "yes"; then
  PHP_OQS="/usr/local"
fi

OQS_DIR="$PHP_OQS"

dnl ---------- Header presence ----------
AC_MSG_CHECKING([for liboqs in $OQS_DIR])
if test -f "$OQS_DIR/include/oqs/oqs.h"; then
  AC_MSG_RESULT([found headers])
else
  AC_MSG_ERROR([oqs.h not found in $OQS_DIR/include/oqs])
fi

dnl ---------- Version check: prefer pkg-config, fallback to parsing oqsconfig.h ----------
AC_PATH_TOOL([PKG_CONFIG],[pkg-config],[:])

OQS_VERSION_OK=no
OQS_VERSION_TXT="unknown"

if test "$PKG_CONFIG" != ":"; then
  dnl Try pkg-config to check version
  if $PKG_CONFIG --exists "liboqs >= 0.14.0"; then
    OQS_VERSION_OK=yes
    OQS_VERSION_TXT=`$PKG_CONFIG --modversion liboqs 2>/dev/null || echo unknown`
    AC_MSG_RESULT([using pkg-config: liboqs $OQS_VERSION_TXT >= 0.14.0])
  fi
fi

if test "$OQS_VERSION_OK" = "no"; then
  dnl Fallback: parse oqsconfig.h (defines OQS_VERSION_{MAJOR,MINOR,PATCH,TEXT})
  AC_MSG_CHECKING([for liboqs version >= 0.14.0 via oqsconfig.h])
  OQS_CONF="$OQS_DIR/include/oqs/oqsconfig.h"
  if test -f "$OQS_CONF"; then
    OQS_VER_TXT=`sed -n 's/^#define[[:space:]]\+OQS_VERSION_TEXT[[:space:]]\+"\(.*\)".*/\1/p' "$OQS_CONF"`
    OQS_VER_MAJ=`sed -n 's/^#define[[:space:]]\+OQS_VERSION_MAJOR[[:space:]]\+\([0-9]\+\).*/\1/p' "$OQS_CONF"`
    OQS_VER_MIN=`sed -n 's/^#define[[:space:]]\+OQS_VERSION_MINOR[[:space:]]\+\([0-9]\+\).*/\1/p' "$OQS_CONF"`
    OQS_VER_PAT=`sed -n 's/^#define[[:space:]]\+OQS_VERSION_PATCH[[:space:]]\+\([0-9]\+\).*/\1/p' "$OQS_CONF"`

    if test "x$OQS_VER_MAJ" = "x" -o "x$OQS_VER_MIN" = "x" -o "x$OQS_VER_PAT" = "x"; then
      AC_MSG_ERROR([could not determine liboqs version from $OQS_CONF])
    fi

    dnl Compare tuple (major,minor,patch) >= (0,14,0)
    OQS_OK=no
    if test "$OQS_VER_MAJ" -gt 0; then
      OQS_OK=yes
    elif test "$OQS_VER_MAJ" -eq 0; then
      if test "$OQS_VER_MIN" -gt 14; then
        OQS_OK=yes
      elif test "$OQS_VER_MIN" -eq 14 -a "$OQS_VER_PAT" -ge 0; then
        OQS_OK=yes
      fi
    fi

    if test "$OQS_OK" = "no"; then
      AC_MSG_ERROR([liboqs 0.14.0 or newer is required (found ${OQS_VER_TXT:-$OQS_VER_MAJ.$OQS_VER_MIN.$OQS_VER_PAT})])
    else
      OQS_VERSION_OK=yes
      OQS_VERSION_TXT="${OQS_VER_TXT:-$OQS_VER_MAJ.$OQS_VER_MIN.$OQS_VER_PAT}"
      AC_MSG_RESULT([ok ($OQS_VERSION_TXT)])
    fi
  else
    AC_MSG_ERROR([cannot find $OQS_CONF to verify version])
  fi
fi

dnl ---------- Add include and lib paths from the chosen prefix ----------
PHP_ADD_INCLUDE($OQS_DIR/include)
PHP_ADD_LIBRARY_WITH_PATH(oqs, $OQS_DIR/lib, OQS_SHARED_LIBADD)

PHP_NEW_EXTENSION(oqs, oqs.c, $ext_shared)
PHP_SUBST(OQS_SHARED_LIBADD)
