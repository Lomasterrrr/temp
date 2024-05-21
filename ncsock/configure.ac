AC_PREREQ([2.69])
AC_INIT([libncsock], [20240120])
AC_CONFIG_HEADERS([config.h:config.h.in])
AC_PROG_CC

AC_CANONICAL_HOST
AC_MSG_CHECKING([for operating system])
case "$host_os" in
  *bsd*)
    OS_TYPE=bsd
    AC_DEFINE([IS_BSD], [1], [Define if this is a BSD system])
    ;;
  *linux*)
    OS_TYPE=linux
    AC_DEFINE([IS_LINUX], [1], [Define if this is a Linux system])
    ;;
  *)
    OS_TYPE=unknown
    ;;
esac
AC_MSG_RESULT([$OS_TYPE])

AC_CHECK_SIZEOF([void *], [8])
if test "$ac_cv_sizeof_void_p" = "4"; then
  WORD_SIZE=32
elif test "$ac_cv_sizeof_void_p" = "8"; then
  WORD_SIZE=64
else
  AC_MSG_ERROR([Unsupported word size])
fi
AC_DEFINE_UNQUOTED([WORD_SIZE], [$WORD_SIZE], [Word size in bits])

if test "$ac_cv_c_bigendian" = "yes"; then
  AC_DEFINE([BIG_ENDIAN_SYSTEM], [1], [System is big-endian])
else
  AC_DEFINE([LITTLE_ENDIAN_SYSTEM], [1], [System is little-endian])
fi

AC_CONFIG_FILES([Makefile])
AC_OUTPUT
