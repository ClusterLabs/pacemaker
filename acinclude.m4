dnl
dnl local autoconf/automake macros for pacemaker
dnl

dnl Check if the flag is supported by linker (cacheable)
dnl CC_CHECK_LDFLAGS([FLAG], [ACTION-IF-FOUND],[ACTION-IF-NOT-FOUND])
dnl
dnl Origin (declared license: GPLv2+ with less restrictive exception):
dnl https://git.gnome.org/browse/glib/tree/m4macros/attributes.m4?h=2.49.1
dnl (AC_LANG_PROGRAM substituted by Jan Pokorny <jpokorny@redhat.com>)

AC_DEFUN([CC_CHECK_LDFLAGS], [
  AC_CACHE_CHECK([if $CC supports $1 flag],
    AS_TR_SH([cc_cv_ldflags_$1]),
    [ac_save_LDFLAGS="$LDFLAGS"
     LDFLAGS="$LDFLAGS $1"
     AC_LINK_IFELSE([AC_LANG_PROGRAM([[]], [[]])],
       [eval "AS_TR_SH([cc_cv_ldflags_$1])='yes'"],
       [eval "AS_TR_SH([cc_cv_ldflags_$1])="])
     LDFLAGS="$ac_save_LDFLAGS"
    ])

  AS_IF([eval test x$]AS_TR_SH([cc_cv_ldflags_$1])[ = xyes],
    [$2], [$3])
])
