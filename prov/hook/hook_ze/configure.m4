dnl Configury specific to the libfabrics xe hooking provider

dnl Called to configure this provider
dnl
dnl Arguments:
dnl
dnl $1: action if configured successfully
dnl $2: action if not configured successfully
dnl

AC_DEFUN([FI_HOOK_ZE_CONFIGURE],[
    # Determine if we can support the ze hooking provider
    hook_ze_happy=0
    ze_lib_happy=0
    AS_IF([test x"$enable_hook_ze" != x"no"], [hook_ze_happy=1])
    AS_IF([test x"$hook_ze_dl" == x"1"], [
	hook_ze_happy=0
	AC_MSG_ERROR([ZE hooking provider cannot be compiled as DL])
    ])

    AC_CHECK_FUNC([zeInit],
		  [ze_lib_happy=1],
		  [ze_lib_happy=0])

    AS_IF([test $hook_ze_happy -eq 1 && \
	   test $ze_lib_happy -eq 1], [$1], [$2])

])
