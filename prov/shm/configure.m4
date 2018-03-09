dnl Configury specific to the libfabric shm provider

dnl Called to configure this provider
dnl
dnl Arguments:
dnl
dnl $1: action if configured successfully
dnl $2: action if not configured successfully
dnl
AC_DEFUN([FI_SHM_CONFIGURE],[
	# Determine if we can support the shm provider
	shm_happy=0
	cma_happy=0
	xpmem_happy=0

	AS_IF([test x"$enable_shm" != x"no"],
	      [
	       # check if CMA support are present
	       AC_CHECK_FUNC([process_vm_readv],
			     [cma_happy=1],
			     [cma_happy=0])

	       AS_IF([test $cma_happy -eq 1],
		     [AC_DEFINE([CMA_ACTIVE], [1],
				[Define if CMA support is available])])
	
	       # check if SHM support are present
	       AC_CHECK_FUNC([shm_open],
			     [shm_happy=1],
			     [shm_happy=0])

               AS_IF([test "$enable_xpmem" = "no"],
		     [want_xpmem=0
		      xpmem_happy=0],
		     [want_xpmem=1
		      xpmem_happy=1])

	       # check if XPMEM support is present
	       AS_IF([test $xpmem_happy -eq 1],
		     [FI_CHECK_PACKAGE([xpmem],
				[xpmem.h],
	 			[xpmem],
				[xpmem_make],
				[],
				[$xpmem_PREFIX],
				[$xpmem_LIBDIR],
				[],
				[xpmem_happy=0])])

	       AS_IF([test $xpmem_happy -eq 1],
		     [AC_DEFINE([XPMEM_ACTIVE], [1],
				[Define if XPMEM support is available])],
		     [])

	       # if xpmem was requested but we can't deliver it, abort
	       AS_IF([test $want_xpmem -eq 1 && test $xpmem_happy -eq 0],
		     [AC_MSG_WARN([xpmem support requested, but is unavailable])
		      AC_MSG_ERROR([Cannot continue])])

	       AC_SUBST(xpmem_CPPFLAGS)
	       AC_SUBST(xpmem_LDFLAGS)
	       AC_SUBST(xpmem_LIBS)

	       # look for shm_open in librt if not already present
	       AS_IF([test $shm_happy -eq 0],
		     [FI_CHECK_PACKAGE([shm_lib],
				[sys/mman.h],
				[rt],
				[shm_open],
				[],
				[],
				[],
				[shm_happy=1],
				[shm_happy=0])])
	      ])

	AS_IF([test $shm_happy -eq 1 && \
	       [test $cma_happy -eq 1 || \
		test $xpmem_happy -eq 1]], [$1], [$2])
])
