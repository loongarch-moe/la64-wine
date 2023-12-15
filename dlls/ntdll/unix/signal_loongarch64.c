#ifdef __loongarch_lp64
#include "config.h"

#include <assert.h>
#include <pthread.h>
#include <signal.h>
#include <stdlib.h>
#include <stdarg.h>
#include <stdio.h>
#include <sys/types.h>
#include <unistd.h>

#include "ntstatus.h"
#include "windef.h"
#include "winnt.h"
#include "winternl.h"
#include "wine/asm.h"
#include "unix_private.h"
#include "wine/debug.h"


WINE_DEFAULT_DEBUG_CHANNEL(seh);

#include "dwarf.h"

/***********************************************************************
 *              get_native_context
 */
void *get_native_context( CONTEXT *context )
{
    return context;
}

/***********************************************************************
 *           __wine_setjmpex
 */
__ASM_GLOBAL_FUNC( __wine_setjmpex,
                   "pcalau12i $t1, 0\n\t"
                   "ld.d $t1, $t1, 0\n\t"
                   "xor $t0, $ra, $t1\n\t"
                   "st.d $t0, $a0, 0\n\t"
                   "xor $t0, $sp, $t1\n\t"
                   "st.d $t0, $a0, 8\n\t"
                   "st.d $r21, $a0, 16\n\t"
                   "st.d $fp, $a0, 24\n\t"
                   "st.d $s0, $a0, 32\n\t"
                   "st.d $s1, $a0, 40\n\t"
                   "st.d $s2, $a0, 48\n\t"
                   "st.d $s3, $a0, 56\n\t"
                   "st.d $s4, $a0, 64\n\t"
                   "st.d $s5, $a0, 72\n\t"
                   "st.d $s6, $a0, 80\n\t"
                   "st.d $s7, $a0, 88\n\t"
                   "st.d $s8, $a0, 96\n\t"
                   "fst.d $fs0, $a0, 104\n\t"
                   "fst.d $fs1, $a0, 112\n\t"
                   "fst.d $fs2, $a0, 120\n\t"
                   "fst.d $fs3, $a0, 128\n\t"
                   "fst.d $fs4, $a0, 136\n\t"
                   "fst.d $fs5, $a0, 144\n\t"
                   "fst.d $fs6, $a0, 152\n\t"
                   "fst.d $fs7, $a0, 160\n\t"
                   "b 0\n\t" )

/***********************************************************************
 *           __wine_longjmp
 */
__ASM_GLOBAL_FUNC( __wine_longjmp,
                   "ld.d $t0, $a0, 0\n\t"
                   "pcalau12i $t1, 0\n\t"
                   "ld.d $t1, $t1, 0\n\t"
                   "xor $ra, $t0, $t1\n\t"
                   "ld.d $t0, $a0, 8\n\t"
                   "xor $sp, $t0, $t1\n\t"
                   "ld.d $r21, $a0, 16\n\t"
                   "ld.d $fp, $a0, 24\n\t"
                   "ld.d $s0, $a0, 32\n\t"
                   "ld.d $s1, $a0, 40\n\t"
                   "ld.d $s2, $a0, 48\n\t"
                   "ld.d $s3, $a0, 56\n\t"
                   "ld.d $s4, $a0, 64\n\t"
                   "ld.d $s5, $a0, 72\n\t"
                   "ld.d $s6, $a0, 80\n\t"
                   "ld.d $s7, $a0, 88\n\t"
                   "ld.d $s8, $a0, 96\n\t"
                   "fld.d $fs0, $a0, 104\n\t"
                   "fld.d $fs1, $a0, 112\n\t"
                   "fld.d $fs2, $a0, 120\n\t"
                   "fld.d $fs3, $a0, 128\n\t"
                   "fld.d $fs4, $a0, 136\n\t"
                   "fld.d $fs5, $a0, 144\n\t"
                   "fld.d $fs6, $a0, 152\n\t"
                   "fld.d $fs7, $a0, 160\n\t"
                   "sltui $a0, $a1, 1\n\t"
                   "add.d $a0, $a0, $a1\n\t"
                   "ret \n\t" )


#endif
