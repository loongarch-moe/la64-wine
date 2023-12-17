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
 *           signal_set_full_context
 */
NTSTATUS signal_set_full_context( CONTEXT *context )
{
    ERR("%s: NOT Implemented On LoongArch64\n", __FUNCTION__); exit(1);
    return STATUS_NOT_IMPLEMENTED;
}

/***********************************************************************
 *              NtSetContextThread  (NTDLL.@)
 *              ZwSetContextThread  (NTDLL.@)
 */
NTSTATUS WINAPI NtSetContextThread( HANDLE handle, const CONTEXT *context )
{
    ERR("%s: NOT Implemented On LoongArch64\n", __FUNCTION__); exit(1);
    return STATUS_NOT_IMPLEMENTED;
}


/***********************************************************************
 *              NtGetContextThread  (NTDLL.@)
 *              ZwGetContextThread  (NTDLL.@)
 */
NTSTATUS WINAPI NtGetContextThread( HANDLE handle, CONTEXT *context )
{
    ERR("%s: NOT Implemented On LoongArch64\n", __FUNCTION__); exit(1);
    return STATUS_NOT_IMPLEMENTED;
}


/***********************************************************************
 *              set_thread_wow64_context
 */
NTSTATUS set_thread_wow64_context( HANDLE handle, const void *ctx, ULONG size )
{
    ERR("%s: NOT Implemented On LoongArch64\n", __FUNCTION__); exit(1);
    return STATUS_NOT_IMPLEMENTED;
}


/***********************************************************************
 *              get_thread_wow64_context
 */
NTSTATUS get_thread_wow64_context( HANDLE handle, void *ctx, ULONG size )
{
    ERR("%s: NOT Implemented On LoongArch64\n", __FUNCTION__); exit(1);
    return STATUS_NOT_IMPLEMENTED;
}

/***********************************************************************
 *           call_user_apc_dispatcher
 */
NTSTATUS call_user_apc_dispatcher( CONTEXT *context, ULONG_PTR arg1, ULONG_PTR arg2, ULONG_PTR arg3,
                                   PNTAPCFUNC func, NTSTATUS status )
{
    ERR("%s: NOT Implemented On LoongArch64\n", __FUNCTION__); exit(1);
    return STATUS_NOT_IMPLEMENTED;
}


/***********************************************************************
 *           call_raise_user_exception_dispatcher
 */
void call_raise_user_exception_dispatcher(void)
{
    ERR("%s: NOT Implemented On LoongArch64\n", __FUNCTION__); exit(1);
}


/***********************************************************************
 *           call_user_exception_dispatcher
 */
NTSTATUS call_user_exception_dispatcher( EXCEPTION_RECORD *rec, CONTEXT *context )
{
    ERR("%s: NOT Implemented On LoongArch64\n", __FUNCTION__); exit(1);
    return STATUS_NOT_IMPLEMENTED;
}


/***********************************************************************
 *           KeUserModeCallbackNative
 */
NTSTATUS WINAPI KeUserModeCallbackNative( ULONG id, const void *args, ULONG len, void **ret_ptr, ULONG *ret_len )
{
    ERR("%s: NOT Implemented On LoongArch64\n", __FUNCTION__); exit(1);
    return STATUS_NOT_IMPLEMENTED;
}


/***********************************************************************
 *           NtCallbackReturn  (NTDLL.@)
 */
NTSTATUS WINAPI NtCallbackReturn( void *ret_ptr, ULONG ret_len, NTSTATUS status )
{
    ERR("%s: NOT Implemented On LoongArch64\n", __FUNCTION__); exit(1);
    return STATUS_NOT_IMPLEMENTED;
}


/**********************************************************************
 *           get_thread_ldt_entry
 */
NTSTATUS get_thread_ldt_entry( HANDLE handle, void *data, ULONG len, ULONG *ret_len )
{
    ERR("%s: NOT Implemented On LoongArch64\n", __FUNCTION__); exit(1);
    return STATUS_NOT_IMPLEMENTED;
}


/******************************************************************************
 *           NtSetLdtEntries   (NTDLL.@)
 *           ZwSetLdtEntries   (NTDLL.@)
 */
NTSTATUS WINAPI NtSetLdtEntries( ULONG sel1, LDT_ENTRY entry1, ULONG sel2, LDT_ENTRY entry2 )
{
    ERR("%s: NOT Implemented On LoongArch64\n", __FUNCTION__); exit(1);
    return STATUS_NOT_IMPLEMENTED;
}


/**********************************************************************
 *             signal_init_threading
 */
void signal_init_threading(void)
{
}


/**********************************************************************
 *             signal_alloc_thread
 */
NTSTATUS signal_alloc_thread( TEB *teb )
{
    return STATUS_SUCCESS;
}


/**********************************************************************
 *             signal_free_thread
 */
void signal_free_thread( TEB *teb )
{
    ERR("%s: NOT Implemented On LoongArch64\n", __FUNCTION__); exit(1);
}


/**********************************************************************
 *		signal_init_process
 */
void signal_init_process(void)
{
    ERR("%s: NOT Implemented On LoongArch64\n", __FUNCTION__); exit(1);
}

/***********************************************************************
 *              get_wow_context
 */
void *get_wow_context( CONTEXT *context )
{
    ERR("%s: NOT Implemented On LoongArch64\n", __FUNCTION__); exit(1);
    return 0;
}
/***********************************************************************
 *           call_init_thunk
 */
void call_init_thunk( LPTHREAD_START_ROUTINE entry, void *arg, BOOL suspend, TEB *teb )
{
    ERR("%s: NOT Implemented On LoongArch64\n", __FUNCTION__); exit(1);
}

NTSTATUS unwind_builtin_dll( void *args )
{
    ERR("%s: NOT Implemented On LoongArch64\n", __FUNCTION__); exit(1);
    return STATUS_NOT_IMPLEMENTED;
}

void DECLSPEC_NORETURN signal_start_thread( PRTL_THREAD_START_ROUTINE entry, void *arg,
                                                   BOOL suspend, TEB *teb )
{
    ERR("%s: NOT Implemented On LoongArch64\n", __FUNCTION__); exit(1);
}

void DECLSPEC_NORETURN signal_exit_thread( int status, void (*func)(int), TEB *teb )
{
    ERR("%s: NOT Implemented On LoongArch64\n", __FUNCTION__); exit(1);
}

// /***********************************************************************
//  *           __wine_syscall_dispatcher
//  */
 void __wine_syscall_dispatcher(void)
 {
     ERR("%s: NOT Implemented On LoongArch64\n", __FUNCTION__); exit(1);
 }

// /***********************************************************************
//  *           __wine_unix_call_dispatcher
//  */
 void __wine_unix_call_dispatcher(void)
 {
     ERR("%s: NOT Implemented On LoongArch64\n", __FUNCTION__); exit(1);
 }
void __attribute__((naked)) DbgBreakPoint(void)
{

}
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
