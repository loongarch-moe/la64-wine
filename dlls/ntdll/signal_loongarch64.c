#ifdef __loongarch_lp64
#include <assert.h>
#include <signal.h>
#include <stdlib.h>
#include <stdarg.h>
#include <stdio.h>

#include "ntstatus.h"
#define WIN32_NO_STATUS
#include "windef.h"
#include "winternl.h"
#include "wine/exception.h"
#include "ntdll_misc.h"
#include "wine/debug.h"
#include "ntsyscalls.h"
WINE_DEFAULT_DEBUG_CHANNEL(unwind);
WINE_DECLARE_DEBUG_CHANNEL(relay);
WINE_DECLARE_DEBUG_CHANNEL(threadname);

/*******************************************************************
 *         syscalls
 */
#define SYSCALL_ENTRY(id,name,args) __ASM_SYSCALL_FUNC( id, name )
ALL_SYSCALLS64
DEFINE_SYSCALL_HELPER32()
#undef SYSCALL_ENTRY

/* layering violation: the setjmp buffer is defined in msvcrt, but used by RtlUnwindEx */
struct MSVCRT_JUMP_BUFFER
{
    unsigned __int64 FP;
    unsigned __int64 Reserved;
    unsigned __int64 A0;
    unsigned __int64 A1;
    unsigned __int64 A2;
    unsigned __int64 A3;
    unsigned __int64 A4;
    unsigned __int64 A5;
    unsigned __int64 A6;
    unsigned __int64 A7;
    unsigned __int64 SP;
    double D[8];
};

#define SYSCALL_API __attribute__((naked))

/**********************************************************************
 *              DbgBreakPoint   (NTDLL.@)
 */
__ASM_GLOBAL_FUNC( DbgBreakPoint, "break 0; ret");
/**********************************************************************
 *              DbgUserBreakPoint   (NTDLL.@)
 */
__ASM_GLOBAL_FUNC( DbgUserBreakPoint, "break 0; ret" );

/*******************************************************************
 *		KiUserApcDispatcher (NTDLL.@)
 */
__ASM_GLOBAL_FUNC( KiUserApcDispatcher,
                   "break 1; ret" );

/*******************************************************************
 *		KiUserCallbackDispatcher (NTDLL.@)
 */
__ASM_GLOBAL_FUNC( KiUserCallbackDispatcher,
                   "break 1; ret" );

/*******************************************************************
 *		KiUserExceptionDispatcher (NTDLL.@)
 */
__ASM_GLOBAL_FUNC( KiUserExceptionDispatcher,
                   "break 1; ret" );


/******************************************************************
 *		LdrInitializeThunk (NTDLL.@)
 */
void WINAPI LdrInitializeThunk( CONTEXT *context, ULONG_PTR unk2, ULONG_PTR unk3, ULONG_PTR unk4 )
{
    asm("break 1;ret");
}

/*******************************************************************
 *		__C_specific_handler (NTDLL.@)
 */
EXCEPTION_DISPOSITION WINAPI __C_specific_handler( EXCEPTION_RECORD *rec,
                                                   void *frame,
                                                   CONTEXT *context,
                                                   struct _DISPATCHER_CONTEXT *dispatch )
{
       asm("break 1;ret");

}

/**************************************************************************
 *		__chkstk (NTDLL.@)
 */
__ASM_GLOBAL_FUNC( __chkstk, "break 1;ret")

/*******************************************************************
 *		_local_unwind (NTDLL.@)
 */
void WINAPI _local_unwind( void *frame, void *target_ip )
{
          asm("break 1;ret");

}
/***********************************************************************
 *		RtlCaptureContext (NTDLL.@)
 */
__ASM_GLOBAL_FUNC( RtlCaptureContext,
                    "break 1;ret" )
/*************************************************************************
 *             RtlCaptureStackBackTrace (NTDLL.@)
 */
USHORT WINAPI RtlCaptureStackBackTrace( ULONG skip, ULONG count, PVOID *buffer, ULONG *hash )
{
    FIXME( "(%ld, %ld, %p, %p) stub!\n", skip, count, buffer, hash );
    return 0;
}

/***********************************************************************
 *		RtlRaiseException (NTDLL.@)
 */
__ASM_GLOBAL_FUNC( RtlRaiseException,
                  "break 1;ret");

/*******************************************************************
 *              RtlRestoreContext (NTDLL.@)
 */
void CDECL RtlRestoreContext( CONTEXT *context, EXCEPTION_RECORD *rec )
{
          asm("break 1;ret");
}
/*******************************************************************
 *		RtlUnwind (NTDLL.@)
 */
void WINAPI RtlUnwind( void *frame, void *target_ip, EXCEPTION_RECORD *rec, void *retval )
{
    FIXME( "not implemented\n" );
}
/*******************************************************************
 *		RtlUnwindEx (NTDLL.@)
 */
void WINAPI RtlUnwindEx( PVOID end_frame, PVOID target_ip, EXCEPTION_RECORD *rec,
                         PVOID retval, CONTEXT *context, UNWIND_HISTORY_TABLE *table )
{
    FIXME( "not implemented\n" );
}



/***********************************************************************
 *           RtlUserThreadStart (NTDLL.@)
 */
void WINAPI RtlUserThreadStart( PRTL_THREAD_START_ROUTINE entry, void *arg )
{
          asm("break 1;ret");

}
/**********************************************************************
 *              RtlVirtualUnwind   (NTDLL.@)
 */
PVOID WINAPI RtlVirtualUnwind( ULONG type, ULONG64 base, ULONG64 pc,
                               RUNTIME_FUNCTION *function, CONTEXT *context,
                               PVOID *data, ULONG64 *frame_ret,
                               KNONVOLATILE_CONTEXT_POINTERS *ctx_ptr )
{
    FIXME( "not implemented\n" );
    return NULL;
}
#endif  /* __loongarch_lp64 */
