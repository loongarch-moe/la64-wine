#if 0
#pragma makedep unix
#endif
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

struct syscall_frame
{
    ULONG64               r[32];          /* 000 */
    ULONG64               __pc;           /* 100 */
    ULONG                 cpsr;           /* 108 */
    ULONG                 restore_flags;  /* 10c */
    struct syscall_frame *prev_frame;     /* 110 */
    void                 *syscall_cfa;    /* 118 */
    ULONG64               align;          /* 120 */
    DWORD                 fcsr;           /* 128 */
    ULONG                 fcc;           /* 12c */
};
struct loongarch64_thread_data
{
    struct syscall_frame *syscall_frame; /* 02f0 frame pointer on syscall entry */
    SYSTEM_SERVICE_TABLE *syscall_table; /* 02f8 syscall table */
};

# define REG_sig(reg_name, context) ((context)->uc_mcontext.reg_name)
# define REGn_sig(reg_num, context) ((context)->uc_mcontext.__gregs[reg_num])
# define SP_sig(context)            REGn_sig(3, context)    /* Stack pointer */
# define PC_sig(context) ((context)->uc_mcontext.__pc)

static inline struct loongarch64_thread_data *loongarch64_thread_data(void)
{
    return (struct loongarch64_thread_data *)ntdll_get_thread_data()->cpu_data;
}

/***********************************************************************
 *           restore_context
 *
 * Build a sigcontext from the register values.
 */
static void restore_context( const CONTEXT *context, ucontext_t *sigcontext )
{
    ERR("%s: NOT Implemented On LoongArch64\n", __FUNCTION__); exit(1);
}
/***********************************************************************
 *           restore_fpu
 *
 * Restore the FPU context to a sigcontext.
 */
static inline void restore_fpu( CONTEXT *context, const ucontext_t *sigcontext )
{
    ERR("%s: NOT Implemented On LoongArch64\n", __FUNCTION__); exit(1);
}

/***********************************************************************
 *           setup_exception
 *
 * Modify the signal context to call the exception raise function.
 */
static void setup_exception( ucontext_t *sigcontext, EXCEPTION_RECORD *rec )
{
        ERR("%s: NOT Implemented On LoongArch64\n", __FUNCTION__); exit(1);
/*
    struct exc_stack_layout *stack;
    void *stack_ptr = (void *)(SP_sig(sigcontext) & ~15);
    CONTEXT context;
    NTSTATUS status;

    rec->ExceptionAddress = (void *)PC_sig(sigcontext);
    save_context( &context, sigcontext );

    status = send_debug_event( rec, &context, TRUE );
    if (status == DBG_CONTINUE || status == DBG_EXCEPTION_HANDLED)
    {
        restore_context( &context, sigcontext );
        return;
    }*/

    /* fix up instruction pointer in context for EXCEPTION_BREAKPOINT */
    // if (rec->ExceptionCode == EXCEPTION_BREAKPOINT) context.Pc -= 4;
    //
    // stack = virtual_setup_exception( stack_ptr, sizeof(*stack), rec );
    // stack->rec = *rec;
    // stack->context = context;
    //
    // SP_sig(sigcontext) = (ULONG_PTR)stack;
    // PC_sig(sigcontext) = (ULONG_PTR)pKiUserExceptionDispatcher;
    // REGn_sig(18, sigcontext) = (ULONG_PTR)NtCurrentTeb();
}
/***********************************************************************
 *           save_context
 *
 * Set the register values from a sigcontext.
 */
static void save_context( CONTEXT *context, const ucontext_t *sigcontext )
{
            ERR("%s: NOT Implemented On LoongArch64\n", __FUNCTION__); exit(1);

    // DWORD i;
    //
    // context->ContextFlags = CONTEXT_FULL;
    // context->Fp   = FP_sig(sigcontext);     /* Frame pointer */
    // context->Lr   = LR_sig(sigcontext);     /* Link register */
    // context->Sp   = SP_sig(sigcontext);     /* Stack pointer */
    // context->Pc   = PC_sig(sigcontext);     /* Program Counter */
    // context->Cpsr = PSTATE_sig(sigcontext); /* Current State Register */
    // for (i = 0; i <= 28; i++) context->X[i] = REGn_sig( i, sigcontext );
    // save_fpu( context, sigcontext );
}


static BOOL is_inside_syscall( ucontext_t *sigcontext )
{
    return ((char *)SP_sig(sigcontext) >= (char *)ntdll_get_thread_data()->kernel_stack &&
            (char *)SP_sig(sigcontext) <= (char *)loongarch64_thread_data()->syscall_frame);
}

/***********************************************************************
 *           syscall_frame_fixup_for_fastpath
 *
 * Fixes up the given syscall frame such that the syscall dispatcher
 * can return via the fast path if CONTEXT_INTEGER is set in
 * restore_flags.
 *
 * Clobbers the frame's X16 and X17 register values.
 */
static void syscall_frame_fixup_for_fastpath( struct syscall_frame *frame )
{

}
/***********************************************************************
 *           call_init_thunk
 */
void call_init_thunk( LPTHREAD_START_ROUTINE entry, void *arg, BOOL suspend, TEB *teb,
                      struct syscall_frame *frame, void *syscall_cfa )
{
    struct loongarch64_thread_data *thread_data = (struct loongarch64_thread_data *)&teb->GdiTebBatch;
    CONTEXT *ctx, context = { 0 };
    thread_data->syscall_table = KeServiceDescriptorTable;

    context.A0  = (DWORD64)entry;
    context.A1  = (DWORD64)arg;
    context.Tp = (DWORD64)teb;
    context.Sp  = (DWORD64)teb->Tib.StackBase;
    context.Pc  = (DWORD64)pRtlUserThreadStart;

    if (suspend) wait_suspend( &context );

    ctx = (CONTEXT *)((ULONG_PTR)context.Sp & ~15) - 1;
    *ctx = context;
    ctx->ContextFlags = CONTEXT_FULL;
    memset( frame, 0, sizeof(*frame) );
    NtSetContextThread( GetCurrentThread(), ctx );

    frame->r[3]    = (ULONG64)ctx;
    frame->__pc    = (ULONG64)pLdrInitializeThunk;
    frame->r[4]  = (ULONG64)ctx;
    frame->r[2] = (ULONG64)teb;
    frame->restore_flags |= CONTEXT_INTEGER;
    frame->syscall_cfa    = syscall_cfa;
    syscall_frame_fixup_for_fastpath( frame );

    pthread_sigmask( SIG_UNBLOCK, &server_block_set, NULL );
    __wine_syscall_dispatcher_return( frame, 0 );
    asm("nop");
    return ;
}
/***********************************************************************
 *           handle_syscall_fault
 *
 * Handle a page fault happening during a system call.
 */
static BOOL handle_syscall_fault( ucontext_t *context, EXCEPTION_RECORD *rec )
{
     struct syscall_frame *frame = loongarch64_thread_data()->syscall_frame;
     DWORD i;

     if (!is_inside_syscall( context )) return FALSE;

     if (ntdll_get_thread_data()->jmp_buf)
     {
         TRACE( "returning to handler\n" );
         REGn_sig(0, context) = (ULONG_PTR)ntdll_get_thread_data()->jmp_buf;
         REGn_sig(1, context) = 1;
         PC_sig(context)      = (ULONG_PTR)__wine_longjmp;
         ntdll_get_thread_data()->jmp_buf = NULL;
     }
     else
     {
         TRACE( "returning to user mode ip=%p ret=%08x\n", (void *)frame->__pc, rec->ExceptionCode );
         REGn_sig(0, context) = (ULONG_PTR)frame;
         REGn_sig(1, context) = rec->ExceptionCode;
         PC_sig(context)      = (ULONG_PTR)__wine_syscall_dispatcher_return;
     }
     return TRUE;
}

/**********************************************************************
 *              segv_handler
 * 
 * Handler for SIGSEGV.
 */
static void segv_handler( int signal, siginfo_t *siginfo, void *sigcontext )
{
                ERR("%s: NOT Implemented On LoongArch64\n", __FUNCTION__); exit(1);
    asm("break 1");
//    EXCEPTION_RECORD rec = { 0 };
//    ucontext_t *context = sigcontext;
//
//    rec.NumberParameters = 2;
//    rec.ExceptionInformation[0] = (get_fault_esr( context ) & 0x40) != 0;
//    rec.ExceptionInformation[1] = (ULONG_PTR)siginfo->si_addr;
//    rec.ExceptionCode = virtual_handle_fault( siginfo->si_addr, rec.ExceptionInformation[0],
//                                              (void *)SP_sig(context) );
//    if (!rec.ExceptionCode) return;
//    if (handle_syscall_fault( context, &rec )) return;
//    setup_exception( context, &rec );
}


/**********************************************************************
 *              ill_handler
 * 
 * Handler for SIGILL.
 */
static void ill_handler( int signal, siginfo_t *siginfo, void *sigcontext )
{
    EXCEPTION_RECORD rec = { EXCEPTION_ILLEGAL_INSTRUCTION };
    setup_exception( sigcontext, &rec );
}


/**********************************************************************
 *              bus_handler
 *
 * Handler for SIGBUS.
 */
static void bus_handler( int signal, siginfo_t *siginfo, void *sigcontext )
{
    EXCEPTION_RECORD rec = { EXCEPTION_DATATYPE_MISALIGNMENT };
    setup_exception( sigcontext, &rec );
}



/**********************************************************************
 *              trap_handler
 *
 * Handler for SIGTRAP.
 */
static void trap_handler( int signal, siginfo_t *siginfo, void *sigcontext )
{
    EXCEPTION_RECORD rec = { 0 };
    ucontext_t *context = sigcontext;

    switch (siginfo->si_code)
    {
    case TRAP_TRACE:
        rec.ExceptionCode = EXCEPTION_SINGLE_STEP;
        break;
    case TRAP_BRKPT:
    default:
        /* debug exceptions do not update ESR on Linux, so we fetch the instruction directly. */
        // if (
            // !(PSTATE_sig( context ) & 0x10) && /* AArch64 (not WoW) */
            // !(PC_sig( context ) & 3) &&
            // *(ULONG *)PC_sig( context ) == 0xd43e0060UL) /* brk #0xf003 -> __fastfail */
        // {
        //     CONTEXT ctx;
        //     save_context( &ctx, sigcontext );
        //     rec.ExceptionCode = STATUS_STACK_BUFFER_OVERRUN;
        //     rec.ExceptionAddress = (void *)ctx.Pc;
        //     rec.ExceptionFlags = EH_NONCONTINUABLE;
        //     rec.NumberParameters = 1;
        //     rec.ExceptionInformation[0] = ctx.X[0];
        //     NtRaiseException( &rec, &ctx, FALSE );
        //     return;
        // }
        // PC_sig( context ) += 4;  /* skip the brk instruction */
        rec.ExceptionCode = EXCEPTION_BREAKPOINT;
        rec.NumberParameters = 1;
        break;
    }
    setup_exception( sigcontext, &rec );
}


/**********************************************************************
 *              fpe_handler
 *
 * Handler for SIGFPE.
 */
static void fpe_handler( int signal, siginfo_t *siginfo, void *sigcontext )
{
    EXCEPTION_RECORD rec = { 0 };

    switch (siginfo->si_code & 0xffff )
    {
#ifdef FPE_FLTSUB
    case FPE_FLTSUB:
        rec.ExceptionCode = EXCEPTION_ARRAY_BOUNDS_EXCEEDED;
        break;
#endif
#ifdef FPE_INTDIV
    case FPE_INTDIV:
        rec.ExceptionCode = EXCEPTION_INT_DIVIDE_BY_ZERO;
        break;
#endif
#ifdef FPE_INTOVF
    case FPE_INTOVF:
        rec.ExceptionCode = EXCEPTION_INT_OVERFLOW;
        break;
#endif
#ifdef FPE_FLTDIV
    case FPE_FLTDIV:
        rec.ExceptionCode = EXCEPTION_FLT_DIVIDE_BY_ZERO;
        break;
#endif
#ifdef FPE_FLTOVF
    case FPE_FLTOVF:
        rec.ExceptionCode = EXCEPTION_FLT_OVERFLOW;
        break;
#endif
#ifdef FPE_FLTUND
    case FPE_FLTUND:
        rec.ExceptionCode = EXCEPTION_FLT_UNDERFLOW;
        break;
#endif
#ifdef FPE_FLTRES
    case FPE_FLTRES:
        rec.ExceptionCode = EXCEPTION_FLT_INEXACT_RESULT;
        break;
#endif
#ifdef FPE_FLTINV
    case FPE_FLTINV:
#endif
    default:
        rec.ExceptionCode = EXCEPTION_FLT_INVALID_OPERATION;
        break;
    }

    setup_exception( sigcontext, &rec );
}

/**********************************************************************
 *              abrt_handler
 *
 * Handler for SIGABRT.
 */
static void abrt_handler( int signal, siginfo_t *siginfo, void *sigcontext )
{
    EXCEPTION_RECORD rec = { EXCEPTION_WINE_ASSERTION, EH_NONCONTINUABLE };

    setup_exception( sigcontext, &rec );
}

/**********************************************************************
 *              quit_handler
 * 
 * Handler for SIGQUIT.
 */
static void quit_handler( int signal, siginfo_t *siginfo, void *sigcontext )
{
    if (!is_inside_syscall( sigcontext )) abort_thread( 0 );
    abort_thread(0);
}



/**********************************************************************
 *              usr1_handler
 *
 * Handler for SIGUSR1, used to signal a thread that it got suspended.
 */
static void usr1_handler( int signal, siginfo_t *siginfo, void *sigcontext )
{
    CONTEXT context;
    if (is_inside_syscall( sigcontext ))
    {
        context.ContextFlags = CONTEXT_FULL;
        NtGetContextThread( GetCurrentThread(), &context );
        wait_suspend( &context );
        NtSetContextThread( GetCurrentThread(), &context );
    }
    else
    {
        save_context( &context, sigcontext );
        wait_suspend( &context );
        restore_context( &context, sigcontext );
    }
}


/**********************************************************************
 *              usr2_handler
 *
 * Handler for SIGUSR2, used to set a thread context.
 */
static void usr2_handler( int signal, siginfo_t *siginfo, void *sigcontext )
{
    ERR("%s: NOT Implemented On LoongArch64\n", __FUNCTION__); exit(1);
}


/**********************************************************************
 *              int_handler
 *
 * Handler for SIGINT.
 */
static void int_handler( int signal, siginfo_t *siginfo, void *sigcontext )
{
    HANDLE handle;

    if (!p__wine_ctrl_routine) return;
    if (!NtCreateThreadEx( &handle, THREAD_ALL_ACCESS, NULL, NtCurrentProcess(),
                           p__wine_ctrl_routine, 0 /* CTRL_C_EVENT */, 0, 0, 0, 0, NULL ))
        NtClose( handle );
}

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
    struct syscall_frame *frame = loongarch64_thread_data()->syscall_frame;
    NTSTATUS ret = STATUS_SUCCESS;
    BOOL self = (handle == GetCurrentThread());
    DWORD flags = context->ContextFlags;

    if (!self)
    {
        ret = set_thread_context( handle, context, &self, IMAGE_FILE_MACHINE_LOONGARCH64 );
        if (ret || !self) return ret;
    }

    if (flags & CONTEXT_INTEGER)
    {
        frame->r[0] = context->R0;
        frame->r[1] = context->Ra;
        frame->r[2] = context->Tp;
        frame->r[3] = context->Sp;
        frame->r[4] = context->A0;
        frame->r[5] = context->A1;
        frame->r[6] = context->A2;
        frame->r[7] = context->A3;
        frame->r[8] = context->A4;
        frame->r[9] = context->A5;
        frame->r[10] = context->A6;
        frame->r[11] = context->A7;
        frame->r[12] = context->T0;
        frame->r[13] = context->T1;
        frame->r[14] = context->T2;
        frame->r[15] = context->T3;
        frame->r[16] = context->T4;
        frame->r[17] = context->T5;
        frame->r[18] = context->T6;
        frame->r[19] = context->T7;
        frame->r[20] = context->T8;
        frame->r[21] = context->X0;
        frame->r[22] = context->Fp;
        frame->r[23] = context->S0;
        frame->r[24] = context->S1;
        frame->r[25] = context->S2;
        frame->r[26] = context->S3;
        frame->r[27] = context->S4;
        frame->r[28] = context->S5;
        frame->r[29] = context->S6;
        frame->r[30] = context->S7;
        frame->r[31] = context->S8;
    }
    if (flags & CONTEXT_CONTROL)
    {

        frame->r[2] = context->Tp;
        frame->r[3] = context->Sp;
        frame->r[22] = context->Fp;
        frame->__pc    = context->Pc;
        frame->fcsr    = context->Fcsr;
    }
    if (flags & CONTEXT_FLOATING_POINT)
    {
        frame->fcc    = context->Fcc;
        //FIXME
    }
    frame->restore_flags |= flags & ~CONTEXT_INTEGER;
    return STATUS_SUCCESS;
}



/***********************************************************************
 *              NtGetContextThread  (NTDLL.@)
 *              ZwGetContextThread  (NTDLL.@)
 */
NTSTATUS WINAPI NtGetContextThread( HANDLE handle, CONTEXT *context )
{

    struct syscall_frame *frame = loongarch64_thread_data()->syscall_frame;
    DWORD needed_flags = context->ContextFlags;
    BOOL self = (handle == GetCurrentThread());

    if (!self)
    {
        NTSTATUS ret = get_thread_context( handle, context, &self, IMAGE_FILE_MACHINE_LOONGARCH64 );
        if (ret || !self) return ret;
    }

    if (needed_flags & CONTEXT_INTEGER)
    {
        context->R0 = frame->r[0];
        context->Ra = frame->r[1];
        context->Tp = frame->r[2];
        context->Sp = frame->r[3];
        context->A0 = frame->r[4];
        context->A1 = frame->r[5];
        context->A2 = frame->r[6];
        context->A3 = frame->r[7];
        context->A4 = frame->r[8];
        context->A5 = frame->r[9];
        context->A6 = frame->r[10];
        context->A7 = frame->r[11];
        context->T0 = frame->r[12];
        context->T1 = frame->r[13];
        context->T2 = frame->r[14];
        context->T3 = frame->r[15];
        context->T4 = frame->r[16];
        context->T5 = frame->r[17];
        context->T6 = frame->r[18];
        context->T7 = frame->r[19];
        context->T8 = frame->r[20];
        context->X0 = frame->r[21];
        context->Fp = frame->r[22];
        context->S0 = frame->r[23];
        context->S1 = frame->r[24];
        context->S2 = frame->r[25];
        context->S3 = frame->r[26];
        context->S4 = frame->r[27];
        context->S5 = frame->r[28];
        context->S6 = frame->r[29];
        context->S7 = frame->r[30];
        context->S8 = frame->r[31];
        context->ContextFlags |= CONTEXT_INTEGER;
    }
    if (needed_flags & CONTEXT_CONTROL)
    {
        context->Tp = frame->r[2];
        context->Sp = frame->r[3];
        context->Fp = frame->r[22];
        context->Pc = frame->__pc;
        context->Fcsr = frame->fcsr;
        context->ContextFlags |= CONTEXT_CONTROL;
    }
    if (needed_flags & CONTEXT_FLOATING_POINT)
    {
        context->Fcc = frame->fcc;
        context->ContextFlags |= CONTEXT_FLOATING_POINT;
    }
    return STATUS_SUCCESS;
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
    struct sigaction sig_act;
    void *kernel_stack = (char *)ntdll_get_thread_data()->kernel_stack + kernel_stack_size;

    loongarch64_thread_data()->syscall_frame = (struct syscall_frame *)kernel_stack - 1;


    sig_act.sa_mask = server_block_set;
    sig_act.sa_flags = SA_SIGINFO | SA_RESTART | SA_ONSTACK;
//
//    sig_act.sa_sigaction = int_handler;
//    if (sigaction( SIGINT, &sig_act, NULL ) == -1) goto error;
//    sig_act.sa_sigaction = fpe_handler;
//    if (sigaction( SIGFPE, &sig_act, NULL ) == -1) goto error;
//    sig_act.sa_sigaction = abrt_handler;
//    if (sigaction( SIGABRT, &sig_act, NULL ) == -1) goto error;
//    sig_act.sa_sigaction = quit_handler;
//    if (sigaction( SIGQUIT, &sig_act, NULL ) == -1) goto error;
//    sig_act.sa_sigaction = usr1_handler;
//    if (sigaction( SIGUSR1, &sig_act, NULL ) == -1) goto error;
//    sig_act.sa_sigaction = usr2_handler;
//    if (sigaction( SIGUSR2, &sig_act, NULL ) == -1) goto error;
//    sig_act.sa_sigaction = trap_handler;
//    if (sigaction( SIGTRAP, &sig_act, NULL ) == -1) goto error;
////    sig_act.sa_sigaction = segv_handler;
////    if (sigaction( SIGSEGV, &sig_act, NULL ) == -1) goto error;
//    sig_act.sa_sigaction = ill_handler;
//    if (sigaction( SIGILL, &sig_act, NULL ) == -1) goto error;
//    sig_act.sa_sigaction = bus_handler;
//    if (sigaction( SIGBUS, &sig_act, NULL ) == -1) goto error;
    return;
 error:
    perror("sigaction");
    exit(1);
}

/***********************************************************************
 *              get_wow_context
 */
void *get_wow_context( CONTEXT *context )
{
    return get_cpu_area( main_image_info.Machine );

//    ERR("%s: NOT Implemented On LoongArch64\n", __FUNCTION__); exit(1);
//    return 0;
}


NTSTATUS unwind_builtin_dll( void *args )
{

    struct unwind_builtin_dll_params *params = args;
    DISPATCHER_CONTEXT *dispatch = params->dispatch;
    CONTEXT *context = params->context;
//    struct dwarf_eh_bases bases;
//    const struct dwarf_fde *fde = _Unwind_Find_FDE( (void *)(context->Pc - 1), &bases );

//    if (fde)
//        return dwarf_virtual_unwind( context->Pc, &dispatch->EstablisherFrame, context, fde,
//                                     &bases, &dispatch->LanguageHandler, &dispatch->HandlerData );
//#ifdef HAVE_LIBUNWIND
//    return libunwind_virtual_unwind( context->Pc, &dispatch->EstablisherFrame, context,
//                                     &dispatch->LanguageHandler, &dispatch->HandlerData );
//#else
    ERR("libunwind not available, unable to unwind\n");
    return STATUS_INVALID_DISPOSITION;
//#endif
}

/***********************************************************************
 *           signal_start_thread
 */
__ASM_GLOBAL_FUNC( signal_start_thread,

//                   "stp x29, x30, [sp,#-0xc0]!\n\t"
                   "addi.d $sp, $sp, -0xc0\n\t"
                   "st.d   $t0, $sp, 0\n\t"
                   "st.d   $t1, $sp, 8\n\t"
//                   "mov x29, sp\n\t"
                   "move $t7, $sp\n\t"

//                   "stp x19, x20, [x29, #0x10]\n\t"
                   "st.d $s0, $t7, 0x10\n\t"
                   "st.d $s1, $t7, 0x18\n\t"
//                   "stp x21, x22, [x29, #0x20]\n\t"
                   "st.d $s2, $t7, 0x20\n\t"
                   "st.d $s3, $t7, 0x28\n\t"
//                   "stp x23, x24, [x29, #0x30]\n\t"
                   "st.d $s4, $t7, 0x30\n\t"
                   "st.d $s5, $t7, 0x38\n\t"
//                   "stp x25, x26, [x29, #0x40]\n\t"
                   "st.d $s6, $t7, 0x40\n\t"
                   "st.d $s7, $t7, 0x48\n\t"
//                   "stp x27, x28, [x29, #0x50]\n\t"
                   "nop\n\t"
//                   "add x5, x29, #0xc0\n\t"     /* syscall_cfa */
                   "addi.d $a5,$t7,0xc0\n\t"
                   /* set syscall frame */
//                   "ldr x4, [x3, #0x2f0]\n\t"   /* arm64_thread_data()->syscall_frame */
                   "ld.d $a4, $a3, 0x2f0\n\t"
//                   "cbnz x4, 1f\n\t"
                   "bnez $a4, 1f\n\t"

//                   "sub x4, sp, #0x330\n\t"     /* sizeof(struct syscall_frame) */
                   "addi.d $a4, $sp, -0x330\n\t"
//                   "str x4, [x3, #0x2f0]\n\t"   /* arm64_thread_data()->syscall_frame */
                   "st.d $a4, $a3, 0x2f0\n\t"
                   /* switch to kernel stack */
                   "1:\t"
//                   "mov sp, x4\n\t"
                    "move $sp, $a4\n\t"
//                   "bl " __ASM_NAME("call_init_thunk")
                   "b " __ASM_NAME("call_init_thunk")
                   );

/***********************************************************************
 *           __wine_syscall_dispatcher
 */
__ASM_GLOBAL_FUNC( __wine_syscall_dispatcher,


//                   "ldr x10, [x18, #0x2f0]\n\t" /* loongarch64_thread_data()->syscall_frame */
                   "ld.d $t0, $tp, 0x2f0\n\t"
//                   "stp x18, x19, [x10, #0x90]\n\t"
                   "st.d $tp, $t0, 0x90\n\t"
                   "st.d $s0, $t0, 0x98\n\t"
//                   "stp x20, x21, [x10, #0xa0]\n\t"
                   "st.d $s1, $t0, 0xa0\n\t"
                   "st.d $s2, $t0, 0xa8\n\t"
//                   "stp x22, x23, [x10, #0xb0]\n\t"
                   "st.d $s3, $t0, 0xb0\n\t"
                   "st.d $s4, $t0, 0xb8\n\t"
//                   "stp x24, x25, [x10, #0xc0]\n\t"
                   "st.d $s5, $t0, 0xc0\n\t"
                   "st.d $s6, $t0, 0xc8\n\t"
//                   "stp x26, x27, [x10, #0xd0]\n\t"
                   "st.d $s7, $t0, 0xd0\n\t"
                   "st.d $s8, $t0, 0xd8\n\t"
//                   "stp x28, x29, [x10, #0xe0]\n\t"
                   "nop \n\t"
//                   "mov x19, sp\n\t"
//                   "stp x9, x19, [x10, #0xf0]\n\t"
//                   "mrs x9, NZCV\n\t"
//                   "stp x30, x9, [x10, #0x100]\n\t"
//                   "mrs x9, FPCR\n\t"
//                   "str w9, [x10, #0x128]\n\t"
//                   "mrs x9, FPSR\n\t"
//                   "str w9, [x10, #0x12c]\n\t"
//
//                   "stp q0,  q1,  [x10, #0x130]\n\t"
//                   "stp q2,  q3,  [x10, #0x150]\n\t"
//                   "stp q4,  q5,  [x10, #0x170]\n\t"
//                   "stp q6,  q7,  [x10, #0x190]\n\t"
//                   "stp q8,  q9,  [x10, #0x1b0]\n\t"
//                   "stp q10, q11, [x10, #0x1d0]\n\t"
//                   "stp q12, q13, [x10, #0x1f0]\n\t"
//                   "stp q14, q15, [x10, #0x210]\n\t"
//                   "stp q16, q17, [x10, #0x230]\n\t"
//                   "stp q18, q19, [x10, #0x250]\n\t"
//                   "stp q20, q21, [x10, #0x270]\n\t"
//                   "stp q22, q23, [x10, #0x290]\n\t"
//                   "stp q24, q25, [x10, #0x2b0]\n\t"
//                   "stp q26, q27, [x10, #0x2d0]\n\t"
//                   "stp q28, q29, [x10, #0x2f0]\n\t"
//                   "stp q30, q31, [x10, #0x310]\n\t"
//                   "mov x22, x10\n\t"
                   "move $s3, $t0\n\t"
                   /* switch to kernel stack */
//                   "mov sp, x10\n\t"
                   "move $sp, $t0\n\t"
                   /* we're now on the kernel stack, stitch unwind info with previous frame */
//                   __ASM_CFI_CFA_IS_AT2(x22, 0x98, 0x02) /* frame->syscall_cfa */
        __ASM_CFI_CFA_IS_AT2(s3, 0x98, 0x02) /* frame->syscall_cfa */
//                   __ASM_CFI(".cfi_offset 29, -0xc0\n\t")
//                   __ASM_CFI(".cfi_offset 29, -0xc0\n\t")
//                   __ASM_CFI(".cfi_offset 30, -0xb8\n\t")
//                   __ASM_CFI(".cfi_offset 19, -0xb0\n\t")
//                   __ASM_CFI(".cfi_offset 20, -0xa8\n\t")
//                   __ASM_CFI(".cfi_offset 21, -0xa0\n\t")
//                   __ASM_CFI(".cfi_offset 22, -0x98\n\t")
//                   __ASM_CFI(".cfi_offset 23, -0x90\n\t")
//                   __ASM_CFI(".cfi_offset 24, -0x88\n\t")
//                   __ASM_CFI(".cfi_offset 25, -0x80\n\t")
//                   __ASM_CFI(".cfi_offset 26, -0x78\n\t")
//                   __ASM_CFI(".cfi_offset 27, -0x70\n\t")
//                   __ASM_CFI(".cfi_offset 28, -0x68\n\t")
//                   "and x20, x8, #0xfff\n\t"    /* syscall number */
                   "andi $s1, $a7, 0xfff\n\t"
//                   "ubfx x21, x8, #12, #2\n\t"  /* syscall table number */
                   "srli.w $s2, $a7, 12\n\t"
                   "andi $s2, $s2, 3 \n\t"
//                   "ldr x16, [x18, #0x2f8]\n\t" /* arm64_thread_data()->syscall_table */
                   "ld.d $t2, $tp, 0x2f8\n\t"
//                   "add x21, x16, x21, lsl #5\n\t"
                   "slli.w $t7, $s2, 5\n\t"
                   "and $s2, $t7, $t2\n\t"

//                   "ldr x16, [x21, #16]\n\t"    /* table->ServiceLimit */
                   "ld.w $t2, $s2, 16\n\t"

//                   "cmp x20, x16\n\t"
//                   "bcs 4f\n\t"
                   "sub.d $t0, $s2, $t2\n\t"
                   "bgeu $t0, $zero, 4f\n\t"
//                   "ldr x16, [x21, #24]\n\t"    /* table->ArgumentTable */
                   "ld.w $t2, $s2, 24\n\t"

//                   "ldrb w9, [x16, x20]\n\t"
                   "add.d $t2,$t2,$s1\n\t"
                   "ld.w $t3, $t2, 20\n\t"
//                   "subs x9, x9, #64\n\t"
                   "addi.d $t3, $t3, -64\n\t"
//                   "bls 2f\n\t"
                   "bge $t3, $zero, 2f \n\t"
//                   "sub sp, sp, x9\n\t"
                   "sub.d $sp, $sp, $t3\n\t"
                   //"tbz x9, #3, 1f\n\t"
                   "andi $t0, $t3, 0b1000\n\t"
                   "beqz $t0, 1f\n\t"
//                   "sub sp, sp, #8\n"
                   "addi.d $sp, $sp, -8\n\t"
                   "1:\t"
//                   "sub x9, x9, #8\n\t"
                   "addi.d $t3, $t3, -8\n\t"

//                   "ldr x10, [x19, x9]\n\t"
                   "add.d $s0, $t3, $s0\n\t"
                   "ld.d $t4, $s0, 0\n\t"

//                   "str x10, [sp, x9]\n\t"
                   "add.d $t5, $sp, $t3\n\t"
                   "st.d $t4, $t5, 0\n\t"

//                   "cbnz x9, 1b\n"
                   "bnez $t3, 1b\n\t"
                   "2:\t"
//                   "ldr x16, [x21]\n\t"     /* table->ServiceTable */
                   "ld.d $t2, $s2, 0\n\t"

//                   "ldr x16, [x16, x20, lsl 3]\n\t"
                   "move $t4, $s1\n\t"
                   "slli.w $t4, $a4, 3\n\t"
                   "add.d $t2, $t2, $t4\n\t"
                   "ld.d $t2, $t2, 0\n\t"



//                   "blr x16\n\t"
                   "jirl $ra, $t2, 0\n\t"

//                   "mov sp, x22\n"
                   "move $sp, $s3\n\t"
//                   __ASM_CFI_CFA_IS_AT2(sp, 0x98, 0x02) /* frame->syscall_cfa */
//                   __ASM_CFI_CFA_IS_AT2(sp, 0x98, 0x02) /* frame->syscall_cfa */
                   __ASM_LOCAL_LABEL("__wine_syscall_dispatcher_return") ":\n\t"
//                   "ldr w16, [sp, #0x10c]\n\t"  /* frame->restore_flags */
                   "ld.w $t4,$sp,0x10c\n\t"

//                   "tbz x16, #1, 2f\n\t"        /* CONTEXT_INTEGER */
                   "andi $t4, $t4, 0b100\n\t"
                   "beqz $t4, 2f\n\t"


//                   "ldp x12, x13, [sp, #0x80]\n\t" /* frame->x[16..17] */
//                   "ldp x14, x15, [sp, #0xf8]\n\t" /* frame->sp, frame->pc */
//                   "cmp x12, x15\n\t"              /* frame->x16 == frame->pc? */
//                   "ccmp x13, x14, #0, eq\n\t"     /* frame->x17 == frame->sp? */
//                   "beq 1f\n\t"                    /* take slowpath if unequal */
//                   "bl " __ASM_NAME("syscall_dispatcher_return_slowpath") "\n"
                   "1:\n\t"
//                   "ldp x0, x1, [sp, #0x00]\n\t"
//                   "ldp x2, x3, [sp, #0x10]\n\t"
//                   "ldp x4, x5, [sp, #0x20]\n\t"
//                   "ldp x6, x7, [sp, #0x30]\n\t"
//                   "ldp x8, x9, [sp, #0x40]\n\t"
//                   "ldp x10, x11, [sp, #0x50]\n\t"
//                   "ldp x12, x13, [sp, #0x60]\n\t"
//                   "ldp x14, x15, [sp, #0x70]\n"

                   "2:\t"
//                   "ldp x18, x19, [sp, #0x90]\n\t"
                   "ld.d $tp, $sp, 0x90\n\t"
                   "ld.d $s0, $sp, 0x98\n\t"
//                   "ldp x20, x21, [sp, #0xa0]\n\t"
                   "ld.d $s1, $sp, 0xa0\n\t"
                   "ld.d $s2, $sp, 0xa8\n\t"
//                   "ldp x22, x23, [sp, #0xb0]\n\t"
                   "ld.d $s3, $sp, 0xb0\n\t"
                   "ld.d $s4, $sp, 0xb8\n\t"
//                   "ldp x24, x25, [sp, #0xc0]\n\t"
                   "ld.d $s5, $sp, 0xc0\n\t"
                   "ld.d $s6, $sp, 0xc8\n\t"
//                   "ldp x26, x27, [sp, #0xd0]\n\t"
                   "ld.d $s7, $sp, 0xd0\n\t"
                   "ld.d $s8, $sp, 0xd8\n\t"
//                   "ldp x28, x29, [sp, #0xe0]\n\t"
                   "nop \n\t"
//                   "tbz x16, #2, 1f\n\t"        /* CONTEXT_FLOATING_POINT */
//                   "ldp q0,  q1,  [sp, #0x130]\n\t"
//                   "ldp q2,  q3,  [sp, #0x150]\n\t"
//                   "ldp q4,  q5,  [sp, #0x170]\n\t"
//                   "ldp q6,  q7,  [sp, #0x190]\n\t"
//                   "ldp q8,  q9,  [sp, #0x1b0]\n\t"
//                   "ldp q10, q11, [sp, #0x1d0]\n\t"
//                   "ldp q12, q13, [sp, #0x1f0]\n\t"
//                   "ldp q14, q15, [sp, #0x210]\n\t"
//                   "ldp q16, q17, [sp, #0x230]\n\t"
//                   "ldp q18, q19, [sp, #0x250]\n\t"
//                   "ldp q20, q21, [sp, #0x270]\n\t"
//                   "ldp q22, q23, [sp, #0x290]\n\t"
//                   "ldp q24, q25, [sp, #0x2b0]\n\t"
//                   "ldp q26, q27, [sp, #0x2d0]\n\t"
//                   "ldp q28, q29, [sp, #0x2f0]\n\t"
//                   "ldp q30, q31, [sp, #0x310]\n\t"
//                   "ldr w17, [sp, #0x128]\n\t"
//                   "msr FPCR, x17\n\t"
//                   "ldr w17, [sp, #0x12c]\n\t"
//                   "msr FPSR, x17\n"
                   "1:\n\t"
//                   "ldp x16, x17, [sp, #0x100]\n\t"
                   "ld.d $t2, $sp, 0x100\n\t"
//                   "msr NZCV, x17\n\t"
//                   "ldp x30, x17, [sp, #0xf0]\n\t"
                   "ld.d $t0, $sp, 0xf8\n\t"

                   /* switch to user stack */
//                   "mov sp, x17\n\t"
                   "move $sp, $t0\n\t"

//                   "ret x16\n"
                   "move $a0, $t2\n\t"
                   "ret\n\t"
                   "4:\t"

                   //"mov x0, #0xc0000000\n\t" /* STATUS_INVALID_PARAMETER */
                   "li.w $a0, 0xc000000d\n\t"
//                   "movk x0, #0x000d\n\t"
                   "b " __ASM_LOCAL_LABEL("__wine_syscall_dispatcher_return") "\n\t"
                   ".globl " __ASM_NAME("__wine_syscall_dispatcher_return") "\n"
                   __ASM_NAME("__wine_syscall_dispatcher_return")
                   ":\n\t"
//                   "mov sp, x0\n\t"
                   "move $sp, $a0\n\t"

//                   "mov x0, x1\n\t"
                   "move $a0, $a1\n\t"
                   "b " __ASM_LOCAL_LABEL("__wine_syscall_dispatcher_return")
)

// /***********************************************************************
//  *           __wine_unix_call_dispatcher
//  */


__ASM_GLOBAL_FUNC( __wine_unix_call_dispatcher,
//"ldr x10, [x18, #0x2f0]\n\t" /* loongarch64_thread_data()->syscall_frame */
                   "ld.d $t0, $tp, 0x2f0\n\t"
//                   "stp x18, x19, [x10, #0x90]\n\t"
                   "st.d $tp, $t0, 0x90\n\t"
                   "st.d $s0, $t0, 0x98\n\t"
//                   "stp x20, x21, [x10, #0xa0]\n\t"
                   "st.d $s1, $t0, 0xa0\n\t"
                   "st.d $s2, $t0, 0xa8\n\t"
//                   "stp x22, x23, [x10, #0xb0]\n\t"
                   "st.d $s3, $t0, 0xb0\n\t"
                   "st.d $s4, $t0, 0xb8\n\t"
//                   "stp x24, x25, [x10, #0xc0]\n\t"
                   "st.d $s5, $t0, 0xc0\n\t"
                   "st.d $s6, $t0, 0xc8\n\t"
//                   "stp x26, x27, [x10, #0xd0]\n\t"
                   "st.d $s7, $t0, 0xd0\n\t"
                   "st.d $s8, $t0, 0xd8\n\t"
//                   "stp x28, x29, [x10, #0xe0]\n\t"
                   "nop \n\t"

//                   "stp q8,  q9,  [x10, #0x1b0]\n\t"
//                   "stp q10, q11, [x10, #0x1d0]\n\t"
//                   "stp q12, q13, [x10, #0x1f0]\n\t"
//                   "stp q14, q15, [x10, #0x210]\n\t"
                   "nop\n\t"
                   // FIXME
//                   "mov x9, sp\n\t"
//                   "stp x30, x9, [x10, #0xf0]\n\t"
//                   "mrs x9, NZCV\n\t"
//                   "stp x30, x9, [x10, #0x100]\n\t"
//                   "mov x19, x10\n\t"
                   /* switch to kernel stack */
//                   "mov sp, x10\n\t"
                   "move $sp, $t0\n\t"

                   /* we're now on the kernel stack, stitch unwind info with previous frame */
//                   __ASM_CFI_CFA_IS_AT2(x19, 0x98, 0x02) /* frame->syscall_cfa */
//                     __ASM_CFI_CFA_IS_AT2(s0, 0x98, 0x02) /* frame->syscall_cfa */
//                   __ASM_CFI(".cfi_offset 29, -0xc0\n\t")
//                   __ASM_CFI(".cfi_offset 30, -0xb8\n\t")
//                   __ASM_CFI(".cfi_offset 19, -0xb0\n\t")
//                   __ASM_CFI(".cfi_offset 20, -0xa8\n\t")
//                   __ASM_CFI(".cfi_offset 21, -0xa0\n\t")
//                   __ASM_CFI(".cfi_offset 22, -0x98\n\t")
//                   __ASM_CFI(".cfi_offset 23, -0x90\n\t")
//                   __ASM_CFI(".cfi_offset 24, -0x88\n\t")
//                   __ASM_CFI(".cfi_offset 25, -0x80\n\t")
//                   __ASM_CFI(".cfi_offset 26, -0x78\n\t")
//                   __ASM_CFI(".cfi_offset 27, -0x70\n\t")
//                   __ASM_CFI(".cfi_offset 28, -0x68\n\t")

//                   "ldr x16, [x0, x1, lsl 3]\n\t"
                   "move $t2, $a0\n\t"
                   "slli.w $t3, $a1, 3\n\t"
                   "add.d $t2, $t2, $t3\n\t"
                   "ld.d $t4, $t2, 0\n\t"
//                   "mov x0, x2\n\t"             /* args */
                   "move $a0, $a2\n\t"
//                   "blr x16\n\t"
                   "jirl  $t4, $t4, 0\n\t"
//                   "ldr w16, [sp, #0x10c]\n\t"  /* frame->restore_flags */
                   "ld.w $t4,$sp,0x10c\n\t"
//                   "cbnz w16, " __ASM_LOCAL_LABEL("__wine_syscall_dispatcher_return") "\n\t"
                   "bnez $t4, " __ASM_LOCAL_LABEL("__wine_syscall_dispatcher_return") "\n\t"
//                   __ASM_CFI_CFA_IS_AT2(sp, 0x98, 0x02) /* frame->syscall_cfa */
//                   "ldp x18, x19, [sp, #0x90]\n\t"
                   "ld.d $tp, $t0, 0x90\n\t"
                   "ld.d $s0, $t0, 0x98\n\t"
//                   "ldp x16, x17, [sp, #0xf8]\n\t"
                   "ld.d $t1, $t0, 0xf8\n\t"
                   "ld.d $t2, $t0, 0x100\n\t"
//                   /* switch to user stack */
//                   "mov sp, x16\n\t"
                   "move $sp, $t1\n\t"
//                   "ret x17"
                   "move $ra, $t2\n\t"
                   "ret"
//"break 0\n\t"
                   )
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
/***********************************************************************
 *           KeUserModeCallback
 */
NTSTATUS KeUserModeCallback( ULONG id, const void *args, ULONG len, void **ret_ptr, ULONG *ret_len )
{
     ERR("%s: NOT Implemented On LoongArch64\n", __FUNCTION__); exit(1);

}
#endif
