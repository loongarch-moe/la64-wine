
#include <assert.h>

#include "ntstatus.h"
#define WIN32_NO_STATUS
#include "dbghelp_private.h"
#include "winternl.h"
#include "wine/debug.h"

WINE_DEFAULT_DEBUG_CHANNEL(dbghelp);

static BOOL loongarch64_get_addr(HANDLE hThread, const CONTEXT* ctx,
                           enum cpu_addr ca, ADDRESS64* addr)
{
    addr->Mode    = AddrModeFlat;
    addr->Segment = 0; /* don't need segment */
    asm("break 0");

}

static BOOL loongarch64_stack_walk(struct cpu_stack_walk* csw, STACKFRAME64 *frame,
    union ctx *ctx)
{
    return FALSE;
}

static unsigned loongarch64_map_dwarf_register(unsigned regno, const struct module* module, BOOL eh_frame)
{
    if (regno <= 28) return CV_ARM64_X0 + regno;
    if (regno == 29) return CV_ARM64_FP;
    if (regno == 30) return CV_ARM64_LR;
    if (regno == 31) return CV_ARM64_SP;
    if (regno >= 64 && regno <= 95) return CV_ARM64_Q0 + regno - 64;

    FIXME("Don't know how to map register %d\n", regno);
    return CV_ARM64_NOREG;
}

static void *loongarch64_fetch_context_reg(union ctx *pctx, unsigned regno, unsigned *size)
{
#ifdef __loongarch_lp64
   asm("break 0");
#endif

    FIXME("Unknown register %x\n", regno);
    return NULL;
}

static const char* loongarch64_fetch_regname(unsigned regno)
{
}

static BOOL loongarch64_fetch_minidump_thread(struct dump_context* dc, unsigned index, unsigned flags, const CONTEXT* ctx)
{
    if (ctx->ContextFlags && (flags & ThreadWriteInstructionWindow))
    {
      asm("break 0");
    }

    return TRUE;
}

static BOOL loongarch64_fetch_minidump_module(struct dump_context* dc, unsigned index, unsigned flags)
{
    /* FIXME: actually, we should probably take care of FPO data, unless it's stored in
     * function table minidump stream
     */
    return FALSE;
}

struct cpu cpu_loongarch64 = {
    IMAGE_FILE_MACHINE_LOONGARCH64,
    8,
    8,
    loongarch64_get_addr,
    loongarch64_stack_walk,
    NULL,
    loongarch64_map_dwarf_register,
    loongarch64_fetch_context_reg,
    loongarch64_fetch_regname,
    loongarch64_fetch_minidump_thread,
    loongarch64_fetch_minidump_module,
};
