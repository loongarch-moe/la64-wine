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
enum syscall_ids
{
#define SYSCALL_ENTRY(id,name,args) __id_##name = id,
ALL_SYSCALLS64
#undef SYSCALL_ENTRY
};

#define SYSCALL_API __attribute__((naked))

NTSTATUS SYSCALL_API NtAcceptConnectPort( HANDLE *handle, ULONG id, LPC_MESSAGE *msg, BOOLEAN accept,
                                          LPC_SECTION_WRITE *write, LPC_SECTION_READ *read )
{
    __ASM_SYSCALL_FUNC( __id_NtAcceptConnectPort );
}

NTSTATUS SYSCALL_API NtAccessCheck( PSECURITY_DESCRIPTOR descr, HANDLE token, ACCESS_MASK access,
                                    GENERIC_MAPPING *mapping, PRIVILEGE_SET *privs, ULONG *retlen,
                                    ULONG *access_granted, NTSTATUS *access_status )
{
    __ASM_SYSCALL_FUNC( __id_NtAccessCheck );
}

NTSTATUS SYSCALL_API NtAccessCheckAndAuditAlarm( UNICODE_STRING *subsystem, HANDLE handle,
                                                 UNICODE_STRING *typename, UNICODE_STRING *objectname,
                                                 PSECURITY_DESCRIPTOR descr, ACCESS_MASK access,
                                                 GENERIC_MAPPING *mapping, BOOLEAN creation,
                                                 ACCESS_MASK *access_granted, BOOLEAN *access_status,
                                                 BOOLEAN *onclose )
{
    __ASM_SYSCALL_FUNC( __id_NtAccessCheckAndAuditAlarm );
}

NTSTATUS SYSCALL_API NtAddAtom( const WCHAR *name, ULONG length, RTL_ATOM *atom )
{
    __ASM_SYSCALL_FUNC( __id_NtAddAtom );
}

NTSTATUS SYSCALL_API NtAdjustGroupsToken( HANDLE token, BOOLEAN reset, TOKEN_GROUPS *groups,
                                          ULONG length, TOKEN_GROUPS *prev, ULONG *retlen )
{
    __ASM_SYSCALL_FUNC( __id_NtAdjustGroupsToken );
}

NTSTATUS SYSCALL_API NtAdjustPrivilegesToken( HANDLE token, BOOLEAN disable, TOKEN_PRIVILEGES *privs,
                                              DWORD length, TOKEN_PRIVILEGES *prev, DWORD *retlen )
{
    __ASM_SYSCALL_FUNC( __id_NtAdjustPrivilegesToken );
}

NTSTATUS SYSCALL_API NtAlertResumeThread( HANDLE handle, ULONG *count )
{
    __ASM_SYSCALL_FUNC( __id_NtAlertResumeThread );
}

NTSTATUS SYSCALL_API NtAlertThread( HANDLE handle )
{
    __ASM_SYSCALL_FUNC( __id_NtAlertThread );
}

NTSTATUS SYSCALL_API NtAlertThreadByThreadId( HANDLE tid )
{
    __ASM_SYSCALL_FUNC( __id_NtAlertThreadByThreadId );
}

NTSTATUS SYSCALL_API NtAllocateLocallyUniqueId( LUID *luid )
{
    __ASM_SYSCALL_FUNC( __id_NtAllocateLocallyUniqueId );
}

NTSTATUS SYSCALL_API NtAllocateUuids( ULARGE_INTEGER *time, ULONG *delta, ULONG *sequence, UCHAR *seed )
{
    __ASM_SYSCALL_FUNC( __id_NtAllocateUuids );
}

NTSTATUS SYSCALL_API NtAllocateVirtualMemory( HANDLE process, PVOID *ret, ULONG_PTR zero_bits,
                                              SIZE_T *size_ptr, ULONG type, ULONG protect )
{
    __ASM_SYSCALL_FUNC( __id_NtAllocateVirtualMemory );
}

NTSTATUS SYSCALL_API NtAllocateVirtualMemoryEx( HANDLE process, PVOID *ret, SIZE_T *size_ptr, ULONG type,
                                                ULONG protect, MEM_EXTENDED_PARAMETER *parameters,
                                                ULONG count )
{
    __ASM_SYSCALL_FUNC( __id_NtAllocateVirtualMemoryEx );
}

NTSTATUS SYSCALL_API NtAreMappedFilesTheSame(PVOID addr1, PVOID addr2)
{
    __ASM_SYSCALL_FUNC( __id_NtAreMappedFilesTheSame );
}

NTSTATUS SYSCALL_API NtAssignProcessToJobObject( HANDLE job, HANDLE process )
{
    __ASM_SYSCALL_FUNC( __id_NtAssignProcessToJobObject );
}

// NTSTATUS SYSCALL_API NtCallbackReturn( void *ret_ptr, ULONG ret_len, NTSTATUS status )
// {
//     __ASM_SYSCALL_FUNC( __id_NtCallbackReturn );
// }

NTSTATUS SYSCALL_API NtCancelIoFile( HANDLE handle, IO_STATUS_BLOCK *io_status )
{
    __ASM_SYSCALL_FUNC( __id_NtCancelIoFile );
}

NTSTATUS SYSCALL_API NtCancelIoFileEx( HANDLE handle, IO_STATUS_BLOCK *io, IO_STATUS_BLOCK *io_status )
{
    __ASM_SYSCALL_FUNC( __id_NtCancelIoFileEx );
}

NTSTATUS SYSCALL_API NtCancelSynchronousIoFile( HANDLE handle, IO_STATUS_BLOCK *io,
                                                IO_STATUS_BLOCK *io_status )
{
    __ASM_SYSCALL_FUNC( __id_NtCancelSynchronousIoFile );
}

NTSTATUS SYSCALL_API NtCancelTimer( HANDLE handle, BOOLEAN *state )
{
    __ASM_SYSCALL_FUNC( __id_NtCancelTimer );
}

NTSTATUS SYSCALL_API NtClearEvent( HANDLE handle )
{
    __ASM_SYSCALL_FUNC( __id_NtClearEvent );
}

NTSTATUS SYSCALL_API NtClose( HANDLE handle )
{
    __ASM_SYSCALL_FUNC( __id_NtClose );
}

NTSTATUS SYSCALL_API NtCommitTransaction( HANDLE transaction, BOOLEAN wait )
{
    __ASM_SYSCALL_FUNC( __id_NtCommitTransaction );
}

NTSTATUS SYSCALL_API NtCompareObjects( HANDLE first, HANDLE second )
{
    __ASM_SYSCALL_FUNC( __id_NtCompareObjects );
}

NTSTATUS SYSCALL_API NtCompleteConnectPort( HANDLE handle )
{
    __ASM_SYSCALL_FUNC( __id_NtCompleteConnectPort );
}

NTSTATUS SYSCALL_API NtConnectPort( HANDLE *handle, UNICODE_STRING *name, SECURITY_QUALITY_OF_SERVICE *qos,
                                    LPC_SECTION_WRITE *write, LPC_SECTION_READ *read, ULONG *max_len,
                                    void *info, ULONG *info_len )
{
    __ASM_SYSCALL_FUNC( __id_NtConnectPort );
}

static NTSTATUS SYSCALL_API syscall_NtContinue( ARM64_NT_CONTEXT *context, BOOLEAN alertable )
{
    __ASM_SYSCALL_FUNC( __id_NtContinue );
}

NTSTATUS WINAPI NtContinue( CONTEXT *context, BOOLEAN alertable )
{
    ARM64_NT_CONTEXT arm_ctx;

    return syscall_NtContinue( &arm_ctx, alertable );
}

NTSTATUS SYSCALL_API NtCreateDebugObject( HANDLE *handle, ACCESS_MASK access,
                                          OBJECT_ATTRIBUTES *attr, ULONG flags )
{
    __ASM_SYSCALL_FUNC( __id_NtCreateDebugObject );
}

NTSTATUS SYSCALL_API NtCreateDirectoryObject( HANDLE *handle, ACCESS_MASK access, OBJECT_ATTRIBUTES *attr )
{
    __ASM_SYSCALL_FUNC( __id_NtCreateDirectoryObject );
}

NTSTATUS SYSCALL_API NtCreateEvent( HANDLE *handle, ACCESS_MASK access, const OBJECT_ATTRIBUTES *attr,
                                    EVENT_TYPE type, BOOLEAN state )
{
    __ASM_SYSCALL_FUNC( __id_NtCreateEvent );
}

NTSTATUS SYSCALL_API NtCreateFile( HANDLE *handle, ACCESS_MASK access, OBJECT_ATTRIBUTES *attr,
                                   IO_STATUS_BLOCK *io, LARGE_INTEGER *alloc_size,
                                   ULONG attributes, ULONG sharing, ULONG disposition,
                                   ULONG options, void *ea_buffer, ULONG ea_length )
{
    __ASM_SYSCALL_FUNC( __id_NtCreateFile );
}

NTSTATUS SYSCALL_API NtCreateIoCompletion( HANDLE *handle, ACCESS_MASK access, OBJECT_ATTRIBUTES *attr,
                                           ULONG threads )
{
    __ASM_SYSCALL_FUNC( __id_NtCreateIoCompletion );
}

NTSTATUS SYSCALL_API NtCreateJobObject( HANDLE *handle, ACCESS_MASK access, const OBJECT_ATTRIBUTES *attr )
{
    __ASM_SYSCALL_FUNC( __id_NtCreateJobObject );
}

NTSTATUS SYSCALL_API NtCreateKey( HANDLE *key, ACCESS_MASK access, const OBJECT_ATTRIBUTES *attr,
                                  ULONG index, const UNICODE_STRING *class, ULONG options, ULONG *dispos )
{
    __ASM_SYSCALL_FUNC( __id_NtCreateKey );
}

NTSTATUS SYSCALL_API NtCreateKeyTransacted( HANDLE *key, ACCESS_MASK access, const OBJECT_ATTRIBUTES *attr,
                                            ULONG index, const UNICODE_STRING *class, ULONG options,
                                            HANDLE transacted, ULONG *dispos )
{
    __ASM_SYSCALL_FUNC( __id_NtCreateKeyTransacted );
}

NTSTATUS SYSCALL_API NtCreateKeyedEvent( HANDLE *handle, ACCESS_MASK access,
                                         const OBJECT_ATTRIBUTES *attr, ULONG flags )
{
    __ASM_SYSCALL_FUNC( __id_NtCreateKeyedEvent );
}

NTSTATUS SYSCALL_API NtCreateLowBoxToken( HANDLE *token_handle, HANDLE token, ACCESS_MASK access,
                                          OBJECT_ATTRIBUTES *attr, SID *sid, ULONG count,
                                          SID_AND_ATTRIBUTES *capabilities, ULONG handle_count,
                                          HANDLE *handle )
{
    __ASM_SYSCALL_FUNC( __id_NtCreateLowBoxToken );
}

NTSTATUS SYSCALL_API NtCreateMailslotFile( HANDLE *handle, ULONG access, OBJECT_ATTRIBUTES *attr,
                                           IO_STATUS_BLOCK *io, ULONG options, ULONG quota, ULONG msg_size,
                                           LARGE_INTEGER *timeout )
{
    __ASM_SYSCALL_FUNC( __id_NtCreateMailslotFile );
}

NTSTATUS SYSCALL_API NtCreateMutant( HANDLE *handle, ACCESS_MASK access, const OBJECT_ATTRIBUTES *attr,
                                     BOOLEAN owned )
{
    __ASM_SYSCALL_FUNC( __id_NtCreateMutant );
}

NTSTATUS SYSCALL_API NtCreateNamedPipeFile( HANDLE *handle, ULONG access, OBJECT_ATTRIBUTES *attr,
                                            IO_STATUS_BLOCK *io, ULONG sharing, ULONG dispo, ULONG options,
                                            ULONG pipe_type, ULONG read_mode, ULONG completion_mode,
                                            ULONG max_inst, ULONG inbound_quota, ULONG outbound_quota,
                                            LARGE_INTEGER *timeout )
{
    __ASM_SYSCALL_FUNC( __id_NtCreateNamedPipeFile );
}

NTSTATUS SYSCALL_API NtCreatePagingFile( UNICODE_STRING *name, LARGE_INTEGER *min_size,
                                         LARGE_INTEGER *max_size, LARGE_INTEGER *actual_size )
{
    __ASM_SYSCALL_FUNC( __id_NtCreatePagingFile );
}

NTSTATUS SYSCALL_API NtCreatePort( HANDLE *handle, OBJECT_ATTRIBUTES *attr, ULONG info_len,
                                   ULONG data_len, ULONG *reserved )
{
    __ASM_SYSCALL_FUNC( __id_NtCreatePort );
}

NTSTATUS SYSCALL_API NtCreateSection( HANDLE *handle, ACCESS_MASK access, const OBJECT_ATTRIBUTES *attr,
                                      const LARGE_INTEGER *size, ULONG protect,
                                      ULONG sec_flags, HANDLE file )
{
    __ASM_SYSCALL_FUNC( __id_NtCreateSection );
}

NTSTATUS SYSCALL_API NtCreateSemaphore( HANDLE *handle, ACCESS_MASK access, const OBJECT_ATTRIBUTES *attr,
                                        LONG initial, LONG max )
{
    __ASM_SYSCALL_FUNC( __id_NtCreateSemaphore );
}

NTSTATUS SYSCALL_API NtCreateSymbolicLinkObject( HANDLE *handle, ACCESS_MASK access,
                                                 OBJECT_ATTRIBUTES *attr, UNICODE_STRING *target )
{
    __ASM_SYSCALL_FUNC( __id_NtCreateSymbolicLinkObject );
}

NTSTATUS SYSCALL_API NtCreateThread( HANDLE *handle, ACCESS_MASK access, OBJECT_ATTRIBUTES *attr,
                                     HANDLE process, CLIENT_ID *id, CONTEXT *ctx, INITIAL_TEB *teb,
                                     BOOLEAN suspended )
{
    __ASM_SYSCALL_FUNC( __id_NtCreateThread );
}

NTSTATUS SYSCALL_API NtCreateThreadEx( HANDLE *handle, ACCESS_MASK access, OBJECT_ATTRIBUTES *attr,
                                       HANDLE process, PRTL_THREAD_START_ROUTINE start, void *param,
                                       ULONG flags, ULONG_PTR zero_bits, SIZE_T stack_commit,
                                       SIZE_T stack_reserve, PS_ATTRIBUTE_LIST *attr_list )
{
    __ASM_SYSCALL_FUNC( __id_NtCreateThreadEx );
}

NTSTATUS SYSCALL_API NtCreateTimer( HANDLE *handle, ACCESS_MASK access, const OBJECT_ATTRIBUTES *attr,
                                    TIMER_TYPE type )
{
    __ASM_SYSCALL_FUNC( __id_NtCreateTimer );
}

NTSTATUS SYSCALL_API NtCreateToken( HANDLE *handle, ACCESS_MASK access, OBJECT_ATTRIBUTES *attr,
                                    TOKEN_TYPE type, LUID *token_id, LARGE_INTEGER *expire,
                                    TOKEN_USER *user, TOKEN_GROUPS *groups, TOKEN_PRIVILEGES *privs,
                                    TOKEN_OWNER *owner, TOKEN_PRIMARY_GROUP *group,
                                    TOKEN_DEFAULT_DACL *dacl, TOKEN_SOURCE *source )
{
    __ASM_SYSCALL_FUNC( __id_NtCreateToken );
}

NTSTATUS SYSCALL_API NtCreateTransaction( HANDLE *handle, ACCESS_MASK mask, OBJECT_ATTRIBUTES *obj_attr,
                                          GUID *guid, HANDLE tm, ULONG options, ULONG isol_level,
                                          ULONG isol_flags, PLARGE_INTEGER timeout,
                                          UNICODE_STRING *description )
{
    __ASM_SYSCALL_FUNC( __id_NtCreateTransaction );
}

NTSTATUS SYSCALL_API NtCreateUserProcess( HANDLE *process_handle_ptr, HANDLE *thread_handle_ptr,
                                          ACCESS_MASK process_access, ACCESS_MASK thread_access,
                                          OBJECT_ATTRIBUTES *process_attr, OBJECT_ATTRIBUTES *thread_attr,
                                          ULONG process_flags, ULONG thread_flags,
                                          RTL_USER_PROCESS_PARAMETERS *params, PS_CREATE_INFO *info,
                                          PS_ATTRIBUTE_LIST *ps_attr )
{
    __ASM_SYSCALL_FUNC( __id_NtCreateUserProcess );
}

NTSTATUS SYSCALL_API NtDebugActiveProcess( HANDLE process, HANDLE debug )
{
    __ASM_SYSCALL_FUNC( __id_NtDebugActiveProcess );
}

NTSTATUS SYSCALL_API NtDebugContinue( HANDLE handle, CLIENT_ID *client, NTSTATUS status )
{
    __ASM_SYSCALL_FUNC( __id_NtDebugContinue );
}

NTSTATUS SYSCALL_API NtDelayExecution( BOOLEAN alertable, const LARGE_INTEGER *timeout )
{
    __ASM_SYSCALL_FUNC( __id_NtDelayExecution );
}

NTSTATUS SYSCALL_API NtDeleteAtom( RTL_ATOM atom )
{
    __ASM_SYSCALL_FUNC( __id_NtDeleteAtom );
}

NTSTATUS SYSCALL_API NtDeleteFile( OBJECT_ATTRIBUTES *attr )
{
    __ASM_SYSCALL_FUNC( __id_NtDeleteFile );
}

NTSTATUS SYSCALL_API NtDeleteKey( HANDLE key )
{
    __ASM_SYSCALL_FUNC( __id_NtDeleteKey );
}

NTSTATUS SYSCALL_API NtDeleteValueKey( HANDLE key, const UNICODE_STRING *name )
{
    __ASM_SYSCALL_FUNC( __id_NtDeleteValueKey );
}

NTSTATUS SYSCALL_API NtDeviceIoControlFile( HANDLE handle, HANDLE event, PIO_APC_ROUTINE apc,
                                            void *apc_context, IO_STATUS_BLOCK *io, ULONG code,
                                            void *in_buffer, ULONG in_size,
                                            void *out_buffer, ULONG out_size )
{
    __ASM_SYSCALL_FUNC( __id_NtDeviceIoControlFile );
}

NTSTATUS SYSCALL_API NtDisplayString( UNICODE_STRING *string )
{
    __ASM_SYSCALL_FUNC( __id_NtDisplayString );
}

NTSTATUS SYSCALL_API NtDuplicateObject( HANDLE source_process, HANDLE source, HANDLE dest_process,
                                        HANDLE *dest, ACCESS_MASK access, ULONG attributes, ULONG options )
{
    __ASM_SYSCALL_FUNC( __id_NtDuplicateObject );
}

NTSTATUS SYSCALL_API NtDuplicateToken( HANDLE token, ACCESS_MASK access, OBJECT_ATTRIBUTES *attr,
                                       BOOLEAN effective_only, TOKEN_TYPE type, HANDLE *handle )
{
    __ASM_SYSCALL_FUNC( __id_NtDuplicateToken );
}

NTSTATUS SYSCALL_API NtEnumerateKey( HANDLE handle, ULONG index, KEY_INFORMATION_CLASS info_class,
                                     void *info, DWORD length, DWORD *result_len )
{
    __ASM_SYSCALL_FUNC( __id_NtEnumerateKey );
}

NTSTATUS SYSCALL_API NtEnumerateValueKey( HANDLE handle, ULONG index, KEY_VALUE_INFORMATION_CLASS info_class,
                                          void *info, DWORD length, DWORD *result_len )
{
    __ASM_SYSCALL_FUNC( __id_NtEnumerateValueKey );
}

NTSTATUS SYSCALL_API NtFilterToken( HANDLE token, ULONG flags, TOKEN_GROUPS *disable_sids,
                                    TOKEN_PRIVILEGES *privileges, TOKEN_GROUPS *restrict_sids,
                                    HANDLE *new_token )
{
    __ASM_SYSCALL_FUNC( __id_NtFilterToken );
}

NTSTATUS SYSCALL_API NtFindAtom( const WCHAR *name, ULONG length, RTL_ATOM *atom )
{
    __ASM_SYSCALL_FUNC( __id_NtFindAtom );
}

NTSTATUS SYSCALL_API NtFlushBuffersFile( HANDLE handle, IO_STATUS_BLOCK *io )
{
    __ASM_SYSCALL_FUNC( __id_NtFlushBuffersFile );
}

NTSTATUS SYSCALL_API NtFlushInstructionCache( HANDLE handle, const void *addr, SIZE_T size )
{
    __ASM_SYSCALL_FUNC( __id_NtFlushInstructionCache );
}

NTSTATUS SYSCALL_API NtFlushKey( HANDLE key )
{
    __ASM_SYSCALL_FUNC( __id_NtFlushKey );
}

NTSTATUS SYSCALL_API NtFlushProcessWriteBuffers(void)
{
    __ASM_SYSCALL_FUNC( __id_NtFlushProcessWriteBuffers );
}

NTSTATUS SYSCALL_API NtFlushVirtualMemory( HANDLE process, LPCVOID *addr_ptr,
                                           SIZE_T *size_ptr, ULONG unknown )
{
    __ASM_SYSCALL_FUNC( __id_NtFlushVirtualMemory );
}

NTSTATUS SYSCALL_API NtFreeVirtualMemory( HANDLE process, PVOID *addr_ptr, SIZE_T *size_ptr, ULONG type )
{
    __ASM_SYSCALL_FUNC( __id_NtFreeVirtualMemory );
}

NTSTATUS SYSCALL_API NtFsControlFile( HANDLE handle, HANDLE event, PIO_APC_ROUTINE apc, void *apc_context,
                                      IO_STATUS_BLOCK *io, ULONG code, void *in_buffer, ULONG in_size,
                                      void *out_buffer, ULONG out_size )
{
    __ASM_SYSCALL_FUNC( __id_NtFsControlFile );
}

static NTSTATUS SYSCALL_API syscall_NtGetContextThread( HANDLE handle, ARM64_NT_CONTEXT *context )
{
    __ASM_SYSCALL_FUNC( __id_NtGetContextThread );
}

// NTSTATUS WINAPI NtGetContextThread( HANDLE handle, CONTEXT *context )
// {
//     return 0;
// }

ULONG SYSCALL_API NtGetCurrentProcessorNumber(void)
{
    __ASM_SYSCALL_FUNC( __id_NtGetCurrentProcessorNumber );
}

NTSTATUS SYSCALL_API NtGetNextThread( HANDLE process, HANDLE thread, ACCESS_MASK access, ULONG attributes,
                                      ULONG flags, HANDLE *handle )
{
    __ASM_SYSCALL_FUNC( __id_NtGetNextThread );
}

NTSTATUS SYSCALL_API NtGetNlsSectionPtr( ULONG type, ULONG id, void *unknown, void **ptr, SIZE_T *size )
{
    __ASM_SYSCALL_FUNC( __id_NtGetNlsSectionPtr );
}

NTSTATUS SYSCALL_API NtGetWriteWatch( HANDLE process, ULONG flags, PVOID base, SIZE_T size,
                                      PVOID *addresses, ULONG_PTR *count, ULONG *granularity )
{
    __ASM_SYSCALL_FUNC( __id_NtGetWriteWatch );
}

NTSTATUS SYSCALL_API NtImpersonateAnonymousToken( HANDLE thread )
{
    __ASM_SYSCALL_FUNC( __id_NtImpersonateAnonymousToken );
}

NTSTATUS SYSCALL_API NtInitializeNlsFiles( void **ptr, LCID *lcid, LARGE_INTEGER *size )
{
    __ASM_SYSCALL_FUNC( __id_NtInitializeNlsFiles );
}

NTSTATUS SYSCALL_API NtInitiatePowerAction( POWER_ACTION action, SYSTEM_POWER_STATE state,
                                            ULONG flags, BOOLEAN async )
{
    __ASM_SYSCALL_FUNC( __id_NtInitiatePowerAction );
}

NTSTATUS SYSCALL_API NtIsProcessInJob( HANDLE process, HANDLE job )
{
    __ASM_SYSCALL_FUNC( __id_NtIsProcessInJob );
}

NTSTATUS SYSCALL_API NtListenPort( HANDLE handle, LPC_MESSAGE *msg )
{
    __ASM_SYSCALL_FUNC( __id_NtListenPort );
}

NTSTATUS SYSCALL_API NtLoadDriver( const UNICODE_STRING *name )
{
    __ASM_SYSCALL_FUNC( __id_NtLoadDriver );
}

NTSTATUS SYSCALL_API NtLoadKey( const OBJECT_ATTRIBUTES *attr, OBJECT_ATTRIBUTES *file )
{
    __ASM_SYSCALL_FUNC( __id_NtLoadKey );
}

NTSTATUS SYSCALL_API NtLoadKey2( const OBJECT_ATTRIBUTES *attr, OBJECT_ATTRIBUTES *file, ULONG flags )
{
    __ASM_SYSCALL_FUNC( __id_NtLoadKey2 );
}

NTSTATUS SYSCALL_API NtLoadKeyEx( const OBJECT_ATTRIBUTES *attr, OBJECT_ATTRIBUTES *file, ULONG flags,
                                  HANDLE trustkey, HANDLE event, ACCESS_MASK access,
                                  HANDLE *roothandle, IO_STATUS_BLOCK *iostatus )
{
    __ASM_SYSCALL_FUNC( __id_NtLoadKeyEx );
}

NTSTATUS SYSCALL_API NtLockFile( HANDLE file, HANDLE event, PIO_APC_ROUTINE apc, void* apc_user,
                                 IO_STATUS_BLOCK *io_status, LARGE_INTEGER *offset,
                                 LARGE_INTEGER *count, ULONG *key, BOOLEAN dont_wait, BOOLEAN exclusive )
{
    __ASM_SYSCALL_FUNC( __id_NtLockFile );
}

NTSTATUS SYSCALL_API NtLockVirtualMemory( HANDLE process, PVOID *addr, SIZE_T *size, ULONG unknown )
{
    __ASM_SYSCALL_FUNC( __id_NtLockVirtualMemory );
}

NTSTATUS SYSCALL_API NtMakeTemporaryObject( HANDLE handle )
{
    __ASM_SYSCALL_FUNC( __id_NtMakeTemporaryObject );
}

NTSTATUS SYSCALL_API NtMapViewOfSection( HANDLE handle, HANDLE process, PVOID *addr_ptr,
                                         ULONG_PTR zero_bits, SIZE_T commit_size,
                                         const LARGE_INTEGER *offset_ptr, SIZE_T *size_ptr,
                                         SECTION_INHERIT inherit, ULONG alloc_type, ULONG protect )
{
    __ASM_SYSCALL_FUNC( __id_NtMapViewOfSection );
}

NTSTATUS SYSCALL_API NtMapViewOfSectionEx( HANDLE handle, HANDLE process, PVOID *addr_ptr,
                                           const LARGE_INTEGER *offset_ptr, SIZE_T *size_ptr,
                                           ULONG alloc_type, ULONG protect,
                                           MEM_EXTENDED_PARAMETER *parameters, ULONG count )
{
    __ASM_SYSCALL_FUNC( __id_NtMapViewOfSectionEx );
}

NTSTATUS SYSCALL_API NtNotifyChangeDirectoryFile( HANDLE handle, HANDLE event, PIO_APC_ROUTINE apc,
                                                  void *apc_context, IO_STATUS_BLOCK *iosb, void *buffer,
                                                  ULONG buffer_size, ULONG filter, BOOLEAN subtree )
{
    __ASM_SYSCALL_FUNC( __id_NtNotifyChangeDirectoryFile );
}

NTSTATUS SYSCALL_API NtNotifyChangeKey( HANDLE key, HANDLE event, PIO_APC_ROUTINE apc, void *apc_context,
                                        IO_STATUS_BLOCK *io, ULONG filter, BOOLEAN subtree,
                                        void *buffer, ULONG length, BOOLEAN async )
{
    __ASM_SYSCALL_FUNC( __id_NtNotifyChangeKey );
}

NTSTATUS SYSCALL_API NtNotifyChangeMultipleKeys( HANDLE key, ULONG count, OBJECT_ATTRIBUTES *attr,
                                                 HANDLE event, PIO_APC_ROUTINE apc, void *apc_context,
                                                 IO_STATUS_BLOCK *io, ULONG filter, BOOLEAN subtree,
                                                 void *buffer, ULONG length, BOOLEAN async )
{
    __ASM_SYSCALL_FUNC( __id_NtNotifyChangeMultipleKeys );
}

NTSTATUS SYSCALL_API NtOpenDirectoryObject( HANDLE *handle, ACCESS_MASK access, const OBJECT_ATTRIBUTES *attr )
{
    __ASM_SYSCALL_FUNC( __id_NtOpenDirectoryObject );
}

NTSTATUS SYSCALL_API NtOpenEvent( HANDLE *handle, ACCESS_MASK access, const OBJECT_ATTRIBUTES *attr )
{
    __ASM_SYSCALL_FUNC( __id_NtOpenEvent );
}

NTSTATUS SYSCALL_API NtOpenFile( HANDLE *handle, ACCESS_MASK access, OBJECT_ATTRIBUTES *attr,
                                 IO_STATUS_BLOCK *io, ULONG sharing, ULONG options )
{
    __ASM_SYSCALL_FUNC( __id_NtOpenFile );
}

NTSTATUS SYSCALL_API NtOpenIoCompletion( HANDLE *handle, ACCESS_MASK access, const OBJECT_ATTRIBUTES *attr )
{
    __ASM_SYSCALL_FUNC( __id_NtOpenIoCompletion );
}

NTSTATUS SYSCALL_API NtOpenJobObject( HANDLE *handle, ACCESS_MASK access, const OBJECT_ATTRIBUTES *attr )
{
    __ASM_SYSCALL_FUNC( __id_NtOpenJobObject );
}

NTSTATUS SYSCALL_API NtOpenKey( HANDLE *key, ACCESS_MASK access, const OBJECT_ATTRIBUTES *attr )
{
    __ASM_SYSCALL_FUNC( __id_NtOpenKey );
}

NTSTATUS SYSCALL_API NtOpenKeyEx( HANDLE *key, ACCESS_MASK access, const OBJECT_ATTRIBUTES *attr, ULONG options )
{
    __ASM_SYSCALL_FUNC( __id_NtOpenKeyEx );
}

NTSTATUS SYSCALL_API NtOpenKeyTransacted( HANDLE *key, ACCESS_MASK access, const OBJECT_ATTRIBUTES *attr,
                                          HANDLE transaction )
{
    __ASM_SYSCALL_FUNC( __id_NtOpenKeyTransacted );
}

NTSTATUS SYSCALL_API NtOpenKeyTransactedEx( HANDLE *key, ACCESS_MASK access, const OBJECT_ATTRIBUTES *attr,
                                            ULONG options, HANDLE transaction )
{
    __ASM_SYSCALL_FUNC( __id_NtOpenKeyTransactedEx );
}

NTSTATUS SYSCALL_API NtOpenKeyedEvent( HANDLE *handle, ACCESS_MASK access, const OBJECT_ATTRIBUTES *attr )
{
    __ASM_SYSCALL_FUNC( __id_NtOpenKeyedEvent );
}

NTSTATUS SYSCALL_API NtOpenMutant( HANDLE *handle, ACCESS_MASK access, const OBJECT_ATTRIBUTES *attr )
{
    __ASM_SYSCALL_FUNC( __id_NtOpenMutant );
}

NTSTATUS SYSCALL_API NtOpenProcess( HANDLE *handle, ACCESS_MASK access,
                                    const OBJECT_ATTRIBUTES *attr, const CLIENT_ID *id )
{
    __ASM_SYSCALL_FUNC( __id_NtOpenProcess );
}

NTSTATUS SYSCALL_API NtOpenProcessToken( HANDLE process, DWORD access, HANDLE *handle )
{
    __ASM_SYSCALL_FUNC( __id_NtOpenProcessToken );
}

NTSTATUS SYSCALL_API NtOpenProcessTokenEx( HANDLE process, DWORD access, DWORD attributes, HANDLE *handle )
{
    __ASM_SYSCALL_FUNC( __id_NtOpenProcessTokenEx );
}

NTSTATUS SYSCALL_API NtOpenSection( HANDLE *handle, ACCESS_MASK access, const OBJECT_ATTRIBUTES *attr )
{
    __ASM_SYSCALL_FUNC( __id_NtOpenSection );
}

NTSTATUS SYSCALL_API NtOpenSemaphore( HANDLE *handle, ACCESS_MASK access, const OBJECT_ATTRIBUTES *attr )
{
    __ASM_SYSCALL_FUNC( __id_NtOpenSemaphore );
}

NTSTATUS SYSCALL_API NtOpenSymbolicLinkObject( HANDLE *handle, ACCESS_MASK access,
                                               const OBJECT_ATTRIBUTES *attr )
{
    __ASM_SYSCALL_FUNC( __id_NtOpenSymbolicLinkObject );
}

NTSTATUS SYSCALL_API NtOpenThread( HANDLE *handle, ACCESS_MASK access,
                                   const OBJECT_ATTRIBUTES *attr, const CLIENT_ID *id )
{
    __ASM_SYSCALL_FUNC( __id_NtOpenThread );
}

NTSTATUS SYSCALL_API NtOpenThreadToken( HANDLE thread, DWORD access, BOOLEAN self, HANDLE *handle )
{
    __ASM_SYSCALL_FUNC( __id_NtOpenThreadToken );
}

NTSTATUS SYSCALL_API NtOpenThreadTokenEx( HANDLE thread, DWORD access, BOOLEAN self, DWORD attributes,
                                          HANDLE *handle )
{
    __ASM_SYSCALL_FUNC( __id_NtOpenThreadTokenEx );
}

NTSTATUS SYSCALL_API NtOpenTimer( HANDLE *handle, ACCESS_MASK access, const OBJECT_ATTRIBUTES *attr )
{
    __ASM_SYSCALL_FUNC( __id_NtOpenTimer );
}

NTSTATUS SYSCALL_API NtPowerInformation( POWER_INFORMATION_LEVEL level, void *input, ULONG in_size,
                                         void *output, ULONG out_size )
{
    __ASM_SYSCALL_FUNC( __id_NtPowerInformation );
}

NTSTATUS SYSCALL_API NtPrivilegeCheck( HANDLE token, PRIVILEGE_SET *privs, BOOLEAN *res )
{
    __ASM_SYSCALL_FUNC( __id_NtPrivilegeCheck );
}

NTSTATUS SYSCALL_API NtProtectVirtualMemory( HANDLE process, PVOID *addr_ptr, SIZE_T *size_ptr,
                                             ULONG new_prot, ULONG *old_prot )
{
    __ASM_SYSCALL_FUNC( __id_NtProtectVirtualMemory );
}

NTSTATUS SYSCALL_API NtPulseEvent( HANDLE handle, LONG *prev_state )
{
    __ASM_SYSCALL_FUNC( __id_NtPulseEvent );
}

NTSTATUS SYSCALL_API NtQueryAttributesFile( const OBJECT_ATTRIBUTES *attr, FILE_BASIC_INFORMATION *info )
{
    __ASM_SYSCALL_FUNC( __id_NtQueryAttributesFile );
}

NTSTATUS SYSCALL_API NtQueryDefaultLocale( BOOLEAN user, LCID *lcid )
{
    __ASM_SYSCALL_FUNC( __id_NtQueryDefaultLocale );
}

NTSTATUS SYSCALL_API NtQueryDefaultUILanguage( LANGID *lang )
{
    __ASM_SYSCALL_FUNC( __id_NtQueryDefaultUILanguage );
}

NTSTATUS SYSCALL_API NtQueryDirectoryFile( HANDLE handle, HANDLE event, PIO_APC_ROUTINE apc_routine,
                                           void *apc_context, IO_STATUS_BLOCK *io, void *buffer,
                                           ULONG length, FILE_INFORMATION_CLASS info_class,
                                           BOOLEAN single_entry, UNICODE_STRING *mask,
                                           BOOLEAN restart_scan )
{
    __ASM_SYSCALL_FUNC( __id_NtQueryDirectoryFile );
}

NTSTATUS SYSCALL_API NtQueryDirectoryObject( HANDLE handle, DIRECTORY_BASIC_INFORMATION *buffer,
                                             ULONG size, BOOLEAN single_entry, BOOLEAN restart,
                                             ULONG *context, ULONG *ret_size )
{
    __ASM_SYSCALL_FUNC( __id_NtQueryDirectoryObject );
}

NTSTATUS SYSCALL_API NtQueryEaFile( HANDLE handle, IO_STATUS_BLOCK *io, void *buffer, ULONG length,
                                    BOOLEAN single_entry, void *list, ULONG list_len,
                                    ULONG *index, BOOLEAN restart )
{
    __ASM_SYSCALL_FUNC( __id_NtQueryEaFile );
}

NTSTATUS SYSCALL_API NtQueryEvent( HANDLE handle, EVENT_INFORMATION_CLASS class,
                                   void *info, ULONG len, ULONG *ret_len )
{
    __ASM_SYSCALL_FUNC( __id_NtQueryEvent );
}

NTSTATUS SYSCALL_API NtQueryFullAttributesFile( const OBJECT_ATTRIBUTES *attr,
                                                FILE_NETWORK_OPEN_INFORMATION *info )
{
    __ASM_SYSCALL_FUNC( __id_NtQueryFullAttributesFile );
}

NTSTATUS SYSCALL_API NtQueryInformationAtom( RTL_ATOM atom, ATOM_INFORMATION_CLASS class,
                                             void *ptr, ULONG size, ULONG *retsize )
{
    __ASM_SYSCALL_FUNC( __id_NtQueryInformationAtom );
}

NTSTATUS SYSCALL_API NtQueryInformationFile( HANDLE handle, IO_STATUS_BLOCK *io,
                                             void *ptr, ULONG len, FILE_INFORMATION_CLASS class )
{
    __ASM_SYSCALL_FUNC( __id_NtQueryInformationFile );
}

NTSTATUS SYSCALL_API NtQueryInformationJobObject( HANDLE handle, JOBOBJECTINFOCLASS class, void *info,
                                                  ULONG len, ULONG *ret_len )
{
    __ASM_SYSCALL_FUNC( __id_NtQueryInformationJobObject );
}

NTSTATUS SYSCALL_API NtQueryInformationProcess( HANDLE handle, PROCESSINFOCLASS class, void *info,
                                                ULONG size, ULONG *ret_len )
{
    __ASM_SYSCALL_FUNC( __id_NtQueryInformationProcess );
}

NTSTATUS SYSCALL_API NtQueryInformationThread( HANDLE handle, THREADINFOCLASS class,
                                               void *data, ULONG length, ULONG *ret_len )
{
    __ASM_SYSCALL_FUNC( __id_NtQueryInformationThread );
}

NTSTATUS SYSCALL_API NtQueryInformationToken( HANDLE token, TOKEN_INFORMATION_CLASS class,
                                              void *info, ULONG length, ULONG *retlen )
{
    __ASM_SYSCALL_FUNC( __id_NtQueryInformationToken );
}

NTSTATUS SYSCALL_API NtQueryInstallUILanguage( LANGID *lang )
{
    __ASM_SYSCALL_FUNC( __id_NtQueryInstallUILanguage );
}

NTSTATUS SYSCALL_API NtQueryIoCompletion( HANDLE handle, IO_COMPLETION_INFORMATION_CLASS class,
                                          void *buffer, ULONG len, ULONG *ret_len )
{
    __ASM_SYSCALL_FUNC( __id_NtQueryIoCompletion );
}

NTSTATUS SYSCALL_API NtQueryKey( HANDLE handle, KEY_INFORMATION_CLASS info_class,
                                 void *info, DWORD length, DWORD *result_len )
{
    __ASM_SYSCALL_FUNC( __id_NtQueryKey );
}

NTSTATUS SYSCALL_API NtQueryLicenseValue( const UNICODE_STRING *name, ULONG *type,
                                          void *data, ULONG length, ULONG *retlen )
{
    __ASM_SYSCALL_FUNC( __id_NtQueryLicenseValue );
}

NTSTATUS SYSCALL_API NtQueryMultipleValueKey( HANDLE key, KEY_MULTIPLE_VALUE_INFORMATION *info,
                                              ULONG count, void *buffer, ULONG length, ULONG *retlen )
{
    __ASM_SYSCALL_FUNC( __id_NtQueryMultipleValueKey );
}

NTSTATUS SYSCALL_API NtQueryMutant( HANDLE handle, MUTANT_INFORMATION_CLASS class,
                                    void *info, ULONG len, ULONG *ret_len )
{
    __ASM_SYSCALL_FUNC( __id_NtQueryMutant );
}

NTSTATUS SYSCALL_API NtQueryObject( HANDLE handle, OBJECT_INFORMATION_CLASS info_class,
                                    void *ptr, ULONG len, ULONG *used_len )
{
    __ASM_SYSCALL_FUNC( __id_NtQueryObject );
}

NTSTATUS SYSCALL_API NtQueryPerformanceCounter( LARGE_INTEGER *counter, LARGE_INTEGER *frequency )
{
    __ASM_SYSCALL_FUNC( __id_NtQueryPerformanceCounter );
}

NTSTATUS SYSCALL_API NtQuerySection( HANDLE handle, SECTION_INFORMATION_CLASS class, void *ptr,
                                     SIZE_T size, SIZE_T *ret_size )
{
    __ASM_SYSCALL_FUNC( __id_NtQuerySection );
}

NTSTATUS SYSCALL_API NtQuerySecurityObject( HANDLE handle, SECURITY_INFORMATION info,
                                            PSECURITY_DESCRIPTOR descr, ULONG length, ULONG *retlen )
{
    __ASM_SYSCALL_FUNC( __id_NtQuerySecurityObject );
}

NTSTATUS SYSCALL_API NtQuerySemaphore( HANDLE handle, SEMAPHORE_INFORMATION_CLASS class,
                                       void *info, ULONG len, ULONG *ret_len )
{
    __ASM_SYSCALL_FUNC( __id_NtQuerySemaphore );
}

NTSTATUS SYSCALL_API NtQuerySymbolicLinkObject( HANDLE handle, UNICODE_STRING *target, ULONG *length )
{
    __ASM_SYSCALL_FUNC( __id_NtQuerySymbolicLinkObject );
}

NTSTATUS SYSCALL_API NtQuerySystemEnvironmentValue( UNICODE_STRING *name, WCHAR *buffer, ULONG length,
                                                    ULONG *retlen )
{
    __ASM_SYSCALL_FUNC( __id_NtQuerySystemEnvironmentValue );
}

NTSTATUS SYSCALL_API NtQuerySystemEnvironmentValueEx( UNICODE_STRING *name, GUID *vendor, void *buffer,
                                                      ULONG *retlen, ULONG *attrib )
{
    __ASM_SYSCALL_FUNC( __id_NtQuerySystemEnvironmentValueEx );
}

NTSTATUS SYSCALL_API NtQuerySystemInformation( SYSTEM_INFORMATION_CLASS class,
                                               void *info, ULONG size, ULONG *ret_size )
{
    __ASM_SYSCALL_FUNC( __id_NtQuerySystemInformation );
}

NTSTATUS SYSCALL_API NtQuerySystemInformationEx( SYSTEM_INFORMATION_CLASS class, void *query,
                                                 ULONG query_len, void *info, ULONG size, ULONG *ret_size )
{
    __ASM_SYSCALL_FUNC( __id_NtQuerySystemInformationEx );
}

NTSTATUS SYSCALL_API NtQuerySystemTime( LARGE_INTEGER *time )
{
    __ASM_SYSCALL_FUNC( __id_NtQuerySystemTime );
}

NTSTATUS SYSCALL_API NtQueryTimer( HANDLE handle, TIMER_INFORMATION_CLASS class,
                                   void *info, ULONG len, ULONG *ret_len )
{
    __ASM_SYSCALL_FUNC( __id_NtQueryTimer );
}

NTSTATUS SYSCALL_API NtQueryTimerResolution( ULONG *min_res, ULONG *max_res, ULONG *current_res )
{
    __ASM_SYSCALL_FUNC( __id_NtQueryTimerResolution );
}

NTSTATUS SYSCALL_API NtQueryValueKey( HANDLE handle, const UNICODE_STRING *name,
                                      KEY_VALUE_INFORMATION_CLASS info_class,
                                      void *info, DWORD length, DWORD *result_len )
{
    __ASM_SYSCALL_FUNC( __id_NtQueryValueKey );
}

NTSTATUS SYSCALL_API NtQueryVirtualMemory( HANDLE process, LPCVOID addr, MEMORY_INFORMATION_CLASS info_class,
                                           PVOID buffer, SIZE_T len, SIZE_T *res_len )
{
    __ASM_SYSCALL_FUNC( __id_NtQueryVirtualMemory );
}

NTSTATUS SYSCALL_API NtQueryVolumeInformationFile( HANDLE handle, IO_STATUS_BLOCK *io, void *buffer,
                                                   ULONG length, FS_INFORMATION_CLASS info_class )
{
    __ASM_SYSCALL_FUNC( __id_NtQueryVolumeInformationFile );
}

NTSTATUS SYSCALL_API NtQueueApcThread( HANDLE handle, PNTAPCFUNC func, ULONG_PTR arg1,
                                       ULONG_PTR arg2, ULONG_PTR arg3 )
{
    __ASM_SYSCALL_FUNC( __id_NtQueueApcThread );
}

NTSTATUS WINAPI NtRaiseException( EXCEPTION_RECORD *rec, CONTEXT *context, BOOL first_chance )
{
    __ASM_SYSCALL_FUNC( __id_NtRaiseException );
}

NTSTATUS SYSCALL_API NtRaiseHardError( NTSTATUS status, ULONG count, UNICODE_STRING *params_mask,
                                       void **params, HARDERROR_RESPONSE_OPTION option,
                                       HARDERROR_RESPONSE *response )
{
    __ASM_SYSCALL_FUNC( __id_NtRaiseHardError );
}

NTSTATUS SYSCALL_API NtReadFile( HANDLE handle, HANDLE event, PIO_APC_ROUTINE apc, void *apc_user,
                                 IO_STATUS_BLOCK *io, void *buffer, ULONG length,
                                 LARGE_INTEGER *offset, ULONG *key )
{
    __ASM_SYSCALL_FUNC( __id_NtReadFile );
}

NTSTATUS SYSCALL_API NtReadFileScatter( HANDLE file, HANDLE event, PIO_APC_ROUTINE apc, void *apc_user,
                                        IO_STATUS_BLOCK *io, FILE_SEGMENT_ELEMENT *segments,
                                        ULONG length, LARGE_INTEGER *offset, ULONG *key )
{
    __ASM_SYSCALL_FUNC( __id_NtReadFileScatter );
}

NTSTATUS SYSCALL_API NtReadVirtualMemory( HANDLE process, const void *addr, void *buffer,
                                          SIZE_T size, SIZE_T *bytes_read )
{
    __ASM_SYSCALL_FUNC( __id_NtReadVirtualMemory );
}

NTSTATUS SYSCALL_API NtRegisterThreadTerminatePort( HANDLE handle )
{
    __ASM_SYSCALL_FUNC( __id_NtRegisterThreadTerminatePort );
}

NTSTATUS SYSCALL_API NtReleaseKeyedEvent( HANDLE handle, const void *key,
                                          BOOLEAN alertable, const LARGE_INTEGER *timeout )
{
    __ASM_SYSCALL_FUNC( __id_NtReleaseKeyedEvent );
}

NTSTATUS SYSCALL_API NtReleaseMutant( HANDLE handle, LONG *prev_count )
{
    __ASM_SYSCALL_FUNC( __id_NtReleaseMutant );
}

NTSTATUS SYSCALL_API NtReleaseSemaphore( HANDLE handle, ULONG count, ULONG *previous )
{
    __ASM_SYSCALL_FUNC( __id_NtReleaseSemaphore );
}

NTSTATUS SYSCALL_API NtRemoveIoCompletion( HANDLE handle, ULONG_PTR *key, ULONG_PTR *value,
                                           IO_STATUS_BLOCK *io, LARGE_INTEGER *timeout )
{
    __ASM_SYSCALL_FUNC( __id_NtRemoveIoCompletion );
}

NTSTATUS SYSCALL_API NtRemoveIoCompletionEx( HANDLE handle, FILE_IO_COMPLETION_INFORMATION *info,
                                             ULONG count, ULONG *written, LARGE_INTEGER *timeout,
                                             BOOLEAN alertable )
{
    __ASM_SYSCALL_FUNC( __id_NtRemoveIoCompletionEx );
}

NTSTATUS SYSCALL_API NtRemoveProcessDebug( HANDLE process, HANDLE debug )
{
    __ASM_SYSCALL_FUNC( __id_NtRemoveProcessDebug );
}

NTSTATUS SYSCALL_API NtRenameKey( HANDLE key, UNICODE_STRING *name )
{
    __ASM_SYSCALL_FUNC( __id_NtRenameKey );
}

NTSTATUS SYSCALL_API NtReplaceKey( OBJECT_ATTRIBUTES *attr, HANDLE key, OBJECT_ATTRIBUTES *replace )
{
    __ASM_SYSCALL_FUNC( __id_NtReplaceKey );
}

NTSTATUS SYSCALL_API NtReplyWaitReceivePort( HANDLE handle, ULONG *id, LPC_MESSAGE *reply, LPC_MESSAGE *msg )
{
    __ASM_SYSCALL_FUNC( __id_NtReplyWaitReceivePort );
}

NTSTATUS SYSCALL_API NtRequestWaitReplyPort( HANDLE handle, LPC_MESSAGE *msg_in, LPC_MESSAGE *msg_out )
{
    __ASM_SYSCALL_FUNC( __id_NtRequestWaitReplyPort );
}

NTSTATUS SYSCALL_API NtResetEvent( HANDLE handle, LONG *prev_state )
{
    __ASM_SYSCALL_FUNC( __id_NtResetEvent );
}

NTSTATUS SYSCALL_API NtResetWriteWatch( HANDLE process, PVOID base, SIZE_T size )
{
    __ASM_SYSCALL_FUNC( __id_NtResetWriteWatch );
}

NTSTATUS SYSCALL_API NtRestoreKey( HANDLE key, HANDLE file, ULONG flags )
{
    __ASM_SYSCALL_FUNC( __id_NtRestoreKey );
}

NTSTATUS SYSCALL_API NtResumeProcess( HANDLE handle )
{
    __ASM_SYSCALL_FUNC( __id_NtResumeProcess );
}

NTSTATUS SYSCALL_API NtResumeThread( HANDLE handle, ULONG *count )
{
    __ASM_SYSCALL_FUNC( __id_NtResumeThread );
}

NTSTATUS SYSCALL_API NtRollbackTransaction( HANDLE transaction, BOOLEAN wait )
{
    __ASM_SYSCALL_FUNC( __id_NtRollbackTransaction );
}

NTSTATUS SYSCALL_API NtSaveKey( HANDLE key, HANDLE file )
{
    __ASM_SYSCALL_FUNC( __id_NtSaveKey );
}

NTSTATUS SYSCALL_API NtSecureConnectPort( HANDLE *handle, UNICODE_STRING *name,
                                          SECURITY_QUALITY_OF_SERVICE *qos, LPC_SECTION_WRITE *write,
                                          PSID sid, LPC_SECTION_READ *read, ULONG *max_len,
                                          void *info, ULONG *info_len )
{
    __ASM_SYSCALL_FUNC( __id_NtSecureConnectPort );
}

static NTSTATUS SYSCALL_API syscall_NtSetContextThread( HANDLE handle, const ARM64_NT_CONTEXT *context )
{
    __ASM_SYSCALL_FUNC( __id_NtSetContextThread );
}
/*
NTSTATUS WINAPI NtSetContextThread( HANDLE handle, const CONTEXT *context )
{
        __ASM_SYSCALL_FUNC( __id_NtSetContextThread );
}*/

NTSTATUS SYSCALL_API NtSetDebugFilterState( ULONG component_id, ULONG level, BOOLEAN state )
{
    __ASM_SYSCALL_FUNC( __id_NtSetDebugFilterState );
}

NTSTATUS SYSCALL_API NtSetDefaultLocale( BOOLEAN user, LCID lcid )
{
    __ASM_SYSCALL_FUNC( __id_NtSetDefaultLocale );
}

NTSTATUS SYSCALL_API NtSetDefaultUILanguage( LANGID lang )
{
    __ASM_SYSCALL_FUNC( __id_NtSetDefaultUILanguage );
}

NTSTATUS SYSCALL_API NtSetEaFile( HANDLE handle, IO_STATUS_BLOCK *io, void *buffer, ULONG length )
{
    __ASM_SYSCALL_FUNC( __id_NtSetEaFile );
}

NTSTATUS SYSCALL_API NtSetEvent( HANDLE handle, LONG *prev_state )
{
    __ASM_SYSCALL_FUNC( __id_NtSetEvent );
}

NTSTATUS SYSCALL_API NtSetInformationDebugObject( HANDLE handle, DEBUGOBJECTINFOCLASS class,
                                                  void *info, ULONG len, ULONG *ret_len )
{
    __ASM_SYSCALL_FUNC( __id_NtSetInformationDebugObject );
}

NTSTATUS SYSCALL_API NtSetInformationFile( HANDLE handle, IO_STATUS_BLOCK *io,
                                           void *ptr, ULONG len, FILE_INFORMATION_CLASS class )
{
    __ASM_SYSCALL_FUNC( __id_NtSetInformationFile );
}

NTSTATUS SYSCALL_API NtSetInformationJobObject( HANDLE handle, JOBOBJECTINFOCLASS class,
                                                void *info, ULONG len )
{
    __ASM_SYSCALL_FUNC( __id_NtSetInformationJobObject );
}

NTSTATUS SYSCALL_API NtSetInformationKey( HANDLE key, int class, void *info, ULONG length )
{
    __ASM_SYSCALL_FUNC( __id_NtSetInformationKey );
}

NTSTATUS SYSCALL_API NtSetInformationObject( HANDLE handle, OBJECT_INFORMATION_CLASS info_class,
                                             void *ptr, ULONG len )
{
    __ASM_SYSCALL_FUNC( __id_NtSetInformationObject );
}

NTSTATUS SYSCALL_API NtSetInformationProcess( HANDLE handle, PROCESSINFOCLASS class,
                                              void *info, ULONG size )
{
    __ASM_SYSCALL_FUNC( __id_NtSetInformationProcess );
}

NTSTATUS SYSCALL_API NtSetInformationThread( HANDLE handle, THREADINFOCLASS class,
                                             const void *data, ULONG length )
{
    __ASM_SYSCALL_FUNC( __id_NtSetInformationThread );
}

NTSTATUS SYSCALL_API NtSetInformationToken( HANDLE token, TOKEN_INFORMATION_CLASS class,
                                            void *info, ULONG length )
{
    __ASM_SYSCALL_FUNC( __id_NtSetInformationToken );
}

NTSTATUS SYSCALL_API NtSetInformationVirtualMemory( HANDLE process,
                                                    VIRTUAL_MEMORY_INFORMATION_CLASS info_class,
                                                    ULONG_PTR count, PMEMORY_RANGE_ENTRY addresses,
                                                    PVOID ptr, ULONG size )
{
    __ASM_SYSCALL_FUNC( __id_NtSetInformationVirtualMemory );
}

NTSTATUS SYSCALL_API NtSetIntervalProfile( ULONG interval, KPROFILE_SOURCE source )
{
    __ASM_SYSCALL_FUNC( __id_NtSetIntervalProfile );
}

NTSTATUS SYSCALL_API NtSetIoCompletion( HANDLE handle, ULONG_PTR key, ULONG_PTR value,
                                        NTSTATUS status, SIZE_T count )
{
    __ASM_SYSCALL_FUNC( __id_NtSetIoCompletion );
}

// NTSTATUS SYSCALL_API NtSetLdtEntries( ULONG sel1, LDT_ENTRY entry1, ULONG sel2, LDT_ENTRY entry2 )
// {
//     __ASM_SYSCALL_FUNC( __id_NtSetLdtEntries );
// }

NTSTATUS SYSCALL_API NtSetSecurityObject( HANDLE handle, SECURITY_INFORMATION info,
                                          PSECURITY_DESCRIPTOR descr )
{
    __ASM_SYSCALL_FUNC( __id_NtSetSecurityObject );
}

NTSTATUS SYSCALL_API NtSetSystemInformation( SYSTEM_INFORMATION_CLASS class, void *info, ULONG length )
{
    __ASM_SYSCALL_FUNC( __id_NtSetSystemInformation );
}

NTSTATUS SYSCALL_API NtSetSystemTime( const LARGE_INTEGER *new, LARGE_INTEGER *old )
{
    __ASM_SYSCALL_FUNC( __id_NtSetSystemTime );
}

NTSTATUS SYSCALL_API NtSetThreadExecutionState( EXECUTION_STATE new_state, EXECUTION_STATE *old_state )
{
    __ASM_SYSCALL_FUNC( __id_NtSetThreadExecutionState );
}

NTSTATUS SYSCALL_API NtSetTimer( HANDLE handle, const LARGE_INTEGER *when, PTIMER_APC_ROUTINE callback,
                                 void *arg, BOOLEAN resume, ULONG period, BOOLEAN *state )
{
    __ASM_SYSCALL_FUNC( __id_NtSetTimer );
}

NTSTATUS SYSCALL_API NtSetTimerResolution( ULONG res, BOOLEAN set, ULONG *current_res )
{
    __ASM_SYSCALL_FUNC( __id_NtSetTimerResolution );
}

NTSTATUS SYSCALL_API NtSetValueKey( HANDLE key, const UNICODE_STRING *name, ULONG index,
                                    ULONG type, const void *data, ULONG count )
{
    __ASM_SYSCALL_FUNC( __id_NtSetValueKey );
}

NTSTATUS SYSCALL_API NtSetVolumeInformationFile( HANDLE handle, IO_STATUS_BLOCK *io, void *info,
                                                 ULONG length, FS_INFORMATION_CLASS class )
{
    __ASM_SYSCALL_FUNC( __id_NtSetVolumeInformationFile );
}

NTSTATUS SYSCALL_API NtShutdownSystem( SHUTDOWN_ACTION action )
{
    __ASM_SYSCALL_FUNC( __id_NtShutdownSystem );
}

NTSTATUS SYSCALL_API NtSignalAndWaitForSingleObject( HANDLE signal, HANDLE wait,
                                                     BOOLEAN alertable, const LARGE_INTEGER *timeout )
{
    __ASM_SYSCALL_FUNC( __id_NtSignalAndWaitForSingleObject );
}

NTSTATUS SYSCALL_API NtSuspendProcess( HANDLE handle )
{
    __ASM_SYSCALL_FUNC( __id_NtSuspendProcess );
}

NTSTATUS SYSCALL_API NtSuspendThread( HANDLE handle, ULONG *count )
{
    __ASM_SYSCALL_FUNC( __id_NtSuspendThread );
}

NTSTATUS SYSCALL_API NtSystemDebugControl( SYSDBG_COMMAND command, void *in_buff, ULONG in_len,
                                           void *out_buff, ULONG out_len, ULONG *retlen )
{
    __ASM_SYSCALL_FUNC( __id_NtSystemDebugControl );
}

NTSTATUS SYSCALL_API NtTerminateJobObject( HANDLE handle, NTSTATUS status )
{
    __ASM_SYSCALL_FUNC( __id_NtTerminateJobObject );
}

NTSTATUS SYSCALL_API NtTerminateProcess( HANDLE handle, LONG exit_code )
{
    __ASM_SYSCALL_FUNC( __id_NtTerminateProcess );
}

NTSTATUS SYSCALL_API NtTerminateThread( HANDLE handle, LONG exit_code )
{
    __ASM_SYSCALL_FUNC( __id_NtTerminateThread );
}

NTSTATUS SYSCALL_API NtTestAlert(void)
{
    __ASM_SYSCALL_FUNC( __id_NtTestAlert );
}

NTSTATUS SYSCALL_API NtTraceControl( ULONG code, void *inbuf, ULONG inbuf_len,
                                     void *outbuf, ULONG outbuf_len, ULONG *size )
{
    __ASM_SYSCALL_FUNC( __id_NtTraceControl );
}

NTSTATUS SYSCALL_API NtUnloadDriver( const UNICODE_STRING *name )
{
    __ASM_SYSCALL_FUNC( __id_NtUnloadDriver );
}

NTSTATUS SYSCALL_API NtUnloadKey( OBJECT_ATTRIBUTES *attr )
{
    __ASM_SYSCALL_FUNC( __id_NtUnloadKey );
}

NTSTATUS SYSCALL_API NtUnlockFile( HANDLE handle, IO_STATUS_BLOCK *io_status, LARGE_INTEGER *offset,
                                   LARGE_INTEGER *count, ULONG *key )
{
    __ASM_SYSCALL_FUNC( __id_NtUnlockFile );
}

NTSTATUS SYSCALL_API NtUnlockVirtualMemory( HANDLE process, PVOID *addr, SIZE_T *size, ULONG unknown )
{
    __ASM_SYSCALL_FUNC( __id_NtUnlockVirtualMemory );
}

NTSTATUS SYSCALL_API NtUnmapViewOfSection( HANDLE process, PVOID addr )
{
    __ASM_SYSCALL_FUNC( __id_NtUnmapViewOfSection );
}

NTSTATUS SYSCALL_API NtUnmapViewOfSectionEx( HANDLE process, PVOID addr, ULONG flags )
{
    __ASM_SYSCALL_FUNC( __id_NtUnmapViewOfSectionEx );
}

NTSTATUS SYSCALL_API NtWaitForAlertByThreadId( const void *address, const LARGE_INTEGER *timeout )
{
    __ASM_SYSCALL_FUNC( __id_NtWaitForAlertByThreadId );
}

NTSTATUS SYSCALL_API NtWaitForDebugEvent( HANDLE handle, BOOLEAN alertable, LARGE_INTEGER *timeout,
                                          DBGUI_WAIT_STATE_CHANGE *state )
{
    __ASM_SYSCALL_FUNC( __id_NtWaitForDebugEvent );
}

NTSTATUS SYSCALL_API NtWaitForKeyedEvent( HANDLE handle, const void *key,
                                          BOOLEAN alertable, const LARGE_INTEGER *timeout )
{
    __ASM_SYSCALL_FUNC( __id_NtWaitForKeyedEvent );
}

NTSTATUS SYSCALL_API NtWaitForMultipleObjects( DWORD count, const HANDLE *handles, BOOLEAN wait_any,
                                               BOOLEAN alertable, const LARGE_INTEGER *timeout )
{
    __ASM_SYSCALL_FUNC( __id_NtWaitForMultipleObjects );
}

NTSTATUS SYSCALL_API NtWaitForSingleObject( HANDLE handle, BOOLEAN alertable, const LARGE_INTEGER *timeout )
{
    __ASM_SYSCALL_FUNC( __id_NtWaitForSingleObject );
}

NTSTATUS SYSCALL_API NtWriteFile( HANDLE handle, HANDLE event, PIO_APC_ROUTINE apc, void *apc_user,
                                  IO_STATUS_BLOCK *io, const void *buffer, ULONG length,
                                  LARGE_INTEGER *offset, ULONG *key )
{
    __ASM_SYSCALL_FUNC( __id_NtWriteFile );
}

NTSTATUS SYSCALL_API NtWriteFileGather( HANDLE file, HANDLE event, PIO_APC_ROUTINE apc, void *apc_user,
                                        IO_STATUS_BLOCK *io, FILE_SEGMENT_ELEMENT *segments,
                                        ULONG length, LARGE_INTEGER *offset, ULONG *key )
{
    __ASM_SYSCALL_FUNC( __id_NtWriteFileGather );
}

NTSTATUS SYSCALL_API NtWriteVirtualMemory( HANDLE process, void *addr, const void *buffer,
                                           SIZE_T size, SIZE_T *bytes_written )
{
    __ASM_SYSCALL_FUNC( __id_NtWriteVirtualMemory );
}

NTSTATUS SYSCALL_API NtYieldExecution(void)
{
    __ASM_SYSCALL_FUNC( __id_NtYieldExecution );
}

NTSTATUS SYSCALL_API wine_nt_to_unix_file_name( const OBJECT_ATTRIBUTES *attr, char *nameA, ULONG *size,
                                                UINT disposition )
{
    __ASM_SYSCALL_FUNC( __id_wine_nt_to_unix_file_name );
}

NTSTATUS SYSCALL_API wine_unix_to_nt_file_name( const char *name, WCHAR *buffer, ULONG *size )
{
    __ASM_SYSCALL_FUNC( __id_wine_unix_to_nt_file_name );
}


/*******************************************************************
 *		KiUserExceptionDispatcher (NTDLL.@)
 */
NTSTATUS WINAPI KiUserExceptionDispatcher( EXCEPTION_RECORD *rec, CONTEXT *context )
{
    FIXME( "not implemented\n" );
    return STATUS_INVALID_DISPOSITION;
}


/*******************************************************************
 *		KiUserApcDispatcher (NTDLL.@)
 */
void WINAPI KiUserApcDispatcher( CONTEXT *context, ULONG_PTR arg1, ULONG_PTR arg2, ULONG_PTR arg3,
                                 PNTAPCFUNC apc )
{
    FIXME( "not implemented\n" );
}


/*******************************************************************
 *		KiUserCallbackDispatcher (NTDLL.@)
 */
void WINAPI KiUserCallbackDispatcher( ULONG id, void *args, ULONG len )
{
    FIXME( "not implemented\n" );
}


/**************************************************************************
 *              RtlIsEcCode (NTDLL.@)
 */
BOOLEAN WINAPI RtlIsEcCode( const void *ptr )
{
    const UINT64 *map = (const UINT64 *)NtCurrentTeb()->Peb->EcCodeBitMap;
    ULONG_PTR page = (ULONG_PTR)ptr / page_size;
    return (map[page / 64] >> (page & 63)) & 1;
}


/***********************************************************************
 *		RtlCaptureContext (NTDLL.@)
 */
void WINAPI RtlCaptureContext( CONTEXT *context )
{
    FIXME( "not implemented\n" );
}


/*******************************************************************
 *              RtlRestoreContext (NTDLL.@)
 */
void CDECL RtlRestoreContext( CONTEXT *context, EXCEPTION_RECORD *rec )
{
    FIXME( "not implemented\n" );
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
}


/*******************************************************************
 *		RtlUnwindEx (NTDLL.@)
 */
void WINAPI RtlUnwindEx( PVOID end_frame, PVOID target_ip, EXCEPTION_RECORD *rec,
                         PVOID retval, CONTEXT *context, UNWIND_HISTORY_TABLE *table )
{
    FIXME( "not implemented\n" );
}


/*******************************************************************
 *		RtlUnwind (NTDLL.@)
 */
void WINAPI RtlUnwind( void *frame, void *target_ip, EXCEPTION_RECORD *rec, void *retval )
{
    FIXME( "not implemented\n" );
}


/*******************************************************************
 *		_local_unwind (NTDLL.@)
 */
void WINAPI _local_unwind( void *frame, void *target_ip )
{
    CONTEXT context;
    RtlUnwindEx( frame, target_ip, NULL, NULL, &context, NULL );
}


/*******************************************************************
 *		__C_specific_handler (NTDLL.@)
 */
EXCEPTION_DISPOSITION WINAPI __C_specific_handler( EXCEPTION_RECORD *rec,
                                                   void *frame,
                                                   CONTEXT *context,
                                                   struct _DISPATCHER_CONTEXT *dispatch )
{
    FIXME( "not implemented\n" );
    return ExceptionContinueSearch;
}


/*************************************************************************
 *		RtlCaptureStackBackTrace (NTDLL.@)
 */
USHORT WINAPI RtlCaptureStackBackTrace( ULONG skip, ULONG count, PVOID *buffer, ULONG *hash )
{
    FIXME( "not implemented\n" );
    return 0;
}


static int code_match( BYTE *code, const BYTE *seq, size_t len )
{
    for ( ; len; len--, code++, seq++) if (*seq && *code != *seq) return 0;
    return 1;
}

void *check_call( void **target, void *exit_thunk, void *dest )
{
    return NULL;
}

static void __attribute__((naked)) arm64x_check_call(void)
{

}


/**************************************************************************
 *		__chkstk (NTDLL.@)
 *
 * Supposed to touch all the stack pages, but we shouldn't need that.
 */
void __attribute__((naked)) __chkstk(void)
{
    asm( "ret" );
}


/**************************************************************************
 *		__chkstk_arm64ec (NTDLL.@)
 *
 * Supposed to touch all the stack pages, but we shouldn't need that.
 */
void __attribute__((naked)) __chkstk_arm64ec(void)
{
    asm( "ret" );
}


/***********************************************************************
 *		RtlRaiseException (NTDLL.@)
 */
void WINAPI RtlRaiseException( struct _EXCEPTION_RECORD * rec)
{
    FIXME( "not implemented\n" );
}


/***********************************************************************
 *           RtlUserThreadStart (NTDLL.@)
 */
void WINAPI RtlUserThreadStart( PRTL_THREAD_START_ROUTINE entry, void *arg )
{
    __TRY
    {
        pBaseThreadInitThunk( 0, (LPTHREAD_START_ROUTINE)entry, arg );
    }
    __EXCEPT(call_unhandled_exception_filter)
    {
        NtTerminateProcess( GetCurrentProcess(), GetExceptionCode() );
    }
    __ENDTRY
}


/******************************************************************
 *		LdrInitializeThunk (NTDLL.@)
 */
void WINAPI LdrInitializeThunk( CONTEXT *context, ULONG_PTR unk2, ULONG_PTR unk3, ULONG_PTR unk4 )
{
    FIXME( "not implemented\n" );
    NtContinue( context, TRUE );
}


/**********************************************************************
 *              DbgBreakPoint   (NTDLL.@)
 */
// void __attribute__((naked)) DbgBreakPoint(void)
// {
//     asm( "break 0\t\n ret" );
// }


/**********************************************************************
 *              DbgUserBreakPoint   (NTDLL.@)
 */
void __attribute__((naked)) DbgUserBreakPoint(void)
{
    asm( "break 0\t\n ret" );
}
#endif  /* __loongarch_lp64 */
