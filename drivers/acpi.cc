/*
 * Copyright (C) 2013 Cloudius Systems, Ltd.
 *
 * This work is open source software, licensed under the terms of the
 * BSD license as described in the LICENSE file in the top-level directory.
 */

#include <map>
#include <memory>

extern "C" {
    #include "acpi.h"
    #include "acpiosxf.h"
    #include "acpixf.h"
}
#include <stdlib.h>
#include <osv/mmu.hh>
#include <osv/sched.hh>
#include "processor.hh"
#include <osv/align.hh>
#include "xen.hh"

#include <osv/debug.h>
#include <osv/mutex.h>
#include <osv/semaphore.hh>

#include "drivers/console.hh"
#include "drivers/pci.hh"
#include <osv/interrupt.hh>

#include <osv/prio.hh>

#define acpi_tag "acpi"
#define acpi_d(...)   tprintf_d(acpi_tag, __VA_ARGS__)
#define acpi_i(...)   tprintf_i(acpi_tag, __VA_ARGS__)
#define acpi_w(...)   tprintf_w(acpi_tag, __VA_ARGS__)
#define acpi_e(...)   tprintf_e(acpi_tag, __VA_ARGS__)

ACPI_STATUS AcpiOsInitialize()
{
    return AE_OK;
}

ACPI_STATUS AcpiOsTerminate()
{
    return AE_OK;
}

ACPI_PHYSICAL_ADDRESS AcpiOsGetRootPointer()
{
    ACPI_SIZE rsdp;
    auto st = AcpiFindRootPointer(&rsdp);
    if (ACPI_FAILURE(st)) {
        abort();
    }
    return rsdp;
}

ACPI_STATUS AcpiOsPredefinedOverride(const ACPI_PREDEFINED_NAMES *InitVal,
        ACPI_STRING *NewVal)
{
    *NewVal = nullptr;
    return AE_OK;
}

ACPI_STATUS AcpiOsTableOverride(ACPI_TABLE_HEADER *ExistingTable,
        ACPI_TABLE_HEADER **NewTable)
{
    *NewTable = nullptr;
    return AE_OK;
}

ACPI_STATUS AcpiOsPhysicalTableOverride(ACPI_TABLE_HEADER *ExistingTable,
    ACPI_PHYSICAL_ADDRESS *NewAddress, UINT32 *NewTableLength)
{
    *NewAddress = 0;
    *NewTableLength = 0;
    return AE_OK;
}

// Note: AcpiOsCreateLock requires a lock which can be used for mutual
// exclusion of a resources between multiple threads *AND* interrupt handlers.
// Normally, this requires a spinlock (which disables interrupts), to ensure
// that while a thread is using the protected resource, an interrupt handler
// with the same context as the thread doesn't use it.
// However, in OSV, interrupt handlers are run in ordinary threads, so the
// mutual exclusion of an ordinary "mutex" is enough.
ACPI_STATUS AcpiOsCreateLock(ACPI_SPINLOCK *OutHandle)
{
    *OutHandle = new mutex();
    return AE_OK;
}

ACPI_CPU_FLAGS AcpiOsAcquireLock(ACPI_SPINLOCK Handle)
{
    reinterpret_cast<mutex *>(Handle) -> lock();
    return 0;
}

void AcpiOsReleaseLock(ACPI_SPINLOCK Handle, ACPI_CPU_FLAGS Flags)
{
    reinterpret_cast<mutex *>(Handle) -> unlock();;
}

void AcpiOsDeleteLock(ACPI_SPINLOCK Handle)
{
    delete reinterpret_cast<mutex *>(Handle);
}

ACPI_STATUS AcpiOsCreateSemaphore(UINT32 MaxUnits,
        UINT32 InitialUnits, ACPI_SEMAPHORE *OutHandle)
{
    // Note: we ignore MaxUnits.
    *OutHandle = new semaphore(InitialUnits);
    return AE_OK;
}

ACPI_STATUS AcpiOsDeleteSemaphore(ACPI_SEMAPHORE Handle)
{
    if (!Handle)
        return AE_BAD_PARAMETER;
    delete reinterpret_cast<semaphore *>(Handle);
    return AE_OK;
}

ACPI_STATUS AcpiOsWaitSemaphore(ACPI_SEMAPHORE Handle,
        UINT32 Units, UINT16 Timeout)
{
    if (!Handle)
        return AE_BAD_PARAMETER;
    semaphore *sem = reinterpret_cast<semaphore *>(Handle);
    switch(Timeout) {
    case ACPI_DO_NOT_WAIT:
        return sem->trywait(Units) ? AE_OK : AE_TIME;
    case ACPI_WAIT_FOREVER:
        sem->wait(Units);
        return AE_OK;
    default:
        sched::timer timer(*sched::thread::current());
        timer.set(std::chrono::milliseconds(Timeout));
        return sem->wait(Units, &timer) ? AE_OK : AE_TIME;
    }
}

ACPI_STATUS AcpiOsSignalSemaphore(ACPI_SEMAPHORE Handle, UINT32 Units)
{
    if (!Handle)
        return AE_BAD_PARAMETER;
    semaphore *sem = reinterpret_cast<semaphore *>(Handle);
    sem->post(Units);
    return AE_OK;
}

void *AcpiOsAllocate(ACPI_SIZE Size)
{
    return malloc(Size);
}

void AcpiOsFree(void *Memory)
{
    free(Memory);
}

void *AcpiOsMapMemory(ACPI_PHYSICAL_ADDRESS Where, ACPI_SIZE Length)
{
    uint64_t _where = align_down(Where, mmu::huge_page_size);
    size_t map_size = align_up(Length + Where - _where, mmu::huge_page_size);
    
    mmu::linear_map(mmu::phys_to_virt(_where), _where, map_size);
    return mmu::phys_to_virt(Where);
}

void AcpiOsUnmapMemory(void *LogicalAddress, ACPI_SIZE Size)
{
    // Unmap is a no-op and leaves the mapppings in place because the amount of
    // mapped ACPI memory is limited, and we don't track whether what it maps
    // was previously mapped (so unmap can poke a hole where a previous mapping
    // existed, even before ACPI).
}

ACPI_STATUS AcpiOsGetPhysicalAddress(void *LogicalAddress,
        ACPI_PHYSICAL_ADDRESS *PhysicalAddress)
{
    *PhysicalAddress = mmu::virt_to_phys(LogicalAddress);
    return AE_OK;
}

#if 0
ACPI_STATUS AcpiOsCreateCache (
    char                    *CacheName,
    UINT16                  ObjectSize,
    UINT16                  MaxDepth,
    ACPI_CACHE_T            **ReturnCache);

ACPI_STATUS
AcpiOsDeleteCache (
    ACPI_CACHE_T            *Cache);

ACPI_STATUS
AcpiOsPurgeCache (
    ACPI_CACHE_T            *Cache);

void *
AcpiOsAcquireObject (
    ACPI_CACHE_T            *Cache);

ACPI_STATUS
AcpiOsReleaseObject (
    ACPI_CACHE_T            *Cache,
    void                    *Object);

#endif

/*
 * Interrupt handlers
 */

namespace osv {
    std::map<UINT32, std::unique_ptr<gsi_edge_interrupt>> acpi_interrupts;
}

ACPI_STATUS
AcpiOsInstallInterruptHandler(
    UINT32                  InterruptNumber,
    ACPI_OSD_HANDLER        ServiceRoutine,
    void                    *Context)
{
    if (ServiceRoutine == nullptr) {
        return AE_BAD_PARAMETER;
    }

    if (osv::acpi_interrupts.count(InterruptNumber)) {
        return AE_ALREADY_EXISTS;
    }

    osv::acpi_interrupts[InterruptNumber] = std::unique_ptr<gsi_edge_interrupt>(
        new gsi_edge_interrupt(InterruptNumber,
                               [=] { ServiceRoutine(Context); }));

    return AE_OK;
}

ACPI_STATUS
AcpiOsRemoveInterruptHandler(
    UINT32                  InterruptNumber,
    ACPI_OSD_HANDLER        ServiceRoutine)
{
    if (ServiceRoutine == nullptr) {
        return AE_BAD_PARAMETER;
    }

    if (!osv::acpi_interrupts.count(InterruptNumber)) {
        return AE_NOT_EXIST;
    }

    osv::acpi_interrupts.erase(InterruptNumber);
    return AE_OK;
}

ACPI_THREAD_ID AcpiOsGetThreadId()
{
    return reinterpret_cast<uintptr_t>(sched::thread::current());
}

ACPI_STATUS AcpiOsExecute(
    ACPI_EXECUTE_TYPE       Type,
    ACPI_OSD_EXEC_CALLBACK  Function,
    void                    *Context)
{
    return AE_NOT_IMPLEMENTED;
}

void AcpiOsWaitEventsComplete()
{
    // FIXME: ?
}

void AcpiOsSleep(UINT64 Milliseconds)
{
    sched::thread::sleep(std::chrono::milliseconds(Milliseconds));
}

void AcpiOsStall(UINT32 Microseconds)
{
    // spec says to spin, but...
    sched::thread::sleep(std::chrono::microseconds(Microseconds));
}

ACPI_STATUS AcpiOsReadPort(
    ACPI_IO_ADDRESS         Address,
    UINT32                  *Value,
    UINT32                  Width)
{
    switch (Width) {
    case 8:
        *Value = processor::inb(Address);
        break;
    case 16:
        *Value = processor::inw(Address);
        break;
    case 32:
        *Value = processor::inl(Address);
        break;
    default:
        return AE_BAD_PARAMETER;
    }
    return AE_OK;
}

ACPI_STATUS AcpiOsWritePort(
    ACPI_IO_ADDRESS         Address,
    UINT32                  Value,
    UINT32                  Width)
{
    switch (Width) {
    case 8:
        processor::outb(Value, Address);
        break;
    case 16:
        processor::outw(Value, Address);
        break;
    case 32:
        processor::outl(Value, Address);
        break;
    default:
        return AE_BAD_PARAMETER;
    }
    return AE_OK;
}


ACPI_STATUS
AcpiOsReadMemory (
    ACPI_PHYSICAL_ADDRESS   Address,
    UINT64                  *Value,
    UINT32                  Width)
{
    switch (Width) {
    case 8:
        *Value = *mmu::phys_cast<u8>(Address);
        break;
    case 16:
        *Value = *mmu::phys_cast<u16>(Address);
        break;
    case 32:
        *Value = *mmu::phys_cast<u32>(Address);
        break;
    case 64:
        *Value = *mmu::phys_cast<u64>(Address);
        break;
    default:
        return AE_BAD_PARAMETER;
    }
    return AE_OK;
}

ACPI_STATUS
AcpiOsWriteMemory (
    ACPI_PHYSICAL_ADDRESS   Address,
    UINT64                  Value,
    UINT32                  Width)
{
    switch (Width) {
    case 8:
        *mmu::phys_cast<u8>(Address) = Value;
        break;
    case 16:
        *mmu::phys_cast<u16>(Address) = Value;
        break;
    case 32:
        *mmu::phys_cast<u32>(Address) = Value;
        break;
    case 64:
        *mmu::phys_cast<u64>(Address) = Value;
        break;
    default:
        return AE_BAD_PARAMETER;
    }
    return AE_OK;
}

ACPI_STATUS
AcpiOsReadPciConfiguration(
    ACPI_PCI_ID             *PciId,
    UINT32                  Reg,
    UINT64                  *Value,
    UINT32                  Width)
{
    switch(Width) {
    case 64:
        // OSv pci config functions does not do 64 bits reads
        return AE_NOT_IMPLEMENTED;
        break;
    case 32:
        *Value = pci::read_pci_config(PciId->Bus,
                                      PciId->Device,
                                      PciId->Function,
                                      Reg);
        break;
    case 16:
        *Value = pci::read_pci_config_word(PciId->Bus,
                                           PciId->Device,
                                           PciId->Function,
                                           Reg);
        break;
    case 8:
        *Value = pci::read_pci_config_byte(PciId->Bus,
                                           PciId->Device,
                                           PciId->Function,
                                           Reg);
        break;
    default:
        return AE_BAD_PARAMETER;
    }
    return AE_OK;
}

ACPI_STATUS
AcpiOsWritePciConfiguration (
    ACPI_PCI_ID             *PciId,
    UINT32                  Reg,
    UINT64                  Value,
    UINT32                  Width)
{
    switch(Width) {
    case 64:
        // OSv pci config functions does not do 64 bits writes
        return AE_NOT_IMPLEMENTED;
        break;
    case 32:
        pci::write_pci_config(PciId->Bus,
                              PciId->Device,
                              PciId->Function,
                              Reg,
                              Value);
        break;
    case 16:
        pci::write_pci_config_word(PciId->Bus,
                                   PciId->Device,
                                   PciId->Function,
                                   Reg,
                                   Value);
        break;
    case 8:
        pci::write_pci_config_byte(PciId->Bus,
                                   PciId->Device,
                                   PciId->Function,
                                   Reg,
                                   Value);
        break;
    default:
        return AE_BAD_PARAMETER;
    }
    return AE_OK;
}

BOOLEAN
AcpiOsReadable(void *Pointer, ACPI_SIZE Length)
{
    return mmu::isreadable(Pointer, Length);
}

BOOLEAN
AcpiOsWritable(void *Pointer, ACPI_SIZE Length)
{
    return true;
}

UINT64 AcpiOsGetTimer()
{
    return clock::get()->time() / 100;
}

ACPI_STATUS AcpiOsSignal(UINT32 Function, void *Info)
{
    abort();
}

void ACPI_INTERNAL_VAR_XFACE AcpiOsPrintf(const char *Format, ...)
{
    va_list va;
    va_start(va, Format);
    AcpiOsVprintf(Format, va);
    va_end(va);
}

void AcpiOsVprintf(const char *Format, va_list Args)
{
    static char msg[1024];

    vsnprintf(msg, sizeof(msg), Format, Args);

    acpi_i(msg);
}

namespace acpi {

#define ACPI_MAX_INIT_TABLES 16

static ACPI_TABLE_DESC TableArray[ACPI_MAX_INIT_TABLES];

void early_init()
{
    ACPI_STATUS status;

    status = AcpiInitializeTables(TableArray, ACPI_MAX_INIT_TABLES, TRUE);
    if (ACPI_FAILURE(status)) {
        acpi_e("AcpiInitializeTables failed: %s\n", AcpiFormatException(status));
        return;
    }

    // Initialize ACPICA subsystem
    status = AcpiInitializeSubsystem();
    if (ACPI_FAILURE(status)) {
        acpi_e("AcpiInitializeSubsystem failed: %s\n", AcpiFormatException(status));
        return;
    }

    // Copy the root table list to dynamic memory
    status = AcpiReallocateRootTable();
    if (ACPI_FAILURE(status)) {
        acpi_e("AcpiReallocateRootTable failed: %s\n", AcpiFormatException(status));
        return;
    }

    // Create the ACPI namespace from ACPI tables
    status = AcpiLoadTables();
    if (ACPI_FAILURE(status)) {
        acpi_e("AcpiLoadTables failed: %s\n", AcpiFormatException(status));
        return;
    }
}

// must be called after the scheduler, apic and smp where started to run
// The following function comes from the documentation example page 262
void init()
{
    ACPI_STATUS status;


    // TODO: Installation of Local handlers

    // Initialize the ACPI hardware
    status = AcpiEnableSubsystem(ACPI_FULL_INITIALIZATION);
    if (ACPI_FAILURE(status)) {
        acpi_e("AcpiEnableSubsystem failed: %s\n", AcpiFormatException(status));
        return;
    }

    // Complete the ACPI namespace object initialization
    status = AcpiInitializeObjects(ACPI_FULL_INITIALIZATION);
    if (ACPI_FAILURE(status)) {
        acpi_e("AcpiInitializeObjects failed: %s\n", AcpiFormatException(status));
    }
}

}

void __attribute__((constructor(init_prio::acpi))) acpi_init_early()
{
     XENPV_ALTERNATIVE({ acpi::early_init(); }, {});
}
