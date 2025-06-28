#pragma once

#include "general.h"
#include "afd_exploit.h"
#include <stdint.h>

// Forward declarations to avoid header conflicts
typedef struct _RTCoreMemoryAccess RTCoreMemoryAccess;
typedef struct _GameAssemblyAnalyzer GameAssemblyAnalyzer;
typedef struct _GameDecryption GameDecryption;
typedef struct _GameAssemblyExtractor GameAssemblyExtractor;

// ============================================================================
// GameAssembly Extractor with RTCore64 + Static Analysis Integration
// Combines RTCore64 kernel bypass with rust-auto-update analysis techniques
// ============================================================================

// Pattern signatures from rust-auto-update (proven working patterns)
extern const char* g_BaseNetworkablePattern;
extern const char* g_Il2CppGetHandlePattern;
extern const char* g_MainCameraPattern;
extern const char* g_EntityManagerPattern;
extern const char* g_LocalPlayerPattern;

// Extracted addresses and offsets (C-compatible structures)
typedef struct _BaseNetworkableOffsets {
    DWORD64 BaseNetworkable_C;
    DWORD64 static_fields;
    DWORD64 wrapper_class_ptr;
    DWORD64 parent_static_fields;
    DWORD64 entity;
} BaseNetworkableOffsets;

typedef struct _CameraOffsets {
    DWORD64 MainCamera_C;
    DWORD64 MainCamera_Chain1;
    DWORD64 MainCamera_Chain2;
    DWORD64 MainCamera_Chain3;
} CameraOffsets;

typedef struct _EntityOffsets {
    DWORD64 EntityList;
    DWORD64 EntityCount;
    DWORD64 PlayerModel;
    DWORD64 Position;
    DWORD64 Health;
    DWORD64 Name;
} EntityOffsets;

typedef struct _GameAssemblyOffsets {
    DWORD64 Il2cppHandle;
    BaseNetworkableOffsets BaseNetworkable;
    CameraOffsets Camera;
    EntityOffsets Entity;
} GameAssemblyOffsets;

// Global data structure for GameAssembly information
typedef struct _GameAssemblyData {
    DWORD64 GameAssemblyBase;
    SIZE_T GameAssemblySize;
    PBYTE LocalGameAssemblyBuffer; // Local copy for static analysis
    
    // Key addresses found by pattern scanning
    DWORD64 BaseNetworkable_Address;
    DWORD64 Il2CppGetHandle_Address;
    DWORD64 MainCamera_Address;
    DWORD64 EntityManager_Address;
    DWORD64 LocalPlayer_Address;
    
    // Extracted offsets
    GameAssemblyOffsets Offsets;
    
    // Decryption functions copied from GameAssembly
    DWORD64 BaseNetworkable_DecryptionFunc;
    DWORD64 BaseNetworkable_DecryptListFunc;
} GameAssemblyData;

// Global instance declaration
extern GameAssemblyData g_GameAssemblyData;

// Runtime memory access using RTCore64 kernel bypass
struct _RTCoreMemoryAccess {
    DWORD ProcessId;
    DWORD64 ProcessCR3;
};

// Function declarations for RTCoreMemoryAccess
BOOL RTCoreMemoryAccess_Initialize(RTCoreMemoryAccess* self, const char* processName);
BOOL RTCoreMemoryAccess_ReadVirtual(RTCoreMemoryAccess* self, DWORD64 virtualAddress, PVOID buffer, SIZE_T size);
BOOL RTCoreMemoryAccess_WriteVirtual(RTCoreMemoryAccess* self, DWORD64 virtualAddress, PVOID buffer, SIZE_T size);
DWORD64 RTCoreMemoryAccess_ReadUInt64(RTCoreMemoryAccess* self, DWORD64 virtualAddress);
DWORD RTCoreMemoryAccess_ReadUInt32(RTCoreMemoryAccess* self, DWORD64 virtualAddress);
DWORD64 RTCoreMemoryAccess_ReadChain(RTCoreMemoryAccess* self, DWORD64 baseAddress, DWORD64* offsets, SIZE_T offsetCount);

// Pattern scanning on extracted GameAssembly
struct _GameAssemblyAnalyzer {
    PBYTE GameAssemblyBuffer;
    SIZE_T GameAssemblySize;
    DWORD64 GameAssemblyBase;
};

// Function declarations for GameAssemblyAnalyzer
BOOL GameAssemblyAnalyzer_Initialize(GameAssemblyAnalyzer* self, PBYTE gameAssemblyBuffer, SIZE_T size, DWORD64 baseAddress);
DWORD64 GameAssemblyAnalyzer_PatternScan(GameAssemblyAnalyzer* self, const char* pattern, const char* sectionName);
BOOL GameAssemblyAnalyzer_ExtractBaseNetworkableOffsets(GameAssemblyAnalyzer* self);
BOOL GameAssemblyAnalyzer_ExtractIl2CppOffsets(GameAssemblyAnalyzer* self);
BOOL GameAssemblyAnalyzer_ExtractCameraOffsets(GameAssemblyAnalyzer* self);
BOOL GameAssemblyAnalyzer_ExtractEntityOffsets(GameAssemblyAnalyzer* self);
BOOL GameAssemblyAnalyzer_ExtractDecryptionFunctions(GameAssemblyAnalyzer* self);
DWORD64 GameAssemblyAnalyzer_ResolveRelativeAddress(GameAssemblyAnalyzer* self, DWORD64 instructionAddress, int operandIndex);
BOOL GameAssemblyAnalyzer_IsValidPEAddress(GameAssemblyAnalyzer* self, DWORD64 address);

// Decryption system for encrypted Rust game values
#define MAX_DECRYPTION_CONTEXTS 16
#define MAX_DECRYPTION_NAME_LEN 64

typedef struct _DecryptionContext {
    BOOL initialized;
    char name[MAX_DECRYPTION_NAME_LEN];
    PBYTE functionCode;
    SIZE_T functionSize;
    DWORD64 (*decryptFunction)(DWORD64);
} DecryptionContext;

struct _GameDecryption {
    DecryptionContext contexts[MAX_DECRYPTION_CONTEXTS];
    DWORD contextCount;
};

// Function declarations for GameDecryption
BOOL GameDecryption_Initialize(GameDecryption* self);
BOOL GameDecryption_InitializeDecryption(GameDecryption* self, const char* name, DWORD64 functionAddress);
DWORD64 GameDecryption_CallDecryption(GameDecryption* self, const char* name, DWORD64 encryptedValue);
VOID GameDecryption_Cleanup(GameDecryption* self);

// Main GameAssembly extraction and analysis system
struct _GameAssemblyExtractor {
    RTCoreMemoryAccess MemoryAccess;
    GameAssemblyAnalyzer Analyzer;
    GameDecryption Decryption;
    BOOL Initialized;
};

// Function declarations for GameAssemblyExtractor
GameAssemblyExtractor* GameAssemblyExtractor_Create(void);
VOID GameAssemblyExtractor_Destroy(GameAssemblyExtractor* self);
BOOL GameAssemblyExtractor_Initialize(GameAssemblyExtractor* self);
BOOL GameAssemblyExtractor_ExtractGameAssembly(GameAssemblyExtractor* self, const char* outputPath);
BOOL GameAssemblyExtractor_AnalyzeGameAssembly(GameAssemblyExtractor* self);
BOOL GameAssemblyExtractor_GetEntityList(GameAssemblyExtractor* self, DWORD64* entityListOut, DWORD64* entityCountOut);
BOOL GameAssemblyExtractor_GetLocalPlayer(GameAssemblyExtractor* self, DWORD64* localPlayerAddress);
BOOL GameAssemblyExtractor_GetPlayerPosition(GameAssemblyExtractor* self, DWORD64 playerAddress, float* x, float* y, float* z);
BOOL GameAssemblyExtractor_GetPlayerHealth(GameAssemblyExtractor* self, DWORD64 playerAddress, float* health);
DWORD64 GameAssemblyExtractor_Il2CppGetHandle(GameAssemblyExtractor* self, int32_t objectHandleID);
BOOL GameAssemblyExtractor_IsInitialized(GameAssemblyExtractor* self);
RTCoreMemoryAccess* GameAssemblyExtractor_GetMemoryAccess(GameAssemblyExtractor* self);

// ============================================================================
// Function Declarations
// ============================================================================

// Main entry point
BOOL InitializeGameAssemblyExtractor();
BOOL TestAdvancedGameAssemblyAccess();

// RTCore64 integration functions
BOOL ExtractGameAssemblyWithRTCore64(DWORD processId, DWORD64 baseAddress, const char* outputPath);
DWORD64 TranslateVirtualToPhysicalAdvanced(DWORD64 cr3, DWORD64 virtualAddr);
DWORD64 FindProcessCR3Advanced(DWORD processId);

// Static analysis functions
DWORD64 PatternScanGameAssembly(PBYTE buffer, SIZE_T size, const char* pattern);
BOOL ExtractAllGameOffsets(PBYTE gameAssemblyBuffer, SIZE_T size, DWORD64 baseAddress);

// Runtime access functions with decryption
DWORD64 ReadEncryptedValue(DWORD64 address, const char* decryptionKey);
BOOL GetLiveEntityData();

// Cleanup functions
VOID CleanupGameAssemblyExtractor();

// Global instance
extern GameAssemblyExtractor* g_GameAssemblyExtractor;

#define TEST_BIT(value, bit) (((value) & (1 << (bit))) != 0) 