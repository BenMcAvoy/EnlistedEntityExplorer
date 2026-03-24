// EnlistedEntityExplorer - Dagor ECS entity reader for enlisted.exe singleplayer
//
// All offsets reverse-engineered via AiDA static analysis.
// IDA image base: 0x140000000
//
// Confirmed via decompilation of sub_1429BB830 (entity lookup), sub_143946160 (query init):
//   - EntDesc layout, EntityId format, template name chain
//   - Component descriptor for get_entity_transform_ecs_query

#define NOMINMAX
#include <windows.h>
#include <tlhelp32.h>
#include <stdio.h>
#include <stdint.h>
#include <vector>
#include <string>
#include <algorithm>

// ============================================================
// Static RVAs (confirmed via IDA, add to runtime module base)
// ============================================================

// Entity descriptor array (QWORD ptr -> EntDesc[], 8 bytes/slot)
static constexpr uintptr_t RVA_ENT_DESCS_PTR   = 0x604BC68;
// Entity count (live slot count)
static constexpr uintptr_t RVA_ENT_COUNT        = 0x604BC70;
// Entity capacity (total allocated slots)
static constexpr uintptr_t RVA_ENT_CAPACITY     = 0x604BC88;
// Archetype -> template index map (QWORD ptr -> uint32[archCount])
static constexpr uintptr_t RVA_ARCH_TEMPL_MAP   = 0x604BF98;
// Archetype count
static constexpr uintptr_t RVA_ARCH_COUNT       = 0x604BFA0;
// Template array (QWORD ptr -> TemplateInfo[], 88 bytes/entry, name char* at +32)
static constexpr uintptr_t RVA_TEMPL_ARRAY_PTR  = 0x604C3F0;
// Template count
static constexpr uintptr_t RVA_TEMPL_COUNT      = 0x604C3F8;
// EntityManager alive flag (BYTE, 1 = initialised)
static constexpr uintptr_t RVA_EM_ALIVE         = 0x604C5A8;

// ---------------------------------------------------------------
// Archetype array (TODO: confirm global address via AiDA)
// Candidates near 0x14604BC68 in .data; need read of globals in
// range 0x14604BC8C .. 0x14604BF98 to identify archetype ptr.
// Once found, replace the placeholder below:
// ---------------------------------------------------------------
static constexpr uintptr_t RVA_ARCH_ARRAY_PTR   = 0x0; // <-- FILL IN

// ============================================================
// Dagor ECS layout constants (confirmed / estimated)
// ============================================================

// EntDesc: 8 bytes per slot
//   [0]     rowLo       - row index in archetype, bits  0-7
//   [1]     rowMid      - row index in archetype, bits  8-15
//   [2]     rowHi       - row index in archetype, bits 16-23
//   [3]     generation  - must match EntityId bits [29:22]
//   [4-5]   archetypeId - 0xFFFF means free / dead slot
//   [6-7]   pad
#pragma pack(push,1)
struct EntDesc {
    uint8_t  rowLo, rowMid, rowHi;
    uint8_t  generation;
    uint16_t archetypeId;
    uint16_t pad;
};
#pragma pack(pop)
static_assert(sizeof(EntDesc) == 8, "EntDesc size mismatch");

static constexpr uint16_t ARCHETYPE_INVALID = 0xFFFF;

inline uint32_t eid_slot(uint32_t eid)       { return eid & 0x3FFFFFu; }
inline uint8_t  eid_gen (uint32_t eid)       { return (uint8_t)(eid >> 22); }
inline uint32_t entdesc_row(const EntDesc& d){ return d.rowLo | (d.rowMid << 8) | (d.rowHi << 16); }

// Template entry: 88 bytes, char* name at +32
static constexpr size_t TEMPLATE_ENTRY_BYTES  = 88;
static constexpr size_t TEMPLATE_NAME_OFFSET  = 32;

// Transform component: 4x3 float matrix (TMatrix / mat43f)
//   col0 = right (x-axis), col1 = up (y-axis), col2 = fwd (z-axis), col3 = position
//   Stored column-major: float[4][3] = 48 bytes
//   Position = float[3] at offset 36 (col3)
static constexpr uint64_t COMP_HASH_TRANSFORM = 0x1f886eb0b1857e72ULL;
static constexpr size_t   TRANSFORM_SIZE       = 48;
static constexpr size_t   TRANSFORM_POS_OFFSET = 36; // byte offset of translation column

// ============================================================
// Archetype struct layout (estimated from Dagor ECS source)
// Needs confirmation via AiDA once archetype array ptr is known
// ============================================================

// Each Archetype object layout (approximate, must verify offsets):
//   +0x00  uint32  componentCount
//   +0x04  uint32  chunkCapacity  (entities per chunk)
//   +0x08  QWORD   ptr -> ComponentInfo[]
//   +0x10  uint32  compInfoCount
//   +0x18  QWORD   ptr -> QWORD[] chunk pointers
//   +0x20  uint32  chunkCount
//
// ComponentInfo (per component in archetype, sorted by hash):
//   +0x00  uint64  hash       (ECS component hash)
//   +0x08  uint32  offset     (byte offset within chunk row)
//   +0x0C  uint16  size       (bytes)
//   +0x0E  uint16  flags
//   -> total: 16 bytes
//
// Chunk data (one blob per chunk):
//   SoA per chunk: components stored as columns
//   component column for comp_i: chunk_base + comp_i.offset
//   element for entity j within chunk: col_base + j * comp_i.size

static constexpr size_t ARCH_OFF_COMP_COUNT  = 0x00;
static constexpr size_t ARCH_OFF_CHUNK_CAP   = 0x04;
static constexpr size_t ARCH_OFF_COMP_PTR    = 0x08;
static constexpr size_t ARCH_OFF_CHUNKS_PTR  = 0x18;
static constexpr size_t ARCH_OFF_CHUNK_COUNT = 0x20;
static constexpr size_t COMP_INFO_SIZE       = 16;
static constexpr size_t COMP_INFO_OFF_HASH   = 0;
static constexpr size_t COMP_INFO_OFF_OFFSET = 8;
static constexpr size_t COMP_INFO_OFF_SIZE   = 12;

// ============================================================
// ReadProcessMemory helpers
// ============================================================
static HANDLE g_hProc = nullptr;

template<typename T>
bool R(uintptr_t addr, T& out) {
    return ReadProcessMemory(g_hProc, (LPCVOID)addr, &out, sizeof(T), nullptr) != 0;
}
bool Rbuf(uintptr_t addr, void* dst, size_t n) {
    SIZE_T got = 0;
    return ReadProcessMemory(g_hProc, (LPCVOID)addr, dst, n, &got) && got == n;
}
std::string Rstr(uintptr_t addr, size_t maxLen = 128) {
    if (!addr) return "(null)";
    char buf[256]{};
    ReadProcessMemory(g_hProc, (LPCVOID)addr, buf, std::min(maxLen, sizeof(buf)-1), nullptr);
    return buf;
}

// ============================================================
// Process/module helpers
// ============================================================
DWORD FindPID(const char* exe) {
    wchar_t wExe[256]{};
    MultiByteToWideChar(CP_ACP, 0, exe, -1, wExe, 256);
    HANDLE snap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    PROCESSENTRY32 pe{sizeof(pe)};
    DWORD pid = 0;
    if (Process32First(snap, &pe)) do {
        if (_wcsicmp(pe.szExeFile, wExe) == 0) { pid = pe.th32ProcessID; break; }
    } while (Process32Next(snap, &pe));
    CloseHandle(snap);
    return pid;
}

uintptr_t ModBase(DWORD pid, const char* mod) {
    wchar_t wMod[256]{};
    MultiByteToWideChar(CP_ACP, 0, mod, -1, wMod, 256);
    HANDLE snap = CreateToolhelp32Snapshot(TH32CS_SNAPMODULE|TH32CS_SNAPMODULE32, pid);
    MODULEENTRY32 me{sizeof(me)};
    uintptr_t base = 0;
    if (Module32First(snap, &me)) do {
        if (_wcsicmp(me.szModule, wMod) == 0) { base = (uintptr_t)me.modBaseAddr; break; }
    } while (Module32Next(snap, &me));
    CloseHandle(snap);
    return base;
}

// ============================================================
// Template name lookup
// ============================================================
std::string GetTemplateName(uintptr_t archTemplMap, uint32_t archCount,
                             uintptr_t templArray,   uint32_t templCount,
                             uint16_t archId)
{
    if (archId == ARCHETYPE_INVALID || archId >= archCount) return "<dead>";
    uint32_t tIdx = 0;
    if (!R(archTemplMap + archId * 4u, tIdx)) return "<rpm>";
    if (tIdx >= templCount) return "<badtempl>";
    uint64_t namePtr = 0;
    if (!R(templArray + tIdx * TEMPLATE_ENTRY_BYTES + TEMPLATE_NAME_OFFSET, namePtr)) return "<rpm>";
    return Rstr((uintptr_t)namePtr);
}

// ============================================================
// Transform lookup (requires RVA_ARCH_ARRAY_PTR to be set)
// ============================================================
bool GetTransformPos(uintptr_t archArray, uint16_t archId, uint32_t rowIdx,
                     float& ox, float& oy, float& oz)
{
    ox = oy = oz = 0.f;
    if (!archArray) return false;           // RVA not set yet

    // Read archetype object pointer from archetype array
    // (actual element size of archArray array entries needs verification)
    uint64_t archPtr = 0;
    if (!R(archArray + archId * sizeof(uint64_t), archPtr) || !archPtr) return false;

    // Read component info array
    uint64_t compInfoPtr = 0;
    uint32_t compCount   = 0;
    if (!R(archPtr + ARCH_OFF_COMP_PTR,   compInfoPtr)) return false;
    if (!R(archPtr + ARCH_OFF_COMP_COUNT, compCount))   return false;

    // Binary search for transform component by hash (components sorted by hash)
    uint32_t transformOffset = 0;
    uint32_t transformSize   = 0;
    bool     found = false;
    {
        int lo = 0, hi = (int)compCount - 1;
        while (lo <= hi) {
            int mid = (lo + hi) / 2;
            uintptr_t entry = (uintptr_t)compInfoPtr + mid * COMP_INFO_SIZE;
            uint64_t hash = 0;
            if (!R(entry + COMP_INFO_OFF_HASH, hash)) break;
            if (hash == COMP_HASH_TRANSFORM) {
                R(entry + COMP_INFO_OFF_OFFSET, transformOffset);
                uint16_t sz = 0;
                R(entry + COMP_INFO_OFF_SIZE, sz);
                transformSize = sz;
                found = true;
                break;
            }
            if (hash < COMP_HASH_TRANSFORM) lo = mid + 1;
            else                             hi = mid - 1;
        }
    }
    if (!found) return false;

    // Read chunk size and chunk array
    uint32_t chunkCap = 0;
    uint64_t chunksPtr = 0;
    if (!R(archPtr + ARCH_OFF_CHUNK_CAP,  chunkCap))  return false;
    if (!R(archPtr + ARCH_OFF_CHUNKS_PTR, chunksPtr)) return false;
    if (!chunkCap || !chunksPtr) return false;

    uint32_t chunkIdx     = rowIdx / chunkCap;
    uint32_t idxInChunk   = rowIdx % chunkCap;

    uint64_t chunkData = 0;
    if (!R(chunksPtr + chunkIdx * sizeof(uint64_t), chunkData) || !chunkData) return false;

    // Component column in chunk (SoA): col_base + idxInChunk * compSize
    uintptr_t colBase = (uintptr_t)chunkData + transformOffset;
    uintptr_t elemAddr = colBase + idxInChunk * transformSize;

    // TMatrix position is last column (bytes 36-47 of 48-byte TMatrix)
    struct Vec3 { float x, y, z; };
    Vec3 pos{};
    if (!R(elemAddr + TRANSFORM_POS_OFFSET, pos)) return false;

    ox = pos.x; oy = pos.y; oz = pos.z;
    return true;
}

// ============================================================
// main
// ============================================================
int main() {
    printf("=== Enlisted Entity Explorer ===\n\n");

    DWORD pid = FindPID("enlisted.exe");
    if (!pid) { printf("[!] enlisted.exe not running.\n"); return 1; }
    printf("[+] PID: %lu\n", pid);

    g_hProc = OpenProcess(PROCESS_VM_READ | PROCESS_QUERY_INFORMATION, FALSE, pid);
    if (!g_hProc) { printf("[!] OpenProcess failed: %lu\n", GetLastError()); return 1; }

    uintptr_t base = ModBase(pid, "enlisted.exe");
    if (!base) { printf("[!] Module base not found.\n"); return 1; }
    printf("[+] Module base: 0x%llX\n\n", (unsigned long long)base);

    // Check entity manager alive
    uint8_t emAlive = 0;
    R(base + RVA_EM_ALIVE, emAlive);
    if (!emAlive) {
        printf("[!] EntityManager not alive (flag=0). Load a mission first.\n");
        return 1;
    }

    // Read global pointers and counts
    uint64_t entDescsPtr = 0; uint32_t entCount = 0, entCap = 0;
    uint64_t archTemplMap= 0; uint32_t archCount = 0;
    uint64_t templArrayP = 0; uint32_t templCount= 0;
    uint64_t archArrayP  = 0;

    R(base + RVA_ENT_DESCS_PTR,  entDescsPtr);
    R(base + RVA_ENT_COUNT,      entCount);
    R(base + RVA_ENT_CAPACITY,   entCap);
    R(base + RVA_ARCH_TEMPL_MAP, archTemplMap);
    R(base + RVA_ARCH_COUNT,     archCount);
    R(base + RVA_TEMPL_ARRAY_PTR,templArrayP);
    R(base + RVA_TEMPL_COUNT,    templCount);
    if (RVA_ARCH_ARRAY_PTR) R(base + RVA_ARCH_ARRAY_PTR, archArrayP);

    printf("[+] EntDescs ptr:   0x%llX\n", (unsigned long long)entDescsPtr);
    printf("[+] Slots:          %u live / %u total\n", entCount, entCap);
    printf("[+] Archetypes:     %u\n", archCount);
    printf("[+] Templates:      %u\n", templCount);
    if (!RVA_ARCH_ARRAY_PTR)
        printf("[~] Archetype array RVA not set -- positions will show 0,0,0\n");
    printf("\n");

    if (!entDescsPtr || entCap == 0) {
        printf("[!] EntDescs array is null.\n"); return 1;
    }

    // Read all entity descriptors in one RPM call
    std::vector<EntDesc> descs(entCap);
    if (!Rbuf((uintptr_t)entDescsPtr, descs.data(), entCap * sizeof(EntDesc))) {
        printf("[!] Failed to read EntDesc array.\n"); return 1;
    }

    // Enumerate live entities
    printf("%-8s  %-6s  %-5s  %-8s  %-12s  %-12s  %-12s  %s\n",
           "Slot", "EID", "Arch", "Row", "X", "Y", "Z", "Template");
    printf("%s\n", std::string(100, '-').c_str());

    uint32_t printed = 0;
    for (uint32_t slot = 0; slot < entCap; ++slot) {
        const EntDesc& d = descs[slot];
        if (d.archetypeId == ARCHETYPE_INVALID) continue;
        if (d.archetypeId >= archCount)         continue;

        uint32_t row = entdesc_row(d);
        uint32_t eid = slot | ((uint32_t)d.generation << 22);

        std::string name = GetTemplateName(
            (uintptr_t)archTemplMap, archCount,
            (uintptr_t)templArrayP,  templCount,
            d.archetypeId);

        float x = 0, y = 0, z = 0;
        GetTransformPos((uintptr_t)archArrayP, d.archetypeId, row, x, y, z);

        printf("%-8u  %6u  %5u  %8u  %12.3f  %12.3f  %12.3f  %s\n",
               slot, eid, (unsigned)d.archetypeId, row, x, y, z, name.c_str());
        ++printed;
    }

    printf("\n[+] %u entities printed.\n", printed);

    if (!RVA_ARCH_ARRAY_PTR) {
        printf("\n[TODO] To enable positions:\n");
        printf("  1. Re-run AiDA and read globals between RVA 0x604BC8C and 0x604BF98\n");
        printf("     to find the archetype array pointer global.\n");
        printf("  2. Set RVA_ARCH_ARRAY_PTR to that value.\n");
        printf("  3. Verify ARCH_OFF_* constants by decompiling a small archetype accessor.\n");
        printf("  4. Transform component hash: 0x%016llX\n",
               (unsigned long long)COMP_HASH_TRANSFORM);
    }

    CloseHandle(g_hProc);
    return 0;
}
