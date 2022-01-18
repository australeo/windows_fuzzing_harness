#include <Windows.h>
#include <iostream>

//Max size of the shared memory region, note if the SHM_SIZE is larger than that specified by the
//process which created the shared memory, you will not be able to open it!
#define MAX_SIZE 10000
#define SHM_SIZE (MAX_SIZE + 0x4)

//Helper struct to wrap the fuzzer input
struct InputBuffer {
    uint32_t Size;
    uint8_t Data[];
};

//Declaration of the function to be fuzzed, if it is not exported or already present in a header
//it can be obtained with some reverse engineering ;)
typedef int (WINAPI *TargetFunctionType)(LPBYTE*, DWORD);

//Global pointer of the target function's type
TargetFunctionType TargetFunction;

//Global pointer to shared memory region where new testcases will appear.
InputBuffer* shared_memory_buffer;

//Name of the dll or exe containing the target function
#define TARGET_LIB "target.dll"

//If target function is not exported, will need to calcuate the function's offset from the module base
//using a decompiler or WinDbg
#define TARGET_OFFSET 0xfeed

/// <summary>
/// Open an existing file mapping with the name provided.
/// </summary>
/// <param name="name">Name of the existing file mapping</param>
/// <returns>true == success, false == fail</returns>
bool setup_shared_memory(const char* name) {
    HANDLE shared_memory_handle = OpenFileMappingA(FILE_MAP_ALL_ACCESS, FALSE, name);
    if (shared_memory_handle == NULL) {
        printf("OpenFileMappingA failed with 0x%x\n", GetLastError());
        return false;
    }

    //If this call fails check your SHM_SIZE. It should be equal to or smaller than the SHM_SIZE used by your fuzzer/loader program.
    shared_memory_buffer = reinterpret_cast<InputBuffer*>(MapViewOfFile(shared_memory_handle, FILE_MAP_ALL_ACCESS, 0, 0, SHM_SIZE));
    if (shared_memory_buffer == NULL) {
        printf("MapViewOfFile failed with 0x%x\n", GetLastError());
        return false;
    }

    return true;
}

/// <summary>
/// Open the binary containing the target function and calculate the offset
/// </summary>
/// <returns>true == success, false == fail</returns>
bool load_library_and_target() {
    HMODULE module_handle = LoadLibraryA(TARGET_LIB);
    if (!module_handle) {
        printf("LoadLibraryA failed with 0x%x\n", GetLastError());
        return false;
    }

    //Calculate the address of the target function and set the offset + module base address to the target variable
    TargetFunction = reinterpret_cast<TargetFunctionType>((uint64_t)module_handle + TARGET_OFFSET);

    //if the target is exported, you can look it up dynamically with GetProcAddress instead
    //TargetFunction = (TargetFunctionType*)GetProcAddress(module_handle, TARGET_FUNCTION_NAME);

    return true;
}

//export the function containing the fuzzing target so that it can be found and looped by the fuzzer
extern "C"
__declspec(dllexport)
/// <summary>
/// Fuzz the target! If there are any extraneous parameters required by the target function define them as local variable in here.
/// </summary>
/// <returns>Return value of the fuzzed function (optional)</returns>
int FuzzMe() {
    DWORD input_size;

    //if there are known constraints, such as a max size, check them here
    if (shared_memory_buffer->Size > MAX_SIZE) {
        input_size = MAX_SIZE;
    }
    else {
        input_size = shared_memory_buffer->Size;
    }

    //call the target function with the mutated input!
    int result = TargetFunction(
        reinterpret_cast<LPBYTE*>(&shared_memory_buffer->Data),
        input_size
    );

    return result;
}

int main(int argc, char** argv)
{
    if (argc < 2) {
        printf("Usage: fuzzing_harness <file mapping name>\n");
        return -1;
    }

    bool setup_success = setup_shared_memory(argv[1]);
    if (setup_success == false) {
        return -1;
    }

    setup_success = load_library_and_target();
    if (setup_success == false) {
        return -1;
    }

    int result = FuzzMe();

    return result;
}
