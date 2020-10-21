#define SYS_READ 0x3

#include <iostream>
#include <string>
#include <fstream>
#include <cassert>
#include <syscall.h>
#include "pin.H"
#include "../Utils/regvalue_utils.h"

using namespace std;
using std::ofstream;
UINT32 count_trace = 0; // current trace number
FILE * trace;


/////////////////////
// GLOBAL VARIABLES
/////////////////////

//chestie implus
KNOB<BOOL>   KnobNoCompress(KNOB_MODE_WRITEONCE, "pintool",
    "no_compress", "0", "Do not compress");

// A knob for defining the output file name
KNOB<string> KnobOutputFile(KNOB_MODE_WRITEONCE, "pintool",
    "o", "regval.out", "specify output file name");

// ofstream object for handling the output
ofstream OutFile;

// We don't want to print the registers too many times, so we put placeholders in the application to tell the tool
// when to start and stop printing.
volatile bool printRegsNow = false;

#ifdef TARGET_MAC
const char* startRtnName = "_Start";
const char* stopRtnName = "_Stop";
#else
const char* startRtnName = "Start";
const char* stopRtnName = "Stop";
#endif


/////////////////////
// ANALYSIS FUNCTIONS
/////////////////////

// Once this is called, the registers will be printed until EndRoutine is called.
static void StartRoutine()
{
    printRegsNow = true;
}

// After this is called, the registers will no longer be printed.
static void StopRoutine()
{
    printRegsNow = false;
}

string Val2Str(const void* value, unsigned int size)
{
    stringstream sstr;
    sstr << hex;
    const unsigned char* cval = (const unsigned char*)value;
    // Traverse cval from end to beginning since the MSB is in the last block of cval.
    while (size)
    {
        --size;
        sstr << (unsigned int)cval[size];
    }
    return string("0x")+sstr.str();
}



static void PrintRegisters(const CONTEXT * ctxt)
{
    if (!printRegsNow) return;
    OutFile << "C;" << endl;
    static const UINT stRegSize = REG_Size(REG_ST_BASE);
    for (int reg = (int)REG_GR_BASE; reg <= (int)REG_GR_LAST; ++reg)
    {
        // For the integer registers, it is safe to use ADDRINT. But make sure to pass a pointer to it.
        ADDRINT val;
        PIN_GetContextRegval(ctxt, (REG)reg, reinterpret_cast<UINT8*>(&val));
        OutFile << REG_StringShort((REG)reg) << ": 0x" << hex << val << endl;
    }
    for (int reg = (int)REG_ST_BASE; reg <= (int)REG_ST_LAST; ++reg)
    {
        // For the x87 FPU stack registers, using PIN_REGISTER ensures a large enough buffer.
        PIN_REGISTER val;
        PIN_GetContextRegval(ctxt, (REG)reg, reinterpret_cast<UINT8*>(&val));
        OutFile << REG_StringShort((REG)reg) << ": " << Val2Str(&val, stRegSize) << endl;

    }
}


/////////////////////
// INSTRUMENTATION FUNCTIONS
/////////////////////

static VOID ImageLoad(IMG img, VOID * v)
{
    if (IMG_IsMainExecutable(img))
    {
        RTN StartRtn = RTN_FindByName(img, startRtnName);
        assert(RTN_Valid(StartRtn));
        RTN_Open(StartRtn);
        RTN_InsertCall(StartRtn, IPOINT_BEFORE, (AFUNPTR)StartRoutine, IARG_END);
        RTN_Close(StartRtn);

        RTN StopRtn = RTN_FindByName(img, stopRtnName);
        assert(RTN_Valid(StopRtn));
        RTN_Open(StopRtn);
        RTN_InsertCall(StopRtn, IPOINT_AFTER, (AFUNPTR)StopRoutine, IARG_END);
        RTN_Close(StopRtn);
    }
}


VOID  docount(const string *s)
{
    OutFile.write(s->c_str(), s->size());
    
}


static VOID Trace(TRACE trace, VOID *v)
{
    /*codu meu*/
    TRACE_InsertCall(trace, IPOINT_BEFORE, (AFUNPTR)PrintRegisters, IARG_CONST_CONTEXT, IARG_END);

}

VOID dump_nop(UINT64 insAddr, std::string insDis) {
    OutFile << "I;" "Aici mai tre sa adaugi ceva flag;"  << insAddr << endl;
    //printf("%lx\t%s\n", insAddr, insDis.c_str());
}

VOID callback_instruction(INS ins, VOID *v) {
    if (INS_IsCall(ins))
    {
        INS_InsertCall(ins, IPOINT_BEFORE, (AFUNPTR)dump_nop, IARG_ADDRINT,
                   INS_Address(ins), IARG_PTR, new string(INS_Disassemble(ins)),
                   IARG_END);
    }
    
}

static VOID Fini(INT32 code, VOID *v)
{
    OutFile.close();
}



/* Print syscall number and arguments*/
VOID SysBefore(ADDRINT ip, ADDRINT num, ADDRINT arg0, ADDRINT arg1, ADDRINT arg2, ADDRINT arg3, ADDRINT arg4, ADDRINT arg5)
{
#if defined(TARGET_LINUX) && defined(TARGET_IA32) 
    // On ia32 Linux, there are only 5 registers for passing system call arguments, 
    // but mmap needs 6. For mmap on ia32, the first argument to the system call 
    // is a pointer to an array of the 6 arguments
    if (num == SYS_mmap)
    {
        ADDRINT * mmapArgs = reinterpret_cast<ADDRINT *>(arg0);
        arg0 = mmapArgs[0];
        arg1 = mmapArgs[1];
        arg2 = mmapArgs[2];
        arg3 = mmapArgs[3];
        arg4 = mmapArgs[4];
        arg5 = mmapArgs[5];
    }
#endif

    fprintf(trace,"0x%lx: %ld(0x%lx, 0x%lx, 0x%lx, 0x%lx, 0x%lx, 0x%lx)",
        (unsigned long)ip,
        (long)num,
        (unsigned long)arg0,
        (unsigned long)arg1,
        (unsigned long)arg2,
        (unsigned long)arg3,
        (unsigned long)arg4,
        (unsigned long)arg5);
}

// Print the return value of the system call
VOID SysAfter(ADDRINT ret)
{
    fprintf(trace,"returns: 0x%lx\n", (unsigned long)ret);
    fflush(trace);
}

VOID SyscallEntry(THREADID threadIndex, CONTEXT *ctxt, SYSCALL_STANDARD std, VOID *v)
{
    SysBefore(PIN_GetContextReg(ctxt, REG_INST_PTR),
        PIN_GetSyscallNumber(ctxt, std),
        PIN_GetSyscallArgument(ctxt, std, 0),
        PIN_GetSyscallArgument(ctxt, std, 1),
        PIN_GetSyscallArgument(ctxt, std, 2),
        PIN_GetSyscallArgument(ctxt, std, 3),
        PIN_GetSyscallArgument(ctxt, std, 4),
        PIN_GetSyscallArgument(ctxt, std, 5));
}

VOID SyscallExit(THREADID threadIndex, CONTEXT *ctxt, SYSCALL_STANDARD std, VOID *v)
{
    SysAfter(PIN_GetSyscallReturn(ctxt, std));
}

// Is called for every instruction and instruments syscalls
VOID Instruction(INS ins, VOID *v)
{
    // For O/S's (Mac) that don't support PIN_AddSyscallEntryFunction(),
    // instrument the system call instruction.

    if (INS_IsSyscall(ins) && INS_HasFallThrough(ins))
    {
        // Arguments and syscall number is only available before
        INS_InsertCall(ins, IPOINT_BEFORE, AFUNPTR(SysBefore),
                       IARG_INST_PTR, IARG_SYSCALL_NUMBER,
                       IARG_SYSARG_VALUE, 0, IARG_SYSARG_VALUE, 1,
                       IARG_SYSARG_VALUE, 2, IARG_SYSARG_VALUE, 3,
                       IARG_SYSARG_VALUE, 4, IARG_SYSARG_VALUE, 5,
                       IARG_END);

        // return value only available after
        INS_InsertCall(ins, IPOINT_AFTER, AFUNPTR(SysAfter),
                       IARG_SYSRET_VALUE,
                       IARG_END);
    }
}



/////////////////////
// MAIN FUNCTION
/////////////////////



int main(int argc, char * argv[])
{

    /*
    * !!!! URGENT SA IMPEMENTEZI SI THREAD CONTEXT DUMPING USING PINTOOL
    *
    *
    *
    */
    // Initialize Pin
    PIN_InitSymbols();
    PIN_Init(argc, argv);


    trace = fopen("strace.out", "w");

    INS_AddInstrumentFunction(Instruction, 0);
    PIN_AddSyscallEntryFunction(SyscallEntry, 0);
    PIN_AddSyscallExitFunction(SyscallExit, 0);



    // Open the output file
    OutFile.open(KnobOutputFile.Value().c_str());

    // Add instrumentation
    IMG_AddInstrumentFunction(ImageLoad, 0);
    TRACE_AddInstrumentFunction(Trace, 0);
    INS_AddInstrumentFunction(callback_instruction, 0);

    PIN_AddFiniFunction(Fini, 0);

 
    /*
    unsigned int address = 0x7ffbea512000;
    while(address < 0x7ffd8d27dff0)
    {
        unsigned int* pcontent = ( unsigned int*)address;
        unsigned int content = *pcontent;
        printf ("Address %p: content %08x\n", pcontent, content);
        address++;
    }*/

    // Start running the application
    PIN_StartProgram(); // never return

    return 0;
}
