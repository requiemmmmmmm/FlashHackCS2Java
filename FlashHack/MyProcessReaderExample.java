import com.sun.jna.Native;
import com.sun.jna.win32.W32APIOptions;
import com.sun.jna.platform.win32.Kernel32;
import com.sun.jna.platform.win32.WinDef.DWORD;
import com.sun.jna.platform.win32.Tlhelp32;
import com.sun.jna.platform.win32.WinNT;
import com.sun.jna.platform.win32.WinBase;
 
//Imports for MyKernel32
import com.sun.jna.win32.StdCallLibrary;
import com.sun.jna.ptr.IntByReference;
import com.sun.jna.Pointer;
import com.sun.jna.Memory;
import com.sun.jna.Structure;
import java.util.Arrays;
import java.util.List;

public class MyProcessReaderExample
{
    private static final boolean DEBUG = false;
    static Kernel32 kernel32 = (Kernel32)Native.loadLibrary(Kernel32.class, W32APIOptions.UNICODE_OPTIONS);
    static MyKernel32 myKernel32 = (MyKernel32)Native.loadLibrary("kernel32", MyKernel32.class);
    static String usage = "Usage: java MyProcessReaderExample [processName] [readSize] [readAddress] [readOffset]" + System.getProperty("line.separator") + "processName example: firefox.exe" + System.getProperty("line.separator") + "readSize (in bytes) example : 4" + System.getProperty("line.separator") + "readAddress (hexadecimal) example : 00010000" + System.getProperty("line.separator") + "readOffset (decimal) example : 0";
    
    // Process access rights
    static final int PROCESS_VM_READ = 0x0010;
    static final int PROCESS_VM_WRITE = 0x0020;
    static final int PROCESS_VM_OPERATION = 0x0008;
    static final int PROCESS_QUERY_INFORMATION = 0x0400;
    
    static final int readRight = PROCESS_VM_READ | PROCESS_QUERY_INFORMATION;
    static final int writeRight = PROCESS_VM_WRITE | PROCESS_VM_OPERATION | PROCESS_QUERY_INFORMATION;
    
    // Структура MODULEENTRY32W для работы с модулями
    public static class MODULEENTRY32W extends Structure {
        public DWORD dwSize;
        public DWORD th32ModuleID;
        public DWORD th32ProcessID;
        public DWORD GlblcntUsage;
        public DWORD ProccntUsage;
        public Pointer modBaseAddr;
        public DWORD modBaseSize;
        public WinNT.HANDLE hModule;
        public char[] szModule = new char[256];
        public char[] szExePath = new char[260];

        public MODULEENTRY32W() {
            dwSize = new DWORD(size());
        }

        @Override
        protected List<String> getFieldOrder() {
            return Arrays.asList("dwSize", "th32ModuleID", "th32ProcessID", "GlblcntUsage", 
                               "ProccntUsage", "modBaseAddr", "modBaseSize", "hModule", 
                               "szModule", "szExePath");
        }
    }
    
    interface MyKernel32 extends StdCallLibrary
    {
        boolean WriteProcessMemory(Pointer hProcess, Pointer lpBaseAddress, Pointer lpBuffer, int nSize, IntByReference lpNumberOfBytesWritten);
        boolean ReadProcessMemory(Pointer hProcess, Pointer lpBaseAddress, Pointer lpBuffer, int nSize, IntByReference lpNumberOfBytesRead);
        Pointer OpenProcess(int dwDesiredAccess, boolean bInheritHandle, int dwProcessId);
        int GetLastError();
        boolean Module32FirstW(WinNT.HANDLE hSnapshot, MODULEENTRY32W lpme);
        boolean Module32NextW(WinNT.HANDLE hSnapshot, MODULEENTRY32W lpme);
    }

    public static void main(String args[]) {
        //Get ProcessID
        long pid = findProcessId("cs2.exe");
        if(pid == 0) {
            System.err.println("ProcessId not found.");
            System.exit(1);
        }
        System.out.println("PID: " + pid);
        
        // Показываем все модули процесса
       // listAllModules(pid);
        
        // Получаем базовый адрес модуля (например, client.dll для CS2)
        long clientBaseAddress = getModuleBaseAddress(pid, "client.dll");
        if(clientBaseAddress == 0) {
            System.err.println("Module client.dll not found.");
            System.exit(1);
        }
        
        Pointer readProcess = openProcess(readRight, pid);//opens process with read privileges
        Pointer writeProcess = openProcess(writeRight | readRight, pid);
        
        // Офсеты (нужно обновить под вашу версию CS2)
        long OFFSET_LOCAL_PLAYER_CONTROLLER = 0x1BE7DA0; // Указатель на структуру игрока
        long OFFSET_HEALTH = 0x1610; // Смещение здоровья внутри структуры
        
        System.out.println("\n=== Reading player data ===");
        
        // Шаг 1: Читаем указатель на LocalPlayerController
        long localPlayerControllerAddress = clientBaseAddress + OFFSET_LOCAL_PLAYER_CONTROLLER;
        System.out.printf("LocalPlayerController pointer address: 0x%X\n", localPlayerControllerAddress);
        
        long localPlayerController = readPointer(readProcess, localPlayerControllerAddress);
        if(localPlayerController == 0) {
            System.out.println("LocalPlayerController is NULL (not in game?)");
            System.exit(0);
        }
        System.out.printf("LocalPlayerController: 0x%X\n", localPlayerController);
        
        // Шаг 2: Читаем здоровье по смещению
        long healthAddress = localPlayerController + OFFSET_HEALTH;
        System.out.printf("Health address: 0x%X\n", healthAddress);
        
        int health = readInt(readProcess, healthAddress);
        System.out.println("Current health: " + health);
        while(true) {
            writeFloat(writeProcess, healthAddress, 0);
        }

    }

    static long findProcessId(String processName) {
        //This Reference will contain the processInfo that will be parsed t recover the ProcessId
        Tlhelp32.PROCESSENTRY32.ByReference processInfo = new Tlhelp32.PROCESSENTRY32.ByReference();
        
        //this handle allows us to parse the process map
        WinNT.HANDLE processesSnapshot = kernel32.CreateToolhelp32Snapshot(Tlhelp32.TH32CS_SNAPPROCESS, new DWORD(0L));
        if(processesSnapshot == kernel32.INVALID_HANDLE_VALUE) {
            if(DEBUG) System.err.println("INVALID_HANDLE_VALUE");
            return 0L;
        }
        
        try {// This will parse all the processes to find the process id corresponding to the process name
            kernel32.Process32First(processesSnapshot, processInfo);
            if(processName.equals(Native.toString(processInfo.szExeFile))) {
                if(DEBUG) if(DEBUG) System.out.println("Process " + processName + " found : " + processInfo.th32ProcessID.longValue());
                return processInfo.th32ProcessID.longValue();
            }
            
            while(kernel32.Process32Next(processesSnapshot, processInfo)) {
                if(processName.equals(Native.toString(processInfo.szExeFile)))
                {
                    if(DEBUG) System.out.println("Process " + processName + " found : " + processInfo.th32ProcessID.longValue());
                    return processInfo.th32ProcessID.longValue();
                }
            }
            
            if(DEBUG) System.out.println("Did not find requested Process: " + processName);
            return 0L;
        } finally {
            kernel32.CloseHandle(processesSnapshot);
        }
    }//findProcessId

    // Вывод всех модулей процесса для отладки
    static void listAllModules(long pid) {
        WinNT.HANDLE snapshot = kernel32.CreateToolhelp32Snapshot(
                new DWORD(Tlhelp32.TH32CS_SNAPMODULE.intValue() | Tlhelp32.TH32CS_SNAPMODULE32.intValue()), 
                new DWORD(pid));
        
        if (snapshot == null || WinBase.INVALID_HANDLE_VALUE.equals(snapshot)) {
            System.err.println("Failed to create module snapshot. Error: " + myKernel32.GetLastError());
            return;
        }
        
        System.out.println("\n=== All loaded modules ===");
        MODULEENTRY32W moduleEntry = new MODULEENTRY32W();
        try {
            if (myKernel32.Module32FirstW(snapshot, moduleEntry)) {
                do {
                    String modName = new String(moduleEntry.szModule).trim().replace("\0", "");
                    if (!modName.isEmpty()) {
                        long base = Pointer.nativeValue(moduleEntry.modBaseAddr);
                        long size = moduleEntry.modBaseSize.longValue();
                        System.out.printf("%-30s Base: 0x%016X  Size: 0x%X\n", modName, base, size);
                    }
                } while (myKernel32.Module32NextW(snapshot, moduleEntry));
            }
        } finally {
            kernel32.CloseHandle(snapshot);
        }
        System.out.println("=========================\n");
    }

    // Получение базового адреса модуля (ModuleHandle) по названию
    static long getModuleBaseAddress(long pid, String moduleName) {
        // Создаём снимок модулей процесса
        WinNT.HANDLE snapshot = kernel32.CreateToolhelp32Snapshot(
                new DWORD(Tlhelp32.TH32CS_SNAPMODULE.intValue() | Tlhelp32.TH32CS_SNAPMODULE32.intValue()), 
                new DWORD(pid));
        
        if (snapshot == null || WinBase.INVALID_HANDLE_VALUE.equals(snapshot)) {
            System.err.println("Failed to create module snapshot. Error: " + myKernel32.GetLastError());
            return 0L;
        }
        
        MODULEENTRY32W moduleEntry = new MODULEENTRY32W();
        try {
            if (myKernel32.Module32FirstW(snapshot, moduleEntry)) {
                do {
                    String modName = new String(moduleEntry.szModule).trim().replace("\0", "");
                    if (modName.equalsIgnoreCase(moduleName)) {
                        long base = Pointer.nativeValue(moduleEntry.modBaseAddr);
                        System.out.printf("Module %s found at base address: 0x%016X\n", moduleName, base);
                        return base;
                    }
                } while (myKernel32.Module32NextW(snapshot, moduleEntry));
            }
            
            System.out.println("Module not found: " + moduleName);
            return 0L;
        } finally {
            kernel32.CloseHandle(snapshot);
        }
    }//getModuleBaseAddress

    static Pointer openProcess(int permissions, long pid) {
        Pointer process = myKernel32.OpenProcess(permissions, true, (int)pid);
        return process;
    }
    static Memory readMemory(Pointer process, long address, int readSize) {
        Memory output = new Memory(readSize);
        Pointer addressPtr = new Pointer(address);
        if(!myKernel32.ReadProcessMemory(process, addressPtr, output, readSize, new IntByReference(0))) {
            int error = myKernel32.GetLastError();
            switch(error) {
            default:
                System.err.println("Failed to read the process: " + error);
                break;
            case 0x12B:
                System.err.println("Failed to read the specified address (0x" + Long.toHexString(address).toUpperCase() + ")");
                break;
            case 0x5:
                System.err.println("Access denied. Try running as administrator.");
                break;
            case 0x3E6:
                System.err.println("Invalid address range.");
                break;
            }
            return null;
        }
        return output;
    }
    
    // Чтение 64-битного указателя (8 байт)
    static long readPointer(Pointer process, long address) {
        Memory data = readMemory(process, address, 8);
        if(data == null) return 0;
        return data.getLong(0);
    }
    
    // Чтение 32-битного значения (int, 4 байта)
    static int readInt(Pointer process, long address) {
        Memory data = readMemory(process, address, 4);
        if(data == null) return 0;
        return data.getInt(0);
    }
    
    // Чтение float (4 байта)
    static float readFloat(Pointer process, long address) {
        Memory data = readMemory(process, address, 4);
        if(data == null) return 0.0f;
        return data.getFloat(0);
    }
    // Запись int значения (4 байта)
    static boolean writeInt(Pointer process, long address, int value) {
        IntByReference written = new IntByReference(0);
        Memory toWrite = new Memory(4);
        
        toWrite.setInt(0, value);
        Pointer addressPtr = new Pointer(address);
        
        if(!myKernel32.WriteProcessMemory(process, addressPtr, toWrite, 4, written)) {
            int error = myKernel32.GetLastError();
            switch(error) {
                default:
                    System.err.println("Failed to write to address 0x" + Long.toHexString(address).toUpperCase() + ": error " + error);
                    break;
                case 0x5:
                    System.err.println("Access denied. Try running as administrator.");
                    break;
            }
            return false;
        }
        return true;
    }
    
    // Запись float значения (4 байта)
    static boolean writeFloat(Pointer process, long address, float value) {
        IntByReference written = new IntByReference(0);
        Memory toWrite = new Memory(4);
        
        toWrite.setFloat(0, value);
        Pointer addressPtr = new Pointer(address);
        
        if(!myKernel32.WriteProcessMemory(process, addressPtr, toWrite, 4, written)) {
            int error = myKernel32.GetLastError();
            System.err.println("Failed to write float to address 0x" + Long.toHexString(address).toUpperCase() + ": error " + error);
            return false;
        }
        return true;
    }
}