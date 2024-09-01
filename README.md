heres source cus its crappy ignore all the things i whitelisted cus i originally made this for me, if you want u can adjust this do it urself lazy monk btw i used skidgpt and even more skidding cus yes 
-- sxlo was here

import ctypes
import os
import psutil
import sys

CRITICAL_PROCESSES = [
    "explorer.exe",       # Manages the Windows graphical user interface
    "System",             # Manages hardware and system-level tasks
    "Registry",           # Registry process
    "winlogon.exe",       # Manages user logon and logoff processes
    "csrss.exe",          # Handles console windows and shutdown processes
    "services.exe",       # Manages Windows services and their associated processes
    "lsass.exe",          # Handles security policies and user authentication
    "smss.exe",           # Responsible for creating system sessions and launching system processes
    "svchost.exe",        # Hosts services running from dynamic-link libraries (DLLs)
    "wininit.exe",        # Handles the initialization of Windows services
    "taskhostw.exe",      # Hosts Windows tasks and services
    "dwm.exe",            # Handles window management and visual effects
    "spoolsv.exe",        # Manages printing tasks and print queue
    "ctfmon.exe",         # Manages alternative input methods and language bars
    "sihost.exe",         # Manages certain user interface aspects
    "audiodg.exe",        # Handles audio processing and isolation
    "taskmgr.exe",        # Provides access to the Task Manager
    "runtimebroker.exe",  # Manages permissions for apps and ensures they run in a secure context
    "msmpeng.exe",        # Microsoft Malware Protection Engine
    "wlidsvc.exe",        # Supports Windows Live sign-ins
    "conhost.exe",        # Provides support for the command prompt
    "ntoskrnl.exe",       # Responsible for system services (Windows NT Operating System Kernel)
    "userinit.exe",       # Initializes user environments
    "taskhost.exe",       # Runs tasks for various services
    "wlanext.exe",        # Windows WLAN Extensibility
    "System Idle Process", # Represents idle time of the CPU
    "brave.exe",          # Brave browser executable
    "NVDisplay.Container.exe", # NVIDIA Display Container
    "AsusCertService.exe", # ASUS Certification Service
    "dasHost.exe",        # Device Association Service Host
    "RazerCentralService.exe", # Razer Central Service
    "GameManagerService3.exe", # Game Manager Service
    "ROGLiveService.exe", # ROG Live Service
    "ArmouryCrate.Service.exe", # Armoury Crate Service
    "CortexLauncherService.exe", # Cortex Launcher Service
    "nvcontainer.exe",    # NVIDIA Container
    "GameSDK.exe",        # Game SDK executable
    "fshoster32.exe",     # FS Host32 executable
    "fshoster64.exe",     # FS Host64 executable
    "gameinputsvc.exe",   # Game Input Service
    "srvstub.exe",        # Service Stub executable
    "AsusFanControlService.exe", # ASUS Fan Control Service
    "fsulprothoster.exe", # FSUL Protocol Host
    "ProductAgentService.exe", # Product Agent Service
    "LightingService.exe", # Lighting Service
    "MpDefenderCoreService.exe", # Microsoft Defender Core Service
    "sqlwriter.exe",      # SQL Writer Service
    "VSSrv.exe",          # Volume Shadow Copy Service
    "extensionCardHal_x86.exe", # Extension Card HAL
    "Aac3572DramHal_x86.exe", # Aac3572 DRAM HAL
    "dllhost.exe",        # COM Surrogate
    "WmiPrvSE.exe",       # WMI Provider Host
    "Razer Synapse Service.exe", # Razer Synapse Service
    "AacKingstonDramHal_x86.exe", # Aac Kingston DRAM HAL
    "CefSharp.BrowserSubprocess.exe", # CefSharp Browser Subprocess
    "SecurityHealthService.exe", # Security Health Service
    "SgrmBroker.exe",     # Sgrm Broker Service
    "Razer Central.exe",  # Razer Central
    "LockApp.exe",        # Lock Screen App
    "msedgewebview2.exe", # Microsoft Edge WebView2
    "smartscreen.exe",    # SmartScreen Filter
    "CompPkgSrv.exe",     # Component Package Service
    "TextInputHost.exe",  # Text Input Host
    "ArmouryCrate.UserSessionHelper.exe", # Armoury Crate User Session Helper
    "MemCompression.exe", # Memory Compression
    "MemCompression",     # Memory Compression (alternate name)
    "TrustedInstaller.exe", # Trusted Installer
    "atkexComSvc.exe",    # ATKEX COM Service
    "GameManagerService.exe", # Game Manager Service
    "UserOOBEBroker.exe", # User OOBE Broker
    "gamingservices.exe", # Gaming Services
    "gamingservicesnet.exe", # Gaming Services Network
    "DiscoverySrv.exe",   # Discovery Service
    "fsnotifier.exe",     # File System Notifier
    "ProcessGovernor.exe", # Process Lasso background process
    "Fsnotifier.exe",     # File System Notifier (capitalized)
    "asus_framework.exe", # ASUS framework process
    "rundll32.exe",       # Essential Windows process
    "VSHelper.exe",       # Visual Studio Helper
    "ArmourySocketServer.exe", # Armoury Socket Server
    "ArmourySwAgent.exe", # Armoury Software Agent
    "Python.exe",         # Python interpreter
    "py.exe",             # Python executable (alternate name)
    "python.exe",         # Python interpreter (alternate name)
    "Razer Synapse 3.exe", # Razer Synapse 3
    "SecurityHealthSystray.exe", # Security Health Systray
    "RazerCortex.exe",    # Razer Cortex
    "AORUS.exe",          # AORUS software
    "jusched.exe",        # Java Update Scheduler
    "NVIDIA Web Helper.exe", # NVIDIA Web Helper
    "Aac3572MbHal_x86.exe", # Alternative name for AAC
    "AacKingstonDramHal_x64.exe", # Alternative name 2 for AAC
    "RzTHX051e.exe",    # Razer services

    # Game-specific processes
    "FortniteClient-Win64-Shipping_EAC_EOS.exe",  # Fortnite
    "Minecraft Launcher.exe",                     # Minecraft Launcher
    "LeagueClient.exe",                           # League of Legends client
    "GTA5.exe",                                   # Grand Theft Auto V
    "valorant.exe",                               # Valorant
    "cod.exe",                                    # Call of Duty (various versions)
    "ApexLegends.exe",                            # Apex Legends
    "Overwatch.exe",                              # Overwatch
    "csgo.exe",                                   # Counter-Strike: Global Offensive
    "EasyAntiCheat_EOS.exe",                      # EasyAntiCheat for fortnite
    "EpicGamesLauncher.exe",                      # Epic Games Launcher
    "FortniteClient-Win64-Shipping.exe",          # Fortnite Alternative Process
    "FortniteLauncher.exe",                       # The Fortnite Launcher Service
    "EpicWebHelper.exe"                           # The epic Web Helper for login services
    
]


def is_admin():
    """Check if the script is running with administrative privileges."""
    try:
        return ctypes.windll.shell32.IsUserAnAdmin()
    except:
        return False

def run_as_admin(script_path):
    """Re-run the script with administrative privileges."""
    ctypes.windll.shell32.ShellExecuteW(None, "runas", sys.executable, script_path, None, 1)

def list_processes():
    print(f"{'PID':<10}{'Name':<25}{'Memory (%)':<15}{'Can Terminate':<15}")
    print("=" * 70)
    processes = []
    for proc in psutil.process_iter(['pid', 'name', 'memory_percent']):
        try:
            proc_info = proc.info
            # Skip critical processes
            if proc_info['name'].lower() in (name.lower() for name in CRITICAL_PROCESSES):
                continue

            # Assume processes that are not critical can be terminated
            can_terminate = "Yes"

            # Only add processes that can be terminated
            processes.append(proc_info)
            print(
                f"{proc_info['pid']:<10}{proc_info['name']:<25}{proc_info['memory_percent']:<15.2f}{can_terminate:<15}")

        except (psutil.NoSuchProcess, psutil.AccessDenied, psutil.ZombieProcess):
            continue  # Skip processes that cannot be accessed
    return processes

def terminate_process(pid):
    try:
        proc = psutil.Process(pid)
        proc.terminate()
        proc.wait(timeout=3)
        print(f"Process {pid} terminated successfully.")
    except (psutil.NoSuchProcess, psutil.AccessDenied, psutil.TimeoutExpired) as e:
        print(f"Failed to terminate process {pid}: {e}")

def terminate_all_background_processes(processes):
    for proc in processes:
        pid = proc['pid']
        terminate_process(pid)

def main():
    if not is_admin():
        print("Requesting administrative privileges...")
        run_as_admin(sys.argv[0])
        return

    while True:
        os.system('cls' if os.name == 'nt' else 'clear')  # Clear the console
        processes = list_processes()

        print("\nEnter the PID of the process you want to terminate, or type 'all' to terminate all background processes (or 'q' to quit): ", end='')
        choice = input().strip()

        if choice.lower() == 'q':
            break

        if choice.lower() == 'all':
            terminate_all_background_processes(processes)
        elif choice.isdigit():
            pid = int(choice)
            selected_process = next((proc for proc in processes if proc['pid'] == pid), None)
            if selected_process:
                terminate_process(pid)
            else:
                print(f"Cannot terminate process with PID {pid}. It may not be in the list or is a critical process.")
        else:
            print("Invalid input. Please enter a valid PID or 'all' to terminate all background processes.")

        input("\nPress Enter to continue...")

if __name__ == "__main__":
    main()

