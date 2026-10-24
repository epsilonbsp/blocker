package main

import "base:runtime"
import "core:fmt"
import vmem "core:mem/virtual"
import "core:net"
import "core:os"
import "core:slice"
import "core:strings"
import "core:sync"
import win "core:sys/windows"
import "core:thread"
import "core:time"

SERVICE_NAME :: "blocker"
SERVICE_DISPLAY_NAME :: "Blocker"
SERVICE_DESCRIPTION :: "Blocks websites by answering DNS lookups for them with 'no such domain'."

TICK_INTERVAL_MS :: 2000 // How often the service rereads the config and checks the network adapters.
UPSTREAM_TIMEOUT :: 2 * time.Second
LOG_MAX_SIZE :: 1024 * 1024
DEFAULT_DNS :: "default"

// Held by whichever process is blocking (the service or 'blocker run'), so only one can run at a time.
RUNNING_MUTEX_NAME :: `Global\blocker`

// Firefox turns off its built-in DNS-over-HTTPS (which would bypass blocker) when this name doesn't resolve.
FIREFOX_CANARY :: "use-application-dns.net"

Provider :: struct {
    name: string,
    desc: string,
    servers: []string,
}

PROVIDERS := [?]Provider{
    {"default", "your network's DNS servers, same as without blocker", nil},
    {"cloudflare", "Cloudflare", {"1.1.1.1", "1.0.0.1"}},
    {"cloudflare_security", "Cloudflare, blocks malware", {"1.1.1.2", "1.0.0.2"}},
    {"cloudflare_family", "Cloudflare, blocks malware + adult content", {"1.1.1.3", "1.0.0.3"}},
    {"google", "Google Public DNS", {"8.8.8.8", "8.8.4.4"}},
    {"quad9", "Quad9, blocks malware", {"9.9.9.9", "149.112.112.112"}},
    {"opendns", "Cisco OpenDNS", {"208.67.222.222", "208.67.220.220"}},
    {"opendns_family", "OpenDNS FamilyShield, blocks adult content", {"208.67.222.123", "208.67.220.123"}},
    {"cleanbrowsing_security", "CleanBrowsing, blocks malware", {"185.228.168.9", "185.228.169.9"}},
    {"cleanbrowsing_adult", "CleanBrowsing, blocks adult content", {"185.228.168.10", "185.228.169.11"}},
    {"cleanbrowsing_family", "CleanBrowsing, blocks adult content + proxies/VPNs", {"185.228.168.168", "185.228.169.168"}},
    {"adguard", "AdGuard, blocks ads + trackers", {"94.140.14.14", "94.140.15.15"}},
    {"adguard_family", "AdGuard, blocks ads + trackers + adult content", {"94.140.14.15", "94.140.15.16"}},
}

// ---------------------------------------------------------------------------
// Win32 bindings missing from core:sys/windows
// ---------------------------------------------------------------------------

foreign import advapi32 "system:Advapi32.lib"
foreign import iphlpapi "system:Iphlpapi.lib"
foreign import dnsapi "system:Dnsapi.lib"
foreign import kernel32 "system:Kernel32.lib"

SC_HANDLE :: distinct win.HANDLE
SERVICE_STATUS_HANDLE :: distinct win.HANDLE

SERVICE_STATUS :: struct {
    dwServiceType: win.DWORD,
    dwCurrentState: win.DWORD,
    dwControlsAccepted: win.DWORD,
    dwWin32ExitCode: win.DWORD,
    dwServiceSpecificExitCode: win.DWORD,
    dwCheckPoint: win.DWORD,
    dwWaitHint: win.DWORD,
}

SERVICE_MAIN_PROC :: #type proc "system" (argc: win.DWORD, argv: [^]win.wstring)
HANDLER_EX_PROC :: #type proc "system" (control, event_type: win.DWORD, event_data, ctx: rawptr) -> win.DWORD

SERVICE_TABLE_ENTRYW :: struct {
    lpServiceName: win.wstring,
    lpServiceProc: SERVICE_MAIN_PROC,
}

SERVICE_DESCRIPTIONW :: struct {
    lpDescription: win.wstring,
}

SC_ACTION :: struct {
    Type: win.DWORD,
    Delay: win.DWORD,
}

SERVICE_FAILURE_ACTIONSW :: struct {
    dwResetPeriod: win.DWORD,
    lpRebootMsg: win.wstring,
    lpCommand: win.wstring,
    cActions: win.DWORD,
    lpsaActions: [^]SC_ACTION,
}

DNS_INTERFACE_SETTINGS :: struct {
    Version: win.ULONG,
    Flags: win.ULONG64,
    Domain: win.wstring,
    NameServer: win.wstring,
    SearchList: win.wstring,
    RegistrationEnabled: win.ULONG,
    RegisterAdapterName: win.ULONG,
    EnableLLMNR: win.ULONG,
    QueryAdapterName: win.ULONG,
    ProfileNameServer: win.wstring,
}

#assert(size_of(DNS_INTERFACE_SETTINGS) == 64)

SC_MANAGER_CONNECT :: 0x0001
SC_MANAGER_CREATE_SERVICE :: 0x0002

SERVICE_QUERY_STATUS :: 0x0004
SERVICE_START :: 0x0010
SERVICE_STOP :: 0x0020
SERVICE_ALL_ACCESS :: 0xF01FF
DELETE :: 0x10000

SERVICE_WIN32_OWN_PROCESS :: 0x10
SERVICE_AUTO_START :: 2
SERVICE_ERROR_NORMAL :: 1

SERVICE_CONFIG_DESCRIPTION :: 1
SERVICE_CONFIG_FAILURE_ACTIONS :: 2
SC_ACTION_RESTART :: 1

SERVICE_CONTROL_STOP :: 1
SERVICE_CONTROL_INTERROGATE :: 4
SERVICE_CONTROL_SHUTDOWN :: 5
SERVICE_ACCEPT_STOP :: 0x1
SERVICE_ACCEPT_SHUTDOWN :: 0x4

SERVICE_STOPPED :: 1
SERVICE_START_PENDING :: 2
SERVICE_STOP_PENDING :: 3
SERVICE_RUNNING :: 4
SERVICE_CONTINUE_PENDING :: 5
SERVICE_PAUSE_PENDING :: 6
SERVICE_PAUSED :: 7

DNS_INTERFACE_SETTINGS_VERSION1 :: 1
DNS_SETTING_IPV6 :: 0x0001
DNS_SETTING_NAMESERVER :: 0x0002

IF_TYPE_SOFTWARE_LOOPBACK :: 24

SYNCHRONIZE :: 0x00100000

ERROR_BUFFER_OVERFLOW :: 111
ERROR_SERVICE_DOES_NOT_EXIST :: 1060
ERROR_SERVICE_NOT_ACTIVE :: 1062
ERROR_FAILED_SERVICE_CONTROLLER_CONNECT :: 1063
ERROR_SERVICE_MARKED_FOR_DELETE :: 1072
ERROR_SERVICE_EXISTS :: 1073
ERROR_CANCELLED :: 1223

@(default_calling_convention = "system")
foreign advapi32 {
    OpenSCManagerW :: proc(lpMachineName, lpDatabaseName: win.wstring, dwDesiredAccess: win.DWORD) -> SC_HANDLE ---
    CreateServiceW :: proc(
        hSCManager: SC_HANDLE,
        lpServiceName, lpDisplayName: win.wstring,
        dwDesiredAccess, dwServiceType, dwStartType, dwErrorControl: win.DWORD,
        lpBinaryPathName, lpLoadOrderGroup: win.wstring,
        lpdwTagId: ^win.DWORD,
        lpDependencies, lpServiceStartName, lpPassword: win.wstring,
    ) -> SC_HANDLE ---
    OpenServiceW :: proc(hSCManager: SC_HANDLE, lpServiceName: win.wstring, dwDesiredAccess: win.DWORD) -> SC_HANDLE ---
    CloseServiceHandle :: proc(hSCObject: SC_HANDLE) -> win.BOOL ---
    DeleteService :: proc(hService: SC_HANDLE) -> win.BOOL ---
    StartServiceW :: proc(hService: SC_HANDLE, dwNumServiceArgs: win.DWORD, lpServiceArgVectors: [^]win.wstring) -> win.BOOL ---
    ControlService :: proc(hService: SC_HANDLE, dwControl: win.DWORD, lpServiceStatus: ^SERVICE_STATUS) -> win.BOOL ---
    QueryServiceStatus :: proc(hService: SC_HANDLE, lpServiceStatus: ^SERVICE_STATUS) -> win.BOOL ---
    ChangeServiceConfig2W :: proc(hService: SC_HANDLE, dwInfoLevel: win.DWORD, lpInfo: rawptr) -> win.BOOL ---
    StartServiceCtrlDispatcherW :: proc(lpServiceStartTable: [^]SERVICE_TABLE_ENTRYW) -> win.BOOL ---
    RegisterServiceCtrlHandlerExW :: proc(lpServiceName: win.wstring, lpHandlerProc: HANDLER_EX_PROC, lpContext: rawptr) -> SERVICE_STATUS_HANDLE ---
    SetServiceStatus :: proc(hServiceStatus: SERVICE_STATUS_HANDLE, lpServiceStatus: ^SERVICE_STATUS) -> win.BOOL ---
}

@(default_calling_convention = "system")
foreign iphlpapi {
    GetInterfaceDnsSettings :: proc(Interface: win.GUID, Settings: ^DNS_INTERFACE_SETTINGS) -> win.DWORD ---
    SetInterfaceDnsSettings :: proc(Interface: win.GUID, Settings: ^DNS_INTERFACE_SETTINGS) -> win.DWORD ---
    FreeInterfaceDnsSettings :: proc(Settings: ^DNS_INTERFACE_SETTINGS) ---
}

@(default_calling_convention = "system")
foreign dnsapi {
    DnsFlushResolverCache :: proc() -> win.BOOL ---
}

@(default_calling_convention = "system")
foreign kernel32 {
    GetLocalTime :: proc(lpSystemTime: ^win.SYSTEMTIME) ---
    CreateMutexW :: proc(lpMutexAttributes: ^win.SECURITY_ATTRIBUTES, bInitialOwner: win.BOOL, lpName: win.wstring) -> win.HANDLE ---
    OpenMutexW :: proc(dwDesiredAccess: win.DWORD, bInheritHandle: win.BOOL, lpName: win.wstring) -> win.HANDLE ---
}

// ---------------------------------------------------------------------------
// Entry point
// ---------------------------------------------------------------------------

g_is_service: bool
g_stop_event: win.HANDLE
g_status_handle: SERVICE_STATUS_HANDLE
g_status: SERVICE_STATUS
g_done_event: win.HANDLE // set by 'blocker run' once DNS settings are restored
g_log_lock: sync.Mutex

main :: proc() {
    args := os.args[1:]
    pause_on_error := false

    // The elevated copy started by run_elevated writes its output to a file for the original process to print.
    if len(args) >= 2 && args[0] == "--output" {
        f, err := os.open(args[1], os.O_WRONLY | os.O_CREATE | os.O_TRUNC)

        if err == nil {
            os.stdout = f
            os.stderr = f
        }

        args = args[2:]
    }

    // 'blocker run' started by run_elevated has its own window, which would close before the error can be read.
    if len(args) >= 1 && args[0] == "--pause" {
        pause_on_error = true
        args = args[1:]
    }

    command := len(args) > 0 ? args[0] : "help"
    rest := len(args) > 1 ? args[1:] : nil
    ok := true

    needs_admin :=
        command == "install" ||
        command == "uninstall" ||
        command == "run" ||
        command == "block" ||
        command == "unblock" ||
        command == "except" ||
        command == "unexcept" ||
        (command == "dns" && len(rest) > 0)

    if needs_admin && !is_elevated() {
        os.exit(run_elevated(args, new_window = command == "run"))
    }

    switch command {
    case "help", "-h", "--help", "/?":
        print_help()
    case "install":
        ok = cmd_install()
    case "uninstall":
        ok = cmd_uninstall()
    case "status":
        ok = cmd_status()
    case "run":
        ok = cmd_run()
    case "block":
        ok = cmd_list_add(rest, .Block)
    case "unblock":
        ok = cmd_list_remove(rest, .Block)
    case "except":
        ok = cmd_list_add(rest, .Except)
    case "unexcept":
        ok = cmd_list_remove(rest, .Except)
    case "dns":
        ok = cmd_dns(rest)
    case "service":
        ok = cmd_service()
    case:
        fmt.eprintf("error: unknown command '%s'\n\n", command)
        print_help()
        ok = false
    }

    if !ok {
        if pause_on_error {
            fmt.print("\nPress Enter to close.")
            buf: [16]u8
            os.read(os.stdin, buf[:])
        }

        os.exit(1)
    }
}

print_help :: proc() {
    fmt.println(`blocker - blocks websites on this PC by filtering DNS lookups

Usage: blocker <command> [args]

Commands:
  help                  Print this help
  install               Install and start the background service (starts on boot)
  uninstall             Stop and remove the background service, restore DNS settings
  status                Show blocked domains, exceptions, DNS provider and service state
  run                   Block in this terminal instead of as a service (Ctrl+C stops)
  block <domain>...     Block a domain and all of its subdomains
  unblock <domain>...   Remove a domain from the block list
  except <domain>...    Allow part of a blocked domain, e.g. music.youtube.com
  unexcept <domain>...  Remove an exception
  dns [provider]        Set the DNS provider for everything that isn't blocked, or list them

Everything except help, status and listing DNS providers requires administrator rights
and will show a UAC prompt when run from a non-elevated terminal. 'run' then opens in a
new window.

DNS providers:`)
    print_providers()
    fmt.printf("\nConfig file: %s\n", data_path("config.txt"))
    fmt.printf("Log file:    %s\n", data_path("blocker.log"))
}

print_providers :: proc() {
    for p in PROVIDERS {
        servers := len(p.servers) == 0 ? "system" : strings.join(p.servers, ", ", context.temp_allocator)
        fmt.printf("  %-23s %s (%s)\n", p.name, p.desc, servers)
    }

    fmt.println("  <ip>[,<ip>...]          Custom IPv4 servers, e.g. 192.168.1.1 or 9.9.9.9,149.112.112.112")
}

// ---------------------------------------------------------------------------
// Commands
// ---------------------------------------------------------------------------

cmd_install :: proc() -> bool {
    if blocker_running() && service_state_string(SERVICE_NAME) == "not installed" {
        fmt.eprintln("error: 'blocker run' is active, stop it with Ctrl+C first")

        return false
    }

    exe, err := os.get_executable_path(context.temp_allocator)

    if err != nil {
        fmt.eprintln("error: cannot determine executable path")

        return false
    }

    scm := OpenSCManagerW(nil, nil, SC_MANAGER_CONNECT | SC_MANAGER_CREATE_SERVICE)

    if scm == nil {
        print_win_error("cannot open service manager")

        return false
    }

    defer CloseServiceHandle(scm)

    bin_path := fmt.tprintf(`"%s" service`, exe)
    svc := CreateServiceW(
        scm,
        win.L(SERVICE_NAME),
        win.L(SERVICE_DISPLAY_NAME),
        SERVICE_ALL_ACCESS,
        SERVICE_WIN32_OWN_PROCESS,
        SERVICE_AUTO_START,
        SERVICE_ERROR_NORMAL,
        win.utf8_to_wstring(bin_path),
        nil,
        nil,
        nil,
        nil,
        nil,
    )

    if svc == nil {
        if win.GetLastError() == ERROR_SERVICE_EXISTS {
            fmt.println("Service is already installed. Run 'blocker uninstall' first to reinstall.")
        } else {
            print_win_error("cannot create service")
        }

        return false
    }

    defer CloseServiceHandle(svc)

    desc := SERVICE_DESCRIPTIONW{win.L(SERVICE_DESCRIPTION)}
    ChangeServiceConfig2W(svc, SERVICE_CONFIG_DESCRIPTION, &desc)

    // Restart quickly if it ever crashes, so Windows isn't left pointing at a DNS server that isn't running.
    actions := [3]SC_ACTION{{SC_ACTION_RESTART, 2_000}, {SC_ACTION_RESTART, 5_000}, {SC_ACTION_RESTART, 30_000}}
    failure := SERVICE_FAILURE_ACTIONSW{dwResetPeriod = 24 * 60 * 60, cActions = len(actions), lpsaActions = &actions[0]}
    ChangeServiceConfig2W(svc, SERVICE_CONFIG_FAILURE_ACTIONS, &failure)

    fmt.printf("Service '%s' installed (%s).\n", SERVICE_NAME, bin_path)
    fmt.println("Note: the service runs this executable from its current location, so don't move or delete it.")

    if !StartServiceW(svc, 0, nil) {
        print_win_error("service installed but failed to start")

        return false
    }

    if !wait_for_state(svc, SERVICE_RUNNING) {
        fmt.eprintf("error: service failed to start, see %s\n", data_path("blocker.log"))

        return false
    }

    fmt.println("Service started. Restart your browser if blocked sites still load.")

    return true
}

cmd_uninstall :: proc() -> bool {
    scm := OpenSCManagerW(nil, nil, SC_MANAGER_CONNECT)

    if scm == nil {
        print_win_error("cannot open service manager")

        return false
    }

    defer CloseServiceHandle(scm)

    svc := OpenServiceW(scm, win.L(SERVICE_NAME), SERVICE_STOP | SERVICE_QUERY_STATUS | DELETE)

    if svc == nil {
        if win.GetLastError() != ERROR_SERVICE_DOES_NOT_EXIST {
            print_win_error("cannot open service")

            return false
        }

        fmt.println("Service is not installed.")
    } else {
        defer CloseServiceHandle(svc)

        status: SERVICE_STATUS

        // The service restores the DNS settings as it stops.
        if ControlService(svc, SERVICE_CONTROL_STOP, &status) {
            fmt.print("Stopping service")
            wait_for_state(svc, SERVICE_STOPPED, show_progress = true)
            fmt.println()
        } else if win.GetLastError() != ERROR_SERVICE_NOT_ACTIVE {
            print_win_error("cannot stop service")
        }

        if DeleteService(svc) {
            fmt.printf("Service '%s' uninstalled.\n", SERVICE_NAME)
        } else if win.GetLastError() == ERROR_SERVICE_MARKED_FOR_DELETE {
            fmt.println("Service is already marked for deletion.")
        } else {
            print_win_error("cannot delete service")

            return false
        }
    }

    // Clean up after a service that crashed or didn't stop in time.
    if saved, ok := read_state(); ok && !blocker_running() {
        if !restore_dns(saved[:]) {
            fmt.eprintf("error: failed to restore some DNS settings, see %s\n", data_path("blocker.log"))

            return false
        }
    }

    return true
}

cmd_status :: proc() -> bool {
    cfg := load_config()

    print_list("Blocked:       ", cfg.blocks[:])
    print_list("Exceptions:    ", cfg.excepts[:])
    fmt.printf("DNS:           %s\n", describe_dns(cfg.dns))

    running := blocker_running()

    if cfg.dns == DEFAULT_DNS {
        // While blocking, Windows points at blocker itself, so look up what the network provides.
        servers: [dynamic]net.IP4_Address

        if saved, has_state := read_state(); running && has_state {
            servers = network_dns(saved[:])
        } else {
            servers = system_dns()
        }

        fmt.printf("               network servers: %s\n", len(servers) > 0 ? ip4_list(servers[:]) : "(none found)")
    }

    state := service_state_string(SERVICE_NAME)
    fmt.printf("Service:       %s\n", state)

    switch {
    case running && state == "running":
        fmt.println("Blocking:      yes (service)")
    case running:
        fmt.println("Blocking:      yes ('blocker run')")
    case:
        fmt.println("Blocking:      no")

        if _, has_state := read_state(); has_state {
            fmt.println("               (DNS settings still point at blocker; start the service or run 'blocker uninstall')")
        }
    }

    if last := last_log_line(); last != "" {
        fmt.printf("Last log:      %s\n", last)
    }

    return true
}

// Waits like the service, but in this terminal until Ctrl+C or the window is closed.
cmd_run :: proc() -> bool {
    g_stop_event = win.CreateEventW(nil, true, false, nil)
    g_done_event = win.CreateEventW(nil, true, false, nil)
    win.SetConsoleCtrlHandler(console_control, true)

    if !start_blocking() {
        stop_blocking()

        return false
    }

    log_line("blocking, press Ctrl+C to stop (restart your browser if blocked sites still load)")
    block_until_stopped()
    log_line("stopped")
    win.SetEvent(g_done_event)

    return true
}

console_control :: proc "system" (ctrl_type: win.DWORD) -> win.BOOL {
    win.SetEvent(g_stop_event)

    // Windows ends the process once this returns (for a closed window), so wait for the DNS settings to be restored.
    win.WaitForSingleObject(g_done_event, 10_000)

    return true
}

List :: enum {
    Block,
    Except,
}

cmd_list_add :: proc(args: []string, which: List) -> bool {
    if len(args) == 0 {
        fmt.eprintf("usage: blocker %s <domain>...\n", which == .Block ? "block" : "except")

        return false
    }

    cfg := load_config()
    list := which == .Block ? &cfg.blocks : &cfg.excepts
    ok := true

    for arg in args {
        domain := normalize_domain(arg)

        if !valid_domain(domain) {
            fmt.eprintf("error: invalid domain '%s'\n", arg)
            ok = false

            continue
        }

        if slice.contains(list[:], domain) {
            fmt.printf("%s is already in the list.\n", domain)

            continue
        }

        append(list, domain)

        if which == .Block {
            fmt.printf("Blocked %s.\n", domain)
        } else {
            fmt.printf("Added exception %s.\n", domain)

            if longest_match(domain, cfg.blocks[:]) == 0 {
                fmt.printf("Note: %s isn't covered by any block rule, so this exception does nothing yet.\n", domain)
            }
        }
    }

    return save_config(cfg) && ok
}

cmd_list_remove :: proc(args: []string, which: List) -> bool {
    if len(args) == 0 {
        fmt.eprintf("usage: blocker %s <domain>...\n", which == .Block ? "unblock" : "unexcept")

        return false
    }

    cfg := load_config()
    list := which == .Block ? &cfg.blocks : &cfg.excepts

    for arg in args {
        domain := normalize_domain(arg)
        i, found := slice.linear_search(list[:], domain)

        if !found {
            fmt.printf("%s is not in the list.\n", domain)

            continue
        }

        ordered_remove(list, i)
        fmt.printf(which == .Block ? "Unblocked %s.\n" : "Removed exception %s.\n", domain)
    }

    return save_config(cfg)
}

print_list :: proc(label: string, items: []string) {
    fmt.print(label)

    if len(items) == 0 {
        fmt.println("(none)")
    }

    for d, i in items {
        fmt.printf("%s%s\n", i == 0 ? "" : "               ", d)
    }
}

cmd_dns :: proc(args: []string) -> bool {
    cfg := load_config()

    if len(args) == 0 {
        fmt.printf("Current DNS: %s\n\nOptions:\n", describe_dns(cfg.dns))
        print_providers()

        return true
    }

    value := strings.to_lower(strings.trim_space(args[0]), context.temp_allocator)

    if _, ok := find_provider(value); !ok {
        for s in strings.split(value, ",", context.temp_allocator) {
            if _, valid := net.parse_ip4_address(strings.trim_space(s)); !valid {
                fmt.eprintf("error: unknown DNS provider or invalid IPv4 address '%s'\n\nOptions:\n", s)
                print_providers()

                return false
            }
        }
    }

    cfg.dns = value

    if !save_config(cfg) {
        return false
    }

    fmt.printf("DNS set to %s.\n", describe_dns(value))

    return true
}

cmd_service :: proc() -> bool {
    g_is_service = true
    table := [2]SERVICE_TABLE_ENTRYW{{win.L(SERVICE_NAME), service_main}, {}}

    if !StartServiceCtrlDispatcherW(&table[0]) {
        if win.GetLastError() == ERROR_FAILED_SERVICE_CONTROLLER_CONNECT {
            fmt.eprintln("error: 'service' is run by the Windows service manager. Use 'blocker install' instead.")
        } else {
            print_win_error("service dispatcher failed")
        }

        return false
    }

    return true
}

// ---------------------------------------------------------------------------
// Elevation
// ---------------------------------------------------------------------------

is_elevated :: proc() -> bool {
    token: win.HANDLE

    if !win.OpenProcessToken(win.GetCurrentProcess(), win.TOKEN_QUERY, &token) {
        return false
    }

    defer win.CloseHandle(token)

    elevated: win.DWORD
    size: win.DWORD

    if !win.GetTokenInformation(token, .TokenElevation, &elevated, size_of(elevated), &size) {
        return false
    }

    return elevated != 0
}

// Reruns this executable with the given arguments as administrator (shows a UAC prompt),
// waits for it to finish, prints its output and returns its exit code.
// With new_window it opens in its own console window instead and isn't waited for.
run_elevated :: proc(args: []string, new_window := false) -> int {
    exe, err := os.get_executable_path(context.temp_allocator)

    if err != nil {
        fmt.eprintln("error: cannot determine executable path")

        return 1
    }

    temp_dir, _ := os.temp_directory(context.temp_allocator)
    output_path := fmt.tprintf(`%s\blocker-%d.out`, strings.trim_right(temp_dir, `\`), win.GetCurrentProcessId())

    params := strings.builder_make(context.temp_allocator)

    if new_window {
        strings.write_string(&params, "--pause")
    } else {
        fmt.sbprintf(&params, `--output "%s"`, output_path)
    }

    for a in args {
        fmt.sbprintf(&params, ` "%s"`, a)
    }

    info := win.SHELLEXECUTEINFOW{
        cbSize = size_of(win.SHELLEXECUTEINFOW),
        fMask = win.SEE_MASK_NOCLOSEPROCESS | win.SEE_MASK_NOASYNC,
        lpVerb = win.L("runas"),
        lpFile = win.utf8_to_wstring(exe),
        lpParameters = win.utf8_to_wstring(strings.to_string(params)),
        nShow = new_window ? win.SW_SHOW : win.SW_HIDE,
    }

    if !win.ShellExecuteExW(&info) {
        if win.GetLastError() == ERROR_CANCELLED {
            fmt.eprintln("error: administrator rights are required, the UAC prompt was declined")
        } else {
            print_win_error("cannot start elevated process")
        }

        return 1
    }

    defer win.CloseHandle(info.hProcess)

    if new_window {
        fmt.println("Blocker is running in a new administrator window. Press Ctrl+C there or close it to stop.")

        return 0
    }

    exit_code: win.DWORD
    win.WaitForSingleObject(info.hProcess, win.INFINITE)
    win.GetExitCodeProcess(info.hProcess, &exit_code)

    if data, read_err := os.read_entire_file(output_path, context.temp_allocator); read_err == nil {
        fmt.print(string(data))
    }

    os.remove(output_path)

    return int(exit_code)
}

// ---------------------------------------------------------------------------
// Windows service
// ---------------------------------------------------------------------------

service_main :: proc "system" (argc: win.DWORD, argv: [^]win.wstring) {
    context = runtime.default_context()
    g_status_handle = RegisterServiceCtrlHandlerExW(win.L(SERVICE_NAME), service_control, nil)

    if g_status_handle == nil {
        return
    }

    g_stop_event = win.CreateEventW(nil, true, false, nil)
    set_service_state(SERVICE_START_PENDING)
    log_line("service starting")

    if !start_blocking() {
        stop_blocking()
        log_line("service failed to start")
        set_service_state(SERVICE_STOPPED, exit_code = 1)

        return
    }

    set_service_state(SERVICE_RUNNING)
    log_line("service running")
    block_until_stopped()
    log_line("service stopped")
    win.CloseHandle(g_stop_event)
    set_service_state(SERVICE_STOPPED)
}

service_control :: proc "system" (control, event_type: win.DWORD, event_data, ctx: rawptr) -> win.DWORD {
    context = runtime.default_context()

    switch control {
    case SERVICE_CONTROL_STOP, SERVICE_CONTROL_SHUTDOWN:
        set_service_state(SERVICE_STOP_PENDING)
        win.SetEvent(g_stop_event)

        return win.NO_ERROR
    case SERVICE_CONTROL_INTERROGATE:
        return win.NO_ERROR
    }

    return win.ERROR_CALL_NOT_IMPLEMENTED
}

set_service_state :: proc(state: win.DWORD, exit_code: win.DWORD = win.NO_ERROR) {
    pending := state == SERVICE_START_PENDING || state == SERVICE_STOP_PENDING

    g_status.dwServiceType = SERVICE_WIN32_OWN_PROCESS
    g_status.dwCurrentState = state
    g_status.dwControlsAccepted = state == SERVICE_RUNNING ? SERVICE_ACCEPT_STOP | SERVICE_ACCEPT_SHUTDOWN : 0
    g_status.dwWin32ExitCode = exit_code
    g_status.dwCheckPoint = pending ? g_status.dwCheckPoint + 1 : 0
    g_status.dwWaitHint = pending ? 10_000 : 0
    SetServiceStatus(g_status_handle, &g_status)
}

// Waits up to 15 seconds for the service to reach the given state.
wait_for_state :: proc(svc: SC_HANDLE, want: win.DWORD, show_progress := false) -> bool {
    status: SERVICE_STATUS

    for _ in 0 ..< 60 {
        if !QueryServiceStatus(svc, &status) {
            return false
        }

        if status.dwCurrentState == want {
            return true
        }

        if want == SERVICE_RUNNING && status.dwCurrentState == SERVICE_STOPPED {
            return false
        }

        if show_progress {
            fmt.print(".")
        }

        win.Sleep(250)
    }

    return false
}

service_state_string :: proc(name: string) -> string {
    scm := OpenSCManagerW(nil, nil, SC_MANAGER_CONNECT)

    if scm == nil {
        return "unknown"
    }

    defer CloseServiceHandle(scm)

    svc := OpenServiceW(scm, win.utf8_to_wstring(name), SERVICE_QUERY_STATUS)

    if svc == nil {
        return win.GetLastError() == ERROR_SERVICE_DOES_NOT_EXIST ? "not installed" : "unknown"
    }

    defer CloseServiceHandle(svc)

    status: SERVICE_STATUS

    if !QueryServiceStatus(svc, &status) {
        return "unknown"
    }

    switch status.dwCurrentState {
    case SERVICE_STOPPED:
        return "stopped"
    case SERVICE_START_PENDING:
        return "starting"
    case SERVICE_STOP_PENDING:
        return "stopping"
    case SERVICE_RUNNING:
        return "running"
    case SERVICE_CONTINUE_PENDING:
        return "resuming"
    case SERVICE_PAUSE_PENDING:
        return "pausing"
    case SERVICE_PAUSED:
        return "paused"
    }

    return "unknown"
}

// ---------------------------------------------------------------------------
// Config
// ---------------------------------------------------------------------------

// config.txt holds one entry per line:
//   dns cloudflare
//   block youtube.com
//   except music.youtube.com
Config :: struct {
    dns: string,
    blocks: [dynamic]string,
    excepts: [dynamic]string,
}

parse_config :: proc(text: string, allocator := context.temp_allocator) -> (cfg: Config) {
    cfg.dns = DEFAULT_DNS
    cfg.blocks = make([dynamic]string, allocator)
    cfg.excepts = make([dynamic]string, allocator)
    text := text

    for line in strings.split_lines_iterator(&text) {
        key, _, value := strings.partition(strings.trim_space(line), " ")
        value = strings.trim_space(value)

        if value == "" {
            continue
        }

        switch key {
        case "dns":
            cfg.dns = value
        case "block":
            append(&cfg.blocks, value)
        case "except":
            append(&cfg.excepts, value)
        }
    }

    return
}

load_config :: proc() -> Config {
    data, _ := os.read_entire_file(data_path("config.txt"), context.temp_allocator)

    return parse_config(string(data))
}

save_config :: proc(cfg: Config) -> bool {
    b := strings.builder_make(context.temp_allocator)
    fmt.sbprintf(&b, "dns %s\r\n", cfg.dns)

    for d in cfg.blocks {
        fmt.sbprintf(&b, "block %s\r\n", d)
    }

    for d in cfg.excepts {
        fmt.sbprintf(&b, "except %s\r\n", d)
    }

    path := data_path("config.txt")
    os.make_directory_all(data_dir())

    if err := os.write_entire_file(path, strings.to_string(b)); err != nil {
        fmt.eprintf("error: cannot write %s: %v\n", path, err)

        return false
    }

    return true
}

find_provider :: proc(name: string) -> (Provider, bool) {
    for p in PROVIDERS {
        if p.name == name {
            return p, true
        }
    }

    return {}, false
}

// The servers for a provider name or a comma separated list of IPv4 addresses.
// Empty for "default", which uses the network's own servers (see network_dns).
resolve_upstreams :: proc(dns: string, allocator := context.temp_allocator) -> []net.IP4_Address {
    servers: []string

    if p, ok := find_provider(dns); ok {
        servers = p.servers
    } else {
        servers = strings.split(dns, ",", context.temp_allocator)
    }

    out := make([dynamic]net.IP4_Address, allocator)

    for s in servers {
        if addr, ok := net.parse_ip4_address(strings.trim_space(s)); ok {
            append(&out, addr)
        }
    }

    return out[:]
}

describe_dns :: proc(dns: string) -> string {
    if p, ok := find_provider(dns); ok {
        if len(p.servers) == 0 {
            return fmt.tprintf("%s - %s", p.name, p.desc)
        }

        return fmt.tprintf("%s - %s (%s)", p.name, p.desc, strings.join(p.servers, ", ", context.temp_allocator))
    }

    return fmt.tprintf("custom (%s)", dns)
}

// Accepts things like "https://www.YouTube.com/watch" and returns "youtube.com".
normalize_domain :: proc(s: string) -> string {
    d := strings.to_lower(strings.trim_space(s), context.temp_allocator)
    d = strings.trim_prefix(d, "https://")
    d = strings.trim_prefix(d, "http://")

    if i := strings.index_any(d, "/?#:"); i >= 0 {
        d = d[:i]
    }

    d = strings.trim_prefix(d, "www.")
    d = strings.trim_suffix(d, ".")

    return d
}

valid_domain :: proc(d: string) -> bool {
    if d == "" || len(d) > 253 || d[0] == '.' || strings.contains(d, "..") {
        return false
    }

    for c in d {
        if !(c >= 'a' && c <= 'z' || c >= '0' && c <= '9' || c == '-' || c == '.' || c == '_') {
            return false
        }
    }

    return true
}

// Returns the length of the most specific rule matching name (0 if none), so that the more
// specific of a block rule and an exception wins.
longest_match :: proc(name: string, rules: []string) -> (best: int) {
    for rule in rules {
        if len(rule) > best && domain_matches(name, rule) {
            best = len(rule)
        }
    }

    return
}

// "youtube.com" matches youtube.com and all of its subdomains.
domain_matches :: proc(name, rule: string) -> bool {
    if name == rule {
        return true
    }

    return len(name) > len(rule) && strings.has_suffix(name, rule) && name[len(name) - len(rule) - 1] == '.'
}

// ---------------------------------------------------------------------------
// Blocking
// ---------------------------------------------------------------------------

// The config as seen by the query threads. Replaced as a whole when config.txt changes.
Live :: struct {
    arena: vmem.Arena,
    text: string,
    cfg: Config,
    upstreams: []net.IP4_Address,
}

g_live: ^Live
g_network_dns: [dynamic]net.IP4_Address // the network's own servers, for dns "default"
g_live_lock: sync.Mutex // guards g_live and g_network_dns

// The original DNS setting of each adapter blocker has taken over, mirrored in state.txt
// so it can be restored even after a crash. Only touched by the service thread.
Saved_DNS :: struct {
    guid: string,
    v6: bool,
    value: string, // "" means automatic (DHCP)
}

g_saved: [dynamic]Saved_DNS
g_running_mutex: win.HANDLE

blocker_running :: proc() -> bool {
    h := OpenMutexW(SYNCHRONIZE, false, win.L(RUNNING_MUTEX_NAME))

    if h != nil {
        win.CloseHandle(h)

        return true
    }

    // The service's mutex can't always be opened by other users, but then it exists.
    return win.GetLastError() == win.ERROR_ACCESS_DENIED
}

// Starts the DNS server and points every connected adapter at it.
start_blocking :: proc() -> bool {
    g_running_mutex = CreateMutexW(nil, false, win.L(RUNNING_MUTEX_NAME))

    if g_running_mutex == nil || win.GetLastError() == win.ERROR_ALREADY_EXISTS {
        log_line("error: blocker is already running (as the service or with 'blocker run')")

        return false
    }

    reload_config()

    sock4, err4 := net.make_bound_udp_socket(net.IP4_Loopback, 53)

    if err4 != nil {
        log_line("error: cannot listen on 127.0.0.1:53 (%v), is another DNS server running?", err4)

        return false
    }

    thread.create_and_start_with_poly_data(sock4, serve_udp)

    if sock6, err6 := net.make_bound_udp_socket(net.IP6_Loopback, 53); err6 == nil {
        thread.create_and_start_with_poly_data(sock6, serve_udp)
    } else {
        log_line("warning: cannot listen on [::1]:53 (%v)", err6)
    }

    if saved, ok := read_state(); ok {
        log_line("restoring DNS settings left over from a previous run")

        if !restore_dns(saved[:]) {
            return false
        }
    }

    tick()

    return true
}

stop_blocking :: proc() {
    if len(g_saved) > 0 && restore_dns(g_saved[:]) {
        clear(&g_saved)
    }
}

// Keeps blocking until g_stop_event is set, then restores the DNS settings.
block_until_stopped :: proc() {
    for win.WaitForSingleObject(g_stop_event, TICK_INTERVAL_MS) != win.WAIT_OBJECT_0 {
        tick()
        free_all(context.temp_allocator)
    }

    stop_blocking()
}

// Runs every TICK_INTERVAL_MS: picks up config edits, and adapters that are new or were
// changed by hand (e.g. the network coming up after boot, or switching Wi-Fi).
tick :: proc() {
    if reload_config() {
        DnsFlushResolverCache()
    }

    take_over_dns()

    servers := network_dns(g_saved[:])

    sync.mutex_lock(&g_live_lock)
    changed := !slice.equal(servers[:], g_network_dns[:])

    if changed {
        clear(&g_network_dns)
        append(&g_network_dns, ..servers[:])
    }

    sync.mutex_unlock(&g_live_lock)

    if changed {
        log_line("network DNS servers: %s", len(servers) > 0 ? ip4_list(servers[:]) : "(none found)")
    }
}

reload_config :: proc() -> (changed: bool) {
    data, _ := os.read_entire_file(data_path("config.txt"), context.temp_allocator)

    if g_live != nil && string(data) == g_live.text {
        return false
    }

    next := new(Live)
    _ = vmem.arena_init_growing(&next.arena)
    allocator := vmem.arena_allocator(&next.arena)
    next.text = strings.clone(string(data), allocator)
    next.cfg = parse_config(next.text, allocator)
    next.upstreams = resolve_upstreams(next.cfg.dns, allocator)

    if len(next.upstreams) == 0 && next.cfg.dns != DEFAULT_DNS {
        log_line("warning: no valid servers for dns '%s', using the network's DNS servers", next.cfg.dns)
    }

    sync.mutex_lock(&g_live_lock)
    old := g_live
    g_live = next
    sync.mutex_unlock(&g_live_lock)

    // Query threads only use g_live while holding the lock, so nothing points into the old one anymore.
    if old != nil {
        vmem.arena_destroy(&old.arena)
        free(old)
    }

    log_line("config loaded: %d blocked, %d exceptions, dns %s", len(next.cfg.blocks), len(next.cfg.excepts), describe_dns(next.cfg.dns))

    return true
}

take_over_dns :: proc() {
    changed := false

    for a := get_adapters(); a != nil; a = a.Next {
        if !is_connected(a) {
            continue
        }

        guid: win.GUID
        id := string(a.AdapterName)

        if win.IIDFromString(win.utf8_to_wstring(id), &guid) != 0 {
            continue
        }

        name, _ := win.wstring_to_utf8(a.FriendlyName, -1, context.temp_allocator)

        for v6 in ([2]bool{false, true}) {
            target := v6 ? "::1" : "127.0.0.1"
            current, ok := get_name_server(guid, v6)

            if !ok || current == target {
                continue
            }

            already_saved := false

            for s in g_saved {
                if s.guid == id && s.v6 == v6 {
                    already_saved = true
                }
            }

            if already_saved {
                log_line("DNS of '%s' was changed to '%s', pointing it back at blocker", name, current)
            } else {
                // Save the original setting before changing it, so a crash can't lose it.
                append(&g_saved, Saved_DNS{strings.clone(id), v6, strings.clone(current)})

                if !write_state(g_saved[:]) {
                    pop(&g_saved)

                    continue
                }

                log_line("DNS of '%s' (IPv%d) -> blocker, was '%s'", name, v6 ? 6 : 4, current == "" ? "automatic" : current)
            }

            set_name_server(guid, v6, target)
            changed = true
        }
    }

    if changed {
        DnsFlushResolverCache()
    }
}

// Puts back the saved settings, and resets anything else still pointing at blocker to automatic.
// Removes state.txt when everything was restored.
restore_dns :: proc(saved: []Saved_DNS) -> bool {
    present := make([dynamic]string, context.temp_allocator)

    for a := get_adapters(); a != nil; a = a.Next {
        append(&present, string(a.AdapterName))
    }

    ok := true

    for s in saved {
        guid: win.GUID

        // Skip adapters that were removed since.
        if !slice.contains(present[:], s.guid) || win.IIDFromString(win.utf8_to_wstring(s.guid), &guid) != 0 {
            continue
        }

        if !set_name_server(guid, s.v6, s.value) {
            ok = false
        }
    }

    for a := get_adapters(); a != nil; a = a.Next {
        guid: win.GUID

        if win.IIDFromString(win.utf8_to_wstring(string(a.AdapterName)), &guid) != 0 {
            continue
        }

        for v6 in ([2]bool{false, true}) {
            if current, got := get_name_server(guid, v6); got && current == (v6 ? "::1" : "127.0.0.1") {
                set_name_server(guid, v6, "")
            }
        }
    }

    if ok {
        os.remove(data_path("state.txt"))
        log_line("DNS settings restored")
    }

    DnsFlushResolverCache()

    return ok
}

// state.txt has one line per saved setting: <adapter guid> <4|6> <original name servers>
write_state :: proc(saved: []Saved_DNS) -> bool {
    b := strings.builder_make(context.temp_allocator)

    for s in saved {
        fmt.sbprintf(&b, "%s %d %s\r\n", s.guid, s.v6 ? 6 : 4, s.value)
    }

    path := data_path("state.txt")
    os.make_directory_all(data_dir())

    if err := os.write_entire_file(path, strings.to_string(b)); err != nil {
        log_line("error: cannot write %s: %v", path, err)

        return false
    }

    return true
}

read_state :: proc() -> (saved: [dynamic]Saved_DNS, ok: bool) {
    data, err := os.read_entire_file(data_path("state.txt"), context.temp_allocator)

    if err != nil {
        return
    }

    saved = make([dynamic]Saved_DNS, context.temp_allocator)
    text := string(data)

    for line in strings.split_lines_iterator(&text) {
        guid, _, rest := strings.partition(strings.trim_right_space(line), " ")
        family, _, value := strings.partition(rest, " ")

        if guid != "" {
            append(&saved, Saved_DNS{guid, family == "6", value})
        }
    }

    return saved, true
}

// The DNS servers the network provides while blocker has taken over: for each connected adapter
// its original static servers, or the ones DHCP handed out.
network_dns :: proc(saved: []Saved_DNS) -> [dynamic]net.IP4_Address {
    out := make([dynamic]net.IP4_Address, context.temp_allocator)

    for a := get_adapters(); a != nil; a = a.Next {
        if !is_connected(a) {
            continue
        }

        for s in saved {
            if s.v6 || s.guid != string(a.AdapterName) {
                continue
            }

            servers := s.value != "" ? s.value : read_dhcp_name_servers(s.guid)
            servers, _ = strings.replace_all(servers, ",", " ", context.temp_allocator)

            for field in strings.fields(servers, context.temp_allocator) {
                if addr, ok := net.parse_ip4_address(field); ok && addr[0] != 127 && !slice.contains(out[:], addr) {
                    append(&out, addr)
                }
            }
        }
    }

    return out
}

// The IPv4 DNS servers Windows uses right now, ignoring loopback (blocker itself).
system_dns :: proc() -> [dynamic]net.IP4_Address {
    out := make([dynamic]net.IP4_Address, context.temp_allocator)

    for a := get_adapters(); a != nil; a = a.Next {
        if !is_connected(a) {
            continue
        }

        for d := a.FirstDnsServerAddress; d != nil; d = d.Next {
            sa := cast([^]u8)d.Address.lpSockaddr

            if sa == nil || (cast(^u16)sa)^ != u16(win.AF_INET) {
                continue
            }

            addr := net.IP4_Address{sa[4], sa[5], sa[6], sa[7]}

            if addr[0] != 127 && !slice.contains(out[:], addr) {
                append(&out, addr)
            }
        }
    }

    return out
}

read_dhcp_name_servers :: proc(guid: string) -> string {
    key := fmt.tprintf(`SYSTEM\CurrentControlSet\Services\Tcpip\Parameters\Interfaces\%s`, guid)
    buf: [512]u16
    size := win.DWORD(size_of(buf))

    if win.RegGetValueW(win.HKEY_LOCAL_MACHINE, win.utf8_to_wstring(key), win.L("DhcpNameServer"), win.RRF_RT_REG_SZ, nil, &buf[0], &size) != 0 {
        return ""
    }

    s, _ := win.utf16_to_utf8(buf[:size / 2], context.temp_allocator)

    return strings.trim_right_null(s)
}

ip4_list :: proc(addrs: []net.IP4_Address) -> string {
    b := strings.builder_make(context.temp_allocator)

    for a, i in addrs {
        fmt.sbprintf(&b, "%s%d.%d.%d.%d", i == 0 ? "" : ", ", a[0], a[1], a[2], a[3])
    }

    return strings.to_string(b)
}

// Up, not loopback, and with a default gateway, i.e. actually used for internet traffic.
is_connected :: proc(a: ^win.IP_Adapter_Addresses) -> bool {
    return a.OperStatus == .Up && a.IfType != IF_TYPE_SOFTWARE_LOOPBACK && a.FirstGatewayAddress != nil
}

get_adapters :: proc() -> ^win.IP_Adapter_Addresses {
    size: u32 = 16 * 1024

    for _ in 0 ..< 4 {
        buf := make([]u64, size / 8 + 1, context.temp_allocator)
        first := cast(^win.IP_Adapter_Addresses)raw_data(buf)
        res := win.GetAdaptersAddresses(.Unspecified, {.Skip_Anycast, .Skip_Multicast, .Include_Gateways}, nil, first, &size)

        if res == 0 {
            return first
        }

        if res != ERROR_BUFFER_OVERFLOW {
            return nil
        }
    }

    return nil
}

// The adapter's static name servers, or "" when it gets them automatically (DHCP).
get_name_server :: proc(guid: win.GUID, v6: bool) -> (string, bool) {
    s := DNS_INTERFACE_SETTINGS{Version = DNS_INTERFACE_SETTINGS_VERSION1, Flags = v6 ? DNS_SETTING_IPV6 : 0}

    if GetInterfaceDnsSettings(guid, &s) != 0 {
        return "", false
    }

    defer FreeInterfaceDnsSettings(&s)

    if s.NameServer == nil {
        return "", true
    }

    ns, _ := win.wstring_to_utf8(s.NameServer, -1, context.temp_allocator)

    return ns, true
}

set_name_server :: proc(guid: win.GUID, v6: bool, name_server: string) -> bool {
    s := DNS_INTERFACE_SETTINGS{
        Version = DNS_INTERFACE_SETTINGS_VERSION1,
        Flags = DNS_SETTING_NAMESERVER | (v6 ? DNS_SETTING_IPV6 : 0),
        NameServer = win.utf8_to_wstring(name_server),
    }

    if err := SetInterfaceDnsSettings(guid, &s); err != 0 {
        log_line("error: SetInterfaceDnsSettings failed (error %d)", err)

        return false
    }

    return true
}

// ---------------------------------------------------------------------------
// DNS server
// ---------------------------------------------------------------------------

Request :: struct {
    sock: net.UDP_Socket,
    from: net.Endpoint,
    len: int,
    buf: [4096]u8,
}

serve_udp :: proc(sock: net.UDP_Socket) {
    for {
        req := new(Request)
        n, from, err := net.recv_udp(sock, req.buf[:])

        if err != nil || n == 0 {
            free(req)

            continue
        }

        req.sock, req.from, req.len = sock, from, n
        thread.create_and_start_with_poly_data(req, handle_query, self_cleanup = true)
    }
}

// Blocked names get a "no such domain" reply, everything else is forwarded upstream.
handle_query :: proc(req: ^Request) {
    defer free(req)
    defer free_all(context.temp_allocator)

    query := req.buf[:req.len]
    name_buf: [256]u8
    name, question_end, ok := parse_question(query, name_buf[:])

    if !ok {
        return
    }

    out: [4096]u8
    reply: []u8

    if name == FIREFOX_CANARY {
        reply = nxdomain(query[:question_end], out[:])
    } else if is_blocked(name) {
        reply = nxdomain(query[:question_end], out[:])
        log_line("blocked %s", name)
    } else {
        reply, ok = forward(query, out[:])

        if !ok {
            return
        }
    }

    net.send_udp(req.sock, reply, req.from)
}

is_blocked :: proc(name: string) -> bool {
    sync.mutex_lock(&g_live_lock)
    defer sync.mutex_unlock(&g_live_lock)

    block := longest_match(name, g_live.cfg.blocks[:])

    return block > 0 && block > longest_match(name, g_live.cfg.excepts[:])
}

forward :: proc(query: []u8, out: []u8) -> ([]u8, bool) {
    servers: [8]net.IP4_Address
    count := 0

    sync.mutex_lock(&g_live_lock)

    for s in (len(g_live.upstreams) > 0 ? g_live.upstreams : g_network_dns[:]) {
        if count < len(servers) {
            servers[count] = s
            count += 1
        }
    }

    sync.mutex_unlock(&g_live_lock)

    for server in servers[:count] {
        sock, err := net.make_unbound_udp_socket(.IP4)

        if err != nil {
            continue
        }

        defer net.close(sock)
        net.set_option(sock, .Receive_Timeout, UPSTREAM_TIMEOUT)

        if _, send_err := net.send_udp(sock, query, {server, 53}); send_err != nil {
            continue
        }

        n, _, recv_err := net.recv_udp(sock, out)

        // The reply must carry the same transaction id as the query.
        if recv_err != nil || n < 12 || out[0] != query[0] || out[1] != query[1] {
            continue
        }

        return out[:n], true
    }

    return nil, false
}

// Reads the single question of a DNS query. Returns the lowercased name and where the question ends.
parse_question :: proc(msg: []u8, name_buf: []u8) -> (name: string, end: int, ok: bool) {
    // Must be a query (not a response) with exactly one question.
    if len(msg) < 12 || msg[2] & 0x80 != 0 || msg[4] != 0 || msg[5] != 1 {
        return
    }

    pos, n := 12, 0

    for {
        if pos >= len(msg) {
            return
        }

        label := int(msg[pos])
        pos += 1

        if label == 0 {
            break
        }

        // > 63 also rejects compression pointers, which don't belong in a question.
        if label > 63 || pos + label > len(msg) || n + label + 1 > len(name_buf) {
            return
        }

        if n > 0 {
            name_buf[n] = '.'
            n += 1
        }

        for c in msg[pos:pos + label] {
            name_buf[n] = c >= 'A' && c <= 'Z' ? c + 32 : c
            n += 1
        }

        pos += label
    }

    // qtype + qclass
    if pos + 4 > len(msg) {
        return
    }

    return string(name_buf[:n]), pos + 4, true
}

// Turns a query (header + question) into a "no such domain" reply.
nxdomain :: proc(question: []u8, out: []u8) -> []u8 {
    n := copy(out, question)
    out[2] = 0x80 | (question[2] & 0x79) // response, keep opcode + recursion desired
    out[3] = 0x80 | 3 // recursion available, NXDOMAIN

    // No answer, authority or additional records.
    for i in 6 ..< 12 {
        out[i] = 0
    }

    return out[:n]
}

// ---------------------------------------------------------------------------
// Files and logging
// ---------------------------------------------------------------------------

data_dir :: proc() -> string {
    dir := os.get_env("ProgramData", context.temp_allocator)

    if dir == "" {
        dir = `C:\ProgramData`
    }

    return fmt.tprintf(`%s\blocker`, dir)
}

data_path :: proc(name: string) -> string {
    return fmt.tprintf(`%s\%s`, data_dir(), name)
}

// Prints the message (unless running as a service) and appends it to the log file.
// Safe to call from any thread.
log_line :: proc(format: string, args: ..any) {
    msg := fmt.tprintf(format, ..args)

    if !g_is_service {
        fmt.println(msg)
    }

    local: win.SYSTEMTIME
    GetLocalTime(&local)
    line := fmt.tprintf(
        "%04d-%02d-%02d %02d:%02d:%02d.%03d  %s%s\r\n",
        local.year,
        local.month,
        local.day,
        local.hour,
        local.minute,
        local.second,
        local.milliseconds,
        g_is_service ? "" : "[manual] ",
        msg,
    )

    sync.mutex_lock(&g_log_lock)
    defer sync.mutex_unlock(&g_log_lock)

    path := data_path("blocker.log")
    os.make_directory_all(data_dir())

    flags := os.O_WRONLY | os.O_CREATE | os.O_APPEND

    if info, err := os.stat(path, context.temp_allocator); err == nil && info.size > LOG_MAX_SIZE {
        flags = os.O_WRONLY | os.O_CREATE | os.O_TRUNC
    }

    f, err := os.open(path, flags)

    // Logging is best effort (e.g. non-admin users can't write to ProgramData).
    if err != nil {
        return
    }

    defer os.close(f)

    os.write_string(f, line)
}

last_log_line :: proc() -> string {
    data, err := os.read_entire_file(data_path("blocker.log"), context.temp_allocator)

    if err != nil {
        return ""
    }

    text := strings.trim_right_space(string(data))

    if i := strings.last_index_byte(text, '\n'); i >= 0 {
        text = text[i + 1:]
    }

    return strings.trim_space(text)
}

print_win_error :: proc(what: string) {
    code := win.GetLastError()

    if code == win.ERROR_ACCESS_DENIED {
        fmt.eprintf("error: %s: access denied (run from an administrator prompt)\n", what)
    } else {
        fmt.eprintf("error: %s (error %d)\n", what, code)
    }
}
