//go:build darwin
// +build darwin

package cocoasudo

/*
	#cgo LDFLAGS: -lSystem -framework CoreFoundation -framework Security
	#include <stdlib.h>
	#include "cocoasudo.h"
*/
import "C"
import "unsafe"

func CocoaSudo(executable string, command string, message string) int {
	executable_cstr := C.CString(executable)
	command_cstr := C.CString(command)
	message_cstr := C.CString(message)

	ret := C.simple_cocoa(executable_cstr, command_cstr, message_cstr)
	C.free(unsafe.Pointer(executable_cstr))
	C.free(unsafe.Pointer(command_cstr))
	C.free(unsafe.Pointer(message_cstr))
	return int(ret)
}

// func main() {
// 	CocoaSudo("/usr/bin/env", "echo hello ")
// }
