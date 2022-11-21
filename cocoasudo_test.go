package cocoasudo

import (
	"fmt"
	"testing"
)

func TestEcho(t *testing.T) {
	fmt.Println("test 1 code:", CocoaSudo("/usr/bin/env", "echo test s", "whatever"))
	fmt.Println()

	fmt.Println("test 1 code:", CocoaSudo("/usr/bin/env", "echo lest s", "whatever"))
	fmt.Println()

	fmt.Println("test 3 code:", CocoaSudo("/usr/bin/env", "echo next", "whatever"))
}
