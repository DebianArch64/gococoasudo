//go:build !darwin

package cocoasudo

func CocoaSudo(executable string, command string, message string) int {
	fmt.Println("Not implemented.")
	return
}
