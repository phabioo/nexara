//go:build !linux

package setup

func chmodSocket(string) error { return nil }
