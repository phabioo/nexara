package config

import "runtime"

func runtimeHasUnixModes() bool { return runtime.GOOS != "windows" }
