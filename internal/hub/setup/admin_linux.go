package setup

import "os"

func chmodSocket(path string) error { return os.Chmod(path, 0o660) }
