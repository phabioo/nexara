//go:build unix

package update

import "syscall"

// openFlags are added to every open of a file the hub user can replace: a
// symlink swapped in after the check is refused instead of followed, and a
// FIFO swapped in does not block the helper in open(2). The result is checked
// again on the opened descriptor.
const openFlags = syscall.O_NOFOLLOW | syscall.O_NONBLOCK
