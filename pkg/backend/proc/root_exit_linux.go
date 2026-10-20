//go:build linux

package proc

import (
	"context"
	"errors"
	"fmt"
	"os"
	"sync"
	"sync/atomic"

	"golang.org/x/sys/unix"
)

// rootExitObserver is read-only evidence of death, not authentication of
// the resumed process or permission to signal a possibly recycled PID.
type rootExitObserver interface {
	Exited() (bool, error)
	Wait(context.Context) error
	Close() error
}

type pidfdRootExit struct {
	file   *os.File
	poll   func([]unix.PollFd, int) (int, error)
	once   sync.Once
	err    error
	closed atomic.Bool
}

func observeRootExit(pid int) (rootExitObserver, error) {
	if pid <= 0 {
		return nil, fmt.Errorf("proc: invalid restored root pid %d: %w", pid, unix.EINVAL)
	}
	fd, err := unix.PidfdOpen(pid, 0)
	if err != nil {
		return nil, fmt.Errorf("proc: pidfd_open restored root %d: %w", pid, err)
	}
	if err := unix.SetNonblock(fd, true); err != nil {
		_ = unix.Close(fd)
		return nil, fmt.Errorf("proc: nonblocking root pidfd: %w", err)
	}
	return &pidfdRootExit{file: os.NewFile(uintptr(fd), "restored-root-pidfd"), poll: unix.Poll}, nil
}

func probeRootExit() error {
	o, err := observeRootExit(os.Getpid())
	if err != nil {
		return err
	}
	_, perr := o.Exited()
	cerr := o.Close()
	if perr != nil {
		return perr
	}
	return cerr
}

func (o *pidfdRootExit) pollExit(fd uintptr) (bool, error) {
	fds := []unix.PollFd{{Fd: int32(fd), Events: unix.POLLIN}}
	n, err := o.poll(fds, 0)
	if errors.Is(err, unix.EINTR) || errors.Is(err, unix.EAGAIN) {
		return false, nil
	}
	if err != nil {
		return false, err
	}
	if n == 0 {
		return false, nil
	}
	if fds[0].Revents&(unix.POLLIN|unix.POLLHUP) == 0 {
		return false, fmt.Errorf("proc: invalid root pidfd events %d", fds[0].Revents)
	}
	return true, nil
}

func (o *pidfdRootExit) Exited() (exited bool, err error) {
	if o.closed.Load() {
		return false, os.ErrClosed
	}
	raw, err := o.file.SyscallConn()
	if err != nil {
		return false, err
	}
	if cerr := raw.Control(func(fd uintptr) { exited, err = o.pollExit(fd) }); cerr != nil {
		return false, cerr
	}
	return exited, err
}

func (o *pidfdRootExit) Wait(ctx context.Context) error {
	stop := context.AfterFunc(ctx, func() { _ = o.Close() })
	defer stop()
	raw, err := o.file.SyscallConn()
	if err != nil {
		if ctx.Err() != nil {
			return ctx.Err()
		}
		if o.closed.Load() {
			return os.ErrClosed
		}
		return err
	}
	var exited bool
	var perr error
	err = raw.Read(func(fd uintptr) bool {
		exited, perr = o.pollExit(fd)
		return exited || perr != nil
	})
	if ctx.Err() != nil {
		return ctx.Err()
	}
	if o.closed.Load() {
		return os.ErrClosed
	}
	if perr != nil {
		return perr
	}
	if err != nil {
		return err
	}
	if !exited {
		return fmt.Errorf("proc: root pidfd wait ended without exit evidence")
	}
	return nil
}

func (o *pidfdRootExit) Close() error {
	o.once.Do(func() {
		o.closed.Store(true)
		o.err = o.file.Close()
	})
	return o.err
}
