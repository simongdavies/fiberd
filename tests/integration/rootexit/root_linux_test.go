//go:build linux && integration

package rootexittest

import (
	"context"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"slices"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"testing"
	"time"

	"golang.org/x/sys/unix"

	"github.com/helayoty/fiberd/pkg/backend"
	procbackend "github.com/helayoty/fiberd/pkg/backend/proc"
	"github.com/helayoty/fiberd/pkg/sys/criu"
)

// These tests exercise real process lifetimes and kernel pidfds through
// the public backend. CRIU and the guest record exchange remain fakes:
// no restore, cgroup delegation, hypervisor or privileged setup is needed.
type ownedProcess struct {
	cmd      *exec.Cmd
	waitOnce sync.Once
	stopOnce sync.Once
	waitErr  error
}

func startOwned(t *testing.T, cmd *exec.Cmd) *ownedProcess {
	t.Helper()
	if err := cmd.Start(); err != nil {
		t.Fatal(err)
	}
	p := &ownedProcess{cmd: cmd}
	t.Cleanup(func() { p.stop(t) })
	return p
}

func (p *ownedProcess) Pid() int    { return p.cmd.Process.Pid }
func (p *ownedProcess) Kill() error { return p.cmd.Process.Kill() }
func (p *ownedProcess) Wait() error {
	p.waitOnce.Do(func() { p.waitErr = p.cmd.Wait() })
	return p.waitErr
}

func (p *ownedProcess) stop(t *testing.T) {
	t.Helper()
	p.stopOnce.Do(func() {
		if err := p.Kill(); err != nil && !errors.Is(err, os.ErrProcessDone) && !errors.Is(err, syscall.ESRCH) {
			t.Errorf("kill owned process %d: %v", p.Pid(), err)
		}
		var exited *exec.ExitError
		if err := p.Wait(); err != nil && !errors.As(err, &exited) {
			t.Errorf("reap owned process %d: %v", p.Pid(), err)
		}
	})
}

type fakeCommander struct {
	t                 *testing.T
	supervisorCommand string
	deadBeforeCapture bool
	root              *ownedProcess
	supervisor        *ownedProcess
}

func (*fakeCommander) Output(_ context.Context, args []string) ([]byte, error) {
	if len(args) > 0 {
		switch args[0] {
		case "--version":
			return []byte("Version: 4.2.1"), nil
		case "check":
			return nil, nil
		}
	}
	return nil, fmt.Errorf("unexpected fake CRIU command %v", args)
}

func (c *fakeCommander) Start(args []string, _ []*os.File, _ int) (criu.Process, error) {
	c.root = startOwned(c.t, exec.Command("/bin/sleep", "30"))
	if c.deadBeforeCapture {
		if err := c.root.Kill(); err != nil {
			return nil, err
		}
		var info unix.Siginfo
		if err := unix.Waitid(unix.P_PID, c.root.Pid(), &info, unix.WEXITED|unix.WNOWAIT, nil); err != nil {
			return nil, err
		}
	}
	i := slices.Index(args, "--pidfile")
	if i < 0 || i+1 >= len(args) {
		return nil, errors.New("fake restore has no pidfile argument")
	}
	if err := os.WriteFile(args[i+1], []byte(strconv.Itoa(c.root.Pid())), 0o600); err != nil {
		return nil, err
	}
	c.supervisor = startOwned(c.t, exec.Command("/bin/sh", "-c", c.supervisorCommand))
	return c.supervisor, nil
}

type fixture struct {
	be        *procbackend.Backend
	commander *fakeCommander
	fiber     *os.File
	peer      *os.File
	guestDone chan struct{}
	guestErr  chan error
}

const fence = "g/2/1"

func newFixture(t *testing.T, command string, alreadyDead bool) *fixture {
	t.Helper()
	fd, err := unix.PidfdOpen(os.Getpid(), 0)
	if err != nil {
		t.Skipf("native pidfd unavailable: %v", err)
	}
	if err := unix.Close(fd); err != nil {
		t.Fatal(err)
	}
	f := &fixture{commander: &fakeCommander{t: t, supervisorCommand: command, deadBeforeCapture: alreadyDead}}
	t.Cleanup(func() {
		if f.be != nil {
			f.be.Close()
		}
		if f.fiber != nil {
			_ = f.fiber.Close()
		}
		if f.peer != nil {
			_ = f.peer.Close()
		}
		if f.guestDone != nil {
			select {
			case <-f.guestDone:
			case <-time.After(time.Second):
				t.Error("fake guest record reader did not stop")
			}
		}
	})
	pair, err := unix.Socketpair(unix.AF_UNIX, unix.SOCK_SEQPACKET|unix.SOCK_CLOEXEC|unix.SOCK_NONBLOCK, 0)
	if err != nil {
		t.Fatal(err)
	}
	f.fiber, f.peer = os.NewFile(uintptr(pair[0]), "fake-fiber"), os.NewFile(uintptr(pair[1]), "fake-peer")
	f.guestDone, f.guestErr = make(chan struct{}), make(chan error, 1)
	go func() {
		defer close(f.guestDone)
		buf := make([]byte, backend.RecordMax)
		n, err := f.fiber.Read(buf)
		if err != nil {
			f.guestErr <- err
			return
		}
		inc, err := backend.ParseIncarnation(buf[:n])
		if err != nil {
			f.guestErr <- err
			return
		}
		if inc.Fence != fence {
			f.guestErr <- errors.New("fake guest received the wrong fence")
			return
		}
		_, err = f.fiber.Write(backend.Record(backend.RecordAck, fence))
		f.guestErr <- err
	}()
	f.be = procbackend.NewBackend(procbackend.Options{Commander: f.commander,
		RootBind: filepath.Join(t.TempDir(), "root"),
		Borrow: func(pid, _ int) (*os.File, error) {
			if f.commander.root == nil || pid != f.commander.root.Pid() {
				return nil, syscall.ESRCH
			}
			raw, err := f.peer.SyscallConn()
			if err != nil {
				return nil, err
			}
			var duplicate int
			var dupErr error
			if err := raw.Control(func(fd uintptr) {
				duplicate, dupErr = unix.Dup(int(fd))
				if dupErr == nil {
					unix.CloseOnExec(duplicate)
				}
			}); err != nil {
				return nil, err
			}
			if dupErr != nil {
				return nil, dupErr
			}
			return os.NewFile(uintptr(duplicate), "borrowed-fake-peer"), nil
		}})
	return f
}

func (f *fixture) resume(t *testing.T) (backend.Fiber, error) {
	t.Helper()
	fb, err := f.be.Resume(context.Background(), backend.ResumeSpec{Dir: t.TempDir(), Fence: fence,
		Endpoint: filepath.Join(t.TempDir(), "fiber.sock"), CgroupFD: -1, Deadline: time.Second, Generation: 2})
	if err == nil {
		if err := <-f.guestErr; err != nil {
			t.Fatalf("fake guest did not acknowledge the resume: %v", err)
		}
	}
	return fb, err
}

func noExit(t *testing.T, f *fixture) {
	t.Helper()
	select {
	case e := <-f.be.Exits():
		t.Fatalf("supervisor completion or cancellation supplied root exit proof: %+v", e)
	case <-time.After(30 * time.Millisecond):
	}
}

func rootExited(t *testing.T, f *fixture) {
	t.Helper()
	select {
	case e := <-f.be.Exits():
		if e != (backend.Exit{FiberID: fence, Status: "exited"}) {
			t.Fatalf("root exit = %+v", e)
		}
	case <-time.After(time.Second):
		t.Fatal("actual root death was not observed")
	}
	noExit(t, f)
}

func TestSupervisorCompletionIsNotRootExit(t *testing.T) {
	for _, command := range []string{"exit 0", "exit 3", "kill -TERM $$"} {
		t.Run(command, func(t *testing.T) {
			f := newFixture(t, command, false)
			if _, err := f.resume(t); err != nil {
				t.Fatal(err)
			}
			err := f.commander.supervisor.Wait()
			if (err == nil) != (command == "exit 0") {
				t.Fatalf("unexpected supervisor result: %v", err)
			}
			if err := f.commander.root.cmd.Process.Signal(syscall.Signal(0)); err != nil {
				t.Fatal(err)
			}
			noExit(t, f)
			f.commander.root.stop(t)
			rootExited(t, f)
		})
	}
}

func TestRootGoneBeforeCaptureRefusesServing(t *testing.T) {
	f := newFixture(t, "exec sleep 30", true)
	if fb, err := f.resume(t); !errors.Is(err, syscall.ESRCH) || fb.ID != "" {
		t.Fatalf("dead root returned a serving handle: %+v, %v", fb, err)
	}
	noExit(t, f)
}

func pidfdCount(t *testing.T) int {
	t.Helper()
	files, err := os.ReadDir("/proc/self/fd")
	if err != nil {
		t.Fatal(err)
	}
	n := 0
	for _, file := range files {
		target, err := os.Readlink(filepath.Join("/proc/self/fd", file.Name()))
		if err == nil && strings.Contains(target, "[pidfd]") {
			n++
		}
	}
	return n
}

func TestBackendCloseClosesOnlyTheObserver(t *testing.T) {
	f := newFixture(t, "exec sleep 30", false)
	if _, err := f.resume(t); err != nil {
		t.Fatal(err)
	}
	during := pidfdCount(t)
	f.be.Close()
	after := pidfdCount(t)
	if during-after != 1 {
		t.Fatalf("backend close did not release exactly its root pidfd: during=%d after=%d", during, after)
	}
	if err := f.commander.root.cmd.Process.Signal(syscall.Signal(0)); err != nil {
		t.Fatal(err)
	}
	noExit(t, f)
}

func TestModeledReplacementCanOnlyDelayRootProof(t *testing.T) {
	original := startOwned(t, exec.Command("/bin/sleep", "30"))
	original.stop(t)
	f := newFixture(t, "exit 0", false)
	if _, err := f.resume(t); err != nil {
		t.Fatal(err)
	}
	// Model capture after PID reuse using a different actual live process.
	// This does not claim to force the kernel to recycle a numeric PID.
	if original.cmd.ProcessState == nil {
		t.Fatal("the original process was not reaped before candidate capture")
	}
	if err := f.commander.root.cmd.Process.Signal(syscall.Signal(0)); err != nil {
		t.Fatal(err)
	}
	noExit(t, f)
	f.commander.root.stop(t)
	rootExited(t, f)
}
