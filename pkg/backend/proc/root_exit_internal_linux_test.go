//go:build linux

package proc

import (
	"context"
	"errors"
	"os"
	"testing"
	"time"

	"golang.org/x/sys/unix"

	"github.com/helayoty/fiberd/pkg/backend"
	"github.com/helayoty/fiberd/pkg/sys/criu"
)

// Real process lifetimes are tested through the public backend in
// tests/integration/rootexit. Unit cases keep the observer seam process-free.
func TestRootObserverCancellationIsNotExit(t *testing.T) {
	o, err := observeRootExit(os.Getpid())
	if err != nil {
		t.Skipf("native root observer unavailable: %v", err)
	}
	t.Cleanup(func() { _ = o.Close() })
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Millisecond)
	defer cancel()
	if err := o.Wait(ctx); !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("cancellation supplied exit proof: %v", err)
	}
	if _, err := o.Exited(); !errors.Is(err, os.ErrClosed) {
		t.Fatalf("canceled watcher leaked its descriptor: %v", err)
	}
}

func TestRootObserverRejectsPollFailures(t *testing.T) {
	for _, tc := range []struct {
		name   string
		events int16
	}{
		{name: "raw poll error"},
		{name: "invalid descriptor", events: unix.POLLNVAL},
	} {
		t.Run(tc.name, func(t *testing.T) {
			o, err := observeRootExit(os.Getpid())
			if err != nil {
				t.Skipf("native pidfd unavailable: %v", err)
			}
			t.Cleanup(func() { _ = o.Close() })
			native := o.(*pidfdRootExit)
			native.poll = func(fds []unix.PollFd, _ int) (int, error) {
				if tc.events == 0 {
					return 0, unix.EIO
				}
				fds[0].Revents = tc.events
				return 1, nil
			}
			if exited, err := o.Exited(); exited || err == nil {
				t.Fatalf("poll failure supplied death proof: %v, %v", exited, err)
			}
			if err := o.Wait(context.Background()); err == nil {
				t.Fatal("failed poll completed root wait")
			}
		})
	}
}

func TestRootWatcherCloseWithFullExitQueue(t *testing.T) {
	rootEnded := make(chan struct{})
	o := &fakeRootExit{done: rootEnded}
	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)
	f := &fiber{id: "f", restored: &criu.Restored{}}
	b := &Backend{fibers: map[string]*fiber{"f": f}, exits: make(chan backend.Exit, 1),
		rootCtx: ctx, stopRoots: cancel}
	b.exits <- backend.Exit{FiberID: "older"}
	b.rootWaiters.Add(1)
	go b.watchRoot(f, o, func() {})
	close(rootEnded)
	waitFor(t, "root exit is recorded before queue delivery", func() bool {
		b.mu.Lock()
		defer b.mu.Unlock()
		return b.fibers["f"] == nil
	})
	closed := make(chan struct{})
	go func() { b.Close(); close(closed) }()
	select {
	case <-closed:
	case <-time.After(time.Second):
		t.Fatal("backend close leaked a watcher behind exit-queue backpressure")
	}
	if _, err := o.Exited(); !errors.Is(err, os.ErrClosed) {
		t.Fatalf("watcher did not close its observer: %v", err)
	}
}
