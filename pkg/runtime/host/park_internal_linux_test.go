//go:build linux

package host

import (
	"context"
	"crypto/sha256"
	"errors"
	"fmt"
	"maps"
	"net"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"syscall"
	"testing"
	"time"

	"github.com/helayoty/fiberd/pkg/artifact"
	"github.com/helayoty/fiberd/pkg/backend"
	"github.com/helayoty/fiberd/pkg/core"
	"github.com/helayoty/fiberd/pkg/endpoint"
)

type parkGrantVerifier struct{ grant core.Grant }

func (v parkGrantVerifier) Verify(context.Context, []byte) (core.Grant, error) {
	return v.grant, nil
}

type observedParkRuntime struct {
	*Runtime
	published int
}

func (*observedParkRuntime) PublishesDeltas() bool { return true }

func (r *observedParkRuntime) PublishDelta(context.Context, string, core.Grant, string) (string, error) {
	r.published++
	return "published", nil
}

func TestCoreParkPublicationConfiguration(t *testing.T) {
	for _, configured := range []bool{false, true} {
		t.Run(fmt.Sprintf("registry_configured=%v", configured), func(t *testing.T) {
			g := core.Grant{UID: "g1", Tenant: "acme", TemplateDigest: "sha256:tmpl", FiberMax: 1, WBudgetBytes: 64 * mib,
				Policy: core.Policy{Isolation: core.Trusted}}
			rt := newTestRuntime(t, newCodecBackend(core.TierCheckpoint), func(cfg *Config) {
				if configured {
					cfg.DeltaRegistry = artifact.FileScheme + filepath.Join(t.TempDir(), "registry")
					cfg.DeltaKeys = artifact.Keys{Signer: signingKey(t, "home"),
						Seal: &artifact.SealKey{ID: "seal", Key: make([]byte, 32)}}
				}
			})
			a := &core.Core{Runtime: rt, Ledger: core.NewLedger(1), Verify: parkGrantVerifier{g},
				RateLimit: core.NewRateLimit(1000, 256<<20),
				Store:     &core.SnapshotStore{Path: filepath.Join(t.TempDir(), "ledger.json")}}
			ctx := context.Background()
			req := core.CloneRequest{GrantJWT: []byte("grant"), Session: "S", Deadline: time.Second}
			first, code, err := a.Clone(ctx, req)
			if err != nil || code != core.OK {
				t.Fatalf("Clone = %d, %v", code, err)
			}
			if configured {
				blocked := filepath.Join(t.TempDir(), "not-a-directory")
				if err := os.WriteFile(blocked, []byte("blocked"), 0o600); err != nil {
					t.Fatal(err)
				}
				rt.cfg.DeltaRegistry = artifact.FileScheme + filepath.Join(blocked, "registry")
			}
			ref, code, err := a.Park(ctx, first.FiberID, true)
			if ref == "" || !rt.HasDelta(ref) {
				t.Fatalf("Park lost the checkpoint: %q, %d, %v", ref, code, err)
			}
			if configured {
				if code != core.Internal || !errors.Is(err, syscall.ENOTDIR) {
					t.Fatalf("configured publication failure = %d, %v", code, err)
				}
			} else if code != core.OK || err != nil {
				t.Fatalf("local-only Park = %d, %v", code, err)
			}
			snap, err := a.Store.Load()
			if err != nil || len(snap.Sessions) != 1 || snap.Sessions[0].State != core.StateParked || snap.Sessions[0].DeltaRef != ref {
				t.Fatalf("saved checkpoint = %+v, %v", snap, err)
			}
			resumed, code, err := a.Clone(ctx, req)
			if err != nil || code != core.OK || resumed.Kind != core.ActResume {
				t.Fatalf("local resume = %+v, %d, %v", resumed, code, err)
			}
		})
	}
}

func TestCoreParkWaitFailureKeepsCapacity(t *testing.T) {
	oldWait := parkExitWait
	parkExitWait = 30 * time.Millisecond
	t.Cleanup(func() { parkExitWait = oldWait })
	killErr := errors.New("fake: kill denied")
	for _, tc := range []struct {
		name    string
		sync    bool
		cancel  bool
		killErr error
	}{
		{name: "async timeout"},
		{name: "sync timeout", sync: true},
		{name: "async canceled", cancel: true},
		{name: "sync canceled", sync: true, cancel: true},
		{name: "sync kill failure", sync: true, killErr: killErr},
	} {
		t.Run(tc.name, func(t *testing.T) {
			g := core.Grant{UID: "g1", Tenant: "acme", TemplateDigest: "sha256:tmpl", FiberMax: 1, WBudgetBytes: 64 * mib,
				Policy: core.Policy{Isolation: core.Trusted}}
			be := newCodecBackend(core.TierCheckpoint)
			be.noExit = true
			be.killErr = tc.killErr
			rt := newTestRuntime(t, be, nil)
			observed := &observedParkRuntime{Runtime: rt}
			a := &core.Core{Runtime: observed, Ledger: core.NewLedger(1), Verify: parkGrantVerifier{g},
				RateLimit: core.NewRateLimit(1000, 256<<20),
				Store:     &core.SnapshotStore{Path: filepath.Join(t.TempDir(), "ledger.json")}}
			ctx := context.Background()
			req := core.CloneRequest{GrantJWT: []byte("grant"), Session: "S", Deadline: time.Second}
			first, code, err := a.Clone(ctx, req)
			if err != nil || code != core.OK {
				t.Fatalf("Clone = %d, %v", code, err)
			}
			pctx := ctx
			wantErr := context.DeadlineExceeded
			if tc.cancel {
				var cancel context.CancelFunc
				pctx, cancel = context.WithCancel(ctx)
				cancel()
				wantErr = context.Canceled
			}
			ref, code, err := a.Park(pctx, first.FiberID, tc.sync)
			if ref == "" || !rt.HasDelta(ref) || code != core.Internal || !errors.Is(err, wantErr) ||
				!errors.Is(err, core.ErrParkUnconfirmed) || (tc.killErr != nil && !errors.Is(err, tc.killErr)) {
				t.Fatalf("Park without confirmed exit = %q, %d, %v", ref, code, err)
			}
			status := a.Ledger.Statuses()[0]
			if status.Running != 1 || status.Parked != 0 {
				t.Fatalf("unconfirmed termination freed capacity: %+v", status)
			}
			if observed.published != 0 {
				t.Fatal("unconfirmed park was published")
			}
			if _, known := a.Ledger.Fiber(first.FiberID); !known {
				t.Fatal("the unconfirmed fiber left the ledger")
			}
			snap, err := a.Store.Load()
			if err != nil || len(snap.Sessions) != 1 || snap.Sessions[0].PendingParkRef != ref || snap.Sessions[0].State != core.StateRunning {
				t.Fatalf("pending checkpoint not preserved in snapshot: %+v, %v", snap, err)
			}
			before, err := treeHashes(ref)
			if err != nil {
				t.Fatal(err)
			}
			a.OnExit(ctx, core.FiberExit{FiberID: first.FiberID, Reason: "exit"})
			if again, _, err := a.Park(pctx, first.FiberID, tc.sync); again != ref || !errors.Is(err, core.ErrParkUnconfirmed) || len(be.parked()) != 1 {
				t.Fatalf("retry redumped or lost pending park: %q, %v, dumps=%d", again, err, len(be.parked()))
			}
			again, _, err := a.Clone(ctx, req)
			if err == nil || again.FiberID != "" {
				t.Fatalf("pending park attached/restored a nonserving session: %+v, %v", again, err)
			}
			req.Session = "another"
			if _, _, err := a.Clone(ctx, req); !errors.Is(err, core.ErrGrantFull) {
				t.Fatalf("another session did not retain the capacity limit: %v", err)
			}
			noExit(t, rt)
			be.die(first.FiberID, "signal:SIGKILL")
			rt.mu.Lock()
			pending := rt.parks[first.FiberID]
			rt.mu.Unlock()
			select {
			case <-pending.done:
			case <-time.After(time.Second):
				t.Fatal("late exit was not reaped")
			}
			completed, code, err := a.Park(ctx, first.FiberID, tc.sync)
			if completed != ref || code != core.OK || err != nil || len(be.parked()) != 1 {
				t.Fatalf("late completion = %q, %d, %v", completed, code, err)
			}
			after, err := treeHashes(ref)
			if err != nil || !maps.Equal(before, after) {
				t.Fatalf("retry changed checkpoint: %v", err)
			}
			status = a.Ledger.Statuses()[0]
			if status.Running != 0 || status.Parked != 1 || len(rt.parks) != 0 {
				t.Fatalf("completed park leaked accounting/receipt: %+v", status)
			}
			if observed.published != 1 {
				t.Fatalf("confirmed park published %d times", observed.published)
			}
			noExit(t, rt)
			req.Session = "S"
			resumed, code, err := a.Clone(ctx, req)
			if code != core.OK || err != nil || resumed.Kind != core.ActResume {
				t.Fatalf("resume completed park = %+v, %d, %v", resumed, code, err)
			}
		})
	}
}

func TestRecoveredParkQuarantinesEndpoints(t *testing.T) {
	for _, mode := range []string{"unix", "tcp", "handoff"} {
		t.Run(mode, func(t *testing.T) {
			rt := newTestRuntime(t, newCodecBackend(core.TierCheckpoint), func(cfg *Config) {
				cfg.Endpoints = endpoint.Policy{Family: endpoint.Inet4, Host: "127.0.0.1", PortMin: 32001, PortMax: 32002}
			})
			fence := core.Fence{GrantUID: "g1", Epoch: 1, Seq: 1}
			ref := rt.deltaDir(fence)
			m := manifest{Fence: fence.String(), GrantUID: "g1", Endpoint: "tcp://127.0.0.1:32001"}
			switch mode {
			case "unix":
				m.Endpoint = "unix://" + rt.unixPath(fence)
			case "handoff":
				m.Handoff, m.Endpoint = true, ""
			}
			write(t, ref, map[string]string{"pages.img": "saved state"})
			if err := writeJSON(filepath.Join(ref, "manifest.json"), m); err != nil {
				t.Fatal(err)
			}
			ctx := context.Background()
			if err := rt.QuarantinePark(ctx, fence.String(), ref); err != nil {
				t.Fatal(err)
			}
			switch mode {
			case "tcp":
				if _, err := rt.allocPort("replacement", 32001); err == nil {
					t.Fatal("pending TCP endpoint was reused")
				}
				if _, err := rt.allocPort("unrelated", 0); err != nil {
					t.Fatalf("unrelated endpoint blocked: %v", err)
				}
			case "unix":
				if err := rt.claimSocket(rt.unixPath(fence), "replacement"); err == nil {
					t.Fatal("pending socket was reused")
				}
			}
			for _, discard := range []bool{false, true} {
				if err := rt.Release(ctx, fence.String(), discard); !errors.Is(err, core.ErrParkUnconfirmed) {
					t.Fatalf("quarantined release without proof = %v", err)
				}
			}
			if got, err := rt.Park(ctx, fence.String(), true); got != ref || !errors.Is(err, core.ErrParkUnconfirmed) {
				t.Fatalf("quarantined Park without proof = %q, %v", got, err)
			}
			if !exists(filepath.Join(ref, "pages.img")) || len(rt.be.(*codecBackend).killedIDs()) != 0 {
				t.Fatal("quarantine discarded saved state or inferred a killable incarnation")
			}
			seedCgroup(t, rt.root.Child("g1"), liveFiles)
			rt.PruneGrants(map[string]bool{})
			if !rt.root.Child("g1").Exists() {
				t.Fatal("grant pruning removed quarantined state")
			}
		})
	}
}

func TestPendingParkDetachesRelay(t *testing.T) {
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	port := listener.Addr().(*net.TCPAddr).Port
	if err := listener.Close(); err != nil {
		t.Fatal(err)
	}
	be := newCodecBackend(core.TierCheckpoint)
	be.noExit = true
	g := core.Grant{UID: "g1", TemplateDigest: "sha256:tmpl", FiberMax: 1}
	f := newParkFixture(t, be, g, func(cfg *Config) {
		cfg.Endpoints = endpoint.Policy{Family: endpoint.Inet4, Host: "127.0.0.1", PortMin: port, PortMax: port}
	})
	f.r.mu.Lock()
	fiber := f.r.fibers[f.h.ID]
	f.r.mu.Unlock()
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	ref, err := f.r.Park(ctx, f.h.ID, true)
	if !errors.Is(err, core.ErrParkUnconfirmed) || !f.r.HasDelta(ref) {
		t.Fatalf("Park = %q, %v", ref, err)
	}
	fiber.relay.mu.Lock()
	closed := fiber.relay.closed
	fiber.relay.mu.Unlock()
	if !closed {
		t.Fatal("pending park still routes connections")
	}
	if _, err := f.r.allocPort("replacement", 0); err == nil {
		t.Fatal("detaching the relay freed the pending endpoint reservation")
	}
}

func TestWarmLossDoesNotConfirmPendingTermination(t *testing.T) {
	be := newCodecBackend(core.TierCheckpoint)
	be.noExit, be.killErr = true, errors.New("fake: kill failed")
	g := core.Grant{UID: "g1", TemplateDigest: "sha256:tmpl", FiberMax: 1}
	f := newParkFixture(t, be, g, nil)
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	ref, err := f.r.Park(ctx, f.h.ID, true)
	if !errors.Is(err, core.ErrParkUnconfirmed) {
		t.Fatal(err)
	}
	f.r.mu.Lock()
	pending := f.r.parks[f.h.ID]
	f.r.mu.Unlock()
	plainOnly(t)
	killPath := filepath.Join(pending.cg.Path, "cgroup.kill")
	if err := os.Remove(killPath); err != nil {
		t.Fatal(err)
	}
	if err := os.Mkdir(killPath, 0o700); err != nil {
		t.Fatal(err)
	}
	f.r.DropTemplate("g1")
	f.r.warmGone("g1")
	if got, err := f.r.Park(ctx, f.h.ID, true); got != ref || !errors.Is(err, core.ErrParkUnconfirmed) {
		t.Fatalf("warm control loss falsely completed pending park: %q, %v", got, err)
	}
	if !f.r.HasDelta(ref) {
		t.Fatal("warm loss discarded checkpoint")
	}
	select {
	case <-pending.terminated:
		t.Fatal("synthetic cleanup supplied a positive termination receipt")
	default:
	}
	be.die(f.h.ID, "signal:SIGKILL")
	select {
	case <-pending.terminated:
	case <-time.After(time.Second):
		t.Fatal("actual exit was not confirmed")
	}
	if got, err := f.r.Park(ctx, f.h.ID, true); got != ref || err != nil {
		t.Fatalf("actual exit did not complete the retained park: %q, %v", got, err)
	}
}

func TestFailedParkSettlesProvisionalSupervisionLoss(t *testing.T) {
	be := newCodecBackend(core.TierCheckpoint)
	be.noExit = true
	be.parkErr = errors.New("fake helper: control channel lost during park")
	gate := make(chan struct{})
	be.parkGate = gate
	g := core.Grant{UID: "g1", Tenant: "acme", TemplateDigest: "sha256:tmpl", FiberMax: 1,
		Policy: core.Policy{Isolation: core.Trusted}}
	rt := newTestRuntime(t, be, nil)
	a := &core.Core{Runtime: rt, Ledger: core.NewLedger(1), Verify: parkGrantVerifier{g},
		RateLimit: core.NewRateLimit(1000, 256<<20)}
	ctx := context.Background()
	first, code, err := a.Clone(ctx, core.CloneRequest{GrantJWT: []byte("grant"), Session: "S", Deadline: time.Second})
	if err != nil || code != core.OK {
		t.Fatalf("Clone = %d, %v", code, err)
	}
	rt.mu.Lock()
	f := rt.fibers[first.FiberID]
	rt.mu.Unlock()
	done := make(chan error, 1)
	go func() {
		_, _, err := a.Park(ctx, first.FiberID, true)
		done <- err
	}()
	waitFor(t, "park enters the helper barrier", func() bool { return len(be.parked()) == 1 })
	be.report(backend.Exit{FiberID: first.FiberID, Status: "signal:helper", Unconfirmed: true})
	waitFor(t, "pump retains provisional supervision loss", func() bool {
		rt.mu.Lock()
		defer rt.mu.Unlock()
		return f.supervisionLoss != nil
	})
	rt.warmGone("g1")
	close(gate)
	if err := <-done; !errors.Is(err, be.parkErr) {
		t.Fatalf("failed Park = %v", err)
	}
	select {
	case ex := <-rt.Exits():
		a.OnExit(ctx, ex)
	case <-time.After(time.Second):
		t.Fatal("failed park dropped provisional supervision loss; ghost fiber remains")
	}
	if _, known := a.Ledger.Fiber(first.FiberID); known {
		t.Fatal("failed park left an attachable running ledger entry")
	}
	rt.mu.Lock()
	_, live := rt.fibers[first.FiberID]
	rt.mu.Unlock()
	if live || len(rt.parks) != 0 {
		t.Fatal("ordinary failed-park cleanup left a ghost runtime entry")
	}
	select {
	case <-f.done:
	default:
		t.Fatal("ordinary failed-park cleanup did not settle its cleanup receipt")
	}
	select {
	case <-f.terminated:
		t.Fatal("supervision-loss cleanup was upgraded to positive termination proof")
	default:
	}
	noExit(t, rt)
}

func TestResumeCannotStealQuarantinedPort(t *testing.T) {
	be := newSandboxBackend(core.TierCheckpoint)
	rt := newTestRuntime(t, be, func(cfg *Config) {
		cfg.Endpoints = endpoint.Policy{Family: endpoint.Inet4, Host: "127.0.0.1", PortMin: 32001, PortMax: 32001}
	})
	old := core.Fence{GrantUID: "old", Epoch: 1, Seq: 1}
	ref := rt.deltaDir(old)
	m := manifest{Fence: old.String(), GrantUID: old.GrantUID, Endpoint: "tcp://127.0.0.1:32001", Backend: "fake"}
	write(t, ref, map[string]string{"pages.img": "saved"})
	if err := writeJSON(filepath.Join(ref, "manifest.json"), m); err != nil {
		t.Fatal(err)
	}
	ctx := context.Background()
	if err := rt.QuarantinePark(ctx, old.String(), ref); err != nil {
		t.Fatal(err)
	}
	g := core.Grant{UID: "other", TemplateDigest: "sha256:tmpl", FiberMax: 1}
	if err := rt.PrepareTemplate(ctx, g); err != nil {
		t.Fatal(err)
	}
	claimed := filepath.Join(rt.cfg.DeltaDir, "other", "claimed")
	write(t, claimed, map[string]string{"pages.img": "claimed"})
	if err := writeJSON(filepath.Join(claimed, "manifest.json"), m); err != nil {
		t.Fatal(err)
	}
	be.resumeErr = errors.New("fake: restore failed")
	_, err := rt.Clone(ctx, core.CloneSpec{Grant: g, Source: core.SourceDelta, Ref: claimed,
		Fence: core.Fence{GrantUID: g.UID, Epoch: 2, Seq: 1}})
	if err == nil {
		t.Fatal("colliding restore succeeded")
	}
	rt.mu.Lock()
	holder := rt.ports[32001]
	rt.mu.Unlock()
	if holder != old.String() {
		t.Fatalf("restore failure stole quarantined reservation: %q", holder)
	}
}

func TestRelayedConsumedDeltaCannotFreePendingPort(t *testing.T) {
	be := relayBackend(core.TierCheckpoint)
	be.noExit = true
	g := core.Grant{UID: "g1", Tenant: "acme", TemplateDigest: "sha256:tmpl", FiberMax: 3,
		Policy: core.Policy{Isolation: core.Trusted}}
	rt := newTestRuntime(t, be, func(cfg *Config) {
		cfg.Endpoints = endpoint.Policy{Family: endpoint.Inet4, Host: "127.0.0.1", PortMin: 20000, PortMax: 20001}
	})
	a := &core.Core{Runtime: rt, Ledger: core.NewLedger(1), Verify: parkGrantVerifier{g},
		RateLimit: core.NewRateLimit(1000, 256<<20)}
	ctx := context.Background()
	req := core.CloneRequest{GrantJWT: []byte("grant"), Session: "pending", Deadline: time.Second}
	first, code, err := a.Clone(ctx, req)
	if err != nil || code != core.OK {
		t.Fatalf("Clone = %d, %v", code, err)
	}
	oldEndpoint, err := endpoint.Parse(first.Endpoint)
	if err != nil {
		t.Fatal(err)
	}
	canceled, cancel := context.WithCancel(ctx)
	cancel()
	saved, _, err := a.Park(canceled, first.FiberID, true)
	if !errors.Is(err, core.ErrParkUnconfirmed) {
		t.Fatalf("pending Park = %v", err)
	}
	rt.mu.Lock()
	pending := rt.parks[first.FiberID]
	rt.mu.Unlock()
	be.mu.Lock()
	be.noExit = false
	be.mu.Unlock()
	claimed := filepath.Join(rt.cfg.DeltaDir, "g1", "claimed-foreign")
	write(t, claimed, map[string]string{"pages.img": "foreign saved state"})
	m := manifest{Fence: first.FiberID, GrantUID: "g1", Backend: "fake", Endpoint: first.Endpoint,
		Relay: filepath.Join(rt.cfg.RunDir, "g1", "foreign.sock")}
	if err := writeJSON(filepath.Join(claimed, "manifest.json"), m); err != nil {
		t.Fatal(err)
	}
	if !a.Ledger.RestoreParked(core.SessionSnapshot{Name: "foreign", GrantUID: "g1", State: core.StateParked, DeltaRef: claimed}) {
		t.Fatal("could not register the unrelated claimed checkpoint")
	}
	req.Session = "foreign"
	resumed, code, err := a.Clone(ctx, req)
	if err != nil || code != core.OK || resumed.Kind != core.ActResume || resumed.Endpoint == first.Endpoint {
		t.Fatalf("relay fallback resume = %+v, %d, %v", resumed, code, err)
	}
	if got := mustSay(t, resumed.Endpoint, "ping"); got != resumed.FiberID+":ping" {
		t.Fatalf("relayed resumed fiber answered %q", got)
	}
	if _, err := a.Release(ctx, resumed.FiberID, true); err != nil {
		t.Fatal(err)
	}
	if exists(claimed) {
		t.Fatal("consumed source was not discarded")
	}
	// All cleanup callers, not only DiscardDelta, must check active
	// ownership before releasing reservations named by a checkpoint.
	rt.freePorts(first.FiberID)
	req.Session = "probe"
	probe, code, err := a.Clone(ctx, req)
	if err != nil || code != core.OK {
		t.Fatalf("probe clone = %d, %v", code, err)
	}
	probeEndpoint, err := endpoint.Parse(probe.Endpoint)
	if err != nil {
		t.Fatal(err)
	}
	rt.mu.Lock()
	holder := rt.ports[oldEndpoint.Port]
	stillPending := rt.parks[first.FiberID] == pending
	rt.mu.Unlock()
	if holder != first.FiberID || !stillPending || probeEndpoint.Port == oldEndpoint.Port || !rt.HasDelta(saved) {
		t.Fatalf("checkpoint cleanup reused pending endpoint: holder=%q pending=%v probe=%s", holder, stillPending, probe.Endpoint)
	}
	be.die(first.FiberID, "signal:SIGKILL")
	select {
	case <-pending.terminated:
	case <-time.After(time.Second):
		t.Fatal("late root exit was not confirmed")
	}
	if _, code, err := a.Park(ctx, first.FiberID, true); code != core.OK || err != nil {
		t.Fatalf("confirmed pending Park = %d, %v", code, err)
	}
	a.Ledger.ForgetSession("g1", "pending")
	if err := rt.DiscardDelta(ctx, saved); err != nil {
		t.Fatal(err)
	}
	if _, err := rt.allocPort("completed-probe", oldEndpoint.Port); err != nil {
		t.Fatalf("legitimate completed checkpoint cleanup leaked its port: %v", err)
	}
	rt.freePort(oldEndpoint.Port, "completed-probe")
}

func TestPendingParkReleaseAndRevocation(t *testing.T) {
	for _, action := range []string{"release", "discard", "yield", "epoch", "anonymous discard"} {
		t.Run(action, func(t *testing.T) {
			g := core.Grant{UID: "g1", Tenant: "acme", TemplateDigest: "sha256:tmpl", FiberMax: 1,
				Policy: core.Policy{Isolation: core.Trusted}}
			be := newCodecBackend(core.TierCheckpoint)
			be.noExit = true
			rt := newTestRuntime(t, be, nil)
			a := &core.Core{Runtime: rt, Ledger: core.NewLedger(1), Verify: parkGrantVerifier{g},
				RateLimit: core.NewRateLimit(1000, 256<<20),
				Store:     &core.SnapshotStore{Path: filepath.Join(t.TempDir(), "ledger.json")}}
			ctx, cancel := context.WithCancel(context.Background())
			req := core.CloneRequest{GrantJWT: []byte("grant"), Session: "S", Deadline: time.Second}
			if action == "anonymous discard" {
				req.Session = ""
			}
			first, code, err := a.Clone(ctx, req)
			if err != nil || code != core.OK {
				t.Fatalf("Clone = %d, %v", code, err)
			}
			cancel()
			ref, _, err := a.Park(ctx, first.FiberID, true)
			if !errors.Is(err, core.ErrParkUnconfirmed) {
				t.Fatalf("pending Park = %v", err)
			}
			switch action {
			case "yield":
				a.Yield(ctx, "g1", "test")
				if _, err := a.Admit(context.Background(), g); err != nil {
					t.Fatal(err)
				}
			case "epoch":
				a.Epoch, err = core.OpenEpochStore(t.TempDir())
				if err != nil {
					t.Fatal(err)
				}
				if _, err := a.BumpEpoch(ctx, "test"); err != nil {
					t.Fatal(err)
				}
			default:
				if _, err := a.Release(ctx, first.FiberID, action != "release"); !errors.Is(err, core.ErrParkUnconfirmed) {
					t.Fatalf("release without exit proof = %v", err)
				}
			}
			saved, err := a.Store.Load()
			if err != nil || len(saved.Sessions) != 1 || saved.Sessions[0].PendingParkRef != ref {
				t.Fatalf("lost pending snapshot: %+v, %v", saved, err)
			}
			if a.Ledger.Statuses()[0].Running != 1 || !rt.HasDelta(ref) {
				t.Fatal("unconfirmed revocation/release freed capacity or checkpoint")
			}
			rt.mu.Lock()
			pending := rt.parks[first.FiberID]
			rt.mu.Unlock()
			be.die(first.FiberID, "signal:SIGKILL")
			select {
			case <-pending.done:
			case <-time.After(time.Second):
				t.Fatal("exit not reaped")
			}
			discard := action == "discard" || action == "anonymous discard"
			if _, err := a.Release(context.Background(), first.FiberID, discard); err != nil {
				t.Fatalf("confirmed pending Release = %v", err)
			}
			saved, err = a.Store.Load()
			if err != nil {
				t.Fatal(err)
			}
			for _, s := range saved.Sessions {
				if s.PendingParkRef != "" {
					t.Fatal("completed pending release left a restart quarantine")
				}
			}
			if len(rt.parks) != 0 || (discard && exists(ref)) || (!discard && !rt.HasDelta(ref)) {
				t.Fatal("completed release leaked receipt or mishandled checkpoint")
			}
		})
	}
}

// parkFixture is a runtime with one prepared grant and one running fiber,
// as every park and resume test starts from.
type parkFixture struct {
	r     *Runtime
	be    backend.Backend
	g     core.Grant
	h     core.FiberHandle
	fence core.Fence
}

func (f *parkFixture) fake() *fakeBackend {
	return f.be.(interface{ base() *fakeBackend }).base()
}

func (b *fakeBackend) base() *fakeBackend { return b }

func newParkFixture(t *testing.T, be backend.Backend, g core.Grant, mod func(*Config)) *parkFixture {
	t.Helper()
	r := newTestRuntime(t, be, mod)
	ctx := context.Background()
	if err := r.PrepareTemplate(ctx, g); err != nil {
		t.Fatalf("PrepareTemplate: %v", err)
	}
	fence := core.Fence{GrantUID: g.UID, Epoch: 1, Seq: 1}
	h, err := r.Clone(ctx, core.CloneSpec{Grant: g, Fence: fence, CallerCert: callerDER})
	if err != nil {
		t.Fatalf("Clone: %v", err)
	}
	return &parkFixture{r: r, be: be, g: g, h: h, fence: fence}
}

// imageBytesOf is what a parked directory weighed before its manifest
// was written beside the images.
func imageBytesOf(t *testing.T, ref string) uint64 {
	t.Helper()
	st, err := os.Stat(filepath.Join(ref, "manifest.json"))
	if err != nil {
		t.Fatal(err)
	}
	return dirBytes(ref) - uint64(st.Size())
}

// fiberFlags reads a known fiber's park bookkeeping.
func (f *parkFixture) fiberFlags(t *testing.T, id string) (released, parked bool) {
	t.Helper()
	f.r.mu.Lock()
	defer f.r.mu.Unlock()
	fb, ok := f.r.fibers[id]
	if !ok {
		t.Fatalf("fiber %s is not running", id)
	}
	return fb.released, fb.parked
}

// TestPark checks that a park is a delta over the template's checkpoint when
// the backend has a codec and a parent, a full image otherwise. What is
// refused leaves the fiber running.
func TestPark(t *testing.T) {
	g := core.Grant{UID: "g1", TemplateDigest: "sha256:tmpl", FiberMax: 2, WBudgetBytes: 64 * mib}
	cases := []struct {
		name  string
		be    func() backend.Backend
		grant core.Grant
		mod   func(*Config)
		// before runs with the fiber running, before the park.
		before func(t *testing.T, f *parkFixture)
		sync   bool
		ctx    func() context.Context
		// wantErr is matched with errors.Is, errText as a fragment.
		wantErr error
		errText string
		// wantRef is whether the returned ref must be the delta dir even
		// on error.
		wantRef bool
		check   func(t *testing.T, f *parkFixture, ref string)
	}{
		{name: "async park: a delta over the self-checkpoint, no exit reported", be: func() backend.Backend { return newCodecBackend(core.TierCheckpoint) }, grant: g,
			check: func(t *testing.T, f *parkFixture, ref string) {
				if ref != filepath.Join(f.r.cfg.DeltaDir, "g1", "1-1") {
					t.Fatalf("ref = %s", ref)
				}
				m := readManifest(t, ref)
				parent := shaOf("zygote pages of g1")
				if m.Fence != "g1/1/1" || m.GrantUID != "g1" || m.Endpoint != f.h.Endpoint || m.Handoff || m.Template != "sha256:tmpl" ||
					m.Backend != "fake" || !m.Delta || m.Parent != parent || m.WBytes != 7 {
					t.Fatalf("manifest = %+v", m)
				}
				if _, err := time.Parse(time.RFC3339Nano, m.ParkedAt); err != nil {
					t.Fatalf("parked_at %q: %v", m.ParkedAt, err)
				}
				if parks := f.fake().parked(); len(parks) != 1 || parks[0] != (backend.ParkSpec{Dir: ref, Sync: false, Deadline: core.DefaultResumeDeadline}) {
					t.Fatalf("backend parks = %+v", parks)
				}
				if !f.r.HasDelta(ref) || !exists(filepath.Join(ref, fakeDeltaFile)) {
					t.Fatal("the delta is not there")
				}
				noExit(t, f.r)
				if f.r.root.Child("g1").Child("f-1-1").Exists() || len(f.r.fibers) != 0 {
					t.Fatal("the parked fiber's leaf or record remains")
				}
				if len(f.fake().killedIDs()) != 0 {
					t.Fatal("an async park must not kill the fiber: the checkpoint ends it")
				}
			}},
		{name: "sync park: the images are durable, then the fiber is killed", be: func() backend.Backend { return newCodecBackend(core.TierCheckpoint) }, grant: g, sync: true,
			check: func(t *testing.T, f *parkFixture, ref string) {
				if parks := f.fake().parked(); len(parks) != 1 || !parks[0].Sync {
					t.Fatalf("backend parks = %+v", parks)
				}
				if strings.Join(f.fake().killedIDs(), ",") != "g1/1/1" {
					t.Fatalf("killed %v", f.fake().killedIDs())
				}
				if m := readManifest(t, ref); !m.Delta {
					t.Fatalf("manifest = %+v", m)
				}
				noExit(t, f.r)
			}},
		{name: "confirmed exit completes despite a kill command error", be: func() backend.Backend {
			be := newCodecBackend(core.TierCheckpoint)
			be.killErr = errors.New("fake: kill command response lost")
			return be
		}, grant: g, sync: true},
		{name: "below the checkpoint tier", be: func() backend.Backend { return newFakeBackend(core.TierWarm) }, grant: g,
			errText: "park needs FIBER_CHECKPOINT (backend fake offers FIBER_WARM)",
			check: func(t *testing.T, f *parkFixture, _ string) {
				if released, _ := f.fiberFlags(t, "g1/1/1"); released {
					t.Fatal("the fiber was marked released")
				}
			}},
		{name: "a backend without a codec parks a full image", be: func() backend.Backend { return newFakeBackend(core.TierCheckpoint) }, grant: g,
			check: func(t *testing.T, f *parkFixture, ref string) {
				m := readManifest(t, ref)
				if m.Delta || m.Parent != "" || m.WBytes == 0 || m.WBytes != imageBytesOf(t, ref) {
					t.Fatalf("manifest = %+v, images weigh %d bytes", m, imageBytesOf(t, ref))
				}
			}},
		{name: "the codec's image size is the full image's weight when there is no parent", be: func() backend.Backend {
			cb := newCodecBackend(core.TierCheckpoint)
			cb.err = errors.New("fake: no criu")
			cb.imageBytes = 999
			return cb
		}, grant: g,
			check: func(t *testing.T, f *parkFixture, ref string) {
				if m := readManifest(t, ref); m.Delta || m.WBytes != 999 {
					t.Fatalf("manifest = %+v", m)
				}
			}},
		{name: "a delta that cannot be computed keeps the full image", be: func() backend.Backend {
			cb := newCodecBackend(core.TierCheckpoint)
			cb.computeErr = errors.New("fake: pages differ")
			cb.imageErr = errors.New("fake: unreadable")
			return cb
		}, grant: g,
			check: func(t *testing.T, f *parkFixture, ref string) {
				if m := readManifest(t, ref); m.Delta || m.Parent != "" || m.WBytes != imageBytesOf(t, ref) {
					t.Fatalf("manifest = %+v, images weigh %d bytes", m, imageBytesOf(t, ref))
				}
			}},
		{name: "a parent gone from the store keeps the full image", be: func() backend.Backend { return newCodecBackend(core.TierCheckpoint) }, grant: g,
			before: func(t *testing.T, f *parkFixture) {
				sha := f.r.warmOf("g1").parentSHA
				f.r.parentsMu.Lock()
				delete(f.r.parents, sha)
				f.r.parentsMu.Unlock()
				if err := os.RemoveAll(filepath.Join(f.r.parentsDir(), sha)); err != nil {
					t.Fatal(err)
				}
			},
			check: func(t *testing.T, f *parkFixture, ref string) {
				if m := readManifest(t, ref); m.Delta {
					t.Fatalf("manifest = %+v", m)
				}
			}},
		{name: "an unknown fiber", be: func() backend.Backend { return newCodecBackend(core.TierCheckpoint) }, grant: g,
			before:  func(t *testing.T, f *parkFixture) { f.h.ID = "g1/7/7" },
			errText: `unknown fiber "g1/7/7"`},
		{name: "a fiber whose id is no fence", be: func() backend.Backend { return newCodecBackend(core.TierCheckpoint) }, grant: g,
			before: func(t *testing.T, f *parkFixture) {
				f.r.mu.Lock()
				f.r.fibers["odd"] = &fiber{id: "odd", grantUID: "g1", done: make(chan struct{})}
				f.r.mu.Unlock()
				f.h.ID = "odd"
			},
			errText: "want grant/epoch/seq"},
		// The park's wait on the fiber is bounded by the grant's resume
		// deadline, which core sizes, and a plain fiber speaks on a pair
		// the backend borrows, so no channel is handed over.
		{name: "the backend is given the grant's resume deadline and no channel for a plain fiber", be: func() backend.Backend { return newCodecBackend(core.TierCheckpoint) }, grant: g,
			check: func(t *testing.T, f *parkFixture, _ string) {
				_, want := core.GrantDeadlines(f.r, "g1")
				specs := f.fake().parked()
				if len(specs) != 1 || specs[0].Deadline != want || specs[0].Channel != nil {
					t.Fatalf("park specs = %+v, want one with deadline %s and no channel", specs, want)
				}
			}},
		{name: "a dump the backend refuses leaves the fiber running and the log for diagnosis", be: func() backend.Backend {
			cb := newCodecBackend(core.TierCheckpoint)
			cb.parkErr = errors.New("fake: criu dump failed")
			return cb
		}, grant: g, errText: "criu dump failed",
			check: func(t *testing.T, f *parkFixture, _ string) {
				dir := f.r.deltaDir(f.fence)
				if exists(dir) || !exists(filepath.Join(dir+".failed", "dump.log")) {
					t.Fatalf("delta dir exists %v, failed log kept %v", exists(dir), exists(filepath.Join(dir+".failed", "dump.log")))
				}
				if released, parked := f.fiberFlags(t, "g1/1/1"); released || parked {
					t.Fatal("the fiber must be a running fiber again")
				}
				if err := f.r.Release(context.Background(), "g1/1/1", false); err != nil {
					t.Fatalf("release after a failed park: %v", err)
				}
			}},
		{name: "a sync park whose images cannot be made durable leaves the fiber running", be: func() backend.Backend {
			cb := newCodecBackend(core.TierCheckpoint)
			cb.parkDangling = true
			return cb
		}, grant: g, sync: true, wantErr: os.ErrNotExist,
			check: func(t *testing.T, f *parkFixture, _ string) {
				dir := f.r.deltaDir(f.fence)
				if exists(dir) || !exists(dir+".failed") {
					t.Fatal("the failed images must be set aside")
				}
				if released, parked := f.fiberFlags(t, "g1/1/1"); released || parked {
					t.Fatal("the fiber must be a running fiber again")
				}
				if len(f.fake().killedIDs()) != 0 {
					t.Fatal("the fiber was killed although its images are not durable")
				}
			}},
		{name: "over the grant's delta quota: refused before the dump", be: func() backend.Backend { return newCodecBackend(core.TierCheckpoint) },
			grant: core.Grant{UID: "g1", TemplateDigest: "sha256:tmpl", FiberMax: 1, WBudgetBytes: mib},
			before: func(t *testing.T, f *parkFixture) {
				// An earlier park of this grant, 5 MiB in its own delta
				// directory, against a quota of 4 x 1 x 1 MiB.
				write(t, filepath.Join(f.r.cfg.DeltaDir, "g1", "0-9"), map[string]string{"pages-1.img": strings.Repeat("x", 5*mib)})
			},
			wantErr: core.ErrDeltaQuota, errText: "holds 5242880 bytes",
			check: func(t *testing.T, f *parkFixture, _ string) {
				if len(f.fake().parked()) != 0 {
					t.Fatal("the backend was asked to dump")
				}
				if released, parked := f.fiberFlags(t, "g1/1/1"); released || parked {
					t.Fatal("the fiber must be a running fiber again")
				}
				if exists(f.r.deltaDir(f.fence)) {
					t.Fatal("a refused park left a delta directory")
				}
			}},
		{name: "within the quota: an earlier park counts, the dump proceeds", be: func() backend.Backend { return newCodecBackend(core.TierCheckpoint) },
			grant: core.Grant{UID: "g1", TemplateDigest: "sha256:tmpl", FiberMax: 1, WBudgetBytes: mib},
			before: func(t *testing.T, f *parkFixture) {
				write(t, filepath.Join(f.r.cfg.DeltaDir, "g1", "0-9"), map[string]string{"pages-1.img": strings.Repeat("x", 4*mib-100)})
			},
			check: func(t *testing.T, f *parkFixture, ref string) {
				if len(f.fake().parked()) != 1 || !f.r.HasDelta(ref) {
					t.Fatal("the park did not happen")
				}
			}},
		{name: "a device slice is evicted before the checkpoint, even when the engine complains", be: func() backend.Backend {
			sb := newSandboxBackend(core.TierSnapshot)
			sb.evictErr = errors.New("fake: engine busy")
			return sb
		}, grant: core.Grant{UID: "g1", TemplateDigest: "sha256:tmpl", WBudgetBytes: 64 * mib, DeviceBudget: core.DeviceBudget{Bytes: 100}},
			check: func(t *testing.T, f *parkFixture, ref string) {
				if got := f.be.(*sandboxBackend).evictedIDs(); strings.Join(got, ",") != "g1/1/1" {
					t.Fatalf("evicted %v", got)
				}
				if !f.r.HasDelta(ref) {
					t.Fatal("the park did not happen")
				}
			}},
		{name: "a backend that dumped nothing: the ref comes back with the error", be: func() backend.Backend {
			cb := newCodecBackend(core.TierCheckpoint)
			cb.parkNoDir = true
			return cb
		}, grant: g, errText: "but its manifest", wantRef: true,
			check: func(t *testing.T, f *parkFixture, ref string) {
				if ref != f.r.deltaDir(f.fence) {
					t.Fatalf("ref = %q, want the delta dir even on error", ref)
				}
			}},
		{name: "a park stops waiting for the exit when the context ends", be: func() backend.Backend {
			cb := newCodecBackend(core.TierCheckpoint)
			cb.noExit = true
			return cb
		}, grant: g, wantErr: context.Canceled, wantRef: true,
			ctx: func() context.Context {
				ctx, cancel := context.WithCancel(context.Background())
				cancel()
				return ctx
			},
			check: func(t *testing.T, f *parkFixture, ref string) {
				if !f.r.HasDelta(ref) {
					t.Fatal("the park did not complete")
				}
				if released, parked := f.fiberFlags(t, "g1/1/1"); !released || !parked {
					t.Fatal("the fiber must stay marked as parked while its exit is pending")
				}
			}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			f := newParkFixture(t, tc.be(), tc.grant, tc.mod)
			if tc.before != nil {
				tc.before(t, f)
			}
			ctx := context.Background()
			if tc.ctx != nil {
				ctx = tc.ctx()
			}
			ref, err := f.r.Park(ctx, f.h.ID, tc.sync)
			switch {
			case tc.wantErr != nil && !errors.Is(err, tc.wantErr):
				t.Fatalf("Park = %q, %v, want %v", ref, err, tc.wantErr)
			case tc.errText != "" && (err == nil || !strings.Contains(err.Error(), tc.errText)):
				t.Fatalf("Park = %q, %v, want an error mentioning %q", ref, err, tc.errText)
			case tc.wantErr == nil && tc.errText == "" && err != nil:
				t.Fatalf("Park: %v", err)
			}
			if err != nil && !tc.wantRef && ref != "" {
				t.Fatalf("a refused park returned ref %q", ref)
			}
			if tc.check != nil {
				tc.check(t, f, ref)
			}
		})
	}
}

// TestResume checks that a parked delta comes back under a new fence on the
// endpoint it was parked with, after the parent is merged in.
func TestResume(t *testing.T) {
	g := core.Grant{UID: "g1", TemplateDigest: "sha256:tmpl", FiberMax: 2, WBudgetBytes: 64 * mib}
	handoffG := g
	handoffG.Policy.EndpointMode, handoffG.CallerThumbprint = core.EndpointHandoff, "x5t"
	next := core.Fence{GrantUID: "g1", Epoch: 2, Seq: 1}
	// parkFirst parks the fixture's fiber and returns the ref.
	parkFirst := func(t *testing.T, f *parkFixture) string {
		t.Helper()
		ref, err := f.r.Park(context.Background(), f.h.ID, false)
		if err != nil {
			t.Fatalf("Park: %v", err)
		}
		return ref
	}
	// manifestOnly writes a delta directory by hand.
	manifestOnly := func(t *testing.T, f *parkFixture, m manifest, delta *fakeDelta) string {
		t.Helper()
		dir := filepath.Join(f.r.cfg.DeltaDir, "g1", "by-hand")
		write(t, dir, map[string]string{"pages-1.img": "pages"})
		if err := writeJSON(filepath.Join(dir, "manifest.json"), m); err != nil {
			t.Fatal(err)
		}
		if delta != nil {
			if err := writeJSON(filepath.Join(dir, fakeDeltaFile), delta); err != nil {
				t.Fatal(err)
			}
		}
		return dir
	}
	cases := []struct {
		name  string
		be    func() backend.Backend
		grant core.Grant
		// resumeGrant, when set, is the grant the delta is resumed under
		// instead of grant.
		resumeGrant *core.Grant
		mod         func(*Config)
		ref         func(t *testing.T, f *parkFixture) string
		wantErr     error
		errText     string
		check       func(t *testing.T, f *parkFixture, ref string, h core.FiberHandle)
	}{
		{name: "a unix delta resumes on its parked socket path, under the grant's run directory", be: func() backend.Backend { return newCodecBackend(core.TierCheckpoint) },
			grant: g, ref: parkFirst,
			check: func(t *testing.T, f *parkFixture, ref string, h core.FiberHandle) {
				sock := filepath.Join(f.r.cfg.RunDir, "g1", "1-1.sock")
				if h.ID != "g1/2/1" || h.Endpoint != "unix://"+sock {
					t.Fatalf("handle = %+v", h)
				}
				// The backend is told what the resumed fiber's record
				// says: the new fence and the next generation.
				cb := f.be.(*codecBackend)
				ff := cb.fiber("g1/2/1")
				if ff == nil || ff.resume == nil || ff.resume.Dir != ref || ff.resume.Endpoint != sock || ff.resume.WarmID != "g1" ||
					ff.resume.WorkDir != filepath.Join(f.r.cfg.RunDir, "g1") || ff.resume.CgroupFD < 0 || ff.resume.Handoff ||
					ff.resume.Fence != "g1/2/1" || ff.resume.Generation != 2 {
					t.Fatalf("resume spec = %+v", ff)
				}
				parent := shaOf("zygote pages of g1")
				if merged, _ := os.ReadFile(filepath.Join(ref, "merged")); string(merged) != parent || len(cb.merged) != 1 {
					t.Fatalf("merged = %q, %v", merged, cb.merged)
				}
				leaf := f.r.root.Child("g1").Child("f-2-1")
				if !leaf.Exists() || cgUint(t, leaf, "memory.max") != 64*mib {
					t.Fatal("the resumed fiber has no leaf of its own")
				}
				if err := f.r.Release(context.Background(), h.ID, false); err != nil {
					t.Fatal(err)
				}
				if leaf.Exists() {
					t.Fatal("the leaf remains")
				}
			}},
		{name: "below the checkpoint tier", be: func() backend.Backend { return newFakeBackend(core.TierWarm) }, grant: g,
			ref:     func(*testing.T, *parkFixture) string { return "/nonexistent" },
			errText: "resume needs FIBER_CHECKPOINT"},
		{name: "a ref without a manifest", be: func() backend.Backend { return newCodecBackend(core.TierCheckpoint) }, grant: g,
			ref:     func(t *testing.T, _ *parkFixture) string { return t.TempDir() },
			wantErr: os.ErrNotExist},
		{name: "a delta parked by another backend", be: func() backend.Backend { return newCodecBackend(core.TierCheckpoint) }, grant: g,
			ref: func(t *testing.T, f *parkFixture) string {
				return manifestOnly(t, f, manifest{Fence: "g1/1/1", Backend: "runc", Endpoint: "unix:///x.sock"}, nil)
			},
			wantErr: ErrParity, errText: "parked by backend runc, this home runs fake"},
		{name: "a delta whose parent this home lacks", be: func() backend.Backend { return newCodecBackend(core.TierCheckpoint) }, grant: g,
			ref: func(t *testing.T, f *parkFixture) string {
				return manifestOnly(t, f, manifest{Fence: "g1/1/1", Backend: "fake", Endpoint: "unix:///x.sock", Delta: true},
					&fakeDelta{Parent: strings.Repeat("ab", 32), Bytes: 3})
			},
			wantErr: ErrParentMissing, errText: "resume of a delta"},
		{name: "a delta whose info cannot be read", be: func() backend.Backend {
			cb := newCodecBackend(core.TierCheckpoint)
			cb.infoErr = errors.New("fake: bad delta header")
			return cb
		}, grant: g, ref: parkFirst, errText: "bad delta header"},
		{name: "a merge that fails", be: func() backend.Backend {
			cb := newCodecBackend(core.TierCheckpoint)
			cb.mergeErr = errors.New("fake: page mismatch")
			return cb
		}, grant: g, ref: parkFirst, errText: "merge delta"},
		{name: "a delta parked on another endpoint family", be: func() backend.Backend { return newCodecBackend(core.TierCheckpoint) }, grant: g,
			ref: func(t *testing.T, f *parkFixture) string {
				return manifestOnly(t, f, manifest{Fence: "g1/1/1", Backend: "fake", Endpoint: "tcp://10.0.0.2:30000"}, nil)
			},
			errText: "parked on a tcp endpoint, this home serves unix",
			check: func(t *testing.T, f *parkFixture, _ string, _ core.FiberHandle) {
				if f.r.root.Child("g1").Child("f-2-1").Exists() {
					t.Fatal("the leaf was left behind")
				}
			}},
		{name: "a delta with an endpoint that does not parse", be: func() backend.Backend { return newCodecBackend(core.TierCheckpoint) }, grant: g,
			ref: func(t *testing.T, f *parkFixture) string {
				return manifestOnly(t, f, manifest{Fence: "g1/1/1", Backend: "fake", Endpoint: "bogus"}, nil)
			},
			errText: "scheme must be unix or tcp",
			check: func(t *testing.T, f *parkFixture, _ string, _ core.FiberHandle) {
				if f.r.root.Child("g1").Child("f-2-1").Exists() {
					t.Fatal("the leaf was left behind")
				}
			}},
		{name: "a restore the backend refuses leaves nothing behind", be: func() backend.Backend {
			cb := newCodecBackend(core.TierCheckpoint)
			cb.resumeErr = errors.New("fake: criu restore failed")
			return cb
		}, grant: g, ref: parkFirst, errText: "criu restore failed",
			check: func(t *testing.T, f *parkFixture, _ string, _ core.FiberHandle) {
				if f.r.root.Child("g1").Child("f-2-1").Exists() || len(f.r.fibers) != 0 {
					t.Fatal("the leaf or the record was left behind")
				}
				if exists(filepath.Join(f.r.cfg.RunDir, "g1", "1-1.sock")) {
					t.Fatal("the failed resume left the socket name behind")
				}
				if ents, _ := os.ReadDir(f.r.cfg.RunDir); len(ents) != 1 {
					t.Fatalf("the run directory holds %d entries, want the grant's alone", len(ents))
				}
			}},
		{name: "a tcp delta keeps its port across park and resume", be: func() backend.Backend { return newSandboxBackend(core.TierSnapshot) }, grant: g,
			mod: func(c *Config) { c.Endpoints = tcpPolicy }, ref: parkFirst,
			check: func(t *testing.T, f *parkFixture, ref string, h core.FiberHandle) {
				if h.Endpoint != "tcp://127.0.0.1:20000" {
					t.Fatalf("resumed endpoint = %s", h.Endpoint)
				}
				f.r.mu.Lock()
				holder := f.r.ports[20000]
				f.r.mu.Unlock()
				if holder != "g1/2/1" {
					t.Fatalf("port 20000 held by %q, want the new fence", holder)
				}
				if ff := f.be.(*sandboxBackend).fiber("g1/2/1"); ff.resume.Endpoint != "tcp://127.0.0.1:20000" || ff.resume.Generation != 2 {
					t.Fatalf("the backend was told to serve on %s as generation %d", ff.resume.Endpoint, ff.resume.Generation)
				}
				// Another delta parked on the same port, while the resumed
				// fiber holds it, cannot come back here.
				dir := filepath.Join(f.r.cfg.DeltaDir, "g1", "other")
				write(t, dir, map[string]string{"pages-1.img": "pages"})
				if err := writeJSON(filepath.Join(dir, "manifest.json"), manifest{Fence: "g1/1/9", Backend: "fake", Endpoint: "tcp://127.0.0.1:20000"}); err != nil {
					t.Fatal(err)
				}
				_, err := f.r.Clone(context.Background(), core.CloneSpec{Grant: g, Source: core.SourceDelta, Ref: dir, Fence: core.Fence{GrantUID: "g1", Epoch: 3, Seq: 1}})
				if err == nil || !strings.Contains(err.Error(), "held by g1/2/1") {
					t.Fatalf("resume on a held port = %v", err)
				}
				if f.r.root.Child("g1").Child("f-3-1").Exists() {
					t.Fatal("the refused resume left its leaf")
				}
				// Discarding the parked fiber's delta gives its port back.
				if err := f.r.Release(context.Background(), "g1/2/1", false); err != nil {
					t.Fatal(err)
				}
				if _, err := f.r.Park(context.Background(), "g1/2/1", false); err == nil {
					t.Fatal("parking a released fiber must fail")
				}
			}},
		{name: "a handoff delta gets a fresh channel and no record", be: func() backend.Backend { return newSandboxBackend(core.TierSnapshot) }, grant: handoffG,
			mod: func(c *Config) { c.Handoff, c.HandoffKey = handoffRouter(), handoffKey }, ref: parkFirst,
			check: func(t *testing.T, f *parkFixture, ref string, h core.FiberHandle) {
				if m := readManifest(t, ref); !m.Handoff {
					t.Fatalf("manifest = %+v, want a handoff park", m)
				}
				sb := f.be.(*sandboxBackend)
				ff := sb.fiber("g1/2/1")
				if ff.resume.Endpoint != handoffEndpoint || !ff.resume.Handoff || ff.handoff < 0 || ff.identity != nil {
					t.Fatalf("resume = %+v, identity %q", ff.resume, ff.identity)
				}
				f.r.mu.Lock()
				ch := f.r.fibers["g1/2/1"].channel
				f.r.mu.Unlock()
				if ch == nil {
					t.Fatal("the host holds no end of the resumed fiber's channel")
				}
				if h.Endpoint != "tcp://10.0.0.1:443" {
					t.Fatalf("handle endpoint = %s", h.Endpoint)
				}
				if _, pin, cert, ok := f.r.HandoffRoute(h.ID); !ok || pin == "" || len(cert) == 0 {
					t.Fatal("the resumed fiber is not routed")
				}
				if sb.pairs.Load() != 2 {
					t.Fatalf("%d channels made, want one per incarnation", sb.pairs.Load())
				}
			}},
		{name: "a handoff delta on a home that cannot hand off", be: func() backend.Backend { return newCodecBackend(core.TierCheckpoint) }, grant: g,
			ref: func(t *testing.T, f *parkFixture) string {
				return manifestOnly(t, f, manifest{Fence: "g1/1/1", Backend: "fake", Handoff: true}, nil)
			},
			errText: "hand connections",
			check: func(t *testing.T, f *parkFixture, _ string, _ core.FiberHandle) {
				if f.r.root.Child("g1").Child("f-2-1").Exists() {
					t.Fatal("the leaf was left behind")
				}
			}},
		{name: "an id mapper that stops delegating refuses the grant's cgroup", be: func() backend.Backend {
			return &struct {
				*fakeBackend
				*codecMixin
				*selfCheckpointMixin
				*idMapperMixin
			}{newFakeBackend(core.TierCheckpoint), &codecMixin{}, &selfCheckpointMixin{}, &idMapperMixin{uid: uint32(os.Geteuid())}}
		}, grant: g, mod: func(c *Config) { delegatedUnder(c.CgroupRoot, "g1", "g1/f-1-1") },
			ref: func(t *testing.T, f *parkFixture) string {
				ref := parkFirst(t, f)
				f.be.(interface{ mapper() *idMapperMixin }).mapper().err = errors.New("fake: range revoked")
				return ref
			},
			errText: "range revoked"},
		{name: "a leaf that cannot be made", be: func() backend.Backend { return newCodecBackend(core.TierCheckpoint) },
			grant:       g,
			resumeGrant: &core.Grant{UID: "tiny", TemplateDigest: "sha256:tmpl", FiberMax: 1, WBudgetBytes: 64 * mib},
			ref: func(t *testing.T, f *parkFixture) string {
				if err := f.r.PrepareTemplate(context.Background(), core.Grant{UID: "tiny", TemplateDigest: "sha256:tmpl", FiberMax: 1, WBudgetBytes: 64 * mib}); err != nil {
					t.Fatal(err)
				}
				inTheWay(t, f.r.root.Child("tiny"), "f-2-1")
				return manifestOnly(t, f, manifest{Fence: "tiny/1/1", Backend: "fake", Endpoint: "unix:///x.sock"}, nil)
			},
			errText: "f-2-1",
			check: func(t *testing.T, f *parkFixture, _ string, _ core.FiberHandle) {
				if f.r.root.Child("tiny").Child("f-2-1").Exists() {
					t.Fatal("the leaf was left behind")
				}
			}},
		{name: "a handoff restore the backend refuses closes its channel with the rest", be: func() backend.Backend { return newSandboxBackend(core.TierSnapshot) },
			grant: handoffG, mod: func(c *Config) { c.Handoff, c.HandoffKey = handoffRouter(), handoffKey },
			ref: func(t *testing.T, f *parkFixture) string {
				ref := parkFirst(t, f)
				f.be.(*sandboxBackend).resumeErr = errors.New("fake: restore failed")
				return ref
			},
			errText: "restore failed",
			check: func(t *testing.T, f *parkFixture, _ string, _ core.FiberHandle) {
				if f.r.root.Child("g1").Child("f-2-1").Exists() || len(f.r.fibers) != 0 {
					t.Fatal("the leaf or the record was left behind")
				}
				if exists(filepath.Join(f.r.cfg.RunDir, "g1", "1-1.sock")) {
					t.Fatal("the failed resume left the socket name behind")
				}
				if ents, _ := os.ReadDir(f.r.cfg.RunDir); len(ents) != 1 {
					t.Fatalf("the run directory holds %d entries, want the grant's alone", len(ents))
				}
			}},
		{name: "a handoff delta whose channel the backend cannot make", be: func() backend.Backend {
			sb := newSandboxBackend(core.TierSnapshot)
			return sb
		}, grant: g, mod: func(c *Config) { c.Handoff, c.HandoffKey = handoffRouter(), handoffKey },
			ref: func(t *testing.T, f *parkFixture) string {
				f.be.(*sandboxBackend).channelErr = errors.New("fake: netns gone")
				return manifestOnly(t, f, manifest{Fence: "g1/1/1", Backend: "fake", Handoff: true}, nil)
			},
			errText: "netns gone",
			check: func(t *testing.T, f *parkFixture, _ string, _ core.FiberHandle) {
				if f.r.root.Child("g1").Child("f-2-1").Exists() {
					t.Fatal("the leaf was left behind")
				}
			}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			f := newParkFixture(t, tc.be(), tc.grant, tc.mod)
			ref := tc.ref(t, f)
			under := tc.grant
			if tc.resumeGrant != nil {
				under = *tc.resumeGrant
			}
			h, err := f.r.Clone(context.Background(), core.CloneSpec{Grant: under, Source: core.SourceDelta, Ref: ref, Fence: next, Deadline: time.Second})
			switch {
			case tc.wantErr != nil && !errors.Is(err, tc.wantErr):
				t.Fatalf("resume = %v, want %v", err, tc.wantErr)
			case tc.errText != "" && (err == nil || !strings.Contains(err.Error(), tc.errText)):
				t.Fatalf("resume = %v, want an error mentioning %q", err, tc.errText)
			case tc.wantErr == nil && tc.errText == "" && err != nil:
				t.Fatalf("resume: %v", err)
			}
			if tc.check != nil {
				tc.check(t, f, ref, h)
			}
		})
	}
}

// TestReleaseDiscard checks that discarding a parked fiber removes its delta
// and frees the port it kept.
func TestReleaseDiscard(t *testing.T) {
	g := core.Grant{UID: "g1", TemplateDigest: "sha256:tmpl", WBudgetBytes: 64 * mib}
	cases := []struct {
		name    string
		discard bool
		// deltaKept is whether the delta directory survives the release.
		deltaKept bool
		portsHeld int
	}{
		{name: "release without discard keeps the delta and its port", deltaKept: true, portsHeld: 1},
		{name: "release with discard removes the delta and frees the port", discard: true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			f := newParkFixture(t, newSandboxBackend(core.TierSnapshot), g, func(c *Config) { c.Endpoints = tcpPolicy })
			ctx := context.Background()
			ref, err := f.r.Park(ctx, f.h.ID, false)
			if err != nil {
				t.Fatal(err)
			}
			f.r.mu.Lock()
			holder := f.r.ports[20000]
			f.r.mu.Unlock()
			if holder != f.h.ID {
				t.Fatalf("after the park port 20000 is held by %q, want the parked fiber", holder)
			}
			if err := f.r.Release(ctx, f.h.ID, tc.discard); err != nil {
				t.Fatal(err)
			}
			f.r.mu.Lock()
			held := len(f.r.ports)
			f.r.mu.Unlock()
			if exists(ref) != tc.deltaKept || held != tc.portsHeld {
				t.Fatalf("delta exists %v, %d ports held; want %v and %d", exists(ref), held, tc.deltaKept, tc.portsHeld)
			}
		})
	}
}

// TestReleaseOrphan restarts fiberd under a live fiber and releases it
// as an orphan. Its leaf goes, and so does the socket its fence names.
// A resumed fiber serves the socket name of its park, which nothing on
// disk ties to its fence since the fence rides its channel, so that
// name stays until the next fiber binds it. Other fibers' files stay.
// The kill of a task still in the leaf is tests/integration/host
// TestOrphanKilledInLeaf.
func TestReleaseOrphan(t *testing.T) {
	g := core.Grant{UID: "g1", TemplateDigest: "sha256:tmpl", WBudgetBytes: 64 * mib}
	next := core.Fence{GrantUID: "g1", Epoch: 2, Seq: 1}
	// resumed parks the fixture's fiber and resumes it under next.
	resumed := func(t *testing.T, f *parkFixture) core.Fence {
		t.Helper()
		ref, err := f.r.Park(context.Background(), f.h.ID, false)
		if err != nil {
			t.Fatalf("Park: %v", err)
		}
		if _, err := f.r.Clone(context.Background(), core.CloneSpec{Grant: g, Source: core.SourceDelta, Ref: ref, Fence: next, Deadline: time.Second}); err != nil {
			t.Fatalf("resume: %v", err)
		}
		return next
	}
	cases := []struct {
		name string
		be   func() backend.Backend
		mod  func(*Config)
		// fiber readies the orphan and returns its fence.
		fiber func(t *testing.T, f *parkFixture) core.Fence
		gone  []string // under the grant's run directory
		stays []string // the orphan's, under the grant's run directory, but not tied to its fence
	}{
		{name: "a cloned fiber: its socket by its fence", be: func() backend.Backend {
			b := newFakeBackend(core.TierWarm)
			b.endpointFile = true
			return b
		}, fiber: func(_ *testing.T, f *parkFixture) core.Fence { return f.fence }, gone: []string{"1-1.sock"}},
		{name: "a resumed fiber: the socket name of its park stays", be: func() backend.Backend {
			b := newCodecBackend(core.TierCheckpoint)
			b.serve = true
			return b
		}, fiber: resumed, stays: []string{"1-1.sock"}},
		{name: "a fiber resumed on tcp: nothing on disk", be: func() backend.Backend { return newSandboxBackend(core.TierSnapshot) },
			mod: func(c *Config) { c.Endpoints = tcpPolicy }, fiber: resumed},
		{name: "a fiber resumed behind a relay: the socket name of its park stays", be: func() backend.Backend { return relayBackend(core.TierSnapshot) },
			mod: func(c *Config) { c.Endpoints = tcpPolicy }, fiber: resumed, stays: []string{"1-1.sock"}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			f := newParkFixture(t, tc.be(), g, tc.mod)
			orphan := tc.fiber(t, f)
			run := filepath.Join(f.r.cfg.RunDir, "g1")
			for _, n := range append(append([]string{}, tc.gone...), tc.stays...) {
				if !exists(filepath.Join(run, n)) {
					t.Fatalf("%s is not there to begin with", n)
				}
			}
			// Another fiber's socket is not the orphan's.
			write(t, run, map[string]string{"9-9.sock": ""})
			kept := append([]string{"9-9.sock"}, tc.stays...)

			// A restarted fiberd over the same directories knows nothing of
			// the fiber, whose leaf still holds a task.
			cfg := f.r.cfg
			cfg.Backend = newFakeBackend(core.TierWarm)
			r, err := New(cfg)
			if err != nil {
				t.Fatal(err)
			}
			t.Cleanup(r.Close)
			leaf := r.root.Child("g1").Child(leafName(orphan))
			cgSet(t, leaf, "cgroup.procs", "4242")
			list, err := r.List(context.Background())
			if err != nil || len(list) != 1 || list[0].ID != orphan.String() {
				t.Fatalf("List = %+v %v, want the orphan alone", list, err)
			}
			cgSet(t, leaf, "cgroup.procs", "")
			if err := r.Release(context.Background(), orphan.String(), false); err != nil {
				t.Fatal(err)
			}
			if leaf.Exists() {
				t.Fatal("the orphan's leaf remains")
			}
			for _, n := range tc.gone {
				if exists(filepath.Join(run, n)) {
					t.Errorf("the orphan's %s remains", n)
				}
			}
			for _, n := range kept {
				if !exists(filepath.Join(run, n)) {
					t.Errorf("%s, not the orphan's, was removed", n)
				}
			}
		})
	}
}

// TestResumeRefusesHeldSocket checks that a socket name under the grant's
// run directory has one live holder. A resumed fiber binds the name it
// was parked with, which another home minted, so it can meet a local
// fiber's name, and a fresh clone's name can meet a resumed fiber's.
// Either way the newcomer is refused, nothing of the holder's is
// unlinked, and the name is free again once the holder ends.
func TestResumeRefusesHeldSocket(t *testing.T) {
	g := core.Grant{UID: "g1", TemplateDigest: "sha256:tmpl", FiberMax: 4, WBudgetBytes: 64 * mib}
	unixServing := func() backend.Backend {
		b := newCodecBackend(core.TierCheckpoint)
		b.serve = true
		return b
	}
	// threePorts leaves a port for the newcomer beside the two holders'.
	threePorts := func(c *Config) {
		c.Endpoints = tcpPolicy
		c.Endpoints.PortMax = tcpPolicy.PortMin + 2
	}
	// foreign is a delta another home parked, named by the socket its
	// fiber served on there.
	foreign := func(t *testing.T, f *parkFixture, fence, name string, relayed bool) string {
		t.Helper()
		m := manifest{Fence: fence, GrantUID: "g1", Backend: "fake", Endpoint: "unix:///elsewhere/run/g1/" + name}
		if relayed {
			m.Endpoint, m.Relay = "tcp://10.0.0.9:20000", "/elsewhere/run/g1/"+name
		}
		dir := filepath.Join(f.r.cfg.DeltaDir, "g1", "foreign-"+name)
		write(t, dir, map[string]string{"pages-1.img": "pages"})
		if err := writeJSON(filepath.Join(dir, "manifest.json"), m); err != nil {
			t.Fatal(err)
		}
		return dir
	}
	cases := []struct {
		name    string
		be      func() backend.Backend
		mod     func(*Config)
		relayed bool
		// reverse has the resumed fiber hold the name and the clone meet it.
		reverse bool
	}{
		{name: "unix: a resume meets the clone serving its parked name", be: unixServing},
		{name: "relayed: a resume meets the clone serving its parked name", be: func() backend.Backend { return relayBackend(core.TierSnapshot) },
			mod: threePorts, relayed: true},
		{name: "unix: a clone meets the resumed fiber serving its name", be: unixServing, reverse: true},
		{name: "relayed: a clone meets the resumed fiber serving its name", be: func() backend.Backend { return relayBackend(core.TierSnapshot) },
			mod: threePorts, relayed: true, reverse: true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			f := newParkFixture(t, tc.be(), g, tc.mod) // g1/1/1 serves 1-1.sock
			ctx := context.Background()
			if !tc.reverse {
				ref := foreign(t, f, "g1/1/1", "1-1.sock", tc.relayed)
				h, err := f.r.Clone(ctx, core.CloneSpec{Grant: g, Source: core.SourceDelta, Ref: ref, Fence: core.Fence{GrantUID: "g1", Epoch: 2, Seq: 1}})
				if err == nil || !strings.Contains(err.Error(), "held by g1/1/1") {
					t.Fatalf("resume onto a live fiber's socket = %+v, %v; want a refusal naming the holder", h, err)
				}
				if got := mustSay(t, f.h.Endpoint, "ping"); got != "g1/1/1:ping" {
					t.Fatalf("the holder answered %q after the refused resume", got)
				}
				if f.r.root.Child("g1").Child("f-2-1").Exists() || heldPorts(f.r) != boolInt(tc.relayed) {
					t.Fatalf("the refused resume left its leaf or a port (%d held)", heldPorts(f.r))
				}
				return
			}
			ref := foreign(t, f, "g1/1/2", "1-2.sock", tc.relayed)
			resumed, err := f.r.Clone(ctx, core.CloneSpec{Grant: g, Source: core.SourceDelta, Ref: ref, Fence: core.Fence{GrantUID: "g1", Epoch: 2, Seq: 1}})
			if err != nil {
				t.Fatalf("resume of the foreign delta: %v", err)
			}
			if got := mustSay(t, resumed.Endpoint, "ping"); got != "g1/2/1:ping" {
				t.Fatalf("the resumed fiber answered %q", got)
			}
			clone := core.CloneSpec{Grant: g, Fence: core.Fence{GrantUID: "g1", Epoch: 1, Seq: 2}}
			if h, err := f.r.Clone(ctx, clone); err == nil || !strings.Contains(err.Error(), "held by g1/2/1") {
				t.Fatalf("clone of the name a resumed fiber serves = %+v, %v; want a refusal naming the holder", h, err)
			}
			if got := mustSay(t, resumed.Endpoint, "ping"); got != "g1/2/1:ping" {
				t.Fatalf("the holder answered %q after the refused clone", got)
			}
			if f.r.root.Child("g1").Child("f-1-2").Exists() || heldPorts(f.r) != 2*boolInt(tc.relayed) {
				t.Fatalf("the refused clone left its leaf or a port (%d held)", heldPorts(f.r))
			}
			// The holder's end frees the name.
			if err := f.r.Release(ctx, resumed.ID, false); err != nil {
				t.Fatal(err)
			}
			h, err := f.r.Clone(ctx, clone)
			if err != nil {
				t.Fatalf("clone after the holder ended: %v", err)
			}
			if got := mustSay(t, h.Endpoint, "ping"); got != "g1/1/2:ping" {
				t.Fatalf("the clone answered %q", got)
			}
		})
	}
}

func boolInt(b bool) int {
	if b {
		return 1
	}
	return 0
}

// TestParkReportsDeathMeanwhile checks that a fiber dying under a park
// that then fails is reported as the death it was. The park marks the
// exit as its own before the dump, so finish withholds it, and a park
// that gives the fiber back must hand that exit on, or the ledger keeps
// a dead session running.
func TestParkReportsDeathMeanwhile(t *testing.T) {
	g := core.Grant{UID: "g1", TemplateDigest: "sha256:tmpl", FiberMax: 2, WBudgetBytes: 64 * mib}
	cases := []struct {
		name string
		sync bool
		mod  func(b *fakeBackend)
		// dies is whether the fiber dies under the dump, which the test
		// does while the backend's Park is held at its gate.
		dies bool
	}{
		{name: "an async park the backend refuses while the fiber died",
			mod: func(b *fakeBackend) { b.parkErr = errors.New("fake: dump failed") }, dies: true},
		{name: "a sync park whose fsync fails while the fiber died", sync: true,
			mod: func(b *fakeBackend) { b.parkDangling = true }, dies: true},
		{name: "a park the backend refuses with the fiber alive reports nothing",
			mod: func(b *fakeBackend) { b.parkErr = errors.New("fake: dump failed") }},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			cb := newCodecBackend(core.TierCheckpoint)
			tc.mod(cb.fakeBackend)
			gate := make(chan struct{})
			cb.parkGate = gate
			f := newParkFixture(t, cb, g, nil)
			errc := make(chan error, 1)
			go func() {
				_, err := f.r.Park(context.Background(), f.h.ID, tc.sync)
				errc <- err
			}()
			waitFor(t, "the dump to begin", func() bool { return len(cb.parked()) == 1 })
			if tc.dies {
				cb.die(f.h.ID, "exit:7")
				waitFor(t, "the death to be handled", func() bool {
					f.r.mu.Lock()
					defer f.r.mu.Unlock()
					_, running := f.r.fibers[f.h.ID]
					return !running
				})
				noExit(t, f.r) // withheld under the park
			}
			close(gate)
			if err := <-errc; err == nil {
				t.Fatal("the park succeeded")
			}
			if !tc.dies {
				noExit(t, f.r)
				if released, parked := f.fiberFlags(t, f.h.ID); released || parked {
					t.Fatal("the fiber was not given back")
				}
				return
			}
			if e := waitExit(t, f.r); e.FiberID != f.h.ID || e.Reason != "exit" || e.Detail != "exit:7" {
				t.Fatalf("exit = %+v, want the death under the park", e)
			}
			noExit(t, f.r) // once
		})
	}
}

// fsyncLog stands in for fsync under one delta directory. It keeps each
// file's size and content hash at its last fsync, the whole tree as the
// last directory fsync saw it, and the directories in the order they were
// fsynced. One named path can be made to fail.
type fsyncLog struct {
	mu     sync.Mutex
	dir    string
	files  map[string]string
	tree   map[string]string
	dirs   []string
	failAt string
	// atKill is the tree and the fsynced files as they were when the
	// backend was first told to kill the fiber.
	atKill [2]map[string]string
}

// treeHashes is every regular file under dir, by relative path, with its
// size and content hash.
func treeHashes(dir string) (map[string]string, error) {
	out := map[string]string{}
	err := filepath.WalkDir(dir, func(path string, d os.DirEntry, err error) error {
		if err != nil || d.IsDir() {
			return err
		}
		b, err := os.ReadFile(path)
		if err != nil {
			return err
		}
		rel, _ := filepath.Rel(dir, path)
		out[rel] = fmt.Sprintf("%d:%x", len(b), sha256.Sum256(b))
		return nil
	})
	return out, err
}

func (l *fsyncLog) fsync(f *os.File) error {
	l.mu.Lock()
	defer l.mu.Unlock()
	rel, _ := filepath.Rel(l.dir, f.Name())
	if rel == l.failAt {
		return errors.New("fake: fsync failed")
	}
	if st, err := f.Stat(); err != nil || st.IsDir() {
		if err != nil {
			return err
		}
		l.dirs = append(l.dirs, rel)
		tree, err := treeHashes(l.dir)
		l.tree = tree
		return err
	}
	b, err := os.ReadFile(f.Name())
	if err != nil {
		return err
	}
	l.files[rel] = fmt.Sprintf("%d:%x", len(b), sha256.Sum256(b))
	return nil
}

// kill records the directory as it is when the fiber is being killed.
func (l *fsyncLog) kill() {
	l.mu.Lock()
	defer l.mu.Unlock()
	if l.atKill[0] != nil {
		return
	}
	tree, _ := treeHashes(l.dir)
	l.atKill = [2]map[string]string{tree, maps.Clone(l.files)}
}

// durable fails unless the tree as it is now is what the last directory
// fsync saw, and every file in it was fsynced with the content it has.
func (l *fsyncLog) durable(t *testing.T) {
	t.Helper()
	l.mu.Lock()
	defer l.mu.Unlock()
	now, err := treeHashes(l.dir)
	if err != nil {
		t.Fatal(err)
	}
	if !maps.Equal(now, l.tree) {
		t.Fatalf("the directory changed after its last fsync: now %v, fsynced %v", now, l.tree)
	}
	for rel, h := range now {
		if l.files[rel] != h {
			t.Fatalf("%s was not fsynced after its last write (fsynced %q, now %q)", rel, l.files[rel], h)
		}
	}
}

// killWatch is a codec backend that tells the log when it kills.
type killWatch struct {
	*codecBackend
	log *fsyncLog
}

func (k *killWatch) Kill(fiberID string) error {
	k.log.kill()
	return k.codecBackend.Kill(fiberID)
}

// TestParkDurability checks a sync park's promise: the fiber keeps running
// until the delta, its manifest and every file under the directory, nested
// ones included, are fsynced, and only then is it killed. An fsync that
// fails gives the fiber back.
func TestParkDurability(t *testing.T) {
	g := core.Grant{UID: "g1", TemplateDigest: "sha256:tmpl", FiberMax: 2, WBudgetBytes: 64 * mib}
	nested := map[string]string{"pages-1.img": "dirty pages", "dump.log": "ok\n", "blobs/sha256/abc": "a layer", "blobs/index.json": "{}"}
	cases := []struct {
		name string
		// files is what the backend dumps, nil for its default.
		files  map[string]string
		failAt string
		check  func(t *testing.T, f *parkFixture, l *fsyncLog, ref string, err error)
	}{
		{name: "every file is fsynced after its last write, the delta and manifest included",
			check: func(t *testing.T, f *parkFixture, l *fsyncLog, ref string, err error) {
				if err != nil {
					t.Fatal(err)
				}
				l.durable(t)
				for _, name := range []string{"manifest.json", fakeDeltaFile, "pages-1.img"} {
					if _, ok := l.files[name]; !ok {
						t.Fatalf("%s was never fsynced (fsynced %v)", name, l.files)
					}
				}
			}},
		{name: "the fiber is killed only after everything is durable",
			check: func(t *testing.T, f *parkFixture, l *fsyncLog, ref string, err error) {
				if err != nil {
					t.Fatal(err)
				}
				if strings.Join(f.fake().killedIDs(), ",") != "g1/1/1" {
					t.Fatalf("killed %v", f.fake().killedIDs())
				}
				now, err := treeHashes(ref)
				if err != nil {
					t.Fatal(err)
				}
				if tree := l.atKill[0]; !maps.Equal(now, tree) {
					t.Fatalf("the directory changed after the kill: at the kill %v, now %v", tree, now)
				}
				for rel, h := range now {
					if l.atKill[1][rel] != h {
						t.Fatalf("%s was not fsynced before the kill (fsynced %q, now %q)", rel, l.atKill[1][rel], h)
					}
				}
			}},
		{name: "nested files and directories are fsynced, children before parents", files: nested,
			check: func(t *testing.T, f *parkFixture, l *fsyncLog, ref string, err error) {
				if err != nil {
					t.Fatal(err)
				}
				l.durable(t)
				if _, ok := l.files["blobs/sha256/abc"]; !ok {
					t.Fatalf("the nested blob was never fsynced (fsynced %v)", l.files)
				}
				if want := []string{"blobs/sha256", "blobs", "."}; strings.Join(l.dirs, " ") != strings.Join(want, " ") {
					t.Fatalf("directories fsynced %q, want %q", l.dirs, want)
				}
			}},
		{name: "an fsync that fails leaves the fiber running", failAt: "manifest.json",
			check: func(t *testing.T, f *parkFixture, l *fsyncLog, ref string, err error) {
				if err == nil || !strings.Contains(err.Error(), "fsync failed") || ref != "" {
					t.Fatalf("Park = %q, %v, want the fsync failure and no ref", ref, err)
				}
				if released, parked := f.fiberFlags(t, "g1/1/1"); released || parked {
					t.Fatal("the fiber must be a running fiber again")
				}
				if len(f.fake().killedIDs()) != 0 {
					t.Fatal("the fiber was killed although its images are not durable")
				}
				if exists(l.dir) || !exists(l.dir+".failed") {
					t.Fatal("the failed images must be set aside")
				}
				noExit(t, f.r)
			}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			cb := newCodecBackend(core.TierCheckpoint)
			cb.parkFiles = tc.files
			l := &fsyncLog{files: map[string]string{}, failAt: tc.failAt}
			f := newParkFixture(t, &killWatch{cb, l}, g, nil)
			l.dir = f.r.deltaDir(f.fence)
			orig := fsync
			fsync = l.fsync
			t.Cleanup(func() { fsync = orig })
			ref, err := f.r.Park(context.Background(), f.h.ID, true)
			tc.check(t, f, l, ref, err)
		})
	}
}

// TestResumeW checks that a park records the fiber's W and a resume
// carries on from it. A sandbox's own count before its hand-out is its
// footprint, and the pages it dirtied before the park are in the image it
// is restored from, so the footprint of the resumed fiber is that count
// less the parked W.
func TestResumeW(t *testing.T) {
	cases := []struct {
		name string
		// reported is what the backend counts in the resumed leaf before
		// the hand-out, given the parked W.
		reported func(parked uint64) uint64
		// positive is whether the resumed fiber's W, with its leaf charged
		// 5 MiB, must be above zero.
		positive bool
	}{
		{name: "the count less the parked W is the footprint", reported: func(w uint64) uint64 { return w + 1 }, positive: true},
		{name: "no count reported leaves the template's probe", reported: func(uint64) uint64 { return 0 }},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			fb := newFakeBackend(core.TierCheckpoint)
			fb.warm = backend.Warm{Bytes: 1 << 40} // a probe no leaf ever reaches
			fb.footprint = 1
			be := &struct {
				*fakeBackend
				overheadMixin
			}{fb, overheadMixin{}}
			g := core.Grant{UID: "g1", TemplateDigest: "sha256:tmpl", FiberMax: 2}
			f := newParkFixture(t, be, g, nil)
			charge(t, f.r.root.Child("g1").Child("f-1-1"), 5*mib)
			ctx := context.Background()
			ref, err := f.r.Park(ctx, f.h.ID, false)
			if err != nil {
				t.Fatalf("Park: %v", err)
			}
			m := readManifest(t, ref)
			if m.WUsed == 0 {
				t.Fatalf("manifest = %+v, want the W at park recorded", m)
			}
			fb.mu.Lock()
			fb.footprint = tc.reported(m.WUsed)
			fb.mu.Unlock()
			next := core.Fence{GrantUID: "g1", Epoch: 2, Seq: 1}
			h, err := f.r.Clone(ctx, core.CloneSpec{Grant: g, Source: core.SourceDelta, Ref: ref, Fence: next, Deadline: time.Second})
			if err != nil {
				t.Fatalf("resume: %v", err)
			}
			charge(t, f.r.root.Child("g1").Child("f-2-1"), 5*mib)
			st, err := f.r.Stats(ctx, h.ID)
			if err != nil || (st.WUsedBytes > 0) != tc.positive {
				t.Fatalf("Stats = %+v %v, want W above zero %v", st, err, tc.positive)
			}
		})
	}
}

// TestGeneration checks the host's count of a lineage. A clone is
// generation 1. A park writes the fiber's generation into its manifest,
// and a resume of that park is the parked generation plus one, which
// the backend is told. Two resumes of one park are the same generation,
// and a resume of a resumed park counts on. On the old host no count
// existed: the backend was told nothing and the manifest held nothing,
// so a template saw a constant.
func TestGeneration(t *testing.T) {
	g := core.Grant{UID: "g1", TemplateDigest: "sha256:tmpl", FiberMax: 2, WBudgetBytes: 64 * mib}
	cases := []struct {
		name string
		// steps after the clone. "park" parks the latest fiber, "resume"
		// resumes the latest park, "again" releases the latest fiber and
		// resumes the first park once more.
		steps []string
		// want is the generation of every fiber in the order they were
		// born, as the backend was told it. wantParked is what each park's
		// manifest records, in park order.
		want       []int
		wantParked []int
	}{
		{name: "a clone starts its lineage at 1", want: []int{1}},
		{name: "a resume is the parked generation plus one", steps: []string{"park", "resume"}, want: []int{1, 2}, wantParked: []int{1}},
		{name: "a resume of a resumed park counts on", steps: []string{"park", "resume", "park", "resume"}, want: []int{1, 2, 3}, wantParked: []int{1, 2}},
		{name: "a second resume of one park is the same generation", steps: []string{"park", "resume", "again"}, want: []int{1, 2, 2}, wantParked: []int{1}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			ctx := context.Background()
			f := newParkFixture(t, newCodecBackend(core.TierCheckpoint), g, nil)
			cb := f.be.(*codecBackend)
			fibers := []string{f.h.ID}
			var refs []string
			resume := func(ref string) {
				fence := core.Fence{GrantUID: "g1", Epoch: 1, Seq: uint64(len(fibers) + 1)}
				h, err := f.r.Clone(ctx, core.CloneSpec{Grant: g, Source: core.SourceDelta, Ref: ref, Fence: fence, Deadline: time.Second, CallerCert: callerDER})
				if err != nil {
					t.Fatalf("resume %s from %s: %v", fence, ref, err)
				}
				fibers = append(fibers, h.ID)
			}
			for _, step := range tc.steps {
				switch step {
				case "park":
					ref, err := f.r.Park(ctx, fibers[len(fibers)-1], false)
					if err != nil {
						t.Fatalf("park %s: %v", fibers[len(fibers)-1], err)
					}
					refs = append(refs, ref)
				case "resume":
					resume(refs[len(refs)-1])
				case "again":
					if err := f.r.Release(ctx, fibers[len(fibers)-1], false); err != nil {
						t.Fatalf("release: %v", err)
					}
					resume(refs[0])
				}
			}
			var got []int
			for i, id := range fibers {
				ff := cb.fiber(id)
				if ff == nil {
					t.Fatalf("the backend has no record of %s", id)
				}
				switch {
				case i == 0:
					got = append(got, ff.spec.Generation)
				case ff.resume == nil:
					t.Fatalf("%s was not resumed", id)
				default:
					got = append(got, ff.resume.Generation)
				}
			}
			if fmt.Sprint(got) != fmt.Sprint(tc.want) {
				t.Fatalf("the backend was told generations %v, want %v", got, tc.want)
			}
			var parked []int
			for _, ref := range refs {
				var m manifest
				if err := readJSON(filepath.Join(ref, "manifest.json"), &m); err != nil {
					t.Fatal(err)
				}
				parked = append(parked, m.Generation)
			}
			if fmt.Sprint(parked) != fmt.Sprint(tc.wantParked) {
				t.Fatalf("the manifests record generations %v, want %v", parked, tc.wantParked)
			}
		})
	}
}
