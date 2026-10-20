package core

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"os"
	"path/filepath"
	"sort"
	"sync"
	"sync/atomic"
	"time"
)

// Snapshot is the on-disk cache of the ledger. It is a cache: at boot the
// runtime's view of reality wins, and the snapshot only tells fiberd
// which grants to re-admit and which parked sessions to remember.
type Snapshot struct {
	Epoch    uint64            `json:"epoch"`
	SavedAt  time.Time         `json:"saved_at"`
	Grants   []Grant           `json:"grants"`
	Sessions []SessionSnapshot `json:"sessions"`
}

type SessionSnapshot struct {
	Name           string       `json:"name"`
	GrantUID       string       `json:"grant_uid"`
	State          SessionState `json:"state"`
	Fence          Fence        `json:"fence"`
	DeltaRef       string       `json:"delta_ref,omitempty"`
	FiberID        string       `json:"fiber_id,omitempty"`
	PendingParkRef string       `json:"pending_park_ref,omitempty"`
}

// Snapshot captures the ledger.
func (l *Ledger) Snapshot() Snapshot {
	l.mu.Lock()
	defer l.mu.Unlock()
	s := Snapshot{Epoch: l.epoch, SavedAt: l.Now()}
	for _, e := range l.grants {
		s.Grants = append(s.Grants, e.grant)
	}
	for _, sess := range l.sessions {
		ss := SessionSnapshot{Name: sess.Name, GrantUID: sess.GrantUID, State: sess.State, Fence: sess.Fence, DeltaRef: sess.DeltaRef, PendingParkRef: sess.PendingParkRef}
		if sess.State == StateRunning {
			ss.FiberID = sess.Handle.ID
		}
		s.Sessions = append(s.Sessions, ss)
	}
	for id, f := range l.fibers {
		if f.sessionKey == "" && f.pendingParkRef != "" {
			s.Sessions = append(s.Sessions, SessionSnapshot{GrantUID: f.grantUID, State: StateRunning,
				Fence: f.fence, FiberID: id, PendingParkRef: f.pendingParkRef})
		}
	}
	return s
}

// installPendingLocked keeps the old slot reserved without making its endpoint
// attachable or interpreting its saved checkpoint as a consumed source.
// admitHeld prevalidates every entry before changing any ledger state.
func (l *Ledger) installPendingLocked(s SessionSnapshot) {
	g := l.grants[s.GrantUID]
	key := ""
	if s.Name != "" {
		key = s.GrantUID + "/" + s.Name
		l.sessions[key] = &Session{Name: s.Name, GrantUID: s.GrantUID, State: StateRunning,
			Fence: s.Fence, Handle: FiberHandle{ID: s.FiberID}, DeltaRef: s.DeltaRef, PendingParkRef: s.PendingParkRef}
	}
	l.fibers[s.FiberID] = &fiberRef{grantUID: s.GrantUID, sessionKey: key, fence: s.Fence, pendingParkRef: s.PendingParkRef}
	g.live++
}

// RestoreParked re-registers a parked session from a snapshot or a claim
// from another home. Its old fence only records lineage, because Resume
// mints a new one. It returns false when the grant is not admitted or the
// ledger already holds the session, since a parked entry written over a
// live one would resume the session twice.
func (l *Ledger) RestoreParked(s SessionSnapshot) bool {
	return l.restoreParked(s) == nil
}

// errSessionHeld is restoreParked's refusal when the ledger already holds
// the session, as opposed to ErrGrantUnknown when its grant is not
// admitted. locate treats the two differently.
var errSessionHeld = errors.New("ledger: session already held by this home")

// restoreParked is RestoreParked with the reason for a refusal.
func (l *Ledger) restoreParked(s SessionSnapshot) error {
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.restoreParkedLocked(s)
}

func (l *Ledger) restoreParkedLocked(s SessionSnapshot) error {
	if _, ok := l.grants[s.GrantUID]; !ok {
		return ErrGrantUnknown
	}
	key := s.GrantUID + "/" + s.Name
	if _, ok := l.sessions[key]; ok {
		return errSessionHeld
	}
	l.installParkedLocked(s)
	return nil
}

func (l *Ledger) installParkedLocked(s SessionSnapshot) {
	key := s.GrantUID + "/" + s.Name
	l.sessions[key] = &Session{Name: s.Name, GrantUID: s.GrantUID, State: StateParked, Fence: s.Fence, DeltaRef: s.DeltaRef}
}

// SnapshotStore persists snapshots atomically at Path. Each write goes to
// its own temporary file and is renamed into place, so a reader never sees
// a mix. It is safe for concurrent use. Use it by pointer.
type SnapshotStore struct {
	Path string

	mu      sync.Mutex    // one write at a time
	asked   atomic.Uint64 // Persist calls so far
	covered uint64        // the asked count the last Persist write captured after
	lastErr error         // that write's result
}

// Persist writes snapshot() so the file reflects every change made before
// the call. Writes run one at a time and capture the ledger inside the
// lock, so a later write never holds an older snapshot. A caller that
// arrived before a write started shares that write's result.
func (st *SnapshotStore) Persist(snapshot func() Snapshot) error {
	n := st.asked.Add(1)
	st.mu.Lock()
	defer st.mu.Unlock()
	if st.covered >= n {
		return st.lastErr
	}
	st.covered = st.asked.Load()
	st.lastErr = st.write(snapshot())
	return st.lastErr
}

func (st *SnapshotStore) write(s Snapshot) error {
	b, err := json.MarshalIndent(s, "", "  ")
	if err != nil {
		return err
	}
	return writeFileAtomic(st.Path, b, 0o600)
}

// Load returns the snapshot, or an empty one when none exists.
func (st *SnapshotStore) Load() (Snapshot, error) {
	b, err := os.ReadFile(st.Path)
	if errors.Is(err, os.ErrNotExist) {
		return Snapshot{}, nil
	}
	if err != nil {
		return Snapshot{}, err
	}
	var s Snapshot
	if err := json.Unmarshal(b, &s); err != nil {
		// A torn snapshot is a cache miss, not a fatal error: reality is
		// rebuilt from the runtime; only parked sessions are forgotten.
		log.Printf("snapshot: %s unreadable (%v); treating as empty", filepath.Base(st.Path), err)
		return Snapshot{}, nil
	}
	return s, nil
}

// DeltaChecker is implemented by runtimes that can say whether a parked
// delta ref still exists. Without it, parked sessions are restored from
// the snapshot on trust.
type DeltaChecker interface {
	HasDelta(ref string) bool
}

// ReconcileReport says what boot found.
type ReconcileReport struct {
	GrantsReadmitted int
	GrantsExpired    int
	// GrantsUnverified counts snapshot entries whose token did not verify
	// again at boot, or that carried none. They are not re-admitted.
	GrantsUnverified int
	// GrantsUnavailable counts snapshot entries whose token the verifier
	// could not check at boot (ErrVerifyUnavailable, as when the key set
	// was never loaded). They are not re-admitted, but they stay in the
	// snapshot with their parked sessions until the grant is admitted again
	// or a later boot finds it expired.
	GrantsUnavailable int
	ParkedRestored    int
	ParkedDropped     int
	// ParkedHeld counts parked sessions kept in the snapshot under a grant
	// the verifier could not check.
	ParkedHeld    int
	OrphansKilled int
}

// heldGrant is a snapshot entry Reconcile could not verify because the
// verifier was unavailable, with the parked sessions it owns. Nothing in it
// is trusted. It is only carried into the next snapshot.
type heldGrant struct {
	grant    Grant
	sessions []SessionSnapshot
}

// Reconcile is the boot step between epoch++ and opening the warm path.
//
//  1. Each unexpired grant whose token verifies again is re-admitted and
//     its template warmed again, because the old zygote died with the old
//     fiberd process. An entry whose token fails, names another grant or home, or
//     is missing is dropped. An entry the verifier cannot check yet is
//     held. It is not admitted, but it stays in the snapshot for a
//     redelivery or a later boot.
//  2. Each parked session whose delta still exists is remembered, so a
//     Clone(S) after restart resumes it under the new epoch.
//  3. Each fiber the runtime still reports is from a prior epoch and is
//     killed. Nothing minted before the restart validates after it.
//
// Reality wins over the snapshot at every step. The snapshot is a file on
// the home's disk, so only a grant's signature re-admits it, never the
// file.
func (a *Core) Reconcile(ctx context.Context, snap Snapshot) (ReconcileReport, error) {
	var rep ReconcileReport
	pending := make(map[string]SessionSnapshot)
	for i, s := range snap.Sessions {
		if s.PendingParkRef == "" {
			continue
		}
		fence, err := ParseFence(s.FiberID)
		if err != nil || fence != s.Fence || fence.GrantUID != s.GrantUID || s.State != StateRunning || fence.Epoch >= a.Ledger.Epoch() {
			return rep, fmt.Errorf("reconcile: invalid pending park identity %q", s.FiberID)
		}
		for j, other := range snap.Sessions {
			if i != j && s.Name != "" && s.Name == other.Name && s.GrantUID == other.GrantUID {
				return rep, fmt.Errorf("reconcile: duplicate pending session %s/%s", s.GrantUID, s.Name)
			}
		}
		q, ok := a.Runtime.(ParkQuarantiner)
		if !ok {
			return rep, fmt.Errorf("reconcile: %w: runtime cannot quarantine %s at %s", ErrParkUnconfirmed, s.FiberID, s.PendingParkRef)
		}
		if err := q.QuarantinePark(ctx, s.FiberID, s.PendingParkRef); err != nil {
			return rep, fmt.Errorf("reconcile: quarantine %s: %w", s.FiberID, err)
		}
		if _, duplicate := pending[s.FiberID]; duplicate {
			return rep, fmt.Errorf("reconcile: duplicate pending park %s", s.FiberID)
		}
		pending[s.FiberID] = s
	}
	// Admit persists, so file pending evidence under held grants before
	// any admission can replace the old snapshot.
	heldPending := make(map[string]bool)
	for _, s := range pending {
		if !heldPending[s.GrantUID] {
			g := Grant{UID: s.GrantUID}
			for _, saved := range snap.Grants {
				if saved.UID == s.GrantUID {
					g = saved
					break
				}
			}
			a.hold(g)
			heldPending[s.GrantUID] = true
		}
		a.holdParked(s)
	}
	now := a.Ledger.Now()
	untokened := 0
	for _, g := range snap.Grants {
		if g.Expired(now) {
			rep.GrantsExpired++
			_ = a.audit(ctx, BestEffort, AuditRecord{Event: "expire", Fence: Fence{GrantUID: g.UID, Epoch: a.Ledger.Epoch()}, Detail: "at boot"})
			continue
		}
		if g.Token == "" {
			rep.GrantsUnverified++
			untokened++
			continue
		}
		vg, err := a.reverify(ctx, g)
		if err != nil {
			if errors.Is(err, ErrVerifyUnavailable) {
				// The verifier cannot decide, which says nothing about the
				// token. Dropping the entry here would lose its parked
				// sessions for good at the persist below, so it is held
				// instead.
				rep.GrantsUnavailable++
				a.hold(g)
				log.Printf("reconcile: holding %s, not re-admitted until its token can be checked: %v", g.UID, err)
				continue
			}
			rep.GrantsUnverified++
			log.Printf("reconcile: not re-admitting %s: %v", g.UID, err)
			_ = a.audit(ctx, BestEffort, AuditRecord{Event: "refuse", Fence: Fence{GrantUID: g.UID, Epoch: a.Ledger.Epoch()}, Detail: "at boot: " + err.Error()})
			continue
		}
		if _, err := a.Admit(ctx, vg); err != nil {
			log.Printf("reconcile: re-admit %s: %v", g.UID, err)
			continue
		}
		rep.GrantsReadmitted++
	}
	if untokened > 0 {
		log.Printf("reconcile: %d snapshot grant(s) carried no token and were not re-admitted; a valid token presented again admits each", untokened)
	}
	checker, canCheck := a.Runtime.(DeltaChecker)
	for _, s := range snap.Sessions {
		if s.State != StateParked || s.DeltaRef == "" {
			continue
		}
		if canCheck && !checker.HasDelta(s.DeltaRef) {
			rep.ParkedDropped++
			continue
		}
		if a.holdParked(s) {
			rep.ParkedHeld++
			continue
		}
		if !a.Ledger.RestoreParked(s) {
			rep.ParkedDropped++
			continue
		}
		rep.ParkedRestored++
	}
	running, err := a.Runtime.List(ctx)
	if err != nil {
		return rep, fmt.Errorf("reconcile: list: %w", err)
	}
	for _, h := range running {
		if _, quarantined := pending[h.ID]; quarantined {
			continue
		}
		fence, perr := ParseFence(h.ID)
		if perr == nil && fence.Epoch >= a.Ledger.Epoch() {
			// Cannot happen (the epoch just moved), but never kill what
			// might be ours.
			continue
		}
		if err := a.Runtime.Release(ctx, h.ID, false); err != nil {
			log.Printf("reconcile: kill orphan %s: %v", h.ID, err)
			continue
		}
		rep.OrphansKilled++
		_ = a.audit(ctx, BestEffort, AuditRecord{Event: "orphan", Fence: fence, FiberID: h.ID, Detail: "killed at boot: prior epoch"})
	}
	// A session that was running when the old fiberd process stopped is gone. Its
	// fiber died with that process or was killed just above. The delta it
	// was resumed from was consumed by that resume, so it goes too. This
	// runs after the runtime's List, once the runtime answers. Parked
	// sessions keep their deltas.
	for _, s := range snap.Sessions {
		if s.State == StateRunning && s.DeltaRef != "" && s.PendingParkRef == "" {
			a.discardDelta(ctx, s.Fence, s.Name, s.DeltaRef)
		}
	}
	a.persist()
	a.notify()
	return rep, nil
}

// reverify checks a snapshot entry's token the way Clone checks a
// presented one, and returns what the token says, with the token kept, in
// place of what the file says.
func (a *Core) reverify(ctx context.Context, g Grant) (Grant, error) {
	vg, err := a.Verify.Verify(ctx, []byte(g.Token))
	if err != nil {
		return Grant{}, fmt.Errorf("snapshot token: %w", err)
	}
	if vg.UID != g.UID {
		return Grant{}, fmt.Errorf("snapshot token is for grant %q", vg.UID)
	}
	if a.NodeID != "" && vg.Audience != a.NodeID {
		return Grant{}, fmt.Errorf("%w: aud=%q node=%q", ErrWrongAudience, vg.Audience, a.NodeID)
	}
	vg.Token = g.Token
	return vg, nil
}

// hold keeps a snapshot grant the verifier could not check, so persist
// carries it into the next snapshot. The entry is the file's, unverified,
// and nothing reads it but the next boot.
func (a *Core) hold(g Grant) {
	a.heldMu.Lock()
	defer a.heldMu.Unlock()
	if a.held == nil {
		a.held = make(map[string]*heldGrant)
	}
	if h := a.held[g.UID]; h != nil {
		h.grant = g
		return
	}
	a.held[g.UID] = &heldGrant{grant: g}
}

// holdParked files a parked session under its held grant and reports
// whether it did. Its delta stays on disk, and Admit restores it once the
// grant is admitted again.
func (a *Core) holdParked(s SessionSnapshot) bool {
	a.heldMu.Lock()
	defer a.heldMu.Unlock()
	h, ok := a.held[s.GrantUID]
	if ok {
		h.sessions = append(h.sessions, s)
	}
	return ok
}

// admitHeld makes the grant and all held reservations visible atomically.
// Failed transfers leave the held evidence intact.
func (a *Core) admitHeld(g Grant) error {
	a.heldMu.Lock()
	defer a.heldMu.Unlock()
	var sessions []SessionSnapshot
	if h := a.held[g.UID]; h != nil {
		sessions = h.sessions
	}
	l := a.Ledger
	l.mu.Lock()
	defer l.mu.Unlock()
	names, ids := make(map[string]bool), make(map[string]bool)
	pendingCount, live := 0, 0
	for _, f := range l.fibers {
		if f.grantUID == g.UID {
			live++
		}
	}
	for _, s := range sessions {
		if s.GrantUID != g.UID {
			return fmt.Errorf("admit: held session grant %s differs from %s", s.GrantUID, g.UID)
		}
		if s.Name != "" {
			key := g.UID + "/" + s.Name
			if names[key] || l.sessions[key] != nil {
				return fmt.Errorf("admit: %w: %s", errSessionHeld, key)
			}
			names[key] = true
		}
		if s.PendingParkRef != "" {
			if s.FiberID == "" || ids[s.FiberID] || l.fibers[s.FiberID] != nil {
				return fmt.Errorf("admit: %w: %s", errSessionHeld, s.FiberID)
			}
			ids[s.FiberID] = true
			pendingCount++
		}
	}
	if pendingCount > 0 && g.FiberMax > 0 && live+pendingCount > g.FiberMax {
		return fmt.Errorf("admit: %w: %d held/running fibers exceed %d", ErrGrantFull, live+pendingCount, g.FiberMax)
	}
	l.admitGrantLocked(g)
	for _, s := range sessions {
		if s.PendingParkRef != "" {
			l.installPendingLocked(s)
		} else {
			l.installParkedLocked(s)
		}
	}
	delete(a.held, g.UID)
	return nil
}

// snapshot is what persist writes. It is the ledger plus the entries boot
// held because the verifier was unavailable. Without them the first persist
// after boot would drop those grants and their parked sessions from the
// file for good.
func (a *Core) snapshot() Snapshot {
	a.heldMu.Lock()
	defer a.heldMu.Unlock()
	s := a.Ledger.Snapshot()
	if len(a.held) == 0 {
		return s
	}
	admitted := make(map[string]bool, len(s.Grants))
	for _, g := range s.Grants {
		admitted[g.UID] = true
	}
	known := make(map[string]bool, len(s.Sessions))
	key := func(sess SessionSnapshot) string {
		if sess.Name == "" {
			return sess.GrantUID + "/@fiber/" + sess.FiberID
		}
		return sess.GrantUID + "/@session/" + sess.Name
	}
	for _, sess := range s.Sessions {
		known[key(sess)] = true
	}
	uids := make([]string, 0, len(a.held))
	for uid := range a.held {
		uids = append(uids, uid)
	}
	sort.Strings(uids)
	for _, uid := range uids {
		if admitted[uid] {
			continue
		}
		h := a.held[uid]
		s.Grants = append(s.Grants, h.grant)
		for _, sess := range h.sessions {
			if !known[key(sess)] {
				s.Sessions = append(s.Sessions, sess)
			}
		}
	}
	return s
}

// Sweep is the lease reaper's step: every admitted grant whose lease has
// lapsed is yielded (fibers released, grant revoked). Parked deltas are
// kept; they are the only state that cannot be rebuilt.
func (a *Core) Sweep(ctx context.Context) int {
	now := a.Ledger.Now()
	n := 0
	for _, st := range a.Ledger.Statuses() {
		g, ok := a.Ledger.Grant(st.GrantUID)
		if ok && g.Expired(now) {
			a.Yield(ctx, g.UID, "lease expired")
			n++
		}
	}
	return n
}
