// Package journal records recoverable host operations in one conditionally written document.
package journal

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"reflect"
	"regexp"
	"time"
)

var (
	ErrConflict   = errors.New("journal revision conflict")
	ErrIntegrity  = errors.New("journal integrity failure")
	ErrOwnership  = errors.New("journal ownership rejected")
	ErrBinding    = errors.New("journal input binding changed")
	ErrNotFound   = errors.New("journal operation not found")
	ErrTransition = errors.New("journal transition rejected")
	ErrBudget     = errors.New("journal budget exhausted")
)

const MaxDocumentBytes = 4 << 20
const (
	EffectIntended  = "intended"
	EffectInFlight  = "in_flight"
	EffectAmbiguous = "ambiguous"
	EffectConfirmed = "confirmed"
)

var identity = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9_.:-]{0,255}$`)

type Lease struct {
	Owner      string    `json:"owner"`
	Generation uint64    `json:"generation"`
	ExpiresAt  time.Time `json:"expires_at"`
}
type Effect struct {
	ID      string          `json:"id"`
	Kind    string          `json:"kind"`
	Binding string          `json:"binding"`
	Status  string          `json:"status"`
	Receipt json.RawMessage `json:"receipt,omitempty"`
}
type Record struct {
	ID         string            `json:"id"`
	Binding    string            `json:"binding"`
	Generation uint64            `json:"generation"`
	Lease      Lease             `json:"lease"`
	Data       json.RawMessage   `json:"data"`
	Counters   map[string]uint64 `json:"counters"`
	Effects    map[string]Effect `json:"effects"`
}
type Document struct {
	SchemaVersion int               `json:"schema_version"`
	Records       map[string]Record `json:"records"`
	Checksum      string            `json:"checksum"`
}

// Backend must atomically replace the entire document only at the supplied revision.
// There is no retry after an ambiguous write. All effect authority lives in this one file.
type Backend interface {
	Load(context.Context) (Document, string, error)
	CompareAndSwap(context.Context, string, Document) (string, error)
}
type Engine struct {
	backend Backend
	clock   func() time.Time
}

func New(backend Backend, clock func() time.Time) *Engine {
	if clock == nil {
		clock = time.Now
	}
	return &Engine{backend: backend, clock: clock}
}
func Empty() Document { return Document{SchemaVersion: 1, Records: map[string]Record{}} }
func clone[T any](v T) T {
	b, _ := json.Marshal(v)
	var result T
	_ = json.Unmarshal(b, &result)
	return result
}
func (e *Engine) load(ctx context.Context) (Document, string, error) {
	if e.backend == nil {
		return Document{}, "", ErrIntegrity
	}
	d, r, err := e.backend.Load(ctx)
	if err != nil {
		return d, r, err
	}
	if err = validateDocument(d); err != nil {
		return d, r, err
	}
	return d, r, nil
}
func (e *Engine) Read(ctx context.Context, id string) (*Record, error) {
	d, _, err := e.load(ctx)
	if err != nil {
		return nil, err
	}
	r, ok := d.Records[id]
	if !ok {
		return nil, ErrNotFound
	}
	return &r, nil
}
func (e *Engine) save(ctx context.Context, d Document, rev string) error {
	if err := validateDocument(d); err != nil {
		return err
	}
	_, err := e.backend.CompareAndSwap(ctx, rev, d)
	return err
}
func (e *Engine) Admit(ctx context.Context, id, binding string, data json.RawMessage) (*Record, error) {
	if !identity.MatchString(id) || binding == "" || !json.Valid(data) {
		return nil, ErrIntegrity
	}
	d, rev, err := e.load(ctx)
	if err != nil {
		return nil, err
	}
	if old, ok := d.Records[id]; ok {
		if old.Binding != binding {
			return nil, ErrBinding
		}
		return &old, nil
	}
	r := Record{ID: id, Binding: binding, Data: clone(data), Counters: map[string]uint64{}, Effects: map[string]Effect{}}
	d.Records[id] = r
	if err = e.save(ctx, d, rev); err != nil {
		return nil, err
	}
	return &r, nil
}
func (e *Engine) Claim(ctx context.Context, id, owner string, ttl time.Duration) (Lease, error) {
	if !identity.MatchString(owner) || ttl <= 0 || ttl > 24*time.Hour {
		return Lease{}, ErrOwnership
	}
	d, rev, err := e.load(ctx)
	if err != nil {
		return Lease{}, err
	}
	r, ok := d.Records[id]
	if !ok {
		return Lease{}, ErrNotFound
	}
	if r.Lease.Owner != "" && r.Lease.ExpiresAt.After(e.clock()) {
		return Lease{}, ErrOwnership
	}
	if r.Generation == ^uint64(0) {
		return Lease{}, ErrOwnership
	}
	r.Generation++
	r.Lease = Lease{Owner: owner, Generation: r.Generation, ExpiresAt: e.clock().UTC().Add(ttl)}
	d.Records[id] = r
	if err = e.save(ctx, d, rev); err != nil {
		return Lease{}, err
	}
	return r.Lease, nil
}
func (e *Engine) owns(r Record, l Lease) bool {
	return l.Owner != "" && r.Lease.Owner == l.Owner && r.Generation == l.Generation && r.Lease.Generation == l.Generation && r.Lease.ExpiresAt.After(e.clock())
}

// Update is a single CAS transaction. A conflict requires caller re-evaluation.
// Identity/lease fields are immutable; counters cannot fall and effects cannot be erased.
func (e *Engine) Update(ctx context.Context, id string, l Lease, update func(*Record) error) (*Record, error) {
	d, rev, err := e.load(ctx)
	if err != nil {
		return nil, err
	}
	old, ok := d.Records[id]
	if !ok {
		return nil, ErrNotFound
	}
	if !e.owns(old, l) {
		return nil, ErrOwnership
	}
	next := clone(old)
	if update == nil {
		return nil, ErrTransition
	}
	if err = update(&next); err != nil {
		return nil, err
	}
	if err = validateTransition(old, next); err != nil {
		return nil, err
	}
	if !e.owns(old, l) {
		return nil, ErrOwnership
	}
	if sameJSON(old, next) {
		return &next, nil
	}
	d.Records[id] = next
	if err = e.save(ctx, d, rev); err != nil {
		return nil, err
	}
	return &next, nil
}
func (e *Engine) Rebind(ctx context.Context, id string, l Lease, binding string, data json.RawMessage) (*Record, error) {
	if binding == "" || !json.Valid(data) {
		return nil, ErrBinding
	}
	d, rev, err := e.load(ctx)
	if err != nil {
		return nil, err
	}
	r, ok := d.Records[id]
	if !ok {
		return nil, ErrNotFound
	}
	if !e.owns(r, l) {
		return nil, ErrOwnership
	}
	r.Binding = binding
	r.Data = clone(data)
	d.Records[id] = r
	if err = e.save(ctx, d, rev); err != nil {
		return nil, err
	}
	return &r, nil
}
func (e *Engine) Renew(ctx context.Context, id string, l Lease, ttl time.Duration) (Lease, error) {
	if ttl <= 0 || ttl > 24*time.Hour {
		return Lease{}, ErrOwnership
	}
	d, rev, err := e.load(ctx)
	if err != nil {
		return Lease{}, err
	}
	r, ok := d.Records[id]
	if !ok {
		return Lease{}, ErrNotFound
	}
	if !e.owns(r, l) {
		return Lease{}, ErrOwnership
	}
	r.Lease.ExpiresAt = e.clock().UTC().Add(ttl)
	d.Records[id] = r
	if err = e.save(ctx, d, rev); err != nil {
		return Lease{}, err
	}
	return r.Lease, nil
}
func (e *Engine) Release(ctx context.Context, id string, l Lease) error {
	d, rev, err := e.load(ctx)
	if err != nil {
		return err
	}
	r, ok := d.Records[id]
	if !ok {
		return ErrNotFound
	}
	if !e.owns(r, l) {
		return ErrOwnership
	}
	r.Lease.Owner = ""
	r.Lease.ExpiresAt = time.Time{}
	d.Records[id] = r
	return e.save(ctx, d, rev)
}
func (e *Engine) Spend(ctx context.Context, id string, l Lease, counter string, limit uint64) (*Record, error) {
	return e.Update(ctx, id, l, func(r *Record) error {
		if !identity.MatchString(counter) {
			return ErrIntegrity
		}
		if r.Counters[counter] >= limit {
			return ErrBudget
		}
		r.Counters[counter]++
		return nil
	})
}
func (e *Engine) Intent(ctx context.Context, id string, l Lease, effect Effect) (*Record, error) {
	return e.Update(ctx, id, l, func(r *Record) error {
		if old, ok := r.Effects[effect.ID]; ok {
			if old.Kind != effect.Kind || old.Binding != effect.Binding {
				return ErrBinding
			}
			return nil
		}
		effect.Status = "intended"
		effect.Receipt = nil
		r.Effects[effect.ID] = effect
		return nil
	})
}
func (e *Engine) Effect(ctx context.Context, id string, l Lease, effectID, status string, receipt json.RawMessage) (*Record, error) {
	return e.Update(ctx, id, l, func(r *Record) error {
		effect, ok := r.Effects[effectID]
		if !ok {
			return ErrNotFound
		}
		if effect.Status == EffectInFlight && status == EffectInFlight {
			return ErrTransition
		}
		effect.Status = status
		effect.Receipt = append(json.RawMessage(nil), receipt...)
		r.Effects[effectID] = effect
		return nil
	})
}
func validateTransition(old, next Record) error {
	if old.ID != next.ID || old.Binding != next.Binding || old.Generation != next.Generation || !reflect.DeepEqual(old.Lease, next.Lease) {
		return ErrTransition
	}
	for key, value := range old.Counters {
		if next.Counters[key] < value {
			return ErrBudget
		}
	}
	for key, before := range old.Effects {
		after, ok := next.Effects[key]
		if !ok || before.ID != after.ID || before.Kind != after.Kind || before.Binding != after.Binding {
			return ErrTransition
		}
		allowed := map[string]map[string]bool{"intended": {"in_flight": true, "confirmed": true}, "in_flight": {"ambiguous": true, "confirmed": true}, "ambiguous": {"confirmed": true}, "confirmed": {}}
		if before.Status != after.Status && !allowed[before.Status][after.Status] {
			return ErrTransition
		}
		if before.Status == "confirmed" && !sameJSON(before.Receipt, after.Receipt) {
			return ErrTransition
		}
	}
	for key, after := range next.Effects {
		if _, exists := old.Effects[key]; !exists && after.Status != "intended" {
			return ErrTransition
		}
	}
	return nil
}
func validateDocument(d Document) error {
	if d.SchemaVersion != 1 || d.Records == nil || len(d.Records) > 1000 {
		return ErrIntegrity
	}
	for key, r := range d.Records {
		if !identity.MatchString(key) || r.ID != key || r.Binding == "" || len(r.Binding) > 1024 || strictDecode(r.Data, new(any)) != nil || r.Counters == nil || r.Effects == nil || len(r.Counters) > 256 || len(r.Effects) > 1000 {
			return ErrIntegrity
		}
		if r.Lease.Generation != r.Generation && r.Lease.Owner != "" {
			return ErrIntegrity
		}
		for counter := range r.Counters {
			if !identity.MatchString(counter) {
				return ErrIntegrity
			}
		}
		for key, effect := range r.Effects {
			if key != effect.ID || !identity.MatchString(key) || !identity.MatchString(effect.Kind) || effect.Binding == "" || len(effect.Binding) > 1024 {
				return ErrIntegrity
			}
			switch effect.Status {
			case "intended", "in_flight", "ambiguous":
				if len(effect.Receipt) > 0 {
					return ErrIntegrity
				}
			case "confirmed":
				if strictDecode(effect.Receipt, new(any)) != nil || bytes.Equal(bytes.TrimSpace(effect.Receipt), []byte("null")) {
					return ErrIntegrity
				}
			default:
				return ErrIntegrity
			}
		}
	}
	return nil
}
func checksum(d Document) (string, error) {
	d.Checksum = ""
	data, err := json.Marshal(d)
	if err != nil {
		return "", ErrIntegrity
	}
	sum := sha256.Sum256(data)
	return hex.EncodeToString(sum[:]), nil
}
func Encode(d Document) ([]byte, error) {
	if err := validateDocument(d); err != nil {
		return nil, err
	}
	sum, err := checksum(d)
	if err != nil {
		return nil, err
	}
	d.Checksum = sum
	b, err := json.MarshalIndent(d, "", "  ")
	if err != nil || len(b) > MaxDocumentBytes {
		return nil, ErrIntegrity
	}
	return b, nil
}
func Decode(data []byte) (Document, error) {
	var d Document
	if len(data) > MaxDocumentBytes {
		return d, ErrIntegrity
	}
	if err := strictDecode(data, &d); err != nil {
		return d, ErrIntegrity
	}
	if err := validateDocument(d); err != nil {
		return d, err
	}
	sum, err := checksum(d)
	if err != nil || sum != d.Checksum {
		return d, ErrIntegrity
	}
	return d, nil
}
func conflict(err error) error {
	if err == nil {
		return nil
	}
	return fmt.Errorf("journal storage: %w", err)
}

// JSON transport may reindent RawMessage fields. Preserve receipt meaning while
// ignoring representation-only whitespace introduced by durable encoding.
func sameJSON(left, right any) bool {
	a, err := json.Marshal(left)
	if err != nil {
		return false
	}
	b, err := json.Marshal(right)
	return err == nil && bytes.Equal(a, b)
}
