//go:build linux

package hostnet

import (
	"bytes"
	"encoding/json"
	"errors"
	"io"
	"os"
	"syscall"

	"golang.org/x/sys/unix"
)

const journalLimit = 32 << 10

// FileJournal holds a process-exclusive lock on a dedicated private directory.
// Keep it open until the controller and its tunnel lifetime have finished.
type FileJournal struct {
	root *os.Root
	lock *os.File
}

type journalRecord struct {
	Version int
	Plan    Plan
}

func OpenJournal(path string) (*FileJournal, error) {
	root, err := os.OpenRoot(path)
	if err != nil {
		return nil, ErrJournal
	}
	info, err := root.Stat(".")
	if err != nil || info.Mode().Perm() != 0700 || info.Sys().(*syscall.Stat_t).Uid != uint32(os.Geteuid()) {
		root.Close()
		return nil, ErrJournal
	}
	lock, err := root.OpenFile("lease.lock", os.O_RDWR|os.O_CREATE|syscall.O_NOFOLLOW, 0600)
	if err != nil {
		root.Close()
		return nil, ErrJournal
	}
	if err := unix.Flock(int(lock.Fd()), unix.LOCK_EX|unix.LOCK_NB); err != nil {
		lock.Close()
		root.Close()
		return nil, ErrJournal
	}
	return &FileJournal{root: root, lock: lock}, nil
}

func (j *FileJournal) Close() error { return errors.Join(j.lock.Close(), j.root.Close()) }

func (j *FileJournal) Load() (*Plan, error) {
	f, err := j.root.OpenFile("lease.json", os.O_RDONLY|syscall.O_NOFOLLOW|syscall.O_NONBLOCK, 0)
	if errors.Is(err, os.ErrNotExist) {
		return nil, nil
	}
	if err != nil {
		return nil, ErrJournal
	}
	defer f.Close()
	if info, err := f.Stat(); err != nil || !info.Mode().IsRegular() {
		return nil, ErrJournal
	}
	raw, err := io.ReadAll(io.LimitReader(f, journalLimit+1))
	if err != nil || len(raw) > journalLimit {
		return nil, ErrJournal
	}
	var record journalRecord
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&record); err != nil || record.Version != 1 || decoder.Decode(new(any)) != io.EOF {
		return nil, ErrJournal
	}
	return &record.Plan, nil
}

func (j *FileJournal) Save(plan Plan) error {
	if pending, err := j.Load(); err != nil || pending != nil {
		return ErrJournal
	}
	raw, err := json.Marshal(journalRecord{Version: 1, Plan: plan})
	if err != nil || len(raw) > journalLimit {
		return ErrJournal
	}
	if err := j.root.Remove("lease.tmp"); err != nil && !errors.Is(err, os.ErrNotExist) {
		return ErrJournal
	}
	f, err := j.root.OpenFile("lease.tmp", os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0600)
	if err != nil {
		return ErrJournal
	}
	_, writeErr := f.Write(raw)
	syncErr := f.Sync()
	closeErr := f.Close()
	if writeErr != nil || syncErr != nil || closeErr != nil {
		return ErrJournal
	}
	if err := j.root.Rename("lease.tmp", "lease.json"); err != nil {
		return ErrJournal
	}
	return j.syncDir()
}

func (j *FileJournal) Delete() error {
	if err := j.root.Remove("lease.json"); err != nil && !errors.Is(err, os.ErrNotExist) {
		return ErrJournal
	}
	return j.syncDir()
}

func (j *FileJournal) syncDir() error {
	dir, err := j.root.Open(".")
	if err != nil {
		return ErrJournal
	}
	defer dir.Close()
	if err := dir.Sync(); err != nil {
		return ErrJournal
	}
	return nil
}
