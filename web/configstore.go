package web

import (
	"sync"
	"time"

	"github.com/ynori7/credential-detector/config"
)

const configStoreTTL = 24 * time.Hour

// ConfigStore holds user-submitted config overrides mapped by ID.
type ConfigStore struct {
	mu    sync.RWMutex
	items map[string]*configEntry
}

type configEntry struct {
	conf    *config.Config
	savedAt time.Time
}

func newConfigStore() *ConfigStore {
	cs := &ConfigStore{items: make(map[string]*configEntry)}
	go cs.cleanup()
	return cs
}

// Save stores the config and returns its ID.
func (cs *ConfigStore) Save(conf *config.Config) string {
	id := generateID()
	cs.mu.Lock()
	cs.items[id] = &configEntry{conf: conf, savedAt: time.Now()}
	cs.mu.Unlock()
	return id
}

// Get retrieves a stored config by ID, or nil if not found.
func (cs *ConfigStore) Get(id string) *config.Config {
	cs.mu.RLock()
	defer cs.mu.RUnlock()
	if e, ok := cs.items[id]; ok {
		return e.conf
	}
	return nil
}

// Delete removes a config from the store.
func (cs *ConfigStore) Delete(id string) {
	cs.mu.Lock()
	delete(cs.items, id)
	cs.mu.Unlock()
}

func (cs *ConfigStore) cleanup() {
	ticker := time.NewTicker(1 * time.Hour)
	defer ticker.Stop()
	for range ticker.C {
		cs.mu.Lock()
		for id, e := range cs.items {
			if time.Since(e.savedAt) > configStoreTTL {
				delete(cs.items, id)
			}
		}
		cs.mu.Unlock()
	}
}
