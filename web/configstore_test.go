package web

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/ynori7/credential-detector/config"
)

func TestConfigStore_SaveAndGet(t *testing.T) {
	cs := newConfigStore()
	conf := &config.Config{MinPasswordLength: 12}

	id := cs.Save(conf)
	assert.NotEmpty(t, id)

	got := cs.Get(id)
	require.NotNil(t, got)
	assert.Equal(t, 12, got.MinPasswordLength)
}

func TestConfigStore_Get_NotFound(t *testing.T) {
	cs := newConfigStore()
	assert.Nil(t, cs.Get("nonexistent"))
}

func TestConfigStore_Delete(t *testing.T) {
	cs := newConfigStore()
	id := cs.Save(&config.Config{MinPasswordLength: 5})
	cs.Delete(id)
	assert.Nil(t, cs.Get(id))
}

func TestConfigStore_IdsAreUnique(t *testing.T) {
	cs := newConfigStore()
	id1 := cs.Save(&config.Config{})
	id2 := cs.Save(&config.Config{})
	assert.NotEqual(t, id1, id2)
}
