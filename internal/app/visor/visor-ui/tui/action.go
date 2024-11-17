package tui

import (
	"sync"

	"github.com/gdamore/tcell/v2"
)

type (
	// RangeFn represents a range iteration callback.
	RangeFn func(tcell.Key, KeyAction)

	// ActionHandler handles a keyboard command.
	ActionHandler func(*tcell.EventKey) *tcell.EventKey

	// KeyAction represents a keyboard action.
	KeyAction struct {
		Description string
		Action      ActionHandler
	}

	// KeyMap tracks key to action mappings.
	KeyMap map[tcell.Key]KeyAction

	// KeyActions tracks mappings between keystrokes and actions.
	KeyActions struct {
		actions KeyMap
		mx      sync.RWMutex
	}
)

// NewKeyActions returns a new instance.
func NewKeyActions() *KeyActions {
	return &KeyActions{
		actions: make(map[tcell.Key]KeyAction),
	}
}

// NewKeyActionWithOpts returns a new keyboard action.
func NewKeyActionWithOpts(d string, a ActionHandler) KeyAction {
	return KeyAction{
		Description: d,
		Action:      a,
	}
}

// NewKeyActionsFromMap construct actions from key map.
func NewKeyActionsFromMap(mm KeyMap) *KeyActions {
	return &KeyActions{actions: mm}
}

// Get fetches an action given a key.
func (a *KeyActions) Get(key tcell.Key) (KeyAction, bool) {
	a.mx.RLock()
	defer a.mx.RUnlock()

	v, ok := a.actions[key]

	return v, ok
}

// Len returns action mapping count.
func (a *KeyActions) Len() int {
	a.mx.RLock()
	defer a.mx.RUnlock()

	return len(a.actions)
}

// Reset clears out actions.
func (a *KeyActions) Reset(aa *KeyActions) {
	a.Clear()
	a.Merge(aa)
}

// Range ranges over all actions and triggers a given function.
func (a *KeyActions) Range(f RangeFn) {
	var km KeyMap
	a.mx.RLock()
	{
		km = a.actions
	}
	a.mx.RUnlock()

	for k, v := range km {
		f(k, v)
	}
}

// Add adds a new key action.
func (a *KeyActions) Add(k tcell.Key, ka KeyAction) {
	a.mx.Lock()
	defer a.mx.Unlock()

	a.actions[k] = ka
}

// Bulk bulk insert key mappings.
func (a *KeyActions) Bulk(aa KeyMap) {
	a.mx.Lock()
	defer a.mx.Unlock()

	for k, v := range aa {
		a.actions[k] = v
	}
}

// Merge merges given actions into existing set.
func (a *KeyActions) Merge(aa *KeyActions) {
	a.mx.Lock()
	defer a.mx.Unlock()

	for k, v := range aa.actions {
		a.actions[k] = v
	}
}

// Clear remove all actions.
func (a *KeyActions) Clear() {
	a.mx.Lock()
	defer a.mx.Unlock()

	for k := range a.actions {
		delete(a.actions, k)
	}
}

// Set replace actions with new ones.
func (a *KeyActions) Set(aa *KeyActions) {
	a.mx.Lock()
	defer a.mx.Unlock()

	for k, v := range aa.actions {
		a.actions[k] = v
	}
}

// Delete deletes actions by the given keys.
func (a *KeyActions) Delete(kk ...tcell.Key) {
	a.mx.Lock()
	defer a.mx.Unlock()

	for _, k := range kk {
		delete(a.actions, k)
	}
}

// HasAction checks if key matches a registered binding.
func (a *KeyActions) HasAction(key tcell.Key) (KeyAction, bool) {
	return a.Get(key)
}

// GetActions returns a collection of actions.
func (a *KeyActions) GetActions() *KeyActions {
	return a
}

// AddActions returns the application actions.
func (a *KeyActions) AddActions(aa *KeyActions) {
	a.Merge(aa)
}
