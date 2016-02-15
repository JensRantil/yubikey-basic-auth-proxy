package main

import (
	. "testing"
	"time"
)

type fakeTimerFactory struct {
	c chan time.Time
}

func (f *fakeTimerFactory) create(_ time.Duration) timer {
	return &fakeTimer{f.c}
}

type fakeTimer struct {
	c chan time.Time
}

func (f *fakeTimer) stop() {
	// Noop.
}

func (f *fakeTimer) channel() <-chan time.Time {
	return f.c
}

func createFakedTimerFactory() (timerFactory, chan time.Time) {
	c := make(chan time.Time)
	return &fakeTimerFactory{c}, c
}

func newTestCache() (*Cache, chan<- time.Time) {
	timerFactory, expireChan := createFakedTimerFactory()

	cache := &Cache{
		data:         make(map[string]CacheValue),
		setChan:      make(chan setValueCommand),
		checkChan:    make(chan checkValueExistCommand),
		stopChan:     make(chan struct{}),
		expiration:   1 * time.Second, // Not used in tests.
		timerFactory: timerFactory,
	}
	return cache, expireChan
}

func TestAddingToCache(t *T) {
	t.Parallel()

	c, _ := newTestCache()
	go c.Start()
	defer c.Stop()

	if c.Contains("hello") {
		t.Error("Key existed before adding it.")
	}
	c.AddOrUpdate("hello", func() {})
	if !c.Contains("hello") {
		t.Error("Key didn't exist after adding it.")
	}
}

func TestExpiration(t *T) {
	t.Parallel()

	c, expireChan := newTestCache()
	go c.Start()
	defer c.Stop()

	if c.Contains("hello") {
		t.Error("Key existed before adding it.")
	}
	c.AddOrUpdate("hello", func() {})
	if !c.Contains("hello") {
		t.Error("Key didn't exist after adding it.")
	}

	expireChan <- time.Now()

	if c.Contains("hello") {
		t.Error("Key didn't expire.")
	}
}

func TestMultipleExpirations(t *T) {
	t.Parallel()

	c, expireChan := newTestCache()
	go c.Start()
	defer c.Stop()

	keys := []string{
		"a", "b", "c",
	}

	for _, key := range keys {
		c.AddOrUpdate(key, func() {})
	}

	for i, _ := range keys {
		expireChan <- time.Now()
		for j := 0; j < i+1; j++ {
			if key := keys[j]; c.Contains(key) {
				t.Error("Key", key, "didn't expire.")
			}
		}
		for j := i + 1; j < len(keys); j++ {
			if key := keys[j]; !c.Contains(key) {
				t.Error("Key", key, "shouldn't have expired.")
			}
		}
	}
}

func TestExpirationPostponing(t *T) {
	t.Parallel()

	c, expireChan := newTestCache()
	go c.Start()
	defer c.Stop()

	c.AddOrUpdate("a", func() {})
	c.AddOrUpdate("b", func() {})
	c.AddOrUpdate("a", func() {})

	expireChan <- time.Now() // Should expire 'b' since it's last updated.

	if c.Contains("b") {
		t.Error("Key 'b' didn't expire.")
	}
	if !c.Contains("a") {
		t.Error("Key 'a' wasn't supposed to expire.")
	}

	expireChan <- time.Now() // Should expire 'a' (since only element left.

	if c.Contains("b") {
		t.Error("Key 'b' didn't expire.")
	}
	if c.Contains("a") {
		t.Error("Key 'a' didn't expire.")
	}
}
