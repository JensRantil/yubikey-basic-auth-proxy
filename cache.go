package main

import (
	"sync"
	"time"
)

type Cache struct {
	timers map[string]*time.Timer
	mutex  *sync.RWMutex

	expiration time.Duration
}

func NewCache(expiration time.Duration) *Cache {
	return &Cache{
		timers:     make(map[string]*time.Timer),
		mutex:      new(sync.RWMutex),
		expiration: expiration,
	}
}

func (c Cache) Add(cache string) {
	c.mutex.Lock()
	defer c.mutex.Unlock()

	if _, exist := c.timers[cache]; exist {
		// Renew the value. That is, postpone expiration. New timer added below.
		c.timers[cache].Stop()
	}

	c.timers[cache] = time.AfterFunc(c.expiration, func() {
		c.mutex.Lock()
		defer c.mutex.Unlock()

		delete(c.timers, cache)
	})

}

func (c Cache) IsStillThere(cache string) bool {
	c.mutex.RLock()
	defer c.mutex.RUnlock()

	_, exist := c.timers[cache]
	return exist
}
