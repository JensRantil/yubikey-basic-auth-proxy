package main

import (
	"sort"
	"time"
)

type EvictionCallback func()

type CacheValue struct {
	callback   EvictionCallback
	expiration time.Time
	key        string
}

type setValueCommand struct {
	item CacheValue
	done chan struct{}
}

type checkValueExistCommand struct {
	key    string
	exists chan bool
}

type timer interface {
	channel() <-chan time.Time
	stop()
}

type timerFactory interface {
	create(time.Duration) timer
}

type realTimer struct {
	delegate *time.Timer
}

func (r *realTimer) channel() <-chan time.Time {
	return r.delegate.C
}

func (r *realTimer) stop() {
	r.delegate.Stop()
}

type realTimerFactory struct{}

func (r realTimerFactory) create(d time.Duration) timer {
	return &realTimer{time.NewTimer(d)}
}

// Access-expired cache that holds values for a certain expiration since write.
// New writes will postpone the expiration.
type Cache struct {
	data         map[string]CacheValue
	setChan      chan setValueCommand
	checkChan    chan checkValueExistCommand
	stopChan     chan struct{}
	expiration   time.Duration
	timerFactory timerFactory
}

func NewCache(expiration time.Duration) *Cache {
	cache := &Cache{
		data:         make(map[string]CacheValue),
		setChan:      make(chan setValueCommand),
		checkChan:    make(chan checkValueExistCommand),
		stopChan:     make(chan struct{}),
		expiration:   expiration,
		timerFactory: realTimerFactory{},
	}

	return cache
}

func (c *Cache) Start() {
	h := make(CacheExpirationSorter, 0)
	var evictionTimer timer
	var evictionTimerChan <-chan time.Time

	for {
		select {
		case command := <-c.setChan:
			if v, exist := c.data[command.item.key]; exist {
				i := sort.Search(
					len(h),
					func(i int) bool {
						return !h[i].expiration.After(v.expiration)
					})
				for h[i].key != command.item.key {
					i++
				}
				h[i] = command.item
			} else {
				h = append(h, command.item)
			}
			c.data[command.item.key] = command.item
			sort.Sort(h) // TODO: Could potentially to insertion sort here instead.

			if evictionTimer != nil {
				evictionTimer.stop()
			}
			evictionTimer := c.timerFactory.create(h[len(h)-1].expiration.Sub(time.Now()))
			evictionTimerChan = evictionTimer.channel()

			command.done <- struct{}{}

		case command := <-c.checkChan:
			_, exists := c.data[command.key]
			command.exists <- exists

		case <-evictionTimerChan:
			valueToEvict := h[len(h)-1]
			if valueToEvict.callback != nil {
				valueToEvict.callback()
			}

			delete(c.data, valueToEvict.key)
			h = h[0 : len(h)-1]

			if len(h) > 0 {
				// Shedule next eviction.
				evictionTimer := c.timerFactory.create(h[len(h)-1].expiration.Sub(time.Now()))
				evictionTimerChan = evictionTimer.channel()
			}

		case <-c.stopChan:
			return
		}
	}
}

func (c *Cache) Stop() {
	close(c.stopChan)
}

func (c *Cache) AddOrUpdate(key string, callback EvictionCallback) {
	command := setValueCommand{
		item: CacheValue{
			key:        key,
			expiration: time.Now().Add(c.expiration),
			callback:   callback,
		},
		done: make(chan struct{}, 1),
	}
	c.setChan <- command
	<-command.done
}

func (c *Cache) Contains(key string) bool {
	command := checkValueExistCommand{
		key:    key,
		exists: make(chan bool, 1),
	}
	c.checkChan <- command
	return <-command.exists
}

type CacheExpirationSorter []CacheValue

func (h CacheExpirationSorter) Len() int           { return len(h) }
func (h CacheExpirationSorter) Less(i, j int) bool { return h[i].expiration.After(h[j].expiration) }
func (h CacheExpirationSorter) Swap(i, j int)      { h[i], h[j] = h[j], h[i] }
