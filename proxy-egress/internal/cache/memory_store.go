package cache

import (
	"context"
	"fmt"
	"regexp"
	"sync"
	"time"
)

type MemoryStore struct {
	data       map[string]*CacheEntry
	mutex      sync.RWMutex
	config     MemoryStoreConfig
	stats      StoreStats
	eviction   *EvictionManager
	background *BackgroundCleaner
}

type MemoryStoreConfig struct {
	MaxSize        int64
	MaxKeys        int64
	EvictionPolicy EvictionPolicy
	CleanupInterval time.Duration
	TTLCheckInterval time.Duration
}

type EvictionPolicy string

const (
	EvictionLRU    EvictionPolicy = "lru"
	EvictionLFU    EvictionPolicy = "lfu"
	EvictionFIFO   EvictionPolicy = "fifo"
	EvictionRandom EvictionPolicy = "random"
)

type EvictionManager struct {
	policy    EvictionPolicy
	lruList   *LRUList
	lfuTracker *LFUTracker
	fifoQueue *FIFOQueue
}

type LRUList struct {
	head   *LRUNode
	tail   *LRUNode
	nodes  map[string]*LRUNode
	mutex  sync.RWMutex
}

type LRUNode struct {
	key   string
	prev  *LRUNode
	next  *LRUNode
	time  time.Time
}

type LFUTracker struct {
	frequencies map[string]int64
	mutex       sync.RWMutex
}

type FIFOQueue struct {
	queue []string
	mutex sync.RWMutex
}

type BackgroundCleaner struct {
	store           *MemoryStore
	cleanupTicker   *time.Ticker
	ttlTicker       *time.Ticker
	stopChan        chan struct{}
	running         bool
	mutex           sync.RWMutex
}

func NewMemoryStore(config MemoryStoreConfig) *MemoryStore {
	if config.MaxSize == 0 {
		config.MaxSize = 50 * 1024 * 1024 // 50MB default
	}
	if config.MaxKeys == 0 {
		config.MaxKeys = 10000 // 10k keys default
	}
	if config.EvictionPolicy == "" {
		config.EvictionPolicy = EvictionLRU
	}
	if config.CleanupInterval == 0 {
		config.CleanupInterval = 5 * time.Minute
	}
	if config.TTLCheckInterval == 0 {
		config.TTLCheckInterval = 1 * time.Minute
	}

	ms := &MemoryStore{
		data:   make(map[string]*CacheEntry),
		config: config,
		stats: StoreStats{
			LastEviction: time.Time{},
		},
		eviction: NewEvictionManager(config.EvictionPolicy),
	}

	ms.background = NewBackgroundCleaner(ms, config.CleanupInterval, config.TTLCheckInterval)
	ms.background.Start()

	return ms
}

func NewEvictionManager(policy EvictionPolicy) *EvictionManager {
	em := &EvictionManager{
		policy: policy,
	}

	switch policy {
	case EvictionLRU:
		em.lruList = NewLRUList()
	case EvictionLFU:
		em.lfuTracker = NewLFUTracker()
	case EvictionFIFO:
		em.fifoQueue = NewFIFOQueue()
	}

	return em
}

func NewLRUList() *LRUList {
	lru := &LRUList{
		nodes: make(map[string]*LRUNode),
	}
	
	lru.head = &LRUNode{}
	lru.tail = &LRUNode{}
	lru.head.next = lru.tail
	lru.tail.prev = lru.head
	
	return lru
}

func (lru *LRUList) Touch(key string) {
	lru.mutex.Lock()
	defer lru.mutex.Unlock()

	if node, exists := lru.nodes[key]; exists {
		lru.moveToHead(node)
		node.time = time.Now()
	} else {
		node := &LRUNode{
			key:  key,
			time: time.Now(),
		}
		lru.nodes[key] = node
		lru.addToHead(node)
	}
}

func (lru *LRUList) Remove(key string) {
	lru.mutex.Lock()
	defer lru.mutex.Unlock()

	if node, exists := lru.nodes[key]; exists {
		lru.removeNode(node)
		delete(lru.nodes, key)
	}
}

func (lru *LRUList) GetLRU() string {
	lru.mutex.RLock()
	defer lru.mutex.RUnlock()

	if lru.tail.prev == lru.head {
		return ""
	}
	return lru.tail.prev.key
}

func (lru *LRUList) addToHead(node *LRUNode) {
	node.prev = lru.head
	node.next = lru.head.next
	lru.head.next.prev = node
	lru.head.next = node
}

func (lru *LRUList) removeNode(node *LRUNode) {
	node.prev.next = node.next
	node.next.prev = node.prev
}

func (lru *LRUList) moveToHead(node *LRUNode) {
	lru.removeNode(node)
	lru.addToHead(node)
}

func NewLFUTracker() *LFUTracker {
	return &LFUTracker{
		frequencies: make(map[string]int64),
	}
}

func (lfu *LFUTracker) Touch(key string) {
	lfu.mutex.Lock()
	defer lfu.mutex.Unlock()
	lfu.frequencies[key]++
}

func (lfu *LFUTracker) Remove(key string) {
	lfu.mutex.Lock()
	defer lfu.mutex.Unlock()
	delete(lfu.frequencies, key)
}

func (lfu *LFUTracker) GetLFU() string {
	lfu.mutex.RLock()
	defer lfu.mutex.RUnlock()

	var minKey string
	var minFreq int64 = -1

	for key, freq := range lfu.frequencies {
		if minFreq == -1 || freq < minFreq {
			minFreq = freq
			minKey = key
		}
	}

	return minKey
}

func NewFIFOQueue() *FIFOQueue {
	return &FIFOQueue{
		queue: make([]string, 0),
	}
}

func (fifo *FIFOQueue) Touch(key string) {
	fifo.mutex.Lock()
	defer fifo.mutex.Unlock()

	for i, k := range fifo.queue {
		if k == key {
			return
		}
		_ = i
	}

	fifo.queue = append(fifo.queue, key)
}

func (fifo *FIFOQueue) Remove(key string) {
	fifo.mutex.Lock()
	defer fifo.mutex.Unlock()

	for i, k := range fifo.queue {
		if k == key {
			fifo.queue = append(fifo.queue[:i], fifo.queue[i+1:]...)
			return
		}
	}
}

func (fifo *FIFOQueue) GetNext() string {
	fifo.mutex.RLock()
	defer fifo.mutex.RUnlock()

	if len(fifo.queue) == 0 {
		return ""
	}
	return fifo.queue[0]
}

func NewBackgroundCleaner(store *MemoryStore, cleanupInterval, ttlInterval time.Duration) *BackgroundCleaner {
	return &BackgroundCleaner{
		store:         store,
		cleanupTicker: time.NewTicker(cleanupInterval),
		ttlTicker:     time.NewTicker(ttlInterval),
		stopChan:      make(chan struct{}),
	}
}

func (bc *BackgroundCleaner) Start() {
	bc.mutex.Lock()
	defer bc.mutex.Unlock()

	if bc.running {
		return
	}

	bc.running = true
	go bc.run()
}

func (bc *BackgroundCleaner) Stop() {
	bc.mutex.Lock()
	defer bc.mutex.Unlock()

	if !bc.running {
		return
	}

	bc.running = false
	close(bc.stopChan)
	bc.cleanupTicker.Stop()
	bc.ttlTicker.Stop()
}

func (bc *BackgroundCleaner) run() {
	for {
		select {
		case <-bc.cleanupTicker.C:
			bc.cleanup()
		case <-bc.ttlTicker.C:
			bc.checkTTL()
		case <-bc.stopChan:
			return
		}
	}
}

func (bc *BackgroundCleaner) cleanup() {
	bc.store.mutex.Lock()
	defer bc.store.mutex.Unlock()

	if bc.store.needsEviction() {
		bc.store.evictEntries()
	}
}

func (bc *BackgroundCleaner) checkTTL() {
	bc.store.mutex.Lock()
	defer bc.store.mutex.Unlock()

	_ = time.Now()
	var expiredKeys []string

	for key, entry := range bc.store.data {
		if entry.IsExpired() {
			expiredKeys = append(expiredKeys, key)
		}
	}

	for _, key := range expiredKeys {
		bc.store.deleteEntry(key)
	}
}

func (ms *MemoryStore) Get(ctx context.Context, key string) (*CacheEntry, error) {
	ms.mutex.RLock()
	entry, exists := ms.data[key]
	ms.mutex.RUnlock()

	if !exists {
		return nil, nil
	}

	if entry.IsExpired() {
		ms.mutex.Lock()
		ms.deleteEntry(key)
		ms.mutex.Unlock()
		return nil, nil
	}

	entry.Touch()
	ms.eviction.Touch(key)

	ms.updateStats()
	return entry, nil
}

func (ms *MemoryStore) Set(ctx context.Context, key string, entry *CacheEntry, ttl time.Duration) error {
	ms.mutex.Lock()
	defer ms.mutex.Unlock()

	if existing, exists := ms.data[key]; exists {
		ms.stats.Size -= existing.Size
	}

	entry.ExpiresAt = time.Now().Add(ttl)
	ms.data[key] = entry
	ms.stats.Size += entry.Size
	ms.stats.KeyCount = int64(len(ms.data))

	ms.eviction.Touch(key)

	if ms.needsEviction() {
		ms.evictEntries()
	}

	ms.updateStats()
	return nil
}

func (ms *MemoryStore) Delete(ctx context.Context, key string) error {
	ms.mutex.Lock()
	defer ms.mutex.Unlock()

	ms.deleteEntry(key)
	ms.updateStats()
	return nil
}

func (ms *MemoryStore) Clear(ctx context.Context) error {
	ms.mutex.Lock()
	defer ms.mutex.Unlock()

	ms.data = make(map[string]*CacheEntry)
	ms.stats.Size = 0
	ms.stats.KeyCount = 0
	ms.eviction = NewEvictionManager(ms.config.EvictionPolicy)

	ms.updateStats()
	return nil
}

func (ms *MemoryStore) Exists(ctx context.Context, key string) (bool, error) {
	ms.mutex.RLock()
	defer ms.mutex.RUnlock()

	entry, exists := ms.data[key]
	if !exists {
		return false, nil
	}

	return !entry.IsExpired(), nil
}

func (ms *MemoryStore) Keys(ctx context.Context, pattern string) ([]string, error) {
	ms.mutex.RLock()
	defer ms.mutex.RUnlock()

	var keys []string
	regex, err := regexp.Compile(pattern)
	if err != nil {
		return nil, fmt.Errorf("invalid pattern: %w", err)
	}

	for key := range ms.data {
		if regex.MatchString(key) {
			keys = append(keys, key)
		}
	}

	return keys, nil
}

func (ms *MemoryStore) Size(ctx context.Context) (int64, error) {
	ms.mutex.RLock()
	defer ms.mutex.RUnlock()

	return ms.stats.Size, nil
}

func (ms *MemoryStore) Stats(ctx context.Context) (StoreStats, error) {
	ms.mutex.RLock()
	defer ms.mutex.RUnlock()

	return ms.stats, nil
}

func (ms *MemoryStore) deleteEntry(key string) {
	if entry, exists := ms.data[key]; exists {
		ms.stats.Size -= entry.Size
		delete(ms.data, key)
		ms.stats.KeyCount = int64(len(ms.data))
		ms.eviction.Remove(key)
	}
}

func (ms *MemoryStore) needsEviction() bool {
	return ms.stats.Size > ms.config.MaxSize || ms.stats.KeyCount > ms.config.MaxKeys
}

func (ms *MemoryStore) evictEntries() {
	evictCount := int64(float64(ms.stats.KeyCount) * 0.1) // Evict 10%
	if evictCount < 1 {
		evictCount = 1
	}

	for i := int64(0); i < evictCount && len(ms.data) > 0; i++ {
		keyToEvict := ms.selectEvictionCandidate()
		if keyToEvict == "" {
			break
		}
		ms.deleteEntry(keyToEvict)
	}

	ms.stats.LastEviction = time.Now()
}

func (ms *MemoryStore) selectEvictionCandidate() string {
	switch ms.config.EvictionPolicy {
	case EvictionLRU:
		if ms.eviction.lruList != nil {
			return ms.eviction.lruList.GetLRU()
		}
	case EvictionLFU:
		if ms.eviction.lfuTracker != nil {
			return ms.eviction.lfuTracker.GetLFU()
		}
	case EvictionFIFO:
		if ms.eviction.fifoQueue != nil {
			return ms.eviction.fifoQueue.GetNext()
		}
	case EvictionRandom:
		for key := range ms.data {
			return key
		}
	}

	for key := range ms.data {
		return key
	}
	return ""
}

func (ms *MemoryStore) updateStats() {
	totalHits := ms.stats.HitRate * float64(ms.stats.KeyCount)
	ms.stats.HitRate = totalHits / float64(ms.stats.KeyCount+1)
	ms.stats.Memory = ms.stats.Size
}

func (em *EvictionManager) Touch(key string) {
	switch em.policy {
	case EvictionLRU:
		if em.lruList != nil {
			em.lruList.Touch(key)
		}
	case EvictionLFU:
		if em.lfuTracker != nil {
			em.lfuTracker.Touch(key)
		}
	case EvictionFIFO:
		if em.fifoQueue != nil {
			em.fifoQueue.Touch(key)
		}
	}
}

func (em *EvictionManager) Remove(key string) {
	switch em.policy {
	case EvictionLRU:
		if em.lruList != nil {
			em.lruList.Remove(key)
		}
	case EvictionLFU:
		if em.lfuTracker != nil {
			em.lfuTracker.Remove(key)
		}
	case EvictionFIFO:
		if em.fifoQueue != nil {
			em.fifoQueue.Remove(key)
		}
	}
}

func (ms *MemoryStore) Close() error {
	if ms.background != nil {
		ms.background.Stop()
	}
	return nil
}

func DefaultMemoryStoreConfig() MemoryStoreConfig {
	return MemoryStoreConfig{
		MaxSize:          50 * 1024 * 1024, // 50MB
		MaxKeys:          10000,
		EvictionPolicy:   EvictionLRU,
		CleanupInterval:  5 * time.Minute,
		TTLCheckInterval: 1 * time.Minute,
	}
}