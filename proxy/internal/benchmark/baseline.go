package benchmark

import (
	"context"
	"fmt"
	"log"
	"math"
	"net"
	"sync"
	"sync/atomic"
	"time"
)

// BenchmarkResult contains the results of a benchmark test
type BenchmarkResult struct {
	TestName         string
	Duration         time.Duration
	PacketsPerSecond float64
	BytesPerSecond   float64
	Latency          LatencyStats
	CPUUsage         float64
	MemoryUsage      float64
	Errors           int64
	AccelerationMode string
}

// LatencyStats contains latency statistics
type LatencyStats struct {
	Min    time.Duration
	Max    time.Duration
	Mean   time.Duration
	Median time.Duration
	P95    time.Duration
	P99    time.Duration
	StdDev time.Duration
}

// BaselineBenchmark performs baseline performance measurements
type BaselineBenchmark struct {
	config  *BenchmarkConfig
	results []BenchmarkResult
	mu      sync.Mutex
}

// BenchmarkConfig contains benchmark configuration
type BenchmarkConfig struct {
	Duration       time.Duration
	PacketSize     int
	NumConnections int
	NumWorkers     int
	TargetHost     string
	TargetPort     int
	TestProtocol   string // "tcp", "udp", "mixed"
	RampUpTime     time.Duration
}

// NewBaselineBenchmark creates a new baseline benchmark
func NewBaselineBenchmark(config *BenchmarkConfig) *BaselineBenchmark {
	if config == nil {
		config = &BenchmarkConfig{
			Duration:       30 * time.Second,
			PacketSize:     1400, // Typical MTU minus headers
			NumConnections: 100,
			NumWorkers:     4,
			TargetHost:     "127.0.0.1",
			TargetPort:     8080,
			TestProtocol:   "tcp",
			RampUpTime:     5 * time.Second,
		}
	}

	return &BaselineBenchmark{
		config:  config,
		results: []BenchmarkResult{},
	}
}

// Run executes the complete benchmark suite
func (bb *BaselineBenchmark) Run(ctx context.Context) error {
	log.Printf("Starting baseline benchmark suite...")
	log.Printf("Configuration: Duration=%v, Connections=%d, Workers=%d, Protocol=%s",
		bb.config.Duration, bb.config.NumConnections, bb.config.NumWorkers, bb.config.TestProtocol)

	// Test 1: Throughput test
	log.Printf("\n=== Running Throughput Test ===")
	if result, err := bb.runThroughputTest(ctx); err != nil {
		log.Printf("Throughput test failed: %v", err)
	} else {
		bb.addResult(result)
		bb.printResult(result)
	}

	// Test 2: Latency test
	log.Printf("\n=== Running Latency Test ===")
	if result, err := bb.runLatencyTest(ctx); err != nil {
		log.Printf("Latency test failed: %v", err)
	} else {
		bb.addResult(result)
		bb.printResult(result)
	}

	// Test 3: Connection scaling test
	log.Printf("\n=== Running Connection Scaling Test ===")
	if result, err := bb.runConnectionScalingTest(ctx); err != nil {
		log.Printf("Connection scaling test failed: %v", err)
	} else {
		bb.addResult(result)
		bb.printResult(result)
	}

	// Test 4: Mixed workload test
	log.Printf("\n=== Running Mixed Workload Test ===")
	if result, err := bb.runMixedWorkloadTest(ctx); err != nil {
		log.Printf("Mixed workload test failed: %v", err)
	} else {
		bb.addResult(result)
		bb.printResult(result)
	}

	// Print summary
	bb.printSummary()

	return nil
}

// runThroughputTest measures maximum throughput
func (bb *BaselineBenchmark) runThroughputTest(ctx context.Context) (BenchmarkResult, error) {
	result := BenchmarkResult{
		TestName:         "Throughput Test",
		AccelerationMode: "baseline",
	}

	var totalPackets int64
	var totalBytes int64
	var totalErrors int64
	latencies := &LatencyCollector{}

	startTime := time.Now()
	endTime := startTime.Add(bb.config.Duration)

	// Create worker pool
	var wg sync.WaitGroup
	workerCtx, cancel := context.WithDeadline(ctx, endTime)
	defer cancel()

	for i := 0; i < bb.config.NumWorkers; i++ {
		wg.Add(1)
		go func(workerID int) {
			defer wg.Done()
			bb.throughputWorker(workerCtx, workerID, &totalPackets, &totalBytes, &totalErrors, latencies)
		}(i)
	}

	// Wait for workers to complete
	wg.Wait()

	// Calculate results
	result.Duration = time.Since(startTime)
	result.PacketsPerSecond = float64(totalPackets) / result.Duration.Seconds()
	result.BytesPerSecond = float64(totalBytes) / result.Duration.Seconds()
	result.Latency = latencies.Calculate()
	result.Errors = totalErrors

	return result, nil
}

// throughputWorker performs throughput testing
func (bb *BaselineBenchmark) throughputWorker(ctx context.Context, workerID int, totalPackets, totalBytes, totalErrors *int64, latencies *LatencyCollector) {
	// Create connections
	conns := make([]net.Conn, bb.config.NumConnections/bb.config.NumWorkers)
	for i := range conns {
		addr := fmt.Sprintf("%s:%d", bb.config.TargetHost, bb.config.TargetPort)
		conn, err := net.DialTimeout(bb.config.TestProtocol, addr, 5*time.Second)
		if err != nil {
			atomic.AddInt64(totalErrors, 1)
			continue
		}
		conns[i] = conn
		defer conn.Close()
	}

	// Generate test data
	data := make([]byte, bb.config.PacketSize)
	for i := range data {
		data[i] = byte(i % 256)
	}

	// Send packets until context is done
	for {
		select {
		case <-ctx.Done():
			return
		default:
			for _, conn := range conns {
				if conn == nil {
					continue
				}

				start := time.Now()
				n, err := conn.Write(data)
				if err != nil {
					atomic.AddInt64(totalErrors, 1)
					continue
				}

				latency := time.Since(start)
				latencies.Add(latency)

				atomic.AddInt64(totalPackets, 1)
				atomic.AddInt64(totalBytes, int64(n))
			}
		}
	}
}

// runLatencyTest measures latency characteristics
func (bb *BaselineBenchmark) runLatencyTest(ctx context.Context) (BenchmarkResult, error) {
	result := BenchmarkResult{
		TestName:         "Latency Test",
		AccelerationMode: "baseline",
	}

	var totalPackets int64
	var totalErrors int64
	latencies := &LatencyCollector{}

	// Use single connection for accurate latency measurement
	addr := fmt.Sprintf("%s:%d", bb.config.TargetHost, bb.config.TargetPort)
	conn, err := net.DialTimeout(bb.config.TestProtocol, addr, 5*time.Second)
	if err != nil {
		return result, fmt.Errorf("failed to connect: %w", err)
	}
	defer conn.Close()

	// Small packet for latency testing
	data := make([]byte, 64)
	response := make([]byte, 64)

	startTime := time.Now()
	endTime := startTime.Add(bb.config.Duration)

	for time.Now().Before(endTime) {
		start := time.Now()

		// Send request
		if _, err := conn.Write(data); err != nil {
			totalErrors++
			continue
		}

		// Read response
		conn.SetReadDeadline(time.Now().Add(1 * time.Second))
		if _, err := conn.Read(response); err != nil {
			totalErrors++
			continue
		}

		latency := time.Since(start)
		latencies.Add(latency)
		totalPackets++

		// Rate limit to avoid overwhelming
		time.Sleep(1 * time.Millisecond)
	}

	// Calculate results
	result.Duration = time.Since(startTime)
	result.PacketsPerSecond = float64(totalPackets) / result.Duration.Seconds()
	result.Latency = latencies.Calculate()
	result.Errors = totalErrors

	return result, nil
}

// runConnectionScalingTest tests connection scaling
func (bb *BaselineBenchmark) runConnectionScalingTest(ctx context.Context) (BenchmarkResult, error) {
	result := BenchmarkResult{
		TestName:         "Connection Scaling Test",
		AccelerationMode: "baseline",
	}

	connectionCounts := []int{10, 50, 100, 500, 1000}
	bestThroughput := 0.0

	for _, numConns := range connectionCounts {
		log.Printf("Testing with %d connections...", numConns)

		var totalBytes int64
		startTime := time.Now()
		testDuration := 10 * time.Second

		// Create connections
		conns := make([]net.Conn, numConns)
		for i := range conns {
			addr := fmt.Sprintf("%s:%d", bb.config.TargetHost, bb.config.TargetPort)
			conn, err := net.DialTimeout(bb.config.TestProtocol, addr, 5*time.Second)
			if err != nil {
				result.Errors++
				continue
			}
			conns[i] = conn
			defer conn.Close()
		}

		// Test throughput with this connection count
		data := make([]byte, bb.config.PacketSize)
		endTime := startTime.Add(testDuration)

		for time.Now().Before(endTime) {
			for _, conn := range conns {
				if conn == nil {
					continue
				}
				n, _ := conn.Write(data)
				atomic.AddInt64(&totalBytes, int64(n))
			}
		}

		throughput := float64(totalBytes) / testDuration.Seconds()
		if throughput > bestThroughput {
			bestThroughput = throughput
			result.BytesPerSecond = throughput
		}
	}

	result.Duration = bb.config.Duration
	return result, nil
}

// runMixedWorkloadTest tests mixed traffic patterns
func (bb *BaselineBenchmark) runMixedWorkloadTest(ctx context.Context) (BenchmarkResult, error) {
	result := BenchmarkResult{
		TestName:         "Mixed Workload Test",
		AccelerationMode: "baseline",
	}

	var totalPackets int64
	var totalBytes int64
	var totalErrors int64
	latencies := &LatencyCollector{}

	startTime := time.Now()
	endTime := startTime.Add(bb.config.Duration)

	var wg sync.WaitGroup
	workerCtx, cancel := context.WithDeadline(ctx, endTime)
	defer cancel()

	// 40% small packets (latency sensitive)
	wg.Add(1)
	go func() {
		defer wg.Done()
		bb.mixedWorkloadWorker(workerCtx, 64, 100*time.Microsecond, &totalPackets, &totalBytes, &totalErrors, latencies)
	}()

	// 40% medium packets (typical traffic)
	wg.Add(1)
	go func() {
		defer wg.Done()
		bb.mixedWorkloadWorker(workerCtx, 1400, 1*time.Millisecond, &totalPackets, &totalBytes, &totalErrors, latencies)
	}()

	// 20% large packets (bulk transfer)
	wg.Add(1)
	go func() {
		defer wg.Done()
		bb.mixedWorkloadWorker(workerCtx, 8192, 10*time.Millisecond, &totalPackets, &totalBytes, &totalErrors, latencies)
	}()

	wg.Wait()

	// Calculate results
	result.Duration = time.Since(startTime)
	result.PacketsPerSecond = float64(totalPackets) / result.Duration.Seconds()
	result.BytesPerSecond = float64(totalBytes) / result.Duration.Seconds()
	result.Latency = latencies.Calculate()
	result.Errors = totalErrors

	return result, nil
}

// mixedWorkloadWorker generates mixed traffic patterns
func (bb *BaselineBenchmark) mixedWorkloadWorker(ctx context.Context, packetSize int, interval time.Duration,
	totalPackets, totalBytes, totalErrors *int64, latencies *LatencyCollector) {

	addr := fmt.Sprintf("%s:%d", bb.config.TargetHost, bb.config.TargetPort)
	conn, err := net.DialTimeout(bb.config.TestProtocol, addr, 5*time.Second)
	if err != nil {
		atomic.AddInt64(totalErrors, 1)
		return
	}
	defer conn.Close()

	data := make([]byte, packetSize)
	ticker := time.NewTicker(interval)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			start := time.Now()
			n, err := conn.Write(data)
			if err != nil {
				atomic.AddInt64(totalErrors, 1)
				continue
			}

			latency := time.Since(start)
			latencies.Add(latency)

			atomic.AddInt64(totalPackets, 1)
			atomic.AddInt64(totalBytes, int64(n))
		}
	}
}

// addResult adds a result to the benchmark
func (bb *BaselineBenchmark) addResult(result BenchmarkResult) {
	bb.mu.Lock()
	defer bb.mu.Unlock()
	bb.results = append(bb.results, result)
}

// printResult prints a single benchmark result
func (bb *BaselineBenchmark) printResult(result BenchmarkResult) {
	fmt.Printf("\nResults for %s:\n", result.TestName)
	fmt.Printf("  Duration: %.2f seconds\n", result.Duration.Seconds())
	fmt.Printf("  Throughput: %.2f Gbps (%.2f Mpps)\n",
		result.BytesPerSecond*8/1e9, result.PacketsPerSecond/1e6)
	fmt.Printf("  Latency:\n")
	fmt.Printf("    Min: %v\n", result.Latency.Min)
	fmt.Printf("    Mean: %v\n", result.Latency.Mean)
	fmt.Printf("    Median: %v\n", result.Latency.Median)
	fmt.Printf("    P95: %v\n", result.Latency.P95)
	fmt.Printf("    P99: %v\n", result.Latency.P99)
	fmt.Printf("    Max: %v\n", result.Latency.Max)
	if result.Errors > 0 {
		fmt.Printf("  Errors: %d\n", result.Errors)
	}
}

// printSummary prints overall benchmark summary
func (bb *BaselineBenchmark) printSummary() {
	bb.mu.Lock()
	defer bb.mu.Unlock()

	fmt.Println("\n=== Baseline Performance Summary ===")
	fmt.Println()

	for _, result := range bb.results {
		fmt.Printf("%s:\n", result.TestName)
		fmt.Printf("  %.2f Gbps, %.2f µs median latency\n",
			result.BytesPerSecond*8/1e9,
			float64(result.Latency.Median.Nanoseconds())/1000)
	}

	fmt.Println("\n=== Performance Baseline Established ===")
	fmt.Println("Use these results to compare with acceleration technologies")
}

// GetResults returns all benchmark results
func (bb *BaselineBenchmark) GetResults() []BenchmarkResult {
	bb.mu.Lock()
	defer bb.mu.Unlock()

	results := make([]BenchmarkResult, len(bb.results))
	copy(results, bb.results)
	return results
}

// LatencyCollector collects and calculates latency statistics
type LatencyCollector struct {
	samples []time.Duration
	mu      sync.Mutex
}

// Add adds a latency sample
func (lc *LatencyCollector) Add(latency time.Duration) {
	lc.mu.Lock()
	defer lc.mu.Unlock()
	lc.samples = append(lc.samples, latency)
}

// Calculate calculates latency statistics
func (lc *LatencyCollector) Calculate() LatencyStats {
	lc.mu.Lock()
	defer lc.mu.Unlock()

	if len(lc.samples) == 0 {
		return LatencyStats{}
	}

	// Sort samples for percentile calculation
	sorted := make([]time.Duration, len(lc.samples))
	copy(sorted, lc.samples)

	// Simple bubble sort for demonstration (use sort.Slice in production)
	for i := 0; i < len(sorted); i++ {
		for j := i + 1; j < len(sorted); j++ {
			if sorted[i] > sorted[j] {
				sorted[i], sorted[j] = sorted[j], sorted[i]
			}
		}
	}

	stats := LatencyStats{
		Min:    sorted[0],
		Max:    sorted[len(sorted)-1],
		Median: sorted[len(sorted)/2],
	}

	// Calculate mean
	var sum time.Duration
	for _, s := range sorted {
		sum += s
	}
	stats.Mean = sum / time.Duration(len(sorted))

	// Calculate percentiles
	p95Index := int(float64(len(sorted)) * 0.95)
	p99Index := int(float64(len(sorted)) * 0.99)
	if p95Index < len(sorted) {
		stats.P95 = sorted[p95Index]
	}
	if p99Index < len(sorted) {
		stats.P99 = sorted[p99Index]
	}

	// Calculate standard deviation
	var variance float64
	meanNanos := float64(stats.Mean.Nanoseconds())
	for _, s := range sorted {
		diff := float64(s.Nanoseconds()) - meanNanos
		variance += diff * diff
	}
	variance /= float64(len(sorted))
	stats.StdDev = time.Duration(math.Sqrt(variance))

	return stats
}