package routing

import (
	"fmt"
	"net/http"
	"regexp"
	"sort"
	"strings"
	"sync"
	"time"

	"marchproxy-egress/internal/manager"
)

// RoutingEngine handles advanced request routing with multiple rule types
type RoutingEngine struct {
	routes       []*Route
	pathTrie     *PathTrie
	headerRules  []*HeaderRule
	weightRules  []*WeightRule
	config       *RoutingConfig
	stats        *RoutingStats
	mu           sync.RWMutex
}

// Route represents a routing rule with conditions and actions
type Route struct {
	ID          string
	Priority    int
	Name        string
	Description string
	Conditions  []Condition
	Actions     []Action
	Services    []*manager.Service
	LoadBalancer LoadBalancer
	Enabled     bool
	Statistics  *RouteStats
	CreatedAt   time.Time
	UpdatedAt   time.Time
}

// Condition represents a routing condition
type Condition interface {
	Match(req *http.Request, ctx *RoutingContext) bool
	String() string
}

// Action represents a routing action
type Action interface {
	Execute(req *http.Request, ctx *RoutingContext) error
	String() string
}

// PathCondition matches request paths
type PathCondition struct {
	Pattern   string
	Type      PathMatchType
	Regex     *regexp.Regexp
	CaseSensitive bool
}

// HeaderCondition matches request headers
type HeaderCondition struct {
	Name     string
	Value    string
	Type     HeaderMatchType
	Regex    *regexp.Regexp
}

// QueryCondition matches query parameters
type QueryCondition struct {
	Name  string
	Value string
	Type  QueryMatchType
	Regex *regexp.Regexp
}

// MethodCondition matches HTTP methods
type MethodCondition struct {
	Methods []string
}

// HostCondition matches host headers
type HostCondition struct {
	Hosts []string
	Type  HostMatchType
	Regex *regexp.Regexp
}

// TimeCondition matches time-based rules
type TimeCondition struct {
	StartTime time.Time
	EndTime   time.Time
	Days      []time.Weekday
	TimeZone  *time.Location
}

// RewriteAction rewrites request paths
type RewriteAction struct {
	Pattern     string
	Replacement string
	Regex       *regexp.Regexp
}

// RedirectAction redirects requests
type RedirectAction struct {
	URL        string
	StatusCode int
	Permanent  bool
}

// HeaderAction modifies headers
type HeaderAction struct {
	Operation HeaderOperation
	Name      string
	Value     string
}

// SetServiceAction sets the target service
type SetServiceAction struct {
	ServiceID int
	Service   *manager.Service
}

// PathMatchType represents path matching types
type PathMatchType int

const (
	PathExact PathMatchType = iota
	PathPrefix
	PathRegex
	PathWildcard
)

// HeaderMatchType represents header matching types
type HeaderMatchType int

const (
	HeaderExact HeaderMatchType = iota
	HeaderRegex
	HeaderPresent
	HeaderAbsent
	HeaderContains
)

// QueryMatchType represents query parameter matching types
type QueryMatchType int

const (
	QueryExact QueryMatchType = iota
	QueryRegex
	QueryPresent
	QueryAbsent
)

// HostMatchType represents host matching types
type HostMatchType int

const (
	HostExact HostMatchType = iota
	HostWildcard
	HostRegex
)

// HeaderOperation represents header operations
type HeaderOperation int

const (
	HeaderSet HeaderOperation = iota
	HeaderAdd
	HeaderRemove
	HeaderReplace
)

// LoadBalancer represents load balancing strategies
type LoadBalancer interface {
	SelectService(services []*manager.Service, req *http.Request, ctx *RoutingContext) *manager.Service
	String() string
}

// RoundRobinBalancer implements round-robin load balancing
type RoundRobinBalancer struct {
	current uint64
	mu      sync.Mutex
}

// WeightedBalancer implements weighted load balancing
type WeightedBalancer struct {
	weights map[int]int
}

// LeastConnectionsBalancer implements least connections load balancing
type LeastConnectionsBalancer struct{}

// IPHashBalancer implements IP hash-based load balancing
type IPHashBalancer struct{}

// PathTrie implements efficient path matching
type PathTrie struct {
	root *TrieNode
	mu   sync.RWMutex
}

// TrieNode represents a node in the path trie
type TrieNode struct {
	segment   string
	routes    []*Route
	children  map[string]*TrieNode
	wildcard  *TrieNode
	isParam   bool
	paramName string
}

// HeaderRule represents header-based routing rule
type HeaderRule struct {
	ID        string
	Header    string
	Values    []string
	Service   *manager.Service
	Weight    int
	Enabled   bool
}

// WeightRule represents weighted routing rule
type WeightRule struct {
	ID      string
	Service *manager.Service
	Weight  int
	Enabled bool
}

// RoutingContext holds routing context information
type RoutingContext struct {
	Request    *http.Request
	Route      *Route
	Service    *manager.Service
	Variables  map[string]string
	Metadata   map[string]interface{}
	StartTime  time.Time
	Retries    int
	Errors     []error
}

// RoutingStats holds routing engine statistics
type RoutingStats struct {
	TotalRequests      uint64
	RoutedRequests     uint64
	UnmatchedRequests  uint64
	RouteMatches       map[string]uint64
	AverageLatency     time.Duration
	SuccessRate        float64
	ErrorRate          float64
	LastUpdate         time.Time
}

// RouteStats holds individual route statistics
type RouteStats struct {
	TotalRequests     uint64
	SuccessfulMatches uint64
	FailedMatches     uint64
	AverageLatency    time.Duration
	LastUsed          time.Time
	ErrorCount        uint64
}

// RoutingConfig holds routing engine configuration
type RoutingConfig struct {
	EnableTrie         bool
	CaseSensitivePaths bool
	MaxTrieDepth       int
	DefaultTimeout     time.Duration
	EnableStats        bool
	StatsInterval      time.Duration
	MaxRoutes          int
	EnableCaching      bool
	CacheSize          int
	CacheTTL           time.Duration
}

// NewRoutingEngine creates a new routing engine
func NewRoutingEngine(config *RoutingConfig) *RoutingEngine {
	if config == nil {
		config = &RoutingConfig{
			EnableTrie:         true,
			CaseSensitivePaths: false,
			MaxTrieDepth:       10,
			DefaultTimeout:     time.Second * 30,
			EnableStats:        true,
			StatsInterval:      time.Minute,
			MaxRoutes:          1000,
			EnableCaching:      true,
			CacheSize:          10000,
			CacheTTL:           time.Minute * 5,
		}
	}

	engine := &RoutingEngine{
		routes:      make([]*Route, 0),
		pathTrie:    NewPathTrie(),
		headerRules: make([]*HeaderRule, 0),
		weightRules: make([]*WeightRule, 0),
		config:      config,
		stats: &RoutingStats{
			RouteMatches: make(map[string]uint64),
			LastUpdate:   time.Now(),
		},
	}

	// Start statistics collection if enabled
	if config.EnableStats {
		go engine.statsCollector()
	}

	return engine
}

// AddRoute adds a new route to the engine
func (re *RoutingEngine) AddRoute(route *Route) error {
	re.mu.Lock()
	defer re.mu.Unlock()

	if len(re.routes) >= re.config.MaxRoutes {
		return fmt.Errorf("maximum routes limit reached: %d", re.config.MaxRoutes)
	}

	// Validate route
	if err := re.validateRoute(route); err != nil {
		return fmt.Errorf("invalid route: %w", err)
	}

	// Initialize route statistics
	route.Statistics = &RouteStats{}
	route.CreatedAt = time.Now()
	route.UpdatedAt = time.Now()

	// Add to routes list
	re.routes = append(re.routes, route)

	// Add to trie if enabled and has path conditions
	if re.config.EnableTrie {
		for _, condition := range route.Conditions {
			if pathCond, ok := condition.(*PathCondition); ok {
				re.pathTrie.Add(pathCond.Pattern, route)
			}
		}
	}

	// Sort routes by priority (highest first)
	sort.Slice(re.routes, func(i, j int) bool {
		return re.routes[i].Priority > re.routes[j].Priority
	})

	fmt.Printf("Routing: Added route '%s' with priority %d\n", route.Name, route.Priority)
	return nil
}

// RemoveRoute removes a route from the engine
func (re *RoutingEngine) RemoveRoute(routeID string) error {
	re.mu.Lock()
	defer re.mu.Unlock()

	for i, route := range re.routes {
		if route.ID == routeID {
			// Remove from routes slice
			re.routes = append(re.routes[:i], re.routes[i+1:]...)
			
			// Remove from trie
			if re.config.EnableTrie {
				for _, condition := range route.Conditions {
					if pathCond, ok := condition.(*PathCondition); ok {
						re.pathTrie.Remove(pathCond.Pattern, route)
					}
				}
			}
			
			fmt.Printf("Routing: Removed route '%s'\n", route.Name)
			return nil
		}
	}

	return fmt.Errorf("route not found: %s", routeID)
}

// Route routes a request and returns the selected service
func (re *RoutingEngine) Route(req *http.Request) (*manager.Service, *RoutingContext, error) {
	re.mu.RLock()
	defer re.mu.RUnlock()

	ctx := &RoutingContext{
		Request:   req,
		Variables: make(map[string]string),
		Metadata:  make(map[string]interface{}),
		StartTime: time.Now(),
	}

	re.stats.TotalRequests++

	// Try trie-based routing first for efficiency
	if re.config.EnableTrie {
		if route := re.pathTrie.Match(req.URL.Path); route != nil {
			if service, err := re.evaluateRoute(route, req, ctx); err == nil && service != nil {
				re.stats.RoutedRequests++
				re.stats.RouteMatches[route.ID]++
				return service, ctx, nil
			}
		}
	}

	// Fall back to sequential route matching
	for _, route := range re.routes {
		if !route.Enabled {
			continue
		}

		if re.matchRoute(route, req, ctx) {
			// Execute actions
			for _, action := range route.Actions {
				if err := action.Execute(req, ctx); err != nil {
					route.Statistics.ErrorCount++
					continue
				}
			}

			// Select service using load balancer
			if len(route.Services) > 0 {
				service := route.LoadBalancer.SelectService(route.Services, req, ctx)
				if service != nil {
					ctx.Route = route
					ctx.Service = service
					
					route.Statistics.SuccessfulMatches++
					route.Statistics.LastUsed = time.Now()
					
					re.stats.RoutedRequests++
					re.stats.RouteMatches[route.ID]++
					
					return service, ctx, nil
				}
			}
		}
	}

	re.stats.UnmatchedRequests++
	return nil, ctx, fmt.Errorf("no matching route found")
}

// matchRoute checks if a route matches the request
func (re *RoutingEngine) matchRoute(route *Route, req *http.Request, ctx *RoutingContext) bool {
	for _, condition := range route.Conditions {
		if !condition.Match(req, ctx) {
			route.Statistics.FailedMatches++
			return false
		}
	}
	return true
}

// evaluateRoute evaluates a route and returns the selected service
func (re *RoutingEngine) evaluateRoute(route *Route, req *http.Request, ctx *RoutingContext) (*manager.Service, error) {
	if !route.Enabled {
		return nil, fmt.Errorf("route disabled")
	}

	// Check all conditions
	if !re.matchRoute(route, req, ctx) {
		return nil, fmt.Errorf("route conditions not met")
	}

	// Execute actions
	for _, action := range route.Actions {
		if err := action.Execute(req, ctx); err != nil {
			return nil, err
		}
	}

	// Select service
	if len(route.Services) > 0 {
		service := route.LoadBalancer.SelectService(route.Services, req, ctx)
		if service != nil {
			ctx.Route = route
			ctx.Service = service
			return service, nil
		}
	}

	return nil, fmt.Errorf("no service available")
}

// validateRoute validates a route configuration
func (re *RoutingEngine) validateRoute(route *Route) error {
	if route.ID == "" {
		return fmt.Errorf("route ID cannot be empty")
	}

	if route.Name == "" {
		return fmt.Errorf("route name cannot be empty")
	}

	if len(route.Conditions) == 0 {
		return fmt.Errorf("route must have at least one condition")
	}

	// Check for duplicate route ID
	for _, existing := range re.routes {
		if existing.ID == route.ID {
			return fmt.Errorf("route ID already exists: %s", route.ID)
		}
	}

	return nil
}

// statsCollector collects routing statistics
func (re *RoutingEngine) statsCollector() {
	ticker := time.NewTicker(re.config.StatsInterval)
	defer ticker.Stop()

	for {
		select {
		case <-ticker.C:
			re.collectStatistics()
		}
	}
}

// collectStatistics collects and updates routing statistics
func (re *RoutingEngine) collectStatistics() {
	re.mu.Lock()
	defer re.mu.Unlock()

	totalRequests := re.stats.TotalRequests
	routedRequests := re.stats.RoutedRequests

	if totalRequests > 0 {
		re.stats.SuccessRate = float64(routedRequests) / float64(totalRequests) * 100.0
		re.stats.ErrorRate = float64(totalRequests-routedRequests) / float64(totalRequests) * 100.0
	}

	re.stats.LastUpdate = time.Now()
}

// Condition implementations

// Match implements PathCondition.Match
func (pc *PathCondition) Match(req *http.Request, ctx *RoutingContext) bool {
	path := req.URL.Path
	if !pc.CaseSensitive {
		path = strings.ToLower(path)
	}

	switch pc.Type {
	case PathExact:
		pattern := pc.Pattern
		if !pc.CaseSensitive {
			pattern = strings.ToLower(pattern)
		}
		return path == pattern

	case PathPrefix:
		pattern := pc.Pattern
		if !pc.CaseSensitive {
			pattern = strings.ToLower(pattern)
		}
		return strings.HasPrefix(path, pattern)

	case PathRegex:
		return pc.Regex != nil && pc.Regex.MatchString(path)

	case PathWildcard:
		pattern := pc.Pattern
		if !pc.CaseSensitive {
			pattern = strings.ToLower(pattern)
		}
		matched, _ := wildcardMatch(pattern, path)
		return matched
	}

	return false
}

func (pc *PathCondition) String() string {
	return fmt.Sprintf("Path(%s, %d)", pc.Pattern, pc.Type)
}

// Match implements HeaderCondition.Match
func (hc *HeaderCondition) Match(req *http.Request, ctx *RoutingContext) bool {
	headerValues := req.Header[hc.Name]

	switch hc.Type {
	case HeaderExact:
		for _, value := range headerValues {
			if value == hc.Value {
				return true
			}
		}
		return false

	case HeaderRegex:
		if hc.Regex != nil {
			for _, value := range headerValues {
				if hc.Regex.MatchString(value) {
					return true
				}
			}
		}
		return false

	case HeaderPresent:
		return len(headerValues) > 0

	case HeaderAbsent:
		return len(headerValues) == 0

	case HeaderContains:
		for _, value := range headerValues {
			if strings.Contains(value, hc.Value) {
				return true
			}
		}
		return false
	}

	return false
}

func (hc *HeaderCondition) String() string {
	return fmt.Sprintf("Header(%s, %s, %d)", hc.Name, hc.Value, hc.Type)
}

// Match implements QueryCondition.Match
func (qc *QueryCondition) Match(req *http.Request, ctx *RoutingContext) bool {
	queryValues := req.URL.Query()[qc.Name]

	switch qc.Type {
	case QueryExact:
		for _, value := range queryValues {
			if value == qc.Value {
				return true
			}
		}
		return false

	case QueryRegex:
		if qc.Regex != nil {
			for _, value := range queryValues {
				if qc.Regex.MatchString(value) {
					return true
				}
			}
		}
		return false

	case QueryPresent:
		return len(queryValues) > 0

	case QueryAbsent:
		return len(queryValues) == 0
	}

	return false
}

func (qc *QueryCondition) String() string {
	return fmt.Sprintf("Query(%s, %s, %d)", qc.Name, qc.Value, qc.Type)
}

// Match implements MethodCondition.Match
func (mc *MethodCondition) Match(req *http.Request, ctx *RoutingContext) bool {
	for _, method := range mc.Methods {
		if req.Method == method {
			return true
		}
	}
	return false
}

func (mc *MethodCondition) String() string {
	return fmt.Sprintf("Method(%v)", mc.Methods)
}

// Match implements HostCondition.Match
func (hc *HostCondition) Match(req *http.Request, ctx *RoutingContext) bool {
	host := req.Host

	switch hc.Type {
	case HostExact:
		for _, allowedHost := range hc.Hosts {
			if host == allowedHost {
				return true
			}
		}
		return false

	case HostWildcard:
		for _, pattern := range hc.Hosts {
			matched, _ := wildcardMatch(pattern, host)
			if matched {
				return true
			}
		}
		return false

	case HostRegex:
		return hc.Regex != nil && hc.Regex.MatchString(host)
	}

	return false
}

func (hc *HostCondition) String() string {
	return fmt.Sprintf("Host(%v, %d)", hc.Hosts, hc.Type)
}

// Match implements TimeCondition.Match
func (tc *TimeCondition) Match(req *http.Request, ctx *RoutingContext) bool {
	now := time.Now()
	if tc.TimeZone != nil {
		now = now.In(tc.TimeZone)
	}

	// Check day of week
	if len(tc.Days) > 0 {
		dayMatched := false
		for _, day := range tc.Days {
			if now.Weekday() == day {
				dayMatched = true
				break
			}
		}
		if !dayMatched {
			return false
		}
	}

	// Check time range
	if !tc.StartTime.IsZero() && !tc.EndTime.IsZero() {
		currentTime := time.Date(0, 0, 0, now.Hour(), now.Minute(), now.Second(), 0, time.UTC)
		startTime := time.Date(0, 0, 0, tc.StartTime.Hour(), tc.StartTime.Minute(), tc.StartTime.Second(), 0, time.UTC)
		endTime := time.Date(0, 0, 0, tc.EndTime.Hour(), tc.EndTime.Minute(), tc.EndTime.Second(), 0, time.UTC)

		if startTime.Before(endTime) {
			return currentTime.After(startTime) && currentTime.Before(endTime)
		} else {
			// Handle overnight time range
			return currentTime.After(startTime) || currentTime.Before(endTime)
		}
	}

	return true
}

func (tc *TimeCondition) String() string {
	return fmt.Sprintf("Time(%v-%v, %v)", tc.StartTime, tc.EndTime, tc.Days)
}

// Action implementations

// Execute implements RewriteAction.Execute
func (ra *RewriteAction) Execute(req *http.Request, ctx *RoutingContext) error {
	if ra.Regex != nil {
		newPath := ra.Regex.ReplaceAllString(req.URL.Path, ra.Replacement)
		req.URL.Path = newPath
		ctx.Variables["original_path"] = req.URL.Path
		ctx.Variables["rewritten_path"] = newPath
	}
	return nil
}

func (ra *RewriteAction) String() string {
	return fmt.Sprintf("Rewrite(%s -> %s)", ra.Pattern, ra.Replacement)
}

// Execute implements RedirectAction.Execute
func (rda *RedirectAction) Execute(req *http.Request, ctx *RoutingContext) error {
	// This would typically be handled by the HTTP handler
	ctx.Metadata["redirect_url"] = rda.URL
	ctx.Metadata["redirect_status"] = rda.StatusCode
	return nil
}

func (rda *RedirectAction) String() string {
	return fmt.Sprintf("Redirect(%s, %d)", rda.URL, rda.StatusCode)
}

// Execute implements HeaderAction.Execute
func (ha *HeaderAction) Execute(req *http.Request, ctx *RoutingContext) error {
	switch ha.Operation {
	case HeaderSet:
		req.Header.Set(ha.Name, ha.Value)
	case HeaderAdd:
		req.Header.Add(ha.Name, ha.Value)
	case HeaderRemove:
		req.Header.Del(ha.Name)
	case HeaderReplace:
		req.Header.Del(ha.Name)
		req.Header.Set(ha.Name, ha.Value)
	}
	return nil
}

func (ha *HeaderAction) String() string {
	return fmt.Sprintf("Header(%d, %s, %s)", ha.Operation, ha.Name, ha.Value)
}

// Execute implements SetServiceAction.Execute
func (ssa *SetServiceAction) Execute(req *http.Request, ctx *RoutingContext) error {
	ctx.Service = ssa.Service
	ctx.Metadata["service_id"] = ssa.ServiceID
	return nil
}

func (ssa *SetServiceAction) String() string {
	return fmt.Sprintf("SetService(%d)", ssa.ServiceID)
}

// Load balancer implementations

// SelectService implements RoundRobinBalancer.SelectService
func (rrb *RoundRobinBalancer) SelectService(services []*manager.Service, req *http.Request, ctx *RoutingContext) *manager.Service {
	if len(services) == 0 {
		return nil
	}

	rrb.mu.Lock()
	defer rrb.mu.Unlock()

	index := rrb.current % uint64(len(services))
	rrb.current++
	
	return services[index]
}

func (rrb *RoundRobinBalancer) String() string {
	return "RoundRobin"
}

// Helper functions

func wildcardMatch(pattern, text string) (bool, error) {
	// Simple wildcard matching with * and ?
	if pattern == "*" {
		return true, nil
	}
	
	// Convert wildcard pattern to regex
	regexPattern := strings.ReplaceAll(pattern, "*", ".*")
	regexPattern = strings.ReplaceAll(regexPattern, "?", ".")
	regexPattern = "^" + regexPattern + "$"
	
	regex, err := regexp.Compile(regexPattern)
	if err != nil {
		return false, err
	}
	
	return regex.MatchString(text), nil
}

// PathTrie implementation

// NewPathTrie creates a new path trie
func NewPathTrie() *PathTrie {
	return &PathTrie{
		root: &TrieNode{
			children: make(map[string]*TrieNode),
		},
	}
}

// Add adds a path and route to the trie
func (pt *PathTrie) Add(path string, route *Route) {
	pt.mu.Lock()
	defer pt.mu.Unlock()

	segments := strings.Split(strings.Trim(path, "/"), "/")
	node := pt.root

	for _, segment := range segments {
		if segment == "" {
			continue
		}

		// Handle parameters (e.g., {id})
		if strings.HasPrefix(segment, "{") && strings.HasSuffix(segment, "}") {
			paramName := segment[1 : len(segment)-1]
			if node.wildcard == nil {
				node.wildcard = &TrieNode{
					segment:   segment,
					children:  make(map[string]*TrieNode),
					isParam:   true,
					paramName: paramName,
				}
			}
			node = node.wildcard
		} else {
			if _, exists := node.children[segment]; !exists {
				node.children[segment] = &TrieNode{
					segment:  segment,
					children: make(map[string]*TrieNode),
				}
			}
			node = node.children[segment]
		}
	}

	node.routes = append(node.routes, route)
}

// Match finds the best matching route for a path
func (pt *PathTrie) Match(path string) *Route {
	pt.mu.RLock()
	defer pt.mu.RUnlock()

	segments := strings.Split(strings.Trim(path, "/"), "/")
	node := pt.root

	for _, segment := range segments {
		if segment == "" {
			continue
		}

		if child, exists := node.children[segment]; exists {
			node = child
		} else if node.wildcard != nil {
			node = node.wildcard
		} else {
			return nil
		}
	}

	if len(node.routes) > 0 {
		// Return highest priority route
		return node.routes[0]
	}

	return nil
}

// Remove removes a route from the trie
func (pt *PathTrie) Remove(path string, route *Route) {
	pt.mu.Lock()
	defer pt.mu.Unlock()

	segments := strings.Split(strings.Trim(path, "/"), "/")
	node := pt.root

	for _, segment := range segments {
		if segment == "" {
			continue
		}

		if strings.HasPrefix(segment, "{") && strings.HasSuffix(segment, "}") {
			if node.wildcard != nil {
				node = node.wildcard
			} else {
				return
			}
		} else {
			if child, exists := node.children[segment]; exists {
				node = child
			} else {
				return
			}
		}
	}

	// Remove route from node
	for i, r := range node.routes {
		if r.ID == route.ID {
			node.routes = append(node.routes[:i], node.routes[i+1:]...)
			break
		}
	}
}

// GetStats returns routing engine statistics
func (re *RoutingEngine) GetStats() *RoutingStats {
	re.mu.RLock()
	defer re.mu.RUnlock()

	stats := *re.stats
	return &stats
}

// GetRoutes returns all configured routes
func (re *RoutingEngine) GetRoutes() []*Route {
	re.mu.RLock()
	defer re.mu.RUnlock()

	routes := make([]*Route, len(re.routes))
	for i, route := range re.routes {
		routeCopy := *route
		routes[i] = &routeCopy
	}
	return routes
}