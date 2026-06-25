package dropshipprapp

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"time"

	"connectrpc.com/connect"

	appv1 "github.com/skunkworq/stealth/internal/gen/dropshippr/app/v1"
	"github.com/skunkworq/stealth/internal/gen/dropshippr/app/v1/appv1connect"
)

const defaultStorePath = ".data/dropshippr-app.json"

type Option func(*Service)

type Service struct {
	mu        sync.Mutex
	storePath string
	state     persistedState
}

type persistedState struct {
	WatchlistedProductIDs []string            `json:"watchlistedProductIds"`
	Scans                 []*appv1.ScanRecord `json:"scans"`
}

func WithStorePath(path string) Option {
	return func(service *Service) {
		service.storePath = path
	}
}

func NewService(options ...Option) (*Service, error) {
	service := &Service{
		storePath: envOrDefault("DROPSHIPPR_APP_STORE_PATH", defaultStorePath),
		state: persistedState{
			WatchlistedProductIDs: []string{"aurora-ice-roller", "nightshade-led-strip"},
			Scans:                 []*appv1.ScanRecord{},
		},
	}
	for _, option := range options {
		option(service)
	}
	if err := service.load(); err != nil {
		return nil, err
	}
	return service, nil
}

func NewHandler(service *Service) http.Handler {
	mux := http.NewServeMux()
	path, handler := appv1connect.NewDropshipprServiceHandler(service)
	mux.Handle(path, handler)
	return mux
}

func WithCORS(next http.Handler, allowedOrigin string) http.Handler {
	if allowedOrigin == "" {
		allowedOrigin = "http://localhost:3218"
	}
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		origin := r.Header.Get("Origin")
		if origin == allowedOrigin {
			w.Header().Set("Access-Control-Allow-Origin", origin)
			w.Header().Set("Vary", "Origin")
			w.Header().Set("Access-Control-Allow-Methods", "POST, GET, OPTIONS")
			w.Header().Set("Access-Control-Allow-Headers", "Content-Type, Connect-Protocol-Version, Connect-Timeout-Ms, X-User-Agent")
			w.Header().Set("Access-Control-Expose-Headers", "Grpc-Status, Grpc-Message, Connect-Protocol-Version")
		}
		if r.Method == http.MethodOptions {
			w.WriteHeader(http.StatusNoContent)
			return
		}
		next.ServeHTTP(w, r)
	})
}

func (s *Service) GetWorkspace(context.Context, *connect.Request[appv1.GetWorkspaceRequest]) (*connect.Response[appv1.GetWorkspaceResponse], error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	watchlistCount := int32(len(s.watchlistSet()))
	return connect.NewResponse(&appv1.GetWorkspaceResponse{
		Workspace: &appv1.Workspace{
			AppName: "dropshippr.app",
			User:    &appv1.UserProfile{Initials: "JS", DisplayName: "Jordan Scout"},
			NavItems: []*appv1.NavItem{
				{Key: "discover", Label: "Discover", Href: "/discover"},
				{Key: "scan", Label: "New scan", Href: "/scan"},
				{Key: "watchlist", Label: "Watchlist", Href: "/watchlist", Count: watchlistCount},
				{Key: "trends", Label: "Trends", Href: "/trends"},
				{Key: "suppliers", Label: "Suppliers", Href: "/suppliers"},
				{Key: "analytics", Label: "Analytics", Href: "/analytics"},
			},
			Collections: []*appv1.Collection{
				{Id: "tiktok-winners", Label: "TikTok winners", Count: 12},
				{Id: "margin-60", Label: "Margin > 60%", Count: 28},
				{Id: "low-saturation", Label: "Low saturation", Count: 41},
			},
			Status: &appv1.WorkspaceStatus{
				ScanState:   "scan online",
				SkuCount:    18742,
				SyncLabel:   "last sync 2m",
				CrawlerRate: "487 SKU/s",
				QueueDepth:  12,
				AppVersion:  "v0.7.4",
				LocalTime:   "09:35 AM",
			},
		},
	}), nil
}

func (s *Service) ListProducts(_ context.Context, req *connect.Request[appv1.ListProductsRequest]) (*connect.Response[appv1.ListProductsResponse], error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	products := s.filteredProducts(req.Msg)
	featured := make([]*appv1.Product, 0, 2)
	for _, product := range s.productsLocked() {
		if product.Id == "cloudwalker-slippers" || product.Id == "aurora-ice-roller" {
			featured = append(featured, product)
		}
	}
	return connect.NewResponse(&appv1.ListProductsResponse{
		Products:         products,
		Categories:       []string{"Home", "Beauty", "Pet", "Tech", "Outdoor", "Fashion", "Kids", "Fitness", "Kitchen"},
		FeaturedProducts: featured,
		TotalCount:       int32(len(products)),
	}), nil
}

func (s *Service) GetProduct(_ context.Context, req *connect.Request[appv1.GetProductRequest]) (*connect.Response[appv1.GetProductResponse], error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	product := s.productByIDLocked(req.Msg.ProductId)
	if product == nil {
		return nil, connect.NewError(connect.CodeNotFound, fmt.Errorf("product %q not found", req.Msg.ProductId))
	}
	return connect.NewResponse(&appv1.GetProductResponse{
		Product: product,
		Detail:  productDetail(product),
	}), nil
}

func (s *Service) ToggleWatchlist(_ context.Context, req *connect.Request[appv1.ToggleWatchlistRequest]) (*connect.Response[appv1.ToggleWatchlistResponse], error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	if s.productByIDLocked(req.Msg.ProductId) == nil {
		return nil, connect.NewError(connect.CodeNotFound, fmt.Errorf("product %q not found", req.Msg.ProductId))
	}
	watchlist := s.watchlistSet()
	if req.Msg.Watchlisted {
		watchlist[req.Msg.ProductId] = true
	} else {
		delete(watchlist, req.Msg.ProductId)
	}
	s.state.WatchlistedProductIDs = sortedKeys(watchlist)
	if err := s.saveLocked(); err != nil {
		return nil, connect.NewError(connect.CodeInternal, err)
	}

	product := s.productByIDLocked(req.Msg.ProductId)
	return connect.NewResponse(&appv1.ToggleWatchlistResponse{
		Product:        product,
		WatchlistCount: int32(len(s.state.WatchlistedProductIDs)),
	}), nil
}

func (s *Service) ListWatchlist(context.Context, *connect.Request[appv1.ListWatchlistRequest]) (*connect.Response[appv1.ListWatchlistResponse], error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	items := make([]*appv1.WatchlistItem, 0)
	for _, product := range s.productsLocked() {
		if !product.Watchlisted {
			continue
		}
		items = append(items, &appv1.WatchlistItem{
			Product:         product,
			AddedLabel:      "ADDED 3D AGO",
			DeltaSinceAdded: map[string]string{"aurora-ice-roller": "+9%", "nightshade-led-strip": "+11%"}[product.Id],
		})
	}
	return connect.NewResponse(&appv1.ListWatchlistResponse{Items: items}), nil
}

func (s *Service) RunScan(ctx context.Context, req *connect.Request[appv1.RunScanRequest], stream *connect.ServerStream[appv1.RunScanResponse]) error {
	query := strings.TrimSpace(req.Msg.Query)
	if query == "" {
		return connect.NewError(connect.CodeInvalidArgument, errors.New("scan query is required"))
	}

	scanID := fmt.Sprintf("scan-%d", time.Now().UnixNano())
	startedAt := time.Now().UTC().Format(time.RFC3339)
	logs := []string{
		"$ scan started: " + query,
		"$ TikTok Shop connected",
		"$ AliExpress connected",
		"$ CJ Dropshipping connected",
		"$ Spocket domestic network queued",
		"$ Zendrop seller-doc branch checked",
		"$ ranked 4 candidate products",
		"$ completed",
	}

	events := []*appv1.RunScanResponse{
		{ScanId: scanID, Kind: "started", Message: logs[0]},
		{ScanId: scanID, Kind: "source", Source: "TikTok Shop", Message: logs[1]},
		{ScanId: scanID, Kind: "source", Source: "AliExpress", Message: logs[2]},
		{ScanId: scanID, Kind: "source", Source: "CJ Dropshipping", Message: logs[3]},
		{ScanId: scanID, Kind: "source", Source: "Spocket", Message: logs[4]},
		{ScanId: scanID, Kind: "source", Source: "Zendrop", Message: logs[5]},
	}
	for _, product := range s.scanProducts(query) {
		events = append(events, &appv1.RunScanResponse{
			ScanId:  scanID,
			Kind:    "product",
			Message: "found " + product.Title,
			Product: product,
		})
	}
	record := &appv1.ScanRecord{
		Id:            scanID,
		Query:         query,
		Status:        "completed",
		StartedAt:     startedAt,
		CompletedAt:   time.Now().UTC().Format(time.RFC3339),
		ProductsFound: 4,
		LogLines:      logs,
	}
	events = append(events, &appv1.RunScanResponse{ScanId: scanID, Kind: "completed", Message: logs[len(logs)-1], Scan: record})

	for _, event := range events {
		if err := stream.Send(event); err != nil {
			return err
		}
		select {
		case <-ctx.Done():
			return ctx.Err()
		default:
		}
	}

	s.mu.Lock()
	s.state.Scans = append([]*appv1.ScanRecord{record}, s.state.Scans...)
	err := s.saveLocked()
	s.mu.Unlock()
	if err != nil {
		return connect.NewError(connect.CodeInternal, err)
	}
	return nil
}

func (s *Service) ListScans(context.Context, *connect.Request[appv1.ListScansRequest]) (*connect.Response[appv1.ListScansResponse], error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return connect.NewResponse(&appv1.ListScansResponse{Scans: append([]*appv1.ScanRecord(nil), s.state.Scans...)}), nil
}

func (s *Service) GetTrends(context.Context, *connect.Request[appv1.GetTrendsRequest]) (*connect.Response[appv1.GetTrendsResponse], error) {
	return connect.NewResponse(&appv1.GetTrendsResponse{
		Metrics: []*appv1.MetricCard{
			{Label: "CATEGORIES TRENDING UP", Value: "6", Delta: "+2 this week of 9", Tone: "good"},
			{Label: "NEW SKUS SURFACED", Value: "412", Delta: "+18%", Tone: "good"},
			{Label: "AVG MARGIN (TOP 50)", Value: "58%", Delta: "+3pts", Tone: "good"},
			{Label: "SATURATION INDEX", Value: "64/100", Delta: "-2", Tone: "good"},
		},
		GlobalTimeline:   globalTimeline(),
		CategoryMomentum: categoryMomentum(),
		CompetitionMap:   heatCells(90),
	}), nil
}

func (s *Service) ListSuppliers(context.Context, *connect.Request[appv1.ListSuppliersRequest]) (*connect.Response[appv1.ListSuppliersResponse], error) {
	return connect.NewResponse(&appv1.ListSuppliersResponse{Suppliers: suppliers()}), nil
}

func (s *Service) GetAnalytics(context.Context, *connect.Request[appv1.GetAnalyticsRequest]) (*connect.Response[appv1.GetAnalyticsResponse], error) {
	return connect.NewResponse(&appv1.GetAnalyticsResponse{
		Metrics: []*appv1.MetricCard{
			{Label: "REVENUE", Value: "$145.4k", Delta: "+18.4% vs prev. 60d", Tone: "good"},
			{Label: "ORDERS", Value: "5,017", Delta: "+12.1%", Tone: "good"},
			{Label: "AVG ORDER VALUE", Value: "$28.99", Delta: "+$2.10", Tone: "good"},
			{Label: "ROAS", Value: "3.4x", Delta: "-0.2x", Tone: "bad"},
		},
		RevenueTimeline: globalTimeline(),
		TopPerformers: []*appv1.AnalyticsPerformer{
			{ProductId: "cloudwalker-slippers", Title: "Cloudwalker Slippers", Category: "Home", Orders: 7360, RevenueCents: 21340000, ProfitCents: 15890000, TrendSeries: []int32{12, 18, 14, 22, 31, 29, 42, 39}},
			{ProductId: "posture-reset-belt", Title: "Posture Reset Belt", Category: "Fitness", Orders: 4840, RevenueCents: 11860000, ProfitCents: 8470000, TrendSeries: []int32{9, 11, 18, 26, 30, 34, 40, 38}},
			{ProductId: "aurora-ice-roller", Title: "Aurora Ice Roller", Category: "Beauty", Orders: 11760, RevenueCents: 21170000, ProfitCents: 15110000, TrendSeries: []int32{18, 16, 20, 15, 17, 25, 28, 36}},
			{ProductId: "foldable-pet-tunnel", Title: "Foldable Pet Tunnel", Category: "Pet", Orders: 2448, RevenueCents: 7830000, ProfitCents: 5480000, TrendSeries: []int32{6, 12, 17, 24, 22, 20, 30, 36}},
			{ProductId: "nightshade-led-strip", Title: "Nightshade LED Strip", Category: "Tech", Orders: 16480, RevenueCents: 28000000, ProfitCents: 19270000, TrendSeries: []int32{13, 22, 18, 28, 35, 37, 42, 44}},
		},
		Funnel: []*appv1.FunnelStep{
			{Label: "Ad impressions", Count: 1240000, PercentLabel: "100.0%", FillPercent: 100},
			{Label: "Clicks", Count: 38400, PercentLabel: "3.1%", FillPercent: 3},
			{Label: "Add to cart", Count: 6240, PercentLabel: "16.3%", FillPercent: 16},
			{Label: "Checkout started", Count: 3120, PercentLabel: "50.0%", FillPercent: 50},
			{Label: "Orders placed", Count: 2480, PercentLabel: "79.5%", FillPercent: 80},
		},
		ChannelSplit: []*appv1.ChannelSplit{
			{Label: "TikTok Shop", RevenueCents: 1842000, Percent: 42, Tone: "good"},
			{Label: "Shopify (direct)", RevenueCents: 1210000, Percent: 28, Tone: "dark"},
			{Label: "Instagram", RevenueCents: 796000, Percent: 18, Tone: "good"},
			{Label: "Amazon", RevenueCents: 526000, Percent: 12, Tone: "warn"},
		},
		GeoDemand: []*appv1.GeoDemand{
			{Country: "United States", Percent: 64},
			{Country: "United Kingdom", Percent: 14},
			{Country: "Germany", Percent: 8},
			{Country: "Canada", Percent: 6},
			{Country: "Australia", Percent: 5},
			{Country: "Other", Percent: 3},
		},
		GeoHeat: heatCells(80),
	}), nil
}

func (s *Service) Search(_ context.Context, req *connect.Request[appv1.SearchRequest]) (*connect.Response[appv1.SearchResponse], error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	query := strings.ToLower(strings.TrimSpace(req.Msg.Query))
	results := []*appv1.SearchResult{}
	for _, product := range s.productsLocked() {
		if query == "" || strings.Contains(strings.ToLower(product.Title+" "+product.Category+" "+product.SupplierName), query) {
			results = append(results, &appv1.SearchResult{
				Id:       product.Id,
				Title:    product.Title,
				Subtitle: product.Category + " · margin " + fmt.Sprint(product.MarginPercent) + "%",
				Href:     "/products/" + product.Id,
				Kind:     "product",
			})
		}
	}
	for _, supplier := range suppliers() {
		searchText := strings.ToLower(strings.Join([]string{
			supplier.Name,
			supplier.Platform,
			supplier.SourceMode,
			strings.Join(supplier.WarehouseRegions, " "),
			strings.Join(supplier.Categories, " "),
			supplier.FulfillmentModel,
			supplier.PrimaryProbe,
			supplier.BestLaneId,
			supplier.Notes,
		}, " "))
		if query == "" || strings.Contains(searchText, query) {
			results = append(results, &appv1.SearchResult{
				Id:       supplier.Id,
				Title:    supplier.Name,
				Subtitle: supplier.Platform + " · " + supplier.FulfillmentModel,
				Href:     "/suppliers?supplier=" + supplier.Id,
				Kind:     "supplier",
			})
		}
	}
	return connect.NewResponse(&appv1.SearchResponse{Results: results}), nil
}

func (s *Service) load() error {
	if s.storePath == "" {
		return nil
	}
	data, err := os.ReadFile(s.storePath)
	if err != nil {
		if os.IsNotExist(err) {
			return nil
		}
		return err
	}
	if len(strings.TrimSpace(string(data))) == 0 {
		return nil
	}
	return json.Unmarshal(data, &s.state)
}

func (s *Service) saveLocked() error {
	if s.storePath == "" {
		return nil
	}
	if err := os.MkdirAll(filepath.Dir(s.storePath), 0o755); err != nil {
		return err
	}
	tempPath := s.storePath + "." + fmt.Sprint(time.Now().UnixNano()) + ".tmp"
	data, err := json.MarshalIndent(s.state, "", "  ")
	if err != nil {
		return err
	}
	if err := os.WriteFile(tempPath, data, 0o644); err != nil {
		return err
	}
	return os.Rename(tempPath, s.storePath)
}

func (s *Service) watchlistSet() map[string]bool {
	out := map[string]bool{}
	for _, id := range s.state.WatchlistedProductIDs {
		out[id] = true
	}
	return out
}

func (s *Service) productsLocked() []*appv1.Product {
	watchlist := s.watchlistSet()
	products := seedProducts()
	for _, product := range products {
		product.Watchlisted = watchlist[product.Id]
	}
	return products
}

func (s *Service) filteredProducts(req *appv1.ListProductsRequest) []*appv1.Product {
	query := strings.ToLower(strings.TrimSpace(req.Query))
	category := strings.ToLower(strings.TrimSpace(req.Category))
	products := make([]*appv1.Product, 0)
	for _, product := range s.productsLocked() {
		if req.WatchlistedOnly && !product.Watchlisted {
			continue
		}
		if category != "" && category != "all" && strings.ToLower(product.Category) != category {
			continue
		}
		if req.MinMarginPercent > 0 && product.MarginPercent < req.MinMarginPercent {
			continue
		}
		searchText := strings.ToLower(product.Title + " " + product.Category + " " + product.Sku + " " + product.SupplierName)
		if query != "" && !strings.Contains(searchText, query) {
			continue
		}
		products = append(products, product)
	}
	sort.SliceStable(products, func(i, j int) bool {
		switch req.Sort {
		case "margin":
			return products[i].MarginPercent > products[j].MarginPercent
		case "saturation":
			return products[i].SaturationScore < products[j].SaturationScore
		case "orders":
			return products[i].Orders_30D > products[j].Orders_30D
		default:
			return products[i].TrendScore > products[j].TrendScore
		}
	})
	return products
}

func (s *Service) productByIDLocked(id string) *appv1.Product {
	for _, product := range s.productsLocked() {
		if product.Id == id {
			return product
		}
	}
	return nil
}

func (s *Service) scanProducts(query string) []*appv1.Product {
	s.mu.Lock()
	defer s.mu.Unlock()
	req := &appv1.ListProductsRequest{Query: "", Sort: "trending"}
	if strings.Contains(strings.ToLower(query), "pet") {
		req.Category = "Pet"
	}
	products := s.filteredProducts(req)
	if len(products) > 4 {
		return products[:4]
	}
	return products
}

func sortedKeys(values map[string]bool) []string {
	out := make([]string, 0, len(values))
	for key := range values {
		out = append(out, key)
	}
	sort.Strings(out)
	return out
}

func envOrDefault(key, fallback string) string {
	if value := strings.TrimSpace(os.Getenv(key)); value != "" {
		return value
	}
	return fallback
}
