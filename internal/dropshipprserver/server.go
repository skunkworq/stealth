// Package dropshipprserver is a Connect-Go implementation of DropshipprService
// mirroring src/lib/dropshippr/service.ts. Reads from the same Neon Postgres
// database used by the TypeScript Next.js handler — both implementations are
// kept feature-equivalent so production can run on Go independently of Next.
//
// Currently a scaffold: GetWorkspace, ListProducts, GetProduct, Search return
// real data from Neon; the remaining RPCs return well-formed empty responses
// so the frontend renders without errors against either backend.
package dropshipprserver

import (
	"context"
	"fmt"
	"strconv"
	"strings"
	"time"

	"connectrpc.com/connect"
	"github.com/jackc/pgx/v5/pgxpool"

	appv1 "github.com/skunkworq/stealth/internal/gen/dropshippr/app/v1"
)

// Server implements appv1connect.DropshipprServiceHandler.
type Server struct {
	db *pgxpool.Pool
}

func New(db *pgxpool.Pool) *Server {
	return &Server{db: db}
}

// ─── GetWorkspace ────────────────────────────────────────────────────────────

func (s *Server) GetWorkspace(ctx context.Context, _ *connect.Request[appv1.GetWorkspaceRequest]) (*connect.Response[appv1.GetWorkspaceResponse], error) {
	var items, watchlisted, runningJobs, jobsLastHour int32
	err := s.db.QueryRow(ctx, `
		SELECT
			(SELECT count(*) FROM items),
			(SELECT count(*) FROM watchlist),
			(SELECT count(*) FROM crawl_jobs WHERE status='running'),
			(SELECT count(*) FROM crawl_jobs WHERE status='ok' AND finished_at > now() - INTERVAL '1 hour')
	`).Scan(&items, &watchlisted, &runningJobs, &jobsLastHour)
	if err != nil {
		return nil, fmt.Errorf("get workspace stats: %w", err)
	}

	rows, err := s.db.Query(ctx, `SELECT provider, count(*)::int FROM items GROUP BY provider ORDER BY 2 DESC`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var collections []*appv1.Collection
	for rows.Next() {
		var p string
		var c int32
		if err := rows.Scan(&p, &c); err != nil {
			return nil, err
		}
		collections = append(collections, &appv1.Collection{Id: p, Label: p, Count: c})
	}

	return connect.NewResponse(&appv1.GetWorkspaceResponse{
		Workspace: &appv1.Workspace{
			AppName: "dropshippr",
			User:    &appv1.UserProfile{Initials: "BE", DisplayName: "Ben"},
			NavItems: []*appv1.NavItem{
				{Key: "discover", Label: "Discover", Href: "/", Count: items},
				{Key: "scan", Label: "Scan", Href: "/scan", Count: runningJobs},
				{Key: "watchlist", Label: "Watchlist", Href: "/watchlist", Count: watchlisted},
				{Key: "trends", Label: "Trends", Href: "/trends", Count: 0},
				{Key: "suppliers", Label: "Suppliers", Href: "/suppliers", Count: int32(len(collections))},
				{Key: "analytics", Label: "Analytics", Href: "/analytics", Count: 0},
			},
			Collections: collections,
			Status: &appv1.WorkspaceStatus{
				ScanState:   ternary(runningJobs > 0, "scanning", "idle"),
				SkuCount:    items,
				SyncLabel:   fmt.Sprintf("last hour: %d ok crawls", jobsLastHour),
				CrawlerRate: "—",
				QueueDepth:  runningJobs,
				AppVersion:  "0.1.0-go",
				LocalTime:   time.Now().UTC().Format(time.RFC3339),
			},
		},
	}), nil
}

// ─── ListProducts ────────────────────────────────────────────────────────────

func (s *Server) ListProducts(ctx context.Context, req *connect.Request[appv1.ListProductsRequest]) (*connect.Response[appv1.ListProductsResponse], error) {
	r := req.Msg
	queryFilter := strings.TrimSpace(r.Query)
	categoryFilter := strings.TrimSpace(r.Category)
	watchOnly := r.WatchlistedOnly
	trending := strings.TrimSpace(r.Sort) != "recent"

	const trendingSQL = `
		WITH base AS (
			SELECT i.id, i.provider, i.source_id, i.title, i.subtitle, i.image_url, i.deep_link, i.last_seen_at
			FROM items i
			LEFT JOIN watchlist w ON w.item_id = i.id
			WHERE ($1 = '' OR i.title ILIKE '%' || $1 || '%')
			  AND ($2 = '' OR i.provider = $2)
			  AND ($3::bool = false OR w.item_id IS NOT NULL)
		)
		SELECT
			b.id, b.provider, b.source_id, b.title, b.subtitle, b.image_url, b.deep_link, b.last_seen_at,
			po.price_minor, po.currency,
			best.best_supply_price_cents,
			(w.item_id IS NOT NULL) AS watchlisted
		FROM base b
		LEFT JOIN LATERAL (
			SELECT price_minor, currency FROM price_observations
			WHERE item_id = b.id ORDER BY captured_at DESC LIMIT 1
		) po ON true
		JOIN LATERAL (
			SELECT pobs.price_minor AS best_supply_price_cents
			FROM item_matches m JOIN price_observations pobs ON pobs.item_id = m.match_item_id
			WHERE m.seed_item_id = b.id AND pobs.price_minor > 0
			ORDER BY pobs.price_minor ASC LIMIT 1
		) best ON true
		LEFT JOIN watchlist w ON w.item_id = b.id
		WHERE po.price_minor IS NOT NULL AND po.price_minor > 0
		ORDER BY ((po.price_minor - best.best_supply_price_cents)::numeric / po.price_minor) DESC
		LIMIT 60
	`
	const recentSQL = `
		WITH base AS (
			SELECT i.id, i.provider, i.source_id, i.title, i.subtitle, i.image_url, i.deep_link, i.last_seen_at
			FROM items i
			LEFT JOIN watchlist w ON w.item_id = i.id
			WHERE ($1 = '' OR i.title ILIKE '%' || $1 || '%')
			  AND ($2 = '' OR i.provider = $2)
			  AND ($3::bool = false OR w.item_id IS NOT NULL)
			ORDER BY i.last_seen_at DESC LIMIT 60
		)
		SELECT
			b.id, b.provider, b.source_id, b.title, b.subtitle, b.image_url, b.deep_link, b.last_seen_at,
			po.price_minor, po.currency,
			best.best_supply_price_cents,
			(w.item_id IS NOT NULL) AS watchlisted
		FROM base b
		LEFT JOIN LATERAL (
			SELECT price_minor, currency FROM price_observations
			WHERE item_id = b.id ORDER BY captured_at DESC LIMIT 1
		) po ON true
		LEFT JOIN LATERAL (
			SELECT pobs.price_minor AS best_supply_price_cents
			FROM item_matches m JOIN price_observations pobs ON pobs.item_id = m.match_item_id
			WHERE m.seed_item_id = b.id AND pobs.price_minor > 0
			ORDER BY pobs.price_minor ASC LIMIT 1
		) best ON true
		LEFT JOIN watchlist w ON w.item_id = b.id
		ORDER BY b.last_seen_at DESC
	`
	sqlText := recentSQL
	if trending {
		sqlText = trendingSQL
	}
	rows, err := s.db.Query(ctx, sqlText, queryFilter, categoryFilter, watchOnly)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	products := make([]*appv1.Product, 0, 60)
	for rows.Next() {
		var id int64
		var provider, sourceID, title, subtitle string
		var imageURL, deepLink *string
		var lastSeen time.Time
		var priceMinor *int64
		var currency *string
		var bestSupply *int64
		var watchlisted bool
		if err := rows.Scan(&id, &provider, &sourceID, &title, &subtitle, &imageURL, &deepLink, &lastSeen,
			&priceMinor, &currency, &bestSupply, &watchlisted); err != nil {
			return nil, err
		}
		cost := int32(deref64(priceMinor))
		var margin int32
		if priceMinor != nil && *priceMinor > 0 && bestSupply != nil && *bestSupply > 0 {
			margin = int32(((*priceMinor - *bestSupply) * 100) / *priceMinor)
		}
		products = append(products, &appv1.Product{
			Id:              strconv.FormatInt(id, 10),
			Title:           title,
			Category:        provider,
			Sku:             sourceID,
			CostCents:       cost,
			RetailCents:     cost,
			MarginPercent:   margin,
			SupplierCountry: providerCountry(provider),
			SupplierName:    provider,
			Hot:             margin >= 50,
			Watchlisted:     watchlisted,
			Icon:            providerIcon(provider),
			SourceUrl:       derefStr(deepLink),
		})
	}

	var total int32
	if err := s.db.QueryRow(ctx, `SELECT count(*)::int FROM items`).Scan(&total); err != nil {
		return nil, err
	}

	categoryRows, err := s.db.Query(ctx, `SELECT DISTINCT provider FROM items ORDER BY provider`)
	if err != nil {
		return nil, err
	}
	defer categoryRows.Close()
	categories := []string{"All"}
	for categoryRows.Next() {
		var p string
		if err := categoryRows.Scan(&p); err != nil {
			return nil, err
		}
		categories = append(categories, p)
	}

	return connect.NewResponse(&appv1.ListProductsResponse{
		Products:   products,
		Categories: categories,
		TotalCount: total,
	}), nil
}

// ─── GetProduct ──────────────────────────────────────────────────────────────

func (s *Server) GetProduct(ctx context.Context, req *connect.Request[appv1.GetProductRequest]) (*connect.Response[appv1.GetProductResponse], error) {
	id, err := strconv.ParseInt(req.Msg.ProductId, 10, 64)
	if err != nil {
		return nil, connect.NewError(connect.CodeInvalidArgument, fmt.Errorf("invalid product_id"))
	}
	var provider, sourceID, title, subtitle string
	var imageURL, deepLink *string
	var firstSeen, lastSeen time.Time
	var priceMinor *int64
	var currency *string
	var watchlisted bool
	err = s.db.QueryRow(ctx, `
		SELECT i.provider, i.source_id, i.title, i.subtitle, i.image_url, i.deep_link, i.first_seen_at, i.last_seen_at,
			(SELECT price_minor FROM price_observations WHERE item_id=i.id ORDER BY captured_at DESC LIMIT 1),
			(SELECT currency FROM price_observations WHERE item_id=i.id ORDER BY captured_at DESC LIMIT 1),
			EXISTS(SELECT 1 FROM watchlist WHERE item_id=i.id)
		FROM items i WHERE i.id = $1
	`, id).Scan(&provider, &sourceID, &title, &subtitle, &imageURL, &deepLink, &firstSeen, &lastSeen,
		&priceMinor, &currency, &watchlisted)
	if err != nil {
		return nil, connect.NewError(connect.CodeNotFound, fmt.Errorf("product %d not found: %w", id, err))
	}

	cost := int32(deref64(priceMinor))
	product := &appv1.Product{
		Id: req.Msg.ProductId, Title: title, Category: provider, Sku: sourceID,
		CostCents: cost, RetailCents: cost,
		SupplierCountry: providerCountry(provider), SupplierName: provider,
		Watchlisted: watchlisted, Icon: providerIcon(provider),
		SourceUrl: derefStr(deepLink),
	}

	return connect.NewResponse(&appv1.GetProductResponse{
		Product: product,
		Detail: &appv1.ProductDetail{
			Summary:      subtitle,
			TrackedSince: firstSeen.Format(time.RFC3339),
			Metrics: []*appv1.MetricCard{
				{Label: "Latest price", Value: formatPrice(deref64(priceMinor), derefStr(currency)), Tone: "neutral"},
				{Label: "Source", Value: provider, Tone: "neutral"},
			},
			ReviewSentiment: &appv1.ReviewSentiment{Rating: "—"},
		},
	}), nil
}

// ─── Search ──────────────────────────────────────────────────────────────────

func (s *Server) Search(ctx context.Context, req *connect.Request[appv1.SearchRequest]) (*connect.Response[appv1.SearchResponse], error) {
	term := strings.TrimSpace(req.Msg.Query)
	if term == "" {
		return connect.NewResponse(&appv1.SearchResponse{}), nil
	}
	rows, err := s.db.Query(ctx, `
		SELECT id, title, provider FROM (
			SELECT id, title, provider,
			       (CASE WHEN title ILIKE '%' || $1 || '%' THEN 2.0 ELSE 0 END) + similarity(title, $1) AS score
			FROM items
		) ranked WHERE score > 0.2 ORDER BY score DESC LIMIT 12
	`, term)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var results []*appv1.SearchResult
	for rows.Next() {
		var id int64
		var title, provider string
		if err := rows.Scan(&id, &title, &provider); err != nil {
			return nil, err
		}
		results = append(results, &appv1.SearchResult{
			Id: strconv.FormatInt(id, 10), Title: title, Subtitle: provider,
			Href: fmt.Sprintf("/product/%d", id), Kind: "product",
		})
	}
	return connect.NewResponse(&appv1.SearchResponse{Results: results}), nil
}

// ─── Watchlist + remaining stubs ─────────────────────────────────────────────

func (s *Server) ToggleWatchlist(ctx context.Context, req *connect.Request[appv1.ToggleWatchlistRequest]) (*connect.Response[appv1.ToggleWatchlistResponse], error) {
	id, err := strconv.ParseInt(req.Msg.ProductId, 10, 64)
	if err != nil {
		return nil, connect.NewError(connect.CodeInvalidArgument, err)
	}
	if req.Msg.Watchlisted {
		_, err = s.db.Exec(ctx, `INSERT INTO watchlist (item_id) VALUES ($1) ON CONFLICT (item_id) DO NOTHING`, id)
	} else {
		_, err = s.db.Exec(ctx, `DELETE FROM watchlist WHERE item_id=$1`, id)
	}
	if err != nil {
		return nil, err
	}
	var count int32
	_ = s.db.QueryRow(ctx, `SELECT count(*)::int FROM watchlist`).Scan(&count)
	return connect.NewResponse(&appv1.ToggleWatchlistResponse{WatchlistCount: count}), nil
}

func (s *Server) ListWatchlist(ctx context.Context, _ *connect.Request[appv1.ListWatchlistRequest]) (*connect.Response[appv1.ListWatchlistResponse], error) {
	return connect.NewResponse(&appv1.ListWatchlistResponse{}), nil
}

func (s *Server) RunScan(ctx context.Context, req *connect.Request[appv1.RunScanRequest], stream *connect.ServerStream[appv1.RunScanResponse]) error {
	scanID := fmt.Sprintf("scan_%d", time.Now().UnixMilli())
	return stream.Send(&appv1.RunScanResponse{
		ScanId: scanID, Kind: "complete", Source: "go-stub",
		Message: "Go server scan stub — wire to crawl-job-runner in next pass.",
	})
}

func (s *Server) ListScans(ctx context.Context, _ *connect.Request[appv1.ListScansRequest]) (*connect.Response[appv1.ListScansResponse], error) {
	return connect.NewResponse(&appv1.ListScansResponse{}), nil
}

func (s *Server) GetTrends(ctx context.Context, _ *connect.Request[appv1.GetTrendsRequest]) (*connect.Response[appv1.GetTrendsResponse], error) {
	return connect.NewResponse(&appv1.GetTrendsResponse{}), nil
}

func (s *Server) ListSuppliers(ctx context.Context, _ *connect.Request[appv1.ListSuppliersRequest]) (*connect.Response[appv1.ListSuppliersResponse], error) {
	rows, err := s.db.Query(ctx, `SELECT provider, count(*)::int FROM items GROUP BY provider ORDER BY 2 DESC`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var suppliers []*appv1.Supplier
	for rows.Next() {
		var p string
		var c int32
		if err := rows.Scan(&p, &c); err != nil {
			return nil, err
		}
		suppliers = append(suppliers, &appv1.Supplier{
			Id: p, Name: p, Country: providerCountry(p), CatalogSkus: c,
			Platform: p, SourceMode: "crawled", PrimaryProbe: p, Rating: "—",
			RiskLevel: "low", FulfillmentModel: "—", ReturnHandling: "—",
			TrackingQuality: "—", BrandingControl: "—",
		})
	}
	return connect.NewResponse(&appv1.ListSuppliersResponse{Suppliers: suppliers}), nil
}

func (s *Server) GetAnalytics(ctx context.Context, _ *connect.Request[appv1.GetAnalyticsRequest]) (*connect.Response[appv1.GetAnalyticsResponse], error) {
	return connect.NewResponse(&appv1.GetAnalyticsResponse{}), nil
}

// ─── helpers ─────────────────────────────────────────────────────────────────

func ternary(cond bool, a, b string) string {
	if cond {
		return a
	}
	return b
}

func deref64(p *int64) int64 {
	if p == nil {
		return 0
	}
	return *p
}

func derefStr(p *string) string {
	if p == nil {
		return ""
	}
	return *p
}

func providerCountry(p string) string {
	switch p {
	case "amazon":
		return "US"
	case "aliexpress", "temu":
		return "CN"
	case "shopify":
		return "Various"
	}
	return "Various"
}

func providerIcon(p string) string {
	switch p {
	case "amazon":
		return "amazon"
	case "aliexpress":
		return "aliexpress"
	case "shopify":
		return "shopify"
	}
	return "box"
}

func formatPrice(priceMinor int64, currency string) string {
	if priceMinor == 0 {
		return "—"
	}
	value := float64(priceMinor) / 100
	if currency == "" {
		return fmt.Sprintf("%.2f", value)
	}
	return fmt.Sprintf("%.2f %s", value, currency)
}
