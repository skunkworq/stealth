package dropshipprapp

import (
	"context"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"testing"

	"connectrpc.com/connect"

	appv1 "github.com/skunkworq/stealth/internal/gen/dropshippr/app/v1"
	"github.com/skunkworq/stealth/internal/gen/dropshippr/app/v1/appv1connect"
)

func newTestClient(t *testing.T) (appv1connect.DropshipprServiceClient, string) {
	t.Helper()

	storePath := filepath.Join(t.TempDir(), "dropshippr-app.json")
	service, err := NewService(WithStorePath(storePath))
	if err != nil {
		t.Fatalf("NewService() error = %v", err)
	}

	mux := http.NewServeMux()
	path, handler := appv1connect.NewDropshipprServiceHandler(service)
	mux.Handle(path, handler)
	server := httptest.NewServer(mux)
	t.Cleanup(server.Close)

	return appv1connect.NewDropshipprServiceClient(server.Client(), server.URL), storePath
}

func TestListProductsFiltersAndSortsSeededInventory(t *testing.T) {
	client, _ := newTestClient(t)

	res, err := client.ListProducts(context.Background(), connect.NewRequest(&appv1.ListProductsRequest{
		Category:         "Beauty",
		MinMarginPercent: 80,
		Sort:             "trending",
	}))
	if err != nil {
		t.Fatalf("ListProducts() error = %v", err)
	}
	if len(res.Msg.Products) == 0 {
		t.Fatal("ListProducts() returned no beauty products")
	}
	if got := res.Msg.Products[0].Id; got != "aurora-ice-roller" {
		t.Fatalf("first product id = %q, want aurora-ice-roller", got)
	}
	for _, product := range res.Msg.Products {
		if product.Category != "Beauty" {
			t.Fatalf("product category = %q, want Beauty", product.Category)
		}
		if product.MarginPercent < 80 {
			t.Fatalf("product margin = %d, want >= 80", product.MarginPercent)
		}
	}
}

func TestToggleWatchlistPersistsAcrossServiceInstances(t *testing.T) {
	client, storePath := newTestClient(t)

	toggle, err := client.ToggleWatchlist(context.Background(), connect.NewRequest(&appv1.ToggleWatchlistRequest{
		ProductId:   "cloudwalker-slippers",
		Watchlisted: true,
	}))
	if err != nil {
		t.Fatalf("ToggleWatchlist() error = %v", err)
	}
	if !toggle.Msg.Product.Watchlisted {
		t.Fatal("ToggleWatchlist() did not mark product as watchlisted")
	}

	service, err := NewService(WithStorePath(storePath))
	if err != nil {
		t.Fatalf("NewService(second) error = %v", err)
	}
	mux := http.NewServeMux()
	path, handler := appv1connect.NewDropshipprServiceHandler(service)
	mux.Handle(path, handler)
	server := httptest.NewServer(mux)
	defer server.Close()

	secondClient := appv1connect.NewDropshipprServiceClient(server.Client(), server.URL)
	watchlist, err := secondClient.ListWatchlist(context.Background(), connect.NewRequest(&appv1.ListWatchlistRequest{}))
	if err != nil {
		t.Fatalf("ListWatchlist() error = %v", err)
	}
	if len(watchlist.Msg.Items) != 3 {
		t.Fatalf("watchlist length = %d, want 3", len(watchlist.Msg.Items))
	}
}

func TestRunScanStreamsLifecycleEventsAndPersistsScan(t *testing.T) {
	client, _ := newTestClient(t)

	stream, err := client.RunScan(context.Background(), connect.NewRequest(&appv1.RunScanRequest{
		Query: "pet trending",
	}))
	if err != nil {
		t.Fatalf("RunScan() error = %v", err)
	}

	var kinds []string
	for stream.Receive() {
		kinds = append(kinds, stream.Msg().Kind)
	}
	if err := stream.Err(); err != nil {
		t.Fatalf("RunScan() stream error = %v", err)
	}
	if len(kinds) < 4 {
		t.Fatalf("RunScan() emitted %d events, want at least 4", len(kinds))
	}
	if kinds[0] != "started" || kinds[len(kinds)-1] != "completed" {
		t.Fatalf("RunScan() lifecycle = %v, want started ... completed", kinds)
	}

	scans, err := client.ListScans(context.Background(), connect.NewRequest(&appv1.ListScansRequest{}))
	if err != nil {
		t.Fatalf("ListScans() error = %v", err)
	}
	if len(scans.Msg.Scans) != 1 {
		t.Fatalf("persisted scans = %d, want 1", len(scans.Msg.Scans))
	}
}

func TestListSuppliersReturnsWholesaleProviderProfiles(t *testing.T) {
	client, _ := newTestClient(t)

	res, err := client.ListSuppliers(context.Background(), connect.NewRequest(&appv1.ListSuppliersRequest{}))
	if err != nil {
		t.Fatalf("ListSuppliers() error = %v", err)
	}

	var cj *appv1.Supplier
	for _, supplier := range res.Msg.Suppliers {
		if supplier.Id == "cjdropshipping" {
			cj = supplier
			break
		}
	}
	if cj == nil {
		t.Fatal("ListSuppliers() did not include cjdropshipping")
	}
	if got := cj.PrimaryProbe; got != "Live product + freight lane pull" {
		t.Fatalf("CJ primary probe = %q, want live freight lane pull", got)
	}
	if got := cj.BestLaneId; got != "CJ-US-EXPRESS" {
		t.Fatalf("CJ best lane = %q, want CJ-US-EXPRESS", got)
	}
	if len(cj.WarehouseRegions) < 3 {
		t.Fatalf("CJ warehouse regions = %v, want CN/US/EU coverage", cj.WarehouseRegions)
	}
}

func TestSearchFindsWholesaleProviders(t *testing.T) {
	client, _ := newTestClient(t)

	res, err := client.Search(context.Background(), connect.NewRequest(&appv1.SearchRequest{Query: "spocket"}))
	if err != nil {
		t.Fatalf("Search() error = %v", err)
	}
	if len(res.Msg.Results) == 0 {
		t.Fatal("Search(spocket) returned no results")
	}
	if got := res.Msg.Results[0].Href; got != "/suppliers?supplier=spocket-domestic-network" {
		t.Fatalf("Search(spocket) href = %q, want supplier deep link", got)
	}
}
