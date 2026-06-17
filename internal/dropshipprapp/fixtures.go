package dropshipprapp

import appv1 "github.com/skunkworq/stealth/internal/gen/dropshippr/app/v1"

func seedProducts() []*appv1.Product {
	return []*appv1.Product{
		product("cloudwalker-slippers", "Cloudwalker Slippers", "Home", "SKU-1000", 420, 2899, 86, 1840, 92, 38, "VN", 14, "Yiwu Linhao Trading", true, "arch", []int32{22, 18, 16, 25, 19, 21, 34, 31, 36, 35, 39, 32, 37}),
		product("nightshade-led-strip", "Nightshade LED Strip", "Tech", "SKU-1004", 210, 1699, 88, 2940, 88, 84, "ID", 9, "Guangzhou Petal Co.", true, "bar", []int32{14, 17, 29, 26, 18, 15, 24, 21, 31, 38, 36, 43, 41}),
		product("posture-reset-belt", "Posture Reset Belt", "Fitness", "SKU-1001", 380, 2450, 84, 1570, 84, 62, "CN", 9, "Saigon Quick Goods", true, "lines", []int32{12, 10, 13, 18, 21, 25, 29, 34, 38, 42, 46, 44, 45}),
		product("whisper-desk-vacuum", "Whisper Desk Vacuum", "Tech", "SKU-1008", 510, 2799, 82, 1280, 81, 47, "CN", 14, "Bangalore Hearth", false, "circle", []int32{10, 13, 16, 22, 21, 26, 29, 31, 27, 37, 34, 38, 36}),
		product("aurora-ice-roller", "Aurora Ice Roller", "Beauty", "SKU-1002", 195, 1800, 89, 2940, 78, 71, "CN", 12, "Yiwu Linhao Trading", true, "half", []int32{18, 22, 17, 21, 16, 23, 19, 12, 20, 24, 22, 29, 39}),
		product("tidal-resistance-band-set", "Tidal Resistance Band Set", "Fitness", "SKU-1011", 290, 2100, 86, 860, 73, 58, "ID", 6, "Istanbul Mavi Tekstil", false, "wave", []int32{18, 14, 19, 16, 27, 39, 44, 36, 38, 33, 36, 34}),
		product("tide-pool-hammock", "Tide Pool Hammock", "Outdoor", "SKU-1005", 1120, 6400, 83, 720, 71, 19, "CN", 7, "Lodz Fast Ship", false, "wave-flat", []int32{16, 28, 21, 34, 30, 12, 9, 18, 22, 29, 17, 37}),
		product("cubelet-toddler-plates", "Cubelet Toddler Plates", "Kids", "SKU-1013", 210, 1499, 86, 1020, 69, 65, "TR", 15, "Istanbul Mavi Tekstil", false, "grid", []int32{10, 15, 20, 25, 29, 32, 35, 34, 37, 36, 38, 39}),
		product("astro-chew-mat", "Astro Chew Mat", "Pet", "SKU-1009", 320, 1950, 84, 610, 67, 31, "VN", 10, "Saigon Quick Goods", false, "diamond", []int32{15, 29, 24, 41, 38, 19, 13, 16, 17, 14, 18, 18}),
		product("velvet-hair-claw-pack", "Velvet Hair Claw Pack", "Fashion", "SKU-1006", 80, 999, 92, 1510, 64, 89, "CN", 8, "Guangzhou Petal Co.", false, "spark", []int32{9, 12, 18, 16, 22, 24, 20, 28, 34, 36, 31, 39}),
		product("mango-steamer-pot", "Mango Steamer Pot", "Kitchen", "SKU-1012", 830, 3600, 77, 740, 61, 41, "TR", 11, "Bangalore Hearth", false, "arch", []int32{8, 10, 14, 13, 17, 19, 18, 22, 25, 27, 30, 34}),
		product("magnetic-lash-kit", "Magnetic Lash Kit", "Beauty", "SKU-1007", 240, 2200, 89, 930, 58, 76, "TR", 7, "Guangzhou Petal Co.", false, "arch", []int32{13, 12, 13, 15, 16, 22, 30, 36, 41, 28, 17, 14}),
		product("foldable-pet-tunnel", "Foldable Pet Tunnel", "Pet", "SKU-1003", 640, 3200, 80, 520, 56, 24, "PL", 4, "Lodz Fast Ship", false, "circle", []int32{8, 11, 16, 20, 22, 25, 24, 20, 19, 27, 34, 36}),
		product("origami-sneaker-rack", "Origami Sneaker Rack", "Home", "SKU-1010", 760, 3800, 80, 480, 49, 22, "CN", 4, "Bangalore Hearth", false, "triangle", []int32{6, 10, 14, 16, 19, 23, 22, 27, 29, 31, 34, 38}),
	}
}

func product(id, title, category, sku string, cost, retail, margin, orders, trend, saturation int32, country string, shipDays int32, supplier string, hot bool, icon string, series []int32) *appv1.Product {
	return &appv1.Product{
		Id:              id,
		Title:           title,
		Category:        category,
		Sku:             sku,
		CostCents:       cost,
		RetailCents:     retail,
		MarginPercent:   margin,
		Orders_30D:      orders,
		TrendScore:      trend,
		SaturationScore: saturation,
		SupplierCountry: country,
		ShipDays:        shipDays,
		SupplierName:    supplier,
		WeeklyOrders:    orders,
		Hot:             hot,
		Icon:            icon,
		SourceUrl:       "https://aliexpress.com/item/" + id,
		TrendSeries:     series,
	}
}

func productDetail(product *appv1.Product) *appv1.ProductDetail {
	return &appv1.ProductDetail{
		Summary:      `Plush memory-foam slippers with a viral hook around "walking on clouds." Strong momentum on TikTok Shop with 1.2M views on the top creator post in the last 14 days.`,
		TrackedSince: "Apr 14",
		Metrics: []*appv1.MetricCard{
			{Label: "SUGGESTED RETAIL", Value: "$28.99", Delta: "+$2.00 vs market", Tone: "good"},
			{Label: "PROFIT / UNIT", Value: "$21.59", Delta: "after fees + shipping", Tone: "neutral"},
			{Label: "TRENDING VELOCITY", Value: "92/100", Delta: "+18 in 7d", Tone: "good"},
			{Label: "SATURATION", Value: "38/100", Delta: "room to grow", Tone: "good"},
		},
		OrdersTimeline: globalTimeline(),
		CategoryHeat:   categoryMomentum(),
		CompetitionMap: heatCells(88),
		Suppliers: []*appv1.ProductSupplier{
			{SupplierId: "cjdropshipping", Name: "CJdropshipping", Country: "CN", LeadDays: 7, Moq: 50, Rating: "4.8", CostCents: 420, Platform: "CJdropshipping", WarehouseRegion: "CN, US, EU", FulfillmentModel: "3PL + freight lanes", TrackingQuality: "high", SampleAvailable: true, BrandingControl: "custom", ProfileUrl: "/suppliers?supplier=cjdropshipping", RiskLevel: "low"},
			{SupplierId: "spocket-domestic-network", Name: "Spocket Domestic Network", Country: "US", LeadDays: 5, Moq: 12, Rating: "4.7", CostCents: 510, Platform: "Spocket", WarehouseRegion: "US, EU", FulfillmentModel: "domestic marketplace", TrackingQuality: "high", SampleAvailable: true, BrandingControl: "basic", ProfileUrl: "/suppliers?supplier=spocket-domestic-network", RiskLevel: "low"},
			{SupplierId: "zendrop-us-suppliers", Name: "Zendrop US Suppliers", Country: "US", LeadDays: 6, Moq: 25, Rating: "4.6", CostCents: 545, Platform: "Zendrop", WarehouseRegion: "US", FulfillmentModel: "US supplier branch", TrackingQuality: "medium", SampleAvailable: true, BrandingControl: "basic", ProfileUrl: "/suppliers?supplier=zendrop-us-suppliers", RiskLevel: "medium"},
			{SupplierId: "dsers-aliexpress", Name: "DSers / AliExpress", Country: "CN", LeadDays: 11, Moq: 1, Rating: "4.3", CostCents: 390, Platform: "DSers", WarehouseRegion: "CN", FulfillmentModel: "AliExpress import", TrackingQuality: "medium", SampleAvailable: false, BrandingControl: "none", ProfileUrl: "/suppliers?supplier=dsers-aliexpress", RiskLevel: "high"},
			{SupplierId: "yiwu-linhao-trading", Name: "Yiwu Linhao Trading", Country: "CN", LeadDays: 7, Moq: 50, Rating: "4.8", CostCents: 420, Platform: "Direct factory", WarehouseRegion: "CN", FulfillmentModel: "direct wholesale", TrackingQuality: "medium", SampleAvailable: true, BrandingControl: "custom", ProfileUrl: "/suppliers?supplier=yiwu-linhao-trading", RiskLevel: "medium"},
		},
		UnitEconomics: []*appv1.UnitEconomicsLine{
			{Label: "Product cost", ValueCents: product.CostCents},
			{Label: "Shipping", ValueCents: 320},
			{Label: "Ads (avg)", ValueCents: 540},
			{Label: "Fees", ValueCents: 110},
			{Label: "Net profit", ValueCents: 1509, Positive: true},
		},
		CompetitorRows: []*appv1.Competitor{
			{Store: "cozyfeet.shop", PriceCents: 3299, Delta: "$-4.00", Channels: "FB · TikTok", Since: "Mar '25", TrustScore: 72},
			{Store: "cloudstep.co", PriceCents: 3499, Delta: "$-6.00", Channels: "IG · TikTok", Since: "Feb '25", TrustScore: 68},
			{Store: "homewalks.store", PriceCents: 2799, Delta: "$+1.00", Channels: "Shopify", Since: "Apr '25", TrustScore: 51},
		},
		ReviewSentiment: &appv1.ReviewSentiment{
			Rating:      "4.6",
			ReviewCount: 4820,
			Breakdown: []*appv1.ReviewBreakdown{
				{Label: "5★", Percent: 64},
				{Label: "4★", Percent: 22},
				{Label: "3★", Percent: 8},
				{Label: "2★", Percent: 4},
				{Label: "1★", Percent: 2},
			},
			PositiveTags: []string{"COMFORTABLE", "WARM", "TRUE TO SIZE"},
			NegativeTags: []string{"SMELL ON ARRIVAL", "SLIPPERY SOLE"},
			NeutralTags:  []string{"GIFT-WORTHY"},
		},
	}
}

func suppliers() []*appv1.Supplier {
	return []*appv1.Supplier{
		{Id: "cjdropshipping", Name: "CJdropshipping", Country: "CN", CatalogSkus: 1240, OnTimePercent: 96, AvgLeadDays: 7, Rating: "4.8", Platform: "CJdropshipping", SourceMode: "live-ready", WarehouseRegions: []string{"CN", "US", "EU"}, Categories: []string{"Home", "Beauty", "Pet", "Fitness"}, FulfillmentModel: "3PL + freight lanes", ReturnHandling: "international", TrackingQuality: "high", BrandingControl: "custom", SampleAvailable: true, Documentation: []string{"CJ auth API", "CJ product API", "CJ logistic API", "DDP lane proof"}, RiskLevel: "low", MarginOpportunityPercent: 86, ProfileUrl: "https://cjdropshipping.com", PrimaryProbe: "Live product + freight lane pull", BestLaneId: "CJ-US-EXPRESS", Notes: "Live read path for products, variants, and freight lanes. Uses cached CJ-Access-Token and conservative DDP/tracking heuristics."},
		{Id: "spocket-domestic-network", Name: "Spocket Domestic Network", Country: "US", CatalogSkus: 940, OnTimePercent: 95, AvgLeadDays: 5, Rating: "4.7", Platform: "Spocket", SourceMode: "credentialed backlog", WarehouseRegions: []string{"US", "EU"}, Categories: []string{"Beauty", "Home", "Fashion", "Pet"}, FulfillmentModel: "domestic supplier marketplace", ReturnHandling: "domestic", TrackingQuality: "high", BrandingControl: "basic", SampleAvailable: true, Documentation: []string{"Seller docs", "Domestic returns", "Sample order proof"}, RiskLevel: "low", MarginOpportunityPercent: 72, ProfileUrl: "https://www.spocket.co", PrimaryProbe: "Session-backed catalog pull", BestLaneId: "SP-US-DOMESTIC", Notes: "Domestic supplier branch where reliability matters more than lowest COGS. Login bootstrap still needs a provider contract."},
		{Id: "zendrop-us-suppliers", Name: "Zendrop US Suppliers", Country: "US", CatalogSkus: 760, OnTimePercent: 91, AvgLeadDays: 6, Rating: "4.6", Platform: "Zendrop", SourceMode: "manual evidence", WarehouseRegions: []string{"US", "CN"}, Categories: []string{"Home", "Kids", "Fitness", "Kitchen"}, FulfillmentModel: "US supplier branch", ReturnHandling: "domestic", TrackingQuality: "medium", BrandingControl: "basic", SampleAvailable: true, Documentation: []string{"Seller docs", "Fulfillment agreement", "US supplier verification"}, RiskLevel: "medium", MarginOpportunityPercent: 68, ProfileUrl: "https://www.zendrop.com", PrimaryProbe: "US supplier evidence review", BestLaneId: "ZD-US-STANDARD", Notes: "Good compliance-document branch, but fulfillment location still needs SKU-level verification before scale."},
		{Id: "dsers-aliexpress", Name: "DSers / AliExpress", Country: "CN", CatalogSkus: 2200, OnTimePercent: 82, AvgLeadDays: 12, Rating: "4.2", Platform: "DSers", SourceMode: "registered stub", WarehouseRegions: []string{"CN"}, Categories: []string{"Beauty", "Tech", "Outdoor", "Fashion", "Kitchen"}, FulfillmentModel: "AliExpress import", ReturnHandling: "international", TrackingQuality: "medium", BrandingControl: "none", SampleAvailable: false, Documentation: []string{"AliExpress wholesale page", "DSers import mapping"}, RiskLevel: "high", MarginOpportunityPercent: 91, ProfileUrl: "https://www.dsers.com", PrimaryProbe: "AliExpress wholesale crawl + DSers import mapping", BestLaneId: "AX-CN-ECONOMY", Notes: "Broad discovery and low commitment, but SKU-level variance and supplier opacity stay high."},
		{Id: "syncee-marketplace", Name: "Syncee Marketplace", Country: "EU", CatalogSkus: 680, OnTimePercent: 93, AvgLeadDays: 8, Rating: "4.5", Platform: "Syncee", SourceMode: "manual evidence", WarehouseRegions: []string{"EU", "US"}, Categories: []string{"Fashion", "Home", "Kids"}, FulfillmentModel: "supplier directory", ReturnHandling: "domestic", TrackingQuality: "medium", BrandingControl: "basic", SampleAvailable: true, Documentation: []string{"Supplier terms", "Return policy"}, RiskLevel: "medium", MarginOpportunityPercent: 61, ProfileUrl: "https://syncee.com", PrimaryProbe: "Directory profile review", BestLaneId: "SY-EU-STANDARD", Notes: "Useful for EU catalogue breadth and supplier diversity; validate direct supplier terms before import."},
		{Id: "salehoo-directory", Name: "SaleHoo Directory", Country: "US", CatalogSkus: 420, OnTimePercent: 90, AvgLeadDays: 10, Rating: "4.4", Platform: "SaleHoo", SourceMode: "directory", WarehouseRegions: []string{"US", "AU", "EU"}, Categories: []string{"Home", "Pet", "Outdoor"}, FulfillmentModel: "verified directory", ReturnHandling: "mixed", TrackingQuality: "medium", BrandingControl: "basic", SampleAvailable: true, Documentation: []string{"Directory verification", "Supplier contact evidence"}, RiskLevel: "medium", MarginOpportunityPercent: 58, ProfileUrl: "https://www.salehoo.com", PrimaryProbe: "Directory shortlist review", BestLaneId: "SH-MIXED", Notes: "Good wholesale discovery source when direct supplier vetting is more important than automated import."},
		{Id: "worldwide-brands", Name: "Worldwide Brands", Country: "US", CatalogSkus: 390, OnTimePercent: 92, AvgLeadDays: 9, Rating: "4.5", Platform: "Worldwide Brands", SourceMode: "directory", WarehouseRegions: []string{"US"}, Categories: []string{"Home", "Kids", "Fitness"}, FulfillmentModel: "certified wholesaler directory", ReturnHandling: "mixed", TrackingQuality: "medium", BrandingControl: "custom", SampleAvailable: true, Documentation: []string{"Wholesaler certification", "Seller-of-record docs"}, RiskLevel: "low", MarginOpportunityPercent: 54, ProfileUrl: "https://www.worldwidebrands.com", PrimaryProbe: "Certified wholesaler review", BestLaneId: "WWB-US-WHOLESALE", Notes: "Slower catalogue expansion, stronger seller-of-record and packaging-documentation posture."},
		{Id: "modalyst-brand-network", Name: "Modalyst Brand Network", Country: "US", CatalogSkus: 530, OnTimePercent: 89, AvgLeadDays: 8, Rating: "4.3", Platform: "Modalyst", SourceMode: "manual evidence", WarehouseRegions: []string{"US", "EU"}, Categories: []string{"Fashion", "Beauty", "Kids"}, FulfillmentModel: "brand marketplace", ReturnHandling: "domestic", TrackingQuality: "medium", BrandingControl: "basic", SampleAvailable: true, Documentation: []string{"Brand authorization", "Return policy"}, RiskLevel: "medium", MarginOpportunityPercent: 63, ProfileUrl: "https://www.modalyst.co", PrimaryProbe: "Brand network profile review", BestLaneId: "MO-US-BRAND", Notes: "Higher perceived brand quality, but COGS needs tighter margin screening."},
		{Id: "yiwu-linhao-trading", Name: "Yiwu Linhao Trading", Country: "CN", CatalogSkus: 1240, OnTimePercent: 96, AvgLeadDays: 7, Rating: "4.8", Platform: "Direct factory", SourceMode: "vetted fixture", WarehouseRegions: []string{"CN"}, Categories: []string{"Home", "Beauty"}, FulfillmentModel: "direct wholesale", ReturnHandling: "international", TrackingQuality: "medium", BrandingControl: "custom", SampleAvailable: true, Documentation: []string{"Factory quote", "Packing slip review"}, RiskLevel: "medium", MarginOpportunityPercent: 82, ProfileUrl: "https://example.com/suppliers/yiwu-linhao-trading", PrimaryProbe: "Factory quote comparison", BestLaneId: "YL-CN-DDP", Notes: "Direct fixture supplier retained from the wireframe dataset for SKU-level quote comparison."},
		{Id: "guangzhou-petal-co", Name: "Guangzhou Petal Co.", Country: "CN", CatalogSkus: 880, OnTimePercent: 92, AvgLeadDays: 6, Rating: "4.6", Platform: "Direct factory", SourceMode: "vetted fixture", WarehouseRegions: []string{"CN"}, Categories: []string{"Beauty", "Tech", "Fashion"}, FulfillmentModel: "direct wholesale", ReturnHandling: "international", TrackingQuality: "medium", BrandingControl: "basic", SampleAvailable: true, Documentation: []string{"Factory quote", "Sample order"}, RiskLevel: "medium", MarginOpportunityPercent: 79, ProfileUrl: "https://example.com/suppliers/guangzhou-petal-co", PrimaryProbe: "Factory quote comparison", BestLaneId: "GP-CN-STANDARD", Notes: "Beauty and accessory supplier with strong cost position but slower compliance evidence."},
		{Id: "saigon-quick-goods", Name: "Saigon Quick Goods", Country: "VN", CatalogSkus: 210, OnTimePercent: 94, AvgLeadDays: 9, Rating: "4.7", Platform: "Direct factory", SourceMode: "vetted fixture", WarehouseRegions: []string{"VN"}, Categories: []string{"Pet", "Fitness", "Home"}, FulfillmentModel: "direct wholesale", ReturnHandling: "international", TrackingQuality: "medium", BrandingControl: "custom", SampleAvailable: true, Documentation: []string{"Factory quote", "DDP quote"}, RiskLevel: "medium", MarginOpportunityPercent: 74, ProfileUrl: "https://example.com/suppliers/saigon-quick-goods", PrimaryProbe: "Factory quote comparison", BestLaneId: "SQ-VN-DDP", Notes: "Useful non-China supplier lane when category saturation rises."},
		{Id: "lodz-fast-ship", Name: "Lodz Fast Ship", Country: "PL", CatalogSkus: 94, OnTimePercent: 98, AvgLeadDays: 4, Rating: "4.9", Platform: "Direct wholesaler", SourceMode: "vetted fixture", WarehouseRegions: []string{"EU"}, Categories: []string{"Outdoor", "Pet"}, FulfillmentModel: "EU wholesale", ReturnHandling: "domestic", TrackingQuality: "high", BrandingControl: "basic", SampleAvailable: true, Documentation: []string{"EU warehouse proof", "Return policy"}, RiskLevel: "low", MarginOpportunityPercent: 52, ProfileUrl: "https://example.com/suppliers/lodz-fast-ship", PrimaryProbe: "EU warehouse proof review", BestLaneId: "LF-EU-FAST", Notes: "Best reliability lane in the fixture set, with less margin but low operational risk."},
	}
}

func globalTimeline() []int32 {
	return []int32{28, 31, 32, 35, 36, 38, 38, 38, 43, 45, 46, 49, 45, 51, 55, 54, 53, 57, 60, 60, 63, 64, 68, 66, 67, 75, 77, 78, 82, 86, 88, 97, 103, 106, 112, 113, 117, 128, 137, 145, 152, 163, 168, 170, 184, 193}
}

func categoryMomentum() []*appv1.CategoryMomentum {
	return []*appv1.CategoryMomentum{
		{Category: "Home", Score: 78},
		{Category: "Pet", Score: 62},
		{Category: "Beauty", Score: 91},
		{Category: "Tech", Score: 84},
		{Category: "Outdoor", Score: 44},
		{Category: "Fashion", Score: 70},
		{Category: "Kids", Score: 55},
		{Category: "Fitness", Score: 68},
	}
}

func heatCells(count int) []*appv1.HeatCell {
	tones := []string{"low", "moderate", "high", "saturated", "moderate", "low", "saturated", "moderate", "high", "saturated"}
	cells := make([]*appv1.HeatCell, 0, count)
	for i := 0; i < count; i++ {
		cells = append(cells, &appv1.HeatCell{Value: int32((i*17 + 31) % 100), Tone: tones[i%len(tones)]})
	}
	return cells
}
