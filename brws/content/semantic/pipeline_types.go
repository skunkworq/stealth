package semantic

// PipelineConfig configures the semantic processing pipeline.
type PipelineConfig struct {
	LLMClient        *LLMClient
	EmbeddingClient  *EmbeddingClient
	VisionClient     *VisionClient
	Cache            *CacheStore
	MaxDepth         int
	MinContentLen    int
	MaxChunks        int
	MaxConcurrentLLM int
}

// DomChunk represents a chunk of the DOM for processing.
type DomChunk struct {
	Selector            string
	Tag                 string
	HTML                string
	StructuralHash      string
	Children            []DomChunk
	Images              []ImageRef
	Depth               int
	InteractiveElements []InteractiveElement
}

// VisionClient wraps an LLMClient for vision tasks.
type VisionClient struct {
	client *LLMClient
}

// NewVisionClient creates a new VisionClient.
func NewVisionClient(llmClient *LLMClient) *VisionClient {
	return &VisionClient{client: llmClient}
}
