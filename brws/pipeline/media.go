package pipeline

import (
	"context"
	"fmt"
	"io"
	"mime"
	"net/http"
	"os"
	"path/filepath"
	"strings"
)

type MediaPipeline struct {
	downloadPath string
	httpClient   *http.Client
	referer      string
}

type MediaItem struct {
	URL      string
	Filename string
	Path     string
	Checksum string
	Status   string
}

func NewMediaPipeline(downloadPath string) *MediaPipeline {
	return &MediaPipeline{
		downloadPath: downloadPath,
		httpClient:   &http.Client{},
	}
}

func (p *MediaPipeline) Open(ctx context.Context) error {
	if p.downloadPath == "" {
		p.downloadPath = "downloads"
	}
	return os.MkdirAll(p.downloadPath, 0755)
}

func (p *MediaPipeline) ProcessItem(ctx context.Context, item interface{}) (interface{}, error) {
	mi, ok := item.(MediaItem)
	if !ok {
		return item, nil
	}

	if mi.Filename == "" {
		mi.Filename = p.suggestFilename(mi.URL)
	}

	filepath := filepath.Join(p.downloadPath, mi.Filename)

	file, err := os.Create(filepath)
	if err != nil {
		mi.Status = "failed"
		return mi, fmt.Errorf("creating file: %w", err)
	}
	defer file.Close()

	req, err := http.NewRequestWithContext(ctx, "GET", mi.URL, nil)
	if err != nil {
		mi.Status = "failed"
		return mi, fmt.Errorf("creating request: %w", err)
	}

	if p.referer != "" {
		req.Header.Set("Referer", p.referer)
	}

	resp, err := p.httpClient.Do(req)
	if err != nil {
		mi.Status = "failed"
		return mi, fmt.Errorf("downloading: %w", err)
	}
	defer resp.Body.Close()

	_, err = io.Copy(file, resp.Body)
	if err != nil {
		mi.Status = "failed"
		return mi, fmt.Errorf("saving: %w", err)
	}

	mi.Path = filepath
	mi.Status = "completed"
	return mi, nil
}

func (p *MediaPipeline) Close(ctx context.Context) error {
	return nil
}

func (p *MediaPipeline) suggestFilename(url string) string {
	parsed := strings.Split(url, "/")
	filename := parsed[len(parsed)-1]

	if !strings.Contains(filename, ".") {
		ext := p.guessExtension(url)
		filename = filename + ext
	}

	return filename
}

func (p *MediaPipeline) guessExtension(url string) string {
	resp, err := p.httpClient.Head(url)
	if err != nil {
		return ".dat"
	}
	defer resp.Body.Close()

	contentType := resp.Header.Get("Content-Type")
	exts, err := mime.ExtensionsByType(contentType)
	if err != nil || len(exts) == 0 {
		return ".dat"
	}
	return exts[0]
}

type ImagesPipeline struct {
	*MediaPipeline
	thumbnailSize int
}

func NewImagesPipeline(downloadPath string) *ImagesPipeline {
	return &ImagesPipeline{
		MediaPipeline: NewMediaPipeline(downloadPath),
		thumbnailSize: 0,
	}
}

func (p *ImagesPipeline) SetThumbnailSize(size int) {
	p.thumbnailSize = size
}

func (p *ImagesPipeline) ProcessItem(ctx context.Context, item interface{}) (interface{}, error) {
	return p.MediaPipeline.ProcessItem(ctx, item)
}
