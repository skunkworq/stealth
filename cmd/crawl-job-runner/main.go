// crawl-job-runner is invoked by the dropshippr TS layer as a subprocess.
// Protocol: it reads a single CrawlJob (proto-JSON) from --job <path> or stdin,
// dispatches to a spider registered in brws/spider/spiders/dropshippr, and
// streams CrawlResult envelopes as newline-delimited proto-JSON on stdout.
// The final envelope is always RESULT_KIND_DONE.
package main

import (
	"bufio"
	"context"
	"flag"
	"fmt"
	"io"
	"os"
	"os/signal"
	"sync"
	"syscall"
	"time"

	"google.golang.org/protobuf/encoding/protojson"

	crawlv1 "github.com/skunkworq/stealth/internal/gen/dropshippr/crawl/v1"
	"github.com/skunkworq/stealth/brws/spider/spiders/dropshippr"
)

func main() {
	jobPath := flag.String("job", "", "path to proto-JSON CrawlJob; '-' or empty reads stdin")
	listSpiders := flag.Bool("list-spiders", false, "print registered spider names and exit")
	flag.Parse()

	if *listSpiders {
		for _, n := range dropshippr.Names() {
			fmt.Println(n)
		}
		return
	}

	job, err := readJob(*jobPath)
	if err != nil {
		fatal("read job: %v", err)
	}
	if job.GetSpiderName() == "" {
		fatal("CrawlJob.spider_name is required")
	}

	spider, err := dropshippr.Lookup(job.GetSpiderName())
	if err != nil {
		fatal("%v (registered: %v)", err, dropshippr.Names())
	}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, syscall.SIGINT, syscall.SIGTERM)
	go func() {
		<-sigCh
		cancel()
	}()

	// stdout writes are serialized so concurrent goroutines inside a spider
	// can safely emit without trampling each other.
	out := bufio.NewWriter(os.Stdout)
	defer out.Flush()
	var writeMu sync.Mutex

	marshaler := protojson.MarshalOptions{UseProtoNames: false, EmitUnpopulated: false}

	var counts struct {
		items, pages, errors int32
	}
	start := time.Now()

	write := func(r *crawlv1.CrawlResult) {
		if r.GetJobId() == "" {
			r.JobId = job.GetId()
		}
		b, err := marshaler.Marshal(r)
		if err != nil {
			fmt.Fprintf(os.Stderr, "marshal CrawlResult: %v\n", err)
			return
		}
		writeMu.Lock()
		_, _ = out.Write(b)
		_, _ = out.Write([]byte{'\n'})
		_ = out.Flush()
		writeMu.Unlock()
	}

	emit := func(r *crawlv1.CrawlResult) {
		switch r.GetKind() {
		case crawlv1.ResultKind_RESULT_KIND_ITEM:
			counts.items++
		case crawlv1.ResultKind_RESULT_KIND_PAGE:
			counts.pages++
		case crawlv1.ResultKind_RESULT_KIND_ERROR:
			counts.errors++
		case crawlv1.ResultKind_RESULT_KIND_DONE:
			// Spiders MUST NOT emit DONE; the runner adds it after they return.
			return
		}
		write(r)
	}

	spiderErr := spider(ctx, job, emit)
	if spiderErr != nil {
		write(&crawlv1.CrawlResult{
			JobId: job.GetId(),
			Kind:  crawlv1.ResultKind_RESULT_KIND_ERROR,
			Payload: &crawlv1.CrawlResult_Error{
				Error: &crawlv1.CrawlError{
					Code:    "spider_failed",
					Message: spiderErr.Error(),
				},
			},
		})
	}

	write(&crawlv1.CrawlResult{
		JobId: job.GetId(),
		Kind:  crawlv1.ResultKind_RESULT_KIND_DONE,
		Payload: &crawlv1.CrawlResult_Done{
			Done: &crawlv1.DoneSummary{
				ItemsEmitted: counts.items,
				PagesCrawled: counts.pages,
				Errors:       counts.errors,
				DurationMs:   time.Since(start).Milliseconds(),
			},
		},
	})

	if spiderErr != nil {
		os.Exit(1)
	}
}

func readJob(path string) (*crawlv1.CrawlJob, error) {
	var (
		data []byte
		err  error
	)
	if path == "" || path == "-" {
		data, err = io.ReadAll(os.Stdin)
	} else {
		data, err = os.ReadFile(path)
	}
	if err != nil {
		return nil, err
	}
	job := &crawlv1.CrawlJob{}
	unmarshaler := protojson.UnmarshalOptions{DiscardUnknown: true}
	if err := unmarshaler.Unmarshal(data, job); err != nil {
		return nil, fmt.Errorf("decode proto-json: %w", err)
	}
	return job, nil
}

func fatal(format string, args ...any) {
	fmt.Fprintf(os.Stderr, "crawl-job-runner: "+format+"\n", args...)
	os.Exit(2)
}
