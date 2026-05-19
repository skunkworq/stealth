package stealth

import (
	"context"
	"fmt"

	"github.com/skunkworq/stealth/brws/browser/engine"
	"github.com/skunkworq/stealth/brws/core/instrumentation"
	"github.com/skunkworq/stealth/brws/stealth/behavior"
	"github.com/skunkworq/stealth/brws/stealth/behavior/tracker"
)

// Mouse moves the mouse to the specified coordinates.
// When the underlying engine supports interaction, it delegates to the engine.
func (c *Adaptive) Mouse(x, y float64) error {
	_ = c.hooks.Execute(context.Background(), instrumentation.HookNames.OnMouseMove)
	c.behavTracker.RecordMouseMove(x, y)
	if ie, ok := c.engine.(engine.InteractiveEngine); ok {
		return ie.Mouse(x, y)
	}
	c.logger.Debug("mouse move (no interactive engine)", "x", x, "y", y)
	return nil
}

// Click performs a mouse click at coordinates.
// When the underlying engine supports interaction, it delegates to the engine.
func (c *Adaptive) Click(x, y float64) error {
	c.behavTracker.RecordMouseMove(x, y)
	if ie, ok := c.engine.(engine.InteractiveEngine); ok {
		return ie.Click(x, y)
	}
	c.logger.Debug("click (no interactive engine)", "x", x, "y", y)
	return nil
}

// ClickSelector clicks an element matching the CSS selector.
// Uses JavaScript to find and click the element. Requires a JS-capable engine.
func (c *Adaptive) ClickSelector(ctx context.Context, selector string) error {
	if !c.engine.Capabilities().JavaScript {
		return fmt.Errorf("click by selector requires JavaScript-capable engine")
	}

	clickScript := fmt.Sprintf(`
		(function() {
			var el = document.querySelector("%s");
			if (el) {
				el.click();
				return true;
			}
			return false;
		})()
	`, selector)

	_, err := c.engine.Do(ctx, &engine.Request{
		URL:             "about:blank",
		ScriptToExecute: clickScript,
		Timeout:         c.options.Timeout,
	})
	if err != nil {
		c.logger.Warn("click selector failed", "selector", selector, "error", err)
		return err
	}

	c.logger.Debug("clicked selector", "selector", selector)
	return nil
}

// Type simulates typing text.
// When the underlying engine supports interaction, it delegates to the engine.
func (c *Adaptive) Type(text string) error {
	_ = c.hooks.Execute(context.Background(), instrumentation.HookNames.OnType)
	c.behavTracker.RecordKeystroke()
	if ie, ok := c.engine.(engine.InteractiveEngine); ok {
		return ie.Type(text)
	}
	c.logger.Debug("type (no interactive engine)", "length", len(text))
	return nil
}

// Scroll scrolls the page.
// When the underlying engine supports interaction, it delegates to the engine.
func (c *Adaptive) Scroll(pixels float64) error {
	_ = c.hooks.Execute(context.Background(), instrumentation.HookNames.OnScroll)
	if ie, ok := c.engine.(engine.InteractiveEngine); ok {
		return ie.Scroll(pixels)
	}
	c.logger.Debug("scroll (no interactive engine)", "pixels", pixels)
	return nil
}

// BehavioralSnapshot returns the accumulated behavioral data from this session.
// Useful for training data collection and self-evaluation.
func (c *Adaptive) BehavioralSnapshot() *behavior.EventData {
	return c.behavTracker.Snapshot()
}

// ResetBehavioralTracker clears the accumulated behavioral data.
func (c *Adaptive) ResetBehavioralTracker() {
	c.behavTracker = tracker.New()
}
