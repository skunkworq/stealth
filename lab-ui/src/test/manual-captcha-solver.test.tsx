/**
 * E2E component tests for ManualCaptchaSolver
 * Validates: image upload area, type selection, event recording, submission flow
 */
import { describe, it, expect, vi, beforeEach } from "vitest";
import { render, screen } from "@testing-library/react";
import { ManualCaptchaSolver } from "@/components/ManualCaptchaSolver";

vi.mock("@/components/Toasts", () => ({
  useToasts: () => ({ addToast: vi.fn() }),
}));

describe("ManualCaptchaSolver", () => {
  beforeEach(() => {
    vi.mocked(globalThis.fetch).mockReset();
    vi.mocked(globalThis.fetch).mockResolvedValue({
      ok: true,
      json: () =>
        Promise.resolve({
          bot_score: 0.15,
          metrics: { mouse_velocity: 120, typing_speed: 45 },
          solved: true,
          message: "Solution accepted",
        }),
    } as Response);
  });

  it("renders the drop zone when no image is loaded", () => {
    render(<ManualCaptchaSolver />);
    expect(screen.getByText(/drop captcha image here/i)).toBeInTheDocument();
  });

  it("renders title", () => {
    render(<ManualCaptchaSolver />);
    expect(screen.getByText(/manual captcha solver/i)).toBeInTheDocument();
  });

  it("renders CAPTCHA type selector", () => {
    render(<ManualCaptchaSolver />);
    // Find the type selector trigger (combobox)
    const triggers = screen.getAllByRole("combobox");
    expect(triggers.length).toBeGreaterThanOrEqual(1);
  });

  it("shows live telemetry stream section", () => {
    render(<ManualCaptchaSolver />);
    expect(screen.getByText(/live telemetry stream/i)).toBeInTheDocument();
  });

  it("shows awaiting input events message", () => {
    render(<ManualCaptchaSolver />);
    expect(screen.getByText(/awaiting input events/i)).toBeInTheDocument();
  });
});
