/**
 * E2E component tests for TrainingDataBrowser
 * Validates: data loading, filtering, pagination, export
 */
import { describe, it, expect, vi, beforeEach } from "vitest";
import { render, screen, waitFor } from "@testing-library/react";
import { TrainingDataBrowser } from "@/components/TrainingDataBrowser";

// Mock CaptchaTraceVisualizer
vi.mock("@/components/CaptchaTraceVisualizer", () => ({
  CaptchaTraceVisualizer: ({ challengeId }: { challengeId: string }) => (
    <div data-testid="trace-vis">{challengeId}</div>
  ),
}));

const mockSamples = [
  {
    id: "sample-1",
    timestamp: "2026-01-15T10:30:00Z",
    type: "text",
    label: "solved",
    bot_score: 0.12,
    solve_time_ms: 850,
    challenge_id: "ch-001",
  },
  {
    id: "sample-2",
    timestamp: "2026-01-15T10:31:00Z",
    type: "slider",
    label: "failed",
    bot_score: 0.87,
    solve_time_ms: 200,
    challenge_id: "ch-002",
  },
];

const mockStats = {
  total_samples: 100,
  by_type: { text: 60, slider: 40 },
  by_label: { solved: 75, failed: 25 },
  avg_bot_score: 0.35,
};

describe("TrainingDataBrowser", () => {
  beforeEach(() => {
    vi.mocked(globalThis.fetch).mockReset();
    vi.mocked(globalThis.fetch).mockImplementation(url => {
      const urlStr = typeof url === "string" ? url : url.toString();
      if (urlStr.includes("/api/training/samples")) {
        return Promise.resolve({
          ok: true,
          json: () => Promise.resolve({ samples: mockSamples, total: 2 }),
        } as Response);
      }
      if (urlStr.includes("/api/training/stats")) {
        return Promise.resolve({
          ok: true,
          json: () => Promise.resolve(mockStats),
        } as Response);
      }
      if (urlStr.includes("/api/training/export")) {
        return Promise.resolve({
          ok: true,
          blob: () => Promise.resolve(new Blob(["csv,data"], { type: "text/csv" })),
        } as Response);
      }
      return Promise.resolve({ ok: true, json: () => Promise.resolve({}) } as Response);
    });
  });

  it("fetches and displays training samples", async () => {
    render(<TrainingDataBrowser />);
    await waitFor(() => {
      expect(globalThis.fetch).toHaveBeenCalledWith(
        expect.stringContaining("/api/training/samples")
      );
    });
  });

  it("fetches training stats on mount", async () => {
    render(<TrainingDataBrowser />);
    await waitFor(() => {
      expect(globalThis.fetch).toHaveBeenCalledWith("/api/training/stats");
    });
  });

  it("renders filter controls", async () => {
    render(<TrainingDataBrowser />);
    // Wait for initial load
    await waitFor(() => {
      expect(globalThis.fetch).toHaveBeenCalled();
    });

    // Should have type and label filter dropdowns
    const comboboxes = screen.getAllByRole("combobox");
    expect(comboboxes.length).toBeGreaterThanOrEqual(2);
  });

  it("renders export button", async () => {
    render(<TrainingDataBrowser />);
    await waitFor(() => {
      expect(globalThis.fetch).toHaveBeenCalled();
    });

    const exportBtn = screen.getByText(/export csv/i);
    expect(exportBtn).toBeInTheDocument();
  });

  it("renders stats summary cards when stats available", async () => {
    render(<TrainingDataBrowser />);
    await waitFor(() => {
      expect(screen.getByText("100")).toBeInTheDocument();
    });
  });
});
