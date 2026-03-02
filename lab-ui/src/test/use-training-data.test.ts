/**
 * Hook tests for useTrainingData
 * Validates: data fetching, filtering, export functionality
 */
import { describe, it, expect, vi, beforeEach } from "vitest";
import { renderHook, waitFor, act } from "@testing-library/react";
import { useTrainingData } from "@/hooks/useTrainingData";

const mockSamples = [
  {
    id: "s-1",
    timestamp: "2026-01-15T10:00:00Z",
    type: "text",
    label: "solved",
    bot_score: 0.1,
    solve_time_ms: 500,
    challenge_id: "ch-1",
  },
];

const mockStats = {
  total_samples: 50,
  by_type: { text: 30, slider: 20 },
  by_label: { solved: 40, failed: 10 },
  avg_bot_score: 0.25,
};

describe("useTrainingData", () => {
  beforeEach(() => {
    vi.mocked(globalThis.fetch).mockReset();
    vi.mocked(globalThis.fetch).mockImplementation(url => {
      const urlStr = typeof url === "string" ? url : url.toString();
      if (urlStr.includes("/api/training/samples")) {
        return Promise.resolve({
          ok: true,
          json: () => Promise.resolve({ samples: mockSamples, total: 1 }),
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
          blob: () => Promise.resolve(new Blob(["data"], { type: "text/csv" })),
        } as Response);
      }
      return Promise.resolve({ ok: true, json: () => Promise.resolve({}) } as Response);
    });
  });

  it("fetches samples and stats on mount", async () => {
    const { result } = renderHook(() => useTrainingData());

    await waitFor(() => {
      expect(result.current.loading).toBe(false);
    });

    expect(result.current.samples).toEqual(mockSamples);
    expect(result.current.stats).toEqual(mockStats);
    expect(result.current.totalCount).toBe(1);
  });

  it("provides default filters", () => {
    const { result } = renderHook(() => useTrainingData());
    expect(result.current.filters.type).toBe("all");
    expect(result.current.filters.label).toBe("all");
    expect(result.current.filters.limit).toBe(20);
    expect(result.current.filters.offset).toBe(0);
  });

  it("refetches when filters change", async () => {
    const { result } = renderHook(() => useTrainingData());

    await waitFor(() => {
      expect(result.current.loading).toBe(false);
    });

    const initialCallCount = vi.mocked(globalThis.fetch).mock.calls.length;

    act(() => {
      result.current.setFilters(prev => ({ ...prev, type: "slider" }));
    });

    await waitFor(() => {
      expect(vi.mocked(globalThis.fetch).mock.calls.length).toBeGreaterThan(initialCallCount);
    });

    // Check that the fetch was called with the right type param
    const fetchCalls = vi.mocked(globalThis.fetch).mock.calls;
    const lastSamplesCall = fetchCalls
      .map(([url]) => (typeof url === "string" ? url : url.toString()))
      .filter(u => u.includes("/api/training/samples"))
      .pop();
    expect(lastSamplesCall).toContain("type=slider");
  });

  it("handles exportCSV", async () => {
    const { result } = renderHook(() => useTrainingData());

    await waitFor(() => {
      expect(result.current.loading).toBe(false);
    });

    // Mock document.createElement for anchor
    const mockClick = vi.fn();
    const mockAnchor = {
      href: "",
      download: "",
      click: mockClick,
    };
    vi.spyOn(document, "createElement").mockReturnValueOnce(mockAnchor as unknown as HTMLElement);
    vi.spyOn(document.body, "appendChild").mockImplementationOnce(
      () => mockAnchor as unknown as Node
    );
    vi.spyOn(document.body, "removeChild").mockImplementationOnce(
      () => mockAnchor as unknown as Node
    );

    await act(async () => {
      await result.current.exportCSV();
    });

    expect(globalThis.fetch).toHaveBeenCalledWith("/api/training/export?format=csv");
  });

  it("refresh triggers re-fetch of both samples and stats", async () => {
    const { result } = renderHook(() => useTrainingData());

    await waitFor(() => {
      expect(result.current.loading).toBe(false);
    });

    const callCountBefore = vi.mocked(globalThis.fetch).mock.calls.length;

    act(() => {
      result.current.refresh();
    });

    await waitFor(() => {
      expect(vi.mocked(globalThis.fetch).mock.calls.length).toBeGreaterThan(callCountBefore);
    });
  });
});
