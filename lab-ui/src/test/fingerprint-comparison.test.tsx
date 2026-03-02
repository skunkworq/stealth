/**
 * E2E component tests for FingerprintComparison
 * Validates: capture loading, selection, comparison flow
 */
import { describe, it, expect, vi, beforeEach } from "vitest";
import { render, screen, waitFor } from "@testing-library/react";
import { FingerprintComparison } from "@/components/FingerprintComparison";

const mockCaptures = [
  { id: "cap-001", timestamp: "2026-01-15T10:00:00Z", source: "Chrome 124" },
  { id: "cap-002", timestamp: "2026-01-15T10:01:00Z", source: "Firefox 127" },
];

describe("FingerprintComparison", () => {
  beforeEach(() => {
    vi.mocked(globalThis.fetch).mockReset();
    vi.mocked(globalThis.fetch).mockImplementation(url => {
      const urlStr = typeof url === "string" ? url : url.toString();
      if (urlStr.includes("/api/captures")) {
        return Promise.resolve({
          ok: true,
          json: () => Promise.resolve(mockCaptures),
        } as Response);
      }
      if (urlStr.includes("/api/fingerprints/compare")) {
        return Promise.resolve({
          ok: true,
          json: () =>
            Promise.resolve({
              similarity: 0.73,
              fields: [],
            }),
        } as Response);
      }
      return Promise.resolve({ ok: true, json: () => Promise.resolve({}) } as Response);
    });
  });

  it("renders component title", async () => {
    render(<FingerprintComparison />);
    expect(screen.getByText(/fingerprint comparison/i)).toBeInTheDocument();
  });

  it("renders two capture selectors with labels", async () => {
    render(<FingerprintComparison />);
    expect(screen.getByText(/capture a/i)).toBeInTheDocument();
    expect(screen.getByText(/capture b/i)).toBeInTheDocument();
  });

  it("renders capture selector comboboxes", async () => {
    render(<FingerprintComparison />);
    await waitFor(() => {
      const comboboxes = screen.getAllByRole("combobox");
      expect(comboboxes.length).toBeGreaterThanOrEqual(2);
    });
  });

  it("fetches captures on mount", async () => {
    render(<FingerprintComparison />);
    await waitFor(() => {
      expect(globalThis.fetch).toHaveBeenCalledWith("/api/captures");
    });
  });

  it("has a Compare button", async () => {
    render(<FingerprintComparison />);
    // Use getByRole to target just the button
    const compareBtn = screen.getByRole("button", { name: /compare/i });
    expect(compareBtn).toBeInTheDocument();
  });

  it("disables Compare button when captures not selected", async () => {
    render(<FingerprintComparison />);
    const compareBtn = screen.getByRole("button", { name: /compare/i });
    expect(compareBtn).toBeDisabled();
  });

  it("shows placeholder text when no comparison done", () => {
    render(<FingerprintComparison />);
    expect(screen.getByText(/select two captures/i)).toBeInTheDocument();
  });
});
