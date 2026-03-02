/**
 * E2E component tests for FingerprintViewer
 * Validates: tab structure, data rendering, export/copy buttons
 */
import { describe, it, expect, vi } from "vitest";
import { render, screen } from "@testing-library/react";
import { FingerprintViewer } from "@/components/FingerprintViewer";

// Mock FingerprintProvider
const mockFingerprint = {
  id: "fp-test-12345678",
  source_ip: "127.0.0.1",
  tls: {
    version: 771,
    version_name: "TLS 1.3",
    ja3_hash: "abc123def456ghi789",
    ja3_string: "771,4865-4866,0-23-65281,29-23-24,0",
    ja4: "t13d1517h2_8daaf6152771",
    cipher_suites: [{ value: 4865, name: "TLS_AES_128_GCM_SHA256", position: 0 }],
    extensions: [],
    alpn: ["h2", "http/1.1"],
  },
  http2: {
    settings: [{ id: 1, name: "HEADER_TABLE_SIZE", value: 65536, position: 0 }],
    pseudo_header_order: [":method", ":authority", ":scheme", ":path"],
  },
  http: {
    method: "GET",
    protocol: "HTTP/2",
    headers: [{ name: "User-Agent", value: "Mozilla/5.0" }],
  },
};

vi.mock("@/components/FingerprintProvider", () => ({
  useFingerprint: () => ({
    fingerprint: mockFingerprint,
    loading: false,
    error: null,
    jsonOutput: JSON.stringify(mockFingerprint, null, 2),
  }),
}));

describe("FingerprintViewer", () => {
  it("renders without crashing", () => {
    render(<FingerprintViewer />);
    expect(screen.getByRole("tab", { name: /tls/i })).toBeInTheDocument();
  });

  it("renders all five fingerprint tabs", () => {
    render(<FingerprintViewer />);
    expect(screen.getByRole("tab", { name: /tls/i })).toBeInTheDocument();
    expect(screen.getByRole("tab", { name: /http\/2/i })).toBeInTheDocument();
    // HTTP tab - match exactly "HTTP" but not "HTTP/2"
    const httpTabs = screen.getAllByRole("tab").filter(tab => tab.textContent === "HTTP");
    expect(httpTabs.length).toBeGreaterThanOrEqual(1);
    expect(screen.getByRole("tab", { name: /behavior/i })).toBeInTheDocument();
    expect(screen.getByRole("tab", { name: /raw/i })).toBeInTheDocument();
  });

  it("displays JA3 hash in summary bar", () => {
    render(<FingerprintViewer />);
    // JA3 is displayed truncated: "JA3: abc123def456gh..."
    expect(screen.getByText(/JA3:/)).toBeInTheDocument();
  });

  it("has Export JSON button", () => {
    render(<FingerprintViewer />);
    expect(screen.getByText(/export json/i)).toBeInTheDocument();
  });

  it("displays viewer title", () => {
    render(<FingerprintViewer />);
    expect(screen.getByText(/multi-layer fingerprint viewer/i)).toBeInTheDocument();
  });
});
