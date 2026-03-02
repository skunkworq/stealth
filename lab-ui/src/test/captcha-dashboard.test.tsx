/**
 * E2E component tests for CaptchaDashboard
 * Validates: tab navigation, data loading, component composition
 */
import { describe, it, expect, vi, beforeEach } from "vitest";
import { render, screen, waitFor } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { CaptchaDashboard } from "@/components/CaptchaDashboard";

// Mock child components to isolate dashboard behavior
vi.mock("@/components/CaptchaTraceVisualizer", () => ({
  CaptchaTraceVisualizer: ({ challengeId }: { challengeId: string }) => (
    <div data-testid="trace-visualizer">{challengeId}</div>
  ),
}));

vi.mock("@/components/CaptchaTrainer", () => ({
  CaptchaTrainer: () => <div data-testid="captcha-trainer">CaptchaTrainer</div>,
}));

vi.mock("@/components/ManualCaptchaSolver", () => ({
  ManualCaptchaSolver: () => <div data-testid="manual-solver">ManualCaptchaSolver</div>,
}));

vi.mock("@/components/TrainingDataBrowser", () => ({
  TrainingDataBrowser: () => <div data-testid="training-browser">TrainingDataBrowser</div>,
}));

vi.mock("@/components/Toasts", () => ({
  useToasts: () => ({ addToast: vi.fn() }),
}));

const mockMetrics = {
  total_challenges: 42,
  success_rate: 0.85,
  avg_solve_time_ms: 1200,
  by_type: {
    text: { count: 20, successes: 18, failures: 2, avg_time_ms: 800, bot_rate: 0.1 },
    slider: { count: 22, successes: 16, failures: 6, avg_time_ms: 1500, bot_rate: 0.3 },
  },
  ml_features_stats: {},
};

const mockCatalogue = [
  {
    type: "text",
    name: "Text CAPTCHA",
    description: "Basic text recognition",
    example: "",
    metrics: [],
  },
  {
    type: "slider",
    name: "Slider CAPTCHA",
    description: "Slide to verify",
    example: "",
    metrics: [],
  },
];

describe("CaptchaDashboard", () => {
  beforeEach(() => {
    vi.mocked(globalThis.fetch).mockReset();
    vi.mocked(globalThis.fetch).mockImplementation(url => {
      const urlStr = typeof url === "string" ? url : url.toString();
      if (urlStr.includes("/api/captcha/metrics")) {
        return Promise.resolve({
          ok: true,
          json: () => Promise.resolve(mockMetrics),
        } as Response);
      }
      if (urlStr.includes("/api/captcha/catalogue")) {
        return Promise.resolve({
          ok: true,
          json: () => Promise.resolve(mockCatalogue),
        } as Response);
      }
      return Promise.resolve({ ok: true, json: () => Promise.resolve({}) } as Response);
    });
  });

  it("renders loading state initially", () => {
    render(<CaptchaDashboard />);
    expect(screen.getByText(/SYNCING_CAPTCHA_TELEMETRY/i)).toBeInTheDocument();
  });

  it("renders overview tab with metrics after loading", async () => {
    render(<CaptchaDashboard />);
    await waitFor(() => {
      expect(screen.getByText("42")).toBeInTheDocument();
    });
    expect(screen.getByText("85.0%")).toBeInTheDocument();
    expect(screen.getByText("1200ms")).toBeInTheDocument();
  });

  it("renders all five tab triggers", async () => {
    render(<CaptchaDashboard />);
    await waitFor(() => {
      expect(screen.getByText("42")).toBeInTheDocument();
    });
    expect(screen.getByRole("tab", { name: /overview/i })).toBeInTheDocument();
    expect(screen.getByRole("tab", { name: /training lab/i })).toBeInTheDocument();
    expect(screen.getByRole("tab", { name: /ml insights/i })).toBeInTheDocument();
    expect(screen.getByRole("tab", { name: /manual solver/i })).toBeInTheDocument();
    expect(screen.getByRole("tab", { name: /dataset/i })).toBeInTheDocument();
  });

  it("switches to Training Lab tab and shows CaptchaTrainer", async () => {
    const user = userEvent.setup();
    render(<CaptchaDashboard />);
    await waitFor(() => {
      expect(screen.getByText("42")).toBeInTheDocument();
    });

    await user.click(screen.getByRole("tab", { name: /training lab/i }));
    expect(screen.getByTestId("captcha-trainer")).toBeInTheDocument();
  });

  it("switches to Manual Solver tab", async () => {
    const user = userEvent.setup();
    render(<CaptchaDashboard />);
    await waitFor(() => {
      expect(screen.getByText("42")).toBeInTheDocument();
    });

    await user.click(screen.getByRole("tab", { name: /manual solver/i }));
    expect(screen.getByTestId("manual-solver")).toBeInTheDocument();
  });

  it("switches to Dataset tab", async () => {
    const user = userEvent.setup();
    render(<CaptchaDashboard />);
    await waitFor(() => {
      expect(screen.getByText("42")).toBeInTheDocument();
    });

    await user.click(screen.getByRole("tab", { name: /dataset/i }));
    expect(screen.getByTestId("training-browser")).toBeInTheDocument();
  });

  it("displays catalogue entries in the overview table", async () => {
    render(<CaptchaDashboard />);
    await waitFor(() => {
      expect(screen.getByText("Text CAPTCHA")).toBeInTheDocument();
    });
    expect(screen.getByText("Slider CAPTCHA")).toBeInTheDocument();
    expect(screen.getByText("Basic text recognition")).toBeInTheDocument();
  });

  it("fetches data on mount", async () => {
    render(<CaptchaDashboard />);
    await waitFor(() => {
      expect(globalThis.fetch).toHaveBeenCalledWith("/api/captcha/metrics");
      expect(globalThis.fetch).toHaveBeenCalledWith("/api/captcha/catalogue");
    });
  });
});
