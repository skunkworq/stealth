export interface ProfileResult {
  name: string;
  platform: string;
  score: number;
  is_bot: boolean;
  vectors: Record<string, number>;
  indicators: string[];
}

export interface ShieldSummary {
  catch_rate: number;
  avg_score: number;
  threshold: number;
}

export interface ShieldEvalResponse {
  profiles: ProfileResult[];
  summary: ShieldSummary;
}

export interface ShieldMetricsResponse {
  weights: Record<string, number>;
  bypass_rates: Record<string, number>;
  threshold: number;
}
