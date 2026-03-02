export interface DetectionVector {
  name: string;
  category: string;
  score: number;
  weight: number;
  detected: boolean;
  description: string;
  indicators: string[];
}

export interface StealthIndicator {
  vector: string;
  name: string;
  severity: number;
  message: string;
}

export interface BehavioralCheck {
  check: string;
  message: string;
  weight: number;
  field: string;
  value: string;
}

export interface V3Assessment {
  id: string;
  timestamp: string;
  action: string;
  v3_score: number;
  detection_score: number;
  behavioral_score: number;
  combined_bot_score: number;
  event_count: number;
  hostname: string;
  vectors: DetectionVector[];
  indicators: StealthIndicator[];
  behavioral_checks?: BehavioralCheck[];
  behavioral_event_breakdown?: Record<string, number>;
}

export interface V3Metrics {
  total: number;
  avg_v3_score: number;
  avg_detection_score: number;
  avg_behavioral_score: number;
  pass_rate: number;
  score_buckets: Record<string, number>;
  by_action: Record<string, { count: number; avg_score: number; pass_rate: number }>;
}
