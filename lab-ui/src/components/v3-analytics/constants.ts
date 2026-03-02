// Score thresholds
export const SCORE_THRESHOLD_HIGH = 0.7;
export const SCORE_THRESHOLD_MEDIUM = 0.3;
export const SEVERITY_THRESHOLD_HIGH = 0.7;
export const SEVERITY_THRESHOLD_MEDIUM = 0.4;

// Display
export const HISTORY_DISPLAY_LIMIT = 50;
export const PERCENTAGE = 100;
export const SCORE_DECIMAL_PLACES = 3;
export const WEIGHT_DECIMAL_PLACES = 2;
export const SEVERITY_DECIMAL_PLACES = 2;
export const REFETCH_DELAY_MS = 300;

export function scoreColor(score: number): string {
  if (score >= SCORE_THRESHOLD_HIGH) return "text-emerald-glow";
  if (score >= SCORE_THRESHOLD_MEDIUM) return "text-amber-glow";
  return "text-red-glow";
}

export function scoreBadgeVariant(
  score: number
): "default" | "secondary" | "destructive" | "outline" {
  if (score >= SCORE_THRESHOLD_HIGH) return "default";
  if (score >= SCORE_THRESHOLD_MEDIUM) return "secondary";
  return "destructive";
}

export function severityColor(severity: number): string {
  if (severity >= SEVERITY_THRESHOLD_HIGH) return "text-red-glow";
  if (severity >= SEVERITY_THRESHOLD_MEDIUM) return "text-amber-glow";
  return "text-muted-foreground";
}
