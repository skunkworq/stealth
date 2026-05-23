package detection

import (
	"strings"

	"github.com/skunkworq/stealth/brws/core/constants"
)

func calculateVectorConfidence(vec *DetectionVector) float64 {
	if vec == nil || vec.Score <= 0 {
		return 0
	}

	firedChecks := 0
	highSeverityChecks := 0
	severitySum := 0.0
	maxCheckWeight := 0.0
	distinctFields := make(map[string]struct{})

	if len(vec.CheckReports) > 0 {
		for _, check := range vec.CheckReports {
			if !check.Fired {
				continue
			}
			firedChecks++
			if check.Weight > maxCheckWeight {
				maxCheckWeight = check.Weight
			}
			if check.Field != "" {
				distinctFields[check.Field] = struct{}{}
			}

			switch strings.ToLower(check.Severity) {
			case "critical":
				severitySum += 1.0
				highSeverityChecks++
			case "high":
				severitySum += 0.85
				highSeverityChecks++
			case "medium":
				severitySum += 0.60
			default:
				severitySum += 0.35
			}
		}
	} else {
		firedChecks = len(vec.Indicators)
		maxCheckWeight = vec.Score
		switch severityFromScore(vec.Score) {
		case "critical":
			severitySum = 1.0
			highSeverityChecks = 1
		case "high":
			severitySum = 0.85
			highSeverityChecks = 1
		case "medium":
			severitySum = 0.60
		default:
			severitySum = 0.35
		}
	}

	if maxCheckWeight == 0 {
		maxCheckWeight = vec.Weight
	}
	if firedChecks == 0 {
		firedChecks = len(vec.Indicators)
	}

	evidenceRatio := minFloat(1.0, float64(firedChecks)/3.0)
	severityRatio := minFloat(1.0, severitySum/maxFloat(1.0, float64(firedChecks)))
	weightRatio := minFloat(1.0, maxFloat(vec.Weight, maxCheckWeight))

	confidence := 0.45*vec.Score + 0.20*evidenceRatio + 0.15*severityRatio + 0.10*weightRatio
	if vec.Detected {
		confidence += 0.10
	}
	if len(distinctFields) >= 2 || firedChecks >= 2 {
		confidence += 0.10
	}
	if highSeverityChecks >= 2 {
		confidence += 0.07
	}
	if isHighSignalCategory(vec.Category) && vec.Score >= constants.SeverityHigh {
		confidence += 0.10
	} else if isHighSignalCategory(vec.Category) && vec.Score >= constants.SeverityMedium {
		confidence += 0.05
	}
	if firedChecks == 1 && isHighSignalCategory(vec.Category) && vec.Score >= 0.45 {
		confidence += 0.08
	}

	return minFloat(1.0, confidence)
}

func calculateDetectionConfidence(detection *StealthDetection) float64 {
	if detection == nil {
		return 0
	}

	activeVectors := 0
	strongVectors := 0
	totalVectorConfidence := 0.0
	maxVectorConfidence := 0.0
	corroboratingCategories := make(map[string]struct{})

	for _, vec := range detection.Vectors {
		if vec.Score <= 0 {
			continue
		}
		activeVectors++
		totalVectorConfidence += vec.Confidence
		if vec.Confidence > maxVectorConfidence {
			maxVectorConfidence = vec.Confidence
		}
		if vec.Confidence >= 0.75 || vec.Score >= 0.50 {
			strongVectors++
			corroboratingCategories[vec.Category] = struct{}{}
		}
	}

	if activeVectors == 0 {
		return minFloat(1.0, detection.Score)
	}

	avgVectorConfidence := totalVectorConfidence / float64(activeVectors)
	confidence := 0.45*detection.Score + 0.35*avgVectorConfidence + 0.20*maxVectorConfidence

	if detection.IsBot {
		if len(corroboratingCategories) >= 2 {
			confidence += 0.10
		}
		if strongVectors >= 2 {
			confidence += 0.08
		}
		if maxVectorConfidence >= 0.85 {
			confidence += 0.12
		} else if maxVectorConfidence >= 0.70 {
			confidence += 0.10
		}
		if activeVectors >= 3 {
			confidence += 0.05
		}
		if activeVectors == 1 && detection.Score >= 0.45 {
			confidence += 0.08
		}
		if detection.Score >= 0.45 {
			confidence += 0.08
		}
	} else {
		maxAllowed := detection.Score + 0.05
		if activeVectors > 1 {
			maxAllowed += 0.05
		}
		confidence = minFloat(confidence, maxAllowed)
	}

	return minFloat(1.0, confidence)
}

func isHighSignalCategory(category string) bool {
	switch category {
	case string(VectorHTTP), string(VectorTLS), string(VectorNavigator), string(VectorIsomorphic),
		string(VectorAutomation), string(VectorBehavioral), string(VectorCrossVector),
		string(VectorFingerprintCoverage):
		return true
	default:
		return false
	}
}

func maxFloat(a, b float64) float64 {
	if a > b {
		return a
	}
	return b
}
