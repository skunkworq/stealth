package challenge

import (
	"fmt"
	"math"
	"sort"
)

// formatFloat formats a float64 to 6 decimal places.
func formatFloat(f float64) string {
	return fmt.Sprintf("%.6f", f)
}

// meanStddev computes mean and standard deviation.
func meanStddev(values []float64) (float64, float64) {
	if len(values) == 0 {
		return 0, 0
	}

	var sum float64
	for _, v := range values {
		sum += v
	}
	mean := sum / float64(len(values))

	var variance float64
	for _, v := range values {
		diff := v - mean
		variance += diff * diff
	}
	variance /= float64(len(values))

	return mean, math.Sqrt(variance)
}

// meanVariance computes mean and variance.
func meanVariance(values []float64) (float64, float64) {
	if len(values) == 0 {
		return 0, 0
	}

	var sum float64
	for _, v := range values {
		sum += v
	}
	mean := sum / float64(len(values))

	var variance float64
	for _, v := range values {
		diff := v - mean
		variance += diff * diff
	}
	variance /= float64(len(values))

	return mean, variance
}

// calculateIntervalEntropy computes Shannon entropy of intervals between timestamps.
// Low entropy = uniform intervals (bot). High entropy = random noise injection.
func calculateIntervalEntropy(timestamps []int64) float64 {
	if len(timestamps) < 2 {
		return 0
	}

	intervals := make([]float64, 0, len(timestamps)-1)
	for i := 1; i < len(timestamps); i++ {
		diff := float64(timestamps[i] - timestamps[i-1])
		if diff > 0 {
			intervals = append(intervals, diff)
		}
	}

	if len(intervals) == 0 {
		return 0
	}

	// Bin intervals into buckets for entropy calculation
	numBins := 10
	minVal, maxVal := intervals[0], intervals[0]
	for _, v := range intervals {
		if v < minVal {
			minVal = v
		}
		if v > maxVal {
			maxVal = v
		}
	}

	if maxVal == minVal {
		return 0 // All identical = zero entropy
	}

	binWidth := (maxVal - minVal) / float64(numBins)
	bins := make([]int, numBins)
	for _, v := range intervals {
		bin := int((v - minVal) / binWidth)
		if bin >= numBins {
			bin = numBins - 1
		}
		bins[bin]++
	}

	// Shannon entropy
	total := float64(len(intervals))
	entropy := 0.0
	for _, count := range bins {
		if count > 0 {
			p := float64(count) / total
			entropy -= p * math.Log2(p)
		}
	}

	return entropy
}

// chiSquaredUniformity computes a chi-squared statistic testing whether values
// follow a uniform distribution. Low values indicate suspiciously uniform data.
func chiSquaredUniformity(values []float64, numBins int) float64 {
	if len(values) < numBins {
		return 100.0 // Not enough data, return high (non-uniform)
	}

	minVal, maxVal := values[0], values[0]
	for _, v := range values[1:] {
		if v < minVal {
			minVal = v
		}
		if v > maxVal {
			maxVal = v
		}
	}

	if maxVal == minVal {
		return 0.0 // All identical = perfectly uniform
	}

	binWidth := (maxVal - minVal) / float64(numBins)
	bins := make([]int, numBins)
	for _, v := range values {
		bin := int((v - minVal) / binWidth)
		if bin >= numBins {
			bin = numBins - 1
		}
		bins[bin]++
	}

	expected := float64(len(values)) / float64(numBins)
	chiSq := 0.0
	for _, count := range bins {
		diff := float64(count) - expected
		chiSq += (diff * diff) / expected
	}

	return chiSq
}

// pearsonCorrelation computes the Pearson product-moment correlation coefficient
// between two sequences. Returns a value in [-1, 1].
func pearsonCorrelation(x, y []float64) float64 {
	n := len(x)
	if n != len(y) || n < 2 {
		return 0
	}

	var sumX, sumY, sumXY, sumX2, sumY2 float64
	for i := 0; i < n; i++ {
		sumX += x[i]
		sumY += y[i]
		sumXY += x[i] * y[i]
		sumX2 += x[i] * x[i]
		sumY2 += y[i] * y[i]
	}

	nf := float64(n)
	num := nf*sumXY - sumX*sumY
	den := math.Sqrt((nf*sumX2 - sumX*sumX) * (nf*sumY2 - sumY*sumY))
	if den == 0 {
		return 0
	}
	return num / den
}

// spearmanCorrelation computes Spearman's rank correlation coefficient between
// two sequences. Values near +1 or -1 indicate monotonic relationship.
// Values near 0 indicate no monotonic relationship (independence).
func spearmanCorrelation(x, y []float64) float64 {
	n := len(x)
	if n != len(y) || n < 3 {
		return 0
	}

	rankX := computeRanks(x)
	rankY := computeRanks(y)

	// Pearson correlation of ranks
	var sumXY, sumX, sumY, sumX2, sumY2 float64
	for i := 0; i < n; i++ {
		sumXY += rankX[i] * rankY[i]
		sumX += rankX[i]
		sumY += rankY[i]
		sumX2 += rankX[i] * rankX[i]
		sumY2 += rankY[i] * rankY[i]
	}

	nf := float64(n)
	num := nf*sumXY - sumX*sumY
	den := math.Sqrt((nf*sumX2 - sumX*sumX) * (nf*sumY2 - sumY*sumY))
	if den == 0 {
		return 0
	}
	return num / den
}

// computeRanks assigns ranks to values (1-based, ascending).
func computeRanks(values []float64) []float64 {
	n := len(values)
	type indexedValue struct {
		val float64
		idx int
	}
	sorted := make([]indexedValue, n)
	for i, v := range values {
		sorted[i] = indexedValue{v, i}
	}
	sort.Slice(sorted, func(i, j int) bool { return sorted[i].val < sorted[j].val })

	result := make([]float64, n)
	for rank, s := range sorted {
		result[s.idx] = float64(rank + 1)
	}
	return result
}

// lagNAutocorrelation computes the autocorrelation of a sequence at arbitrary lag.
// Returns 0 if insufficient data (need at least lag+2 values).
func lagNAutocorrelation(values []float64, lag int) float64 {
	n := len(values)
	if n < lag+2 {
		return 0
	}

	mean := 0.0
	for _, v := range values {
		mean += v
	}
	mean /= float64(n)

	var num, den float64
	for i := 0; i < n-lag; i++ {
		num += (values[i] - mean) * (values[i+lag] - mean)
	}
	for i := 0; i < n; i++ {
		den += (values[i] - mean) * (values[i] - mean)
	}

	if den == 0 {
		return 0
	}
	return num / den
}

// lag1Autocorrelation computes the lag-1 autocorrelation of a sequence.
// Positive values indicate temporal clustering (consecutive values are similar).
// Zero indicates independence. Negative indicates alternating pattern.
func lag1Autocorrelation(values []float64) float64 {
	return lagNAutocorrelation(values, 1)
}
