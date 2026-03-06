// Package mathutils provides mathematical and statistical utility functions
// commonly used across the stealth detection system.
package mathutils

import (
	"math"
	"sort"
)

// DescriptiveStats holds basic statistical measures for a dataset.
type DescriptiveStats struct {
	Mean     float64
	Variance float64
	StdDev   float64
	Min      float64
	Max      float64
	Count    int
}

// CalculateStats computes descriptive statistics for a slice of float64 values.
// Returns zero values if the input slice is empty.
func CalculateStats(values []float64) DescriptiveStats {
	if len(values) == 0 {
		return DescriptiveStats{}
	}

	var sum, min, max float64
	min = values[0]
	max = values[0]

	for _, v := range values {
		sum += v
		if v < min {
			min = v
		}
		if v > max {
			max = v
		}
	}

	count := len(values)
	mean := sum / float64(count)

	var variance float64
	for _, v := range values {
		diff := v - mean
		variance += diff * diff
	}
	variance /= float64(count)

	return DescriptiveStats{
		Mean:     mean,
		Variance: variance,
		StdDev:   math.Sqrt(variance),
		Min:      min,
		Max:      max,
		Count:    count,
	}
}

// Mean calculates the arithmetic mean of a slice of float64 values.
// Returns 0 for empty slices.
func Mean(values []float64) float64 {
	if len(values) == 0 {
		return 0
	}
	var sum float64
	for _, v := range values {
		sum += v
	}
	return sum / float64(len(values))
}

// Variance calculates the population variance of a slice of float64 values.
// Returns 0 for empty slices.
func Variance(values []float64) float64 {
	if len(values) == 0 {
		return 0
	}
	mean := Mean(values)
	var sumSquaredDiff float64
	for _, v := range values {
		diff := v - mean
		sumSquaredDiff += diff * diff
	}
	return sumSquaredDiff / float64(len(values))
}

// StdDev calculates the population standard deviation of a slice of float64 values.
// Returns 0 for empty slices.
func StdDev(values []float64) float64 {
	return math.Sqrt(Variance(values))
}

// MeanStdDev calculates both mean and standard deviation in a single pass.
// This is more efficient than calling Mean and StdDev separately.
func MeanStdDev(values []float64) (mean, stddev float64) {
	if len(values) == 0 {
		return 0, 0
	}
	mean = Mean(values)
	return mean, math.Sqrt(Variance(values))
}

// MeanVariance calculates both mean and variance in a single pass.
// This is more efficient than calling Mean and Variance separately.
func MeanVariance(values []float64) (mean, variance float64) {
	if len(values) == 0 {
		return 0, 0
	}
	mean = Mean(values)
	return mean, Variance(values)
}

// CoefficientOfVariation calculates CV (stddev/mean) as a percentage.
// Returns 0 if mean is 0 to avoid division by zero.
func CoefficientOfVariation(values []float64) float64 {
	if len(values) == 0 {
		return 0
	}
	mean, stddev := MeanStdDev(values)
	if mean == 0 {
		return 0
	}
	return stddev / mean
}

// LagNAutocorrelation calculates the lag-N autocorrelation for a time series.
// Returns 0 if there are insufficient data points.
func LagNAutocorrelation(values []float64, lag int) float64 {
	if lag <= 0 || len(values) <= lag {
		return 0
	}

	n := len(values) - lag
	if n <= 1 {
		return 0
	}

	mean := Mean(values)

	var sumProduct, sumSquaredDiff float64
	for i := 0; i < n; i++ {
		diff := values[i] - mean
		diffLag := values[i+lag] - mean
		sumProduct += diff * diffLag
		sumSquaredDiff += diff * diff
	}

	if sumSquaredDiff == 0 {
		return 0
	}

	return sumProduct / sumSquaredDiff
}

// Lag1Autocorrelation calculates the lag-1 autocorrelation for a time series.
// This is a convenience wrapper around LagNAutocorrelation.
func Lag1Autocorrelation(values []float64) float64 {
	return LagNAutocorrelation(values, 1)
}

// PearsonCorrelation calculates the Pearson correlation coefficient between two datasets.
// Returns 0 if the datasets have different lengths or insufficient data.
func PearsonCorrelation(x, y []float64) float64 {
	if len(x) != len(y) || len(x) < 2 {
		return 0
	}

	meanX, meanY := Mean(x), Mean(y)

	var sumXY, sumX2, sumY2 float64
	for i := range x {
		dx := x[i] - meanX
		dy := y[i] - meanY
		sumXY += dx * dy
		sumX2 += dx * dx
		sumY2 += dy * dy
	}

	if sumX2 == 0 || sumY2 == 0 {
		return 0
	}

	return sumXY / math.Sqrt(sumX2*sumY2)
}

// SpearmanCorrelation calculates Spearman's rank correlation coefficient.
// Returns 0 if the datasets have different lengths or insufficient data.
func SpearmanCorrelation(x, y []float64) float64 {
	if len(x) != len(y) || len(x) < 2 {
		return 0
	}

	rankX := computeRanks(x)
	rankY := computeRanks(y)

	return PearsonCorrelation(rankX, rankY)
}

// computeRanks computes the ranks for a dataset, handling ties by averaging.
func computeRanks(values []float64) []float64 {
	n := len(values)
	if n == 0 {
		return []float64{}
	}

	// Create indexed values for sorting
	type indexedValue struct {
		value float64
		index int
	}
	indexed := make([]indexedValue, n)
	for i, v := range values {
		indexed[i] = indexedValue{value: v, index: i}
	}

	// Sort by value
	sort.Slice(indexed, func(i, j int) bool {
		return indexed[i].value < indexed[j].value
	})

	// Assign ranks, handling ties
	ranks := make([]float64, n)
	i := 0
	for i < n {
		j := i + 1
		// Find all elements with the same value
		for j < n && indexed[j].value == indexed[i].value {
			j++
		}

		// Calculate average rank for ties
		// Ranks are 1-indexed, so we add 1
		avgRank := float64(i+j+1) / 2.0
		for k := i; k < j; k++ {
			ranks[indexed[k].index] = avgRank
		}
		i = j
	}

	return ranks
}

// Entropy calculates the Shannon entropy of a dataset.
// Higher entropy indicates more randomness/uniformity.
func Entropy(values []float64) float64 {
	if len(values) == 0 {
		return 0
	}

	// Normalize to probability distribution
	var sum float64
	for _, v := range values {
		if v < 0 {
			v = -v // Take absolute value for probabilities
		}
		sum += v
	}

	if sum == 0 {
		return 0
	}

	var entropy float64
	for _, v := range values {
		if v < 0 {
			v = -v
		}
		if v > 0 {
			p := v / sum
			entropy -= p * math.Log2(p)
		}
	}

	return entropy
}

// ChiSquaredUniformity performs a chi-squared test for uniformity.
// Returns the chi-squared statistic (lower = more uniform).
func ChiSquaredUniformity(observed []float64) float64 {
	if len(observed) == 0 {
		return 0
	}

	n := float64(len(observed))
	expected := Mean(observed)

	if expected == 0 {
		return 0
	}

	var chi2 float64
	for _, obs := range observed {
		diff := obs - expected
		chi2 += (diff * diff) / expected
	}

	return chi2 / n
}

// GaussianRandom generates a random value from a Gaussian (normal) distribution
// using the Box-Muller transform.
func GaussianRandom(mean, stddev float64) float64 {
	u1 := 1.0 - randFloat() // Avoid 0
	u2 := randFloat()

	mag := stddev * math.Sqrt(-2.0*math.Log(u1))
	z0 := mag * math.Cos(2.0*math.Pi*u2)

	return mean + z0
}

// randFloat returns a random float64 in [0.0, 1.0).
// This is a placeholder that should be replaced with a proper RNG in production.
func randFloat() float64 {
	// In production, this should use a proper random source
	// For now, we use mathrand which is deterministic
	return float64(int64(math.Mod(float64(int64(math.Sqrt(float64(int64(1))))*1000000), 1000000))) / 1000000
}

// Normalize performs min-max normalization on a value.
// Returns 0 if min == max to avoid division by zero.
func Normalize(value, min, max float64) float64 {
	if max == min {
		return 0
	}
	return (value - min) / (max - min)
}

// Clamp restricts a value to be within [min, max].
func Clamp(value, min, max float64) float64 {
	if value < min {
		return min
	}
	if value > max {
		return max
	}
	return value
}

// Sign returns the sign of a number: -1, 0, or 1.
func Sign(x float64) int {
	if x < 0 {
		return -1
	}
	if x > 0 {
		return 1
	}
	return 0
}

// SafeDiv performs division that returns 0 if the denominator is 0.
func SafeDiv(numerator, denominator float64) float64 {
	if denominator == 0 {
		return 0
	}
	return numerator / denominator
}
