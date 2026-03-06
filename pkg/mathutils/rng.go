// Package mathutils provides mathematical and statistical utility functions.
package mathutils

import (
	"math"
	"math/rand/v2"
)

// RNG wraps a random number generator with additional utility methods.
type RNG struct {
	src *rand.Rand
}

// NewRNG creates a new RNG with the given source.
func NewRNG(src rand.Source) *RNG {
	return &RNG{src: rand.New(src)}
}

// NewDefaultRNG creates a new RNG with a default source.
func NewDefaultRNG() *RNG {
	return &RNG{src: rand.New(rand.NewPCG(rand.Uint64(), rand.Uint64()))}
}

// NewSeededRNG creates a new RNG with a seed for reproducibility.
func NewSeededRNG(seed uint64) *RNG {
	return &RNG{src: rand.New(rand.NewPCG(seed, seed+1))}
}

// Intn returns a random integer in [0, n).
func (r *RNG) Intn(n int) int {
	return r.src.IntN(n)
}

// Float64 returns a random float64 in [0.0, 1.0).
func (r *RNG) Float64() float64 {
	return r.src.Float64()
}

// FloatBetween returns a random float64 in [min, max).
func (r *RNG) FloatBetween(min, max float64) float64 {
	return min + r.src.Float64()*(max-min)
}

// Gaussian returns a random value from a Gaussian (normal) distribution
// with the given mean and standard deviation using the Box-Muller transform.
func (r *RNG) Gaussian(mean, stddev float64) float64 {
	u1 := 1.0 - r.src.Float64() // Avoid 0
	u2 := r.src.Float64()

	mag := stddev * math.Sqrt(-2.0*math.Log(u1))
	z0 := mag * math.Cos(2.0*math.Pi*u2)

	return mean + z0
}

// LogNormal returns a random value from a log-normal distribution.
// The parameters mean and stddev are for the underlying normal distribution.
func (r *RNG) LogNormal(mean, stddev float64) float64 {
	return math.Exp(r.Gaussian(mean, stddev))
}

// Choice selects a random element from a slice.
// Returns the zero value if the slice is empty.
func Choice[T any](r *RNG, choices []T) T {
	var zero T
	if len(choices) == 0 {
		return zero
	}
	return choices[r.Intn(len(choices))]
}

// Shuffle randomly shuffles a slice in place.
func Shuffle[T any](r *RNG, items []T) {
	r.src.Shuffle(len(items), func(i, j int) {
		items[i], items[j] = items[j], items[i]
	})
}

// Sample randomly selects n elements from a slice without replacement.
// If n > len(items), returns all items shuffled.
func Sample[T any](r *RNG, items []T, n int) []T {
	if n >= len(items) {
		result := make([]T, len(items))
		copy(result, items)
		Shuffle(r, result)
		return result
	}

	result := make([]T, n)
	indices := r.src.Perm(len(items))
	for i := 0; i < n; i++ {
		result[i] = items[indices[i]]
	}
	return result
}

// WeightedChoice makes a weighted random selection from choices.
// Weights must be non-negative. Returns -1 if all weights are 0 or slice is empty.
func (r *RNG) WeightedChoice(weights []float64) int {
	if len(weights) == 0 {
		return -1
	}

	var total float64
	for _, w := range weights {
		if w > 0 {
			total += w
		}
	}

	if total == 0 {
		return -1
	}

	target := r.Float64() * total
	var cumulative float64
	for i, w := range weights {
		if w > 0 {
			cumulative += w
			if cumulative >= target {
				return i
			}
		}
	}

	// Fallback for floating point precision issues
	return len(weights) - 1
}

// Jitter adds random jitter to a value.
// The jitter amount is +/- (value * factor).
func (r *RNG) Jitter(value, factor float64) float64 {
	if factor <= 0 {
		return value
	}
	jitter := r.FloatBetween(-factor, factor)
	return value * (1 + jitter)
}

// JitterInt adds random integer jitter to a value.
// The jitter is in the range [-maxJitter, maxJitter].
func (r *RNG) JitterInt(value, maxJitter int) int {
	if maxJitter <= 0 {
		return value
	}
	return value + r.Intn(2*maxJitter+1) - maxJitter
}
