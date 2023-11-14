package avalanche

import (
	tmmath "github.com/cometbft/cometbft/libs/math"
	"github.com/cometbft/cometbft/light"
)

// DefaultTrustLevel is the avalanche light client default trust level
var DefaultTrustLevel = NewFractionFromTm(light.DefaultTrustLevel)

// NewFractionFromTm returns a new Fraction instance from a tmmath.Fraction
func NewFractionFromTm(f tmmath.Fraction) Fraction {
	return Fraction{
		Numerator:   f.Numerator,
		Denominator: f.Denominator,
	}
}
