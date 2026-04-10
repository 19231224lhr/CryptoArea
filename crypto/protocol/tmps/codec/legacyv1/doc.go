// Package legacyv1 provides the first stable TMPS compatibility codec.
//
// The codec uses canonical JSON for deterministic output and represents curve
// elements as lowercase 0x-prefixed hex strings while scalars stay in decimal
// string form.
package legacyv1
