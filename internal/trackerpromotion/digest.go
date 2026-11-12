package trackerpromotion

import (
	"crypto/sha256"
	"encoding/hex"
)

func rawDigest(raw []byte) string { h := sha256.Sum256(raw); return hex.EncodeToString(h[:]) }
