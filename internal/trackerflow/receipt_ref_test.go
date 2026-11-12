package trackerflow

import (
	"strings"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestAssessmentAcceptsCanonicalArtifactDigestReference(t *testing.T) {
	r := request()
	for _, reference := range []string{
		"sha256:validated",
		"worker-failure:dispatch-target-1",
		"https://gitlab.example/group/control/-/jobs/42/artifacts/file/.tracker-work/dispatch-1/output/cve-saga/iteration-1/output/cve-case/revision-0004.json#sha256=" + strings.Repeat("a", 64),
		"local-retained:cve-saga/iteration-1/output/cve-case/revision-0004.json#sha256=" + strings.Repeat("f", 64),
	} {
		assessment := Assessment{RequestDigest: r.Digest(), Outcome: "uncertain", ReceiptRef: reference}
		require.NoError(t, assessment.Validate(r), reference)
	}
}

func TestAssessmentRejectsUnsafeOrMalformedReceiptReferences(t *testing.T) {
	r := request()
	for _, reference := range []string{
		"", "https://gitlab.example/artifact\n", "https://gitlab.example/artifact\r", "artifact\tref", "artifact ref", "artifact\x00ref", "artifact<script>", "[artifact](https://example.org)", `artifact"quoted`,
		"artifact#sha256=", "artifact#sha256=" + strings.Repeat("a", 63), "artifact#sha256=" + strings.Repeat("A", 64), "artifact#sha256=" + strings.Repeat("z", 64), "artifact#other=" + strings.Repeat("a", 64), "artifact#sha256=" + strings.Repeat("a", 64) + "#extra", "artifact=" + strings.Repeat("a", 64), strings.Repeat("a", 2049),
	} {
		assessment := Assessment{RequestDigest: r.Digest(), Outcome: "uncertain", ReceiptRef: reference}
		require.Error(t, assessment.Validate(r), reference)
	}
}
