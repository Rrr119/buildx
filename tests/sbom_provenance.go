package tests

import (
	"encoding/json"
	"fmt"
	"os/exec"
	"strings"
	"testing"

	"github.com/containerd/continuity/fs/fstest"
	"github.com/docker/buildx/util/buildflags"
	"github.com/moby/buildkit/identity"
	"github.com/moby/buildkit/util/contentutil"
	"github.com/moby/buildkit/util/testutil"
	"github.com/moby/buildkit/util/testutil/integration"
	"github.com/pkg/errors"
	"github.com/stretchr/testify/require"
)

// sbomProvenancePlatforms is the three-platform matrix used to assert that
// every platform image carries its own SBOM and provenance attestation.
var sbomProvenancePlatforms = []string{"linux/amd64", "linux/arm64", "linux/riscv64"}

// inTotoStatement is the subset of an in-toto v1 statement that cosign
// download attestation emits for BuildKit attestations.
type inTotoStatement struct {
	Type          string `json:"_type"`
	PredicateType string `json:"predicateType"`
	Subject       []struct {
		Name   string `json:"name"`
		Digest struct {
			SHA256 string `json:"sha256"`
		} `json:"digest"`
	} `json:"subject"`
}

func init() {
	buildTests = append(buildTests, testBuildSBOMProvenanceMultiPlatform)
	bakeTests = append(bakeTests, testBakeSBOMProvenanceMultiPlatform)
}

func testBuildSBOMProvenanceMultiPlatform(t *testing.T, sb integration.Sandbox) {
	if isMobyWorker(sb) {
		t.Skip("attestations are not supported by the docker worker")
	}
	requireCosign(t)

	registry, err := sb.NewRegistry()
	if errors.Is(err, integration.ErrRequirements) {
		t.Skip(err.Error())
	}
	require.NoError(t, err)
	target := registry + "/buildx/sbom-provenance-build:" + identity.NewID()

	dir := createTestProject(t)

	out, err := buildCmd(sb, withArgs(
		fmt.Sprintf("--output=type=image,name=%s,push=true", target),
		"--sbom-provenance",
		"--platform="+strings.Join(sbomProvenancePlatforms, ","),
		dir,
	))
	require.NoError(t, err, string(out))

	requireSBOMProvenanceAttestations(t, sb, target)
}

func testBakeSBOMProvenanceMultiPlatform(t *testing.T, sb integration.Sandbox) {
	if isMobyWorker(sb) {
		t.Skip("attestations are not supported by the docker worker")
	}
	requireCosign(t)

	registry, err := sb.NewRegistry()
	if errors.Is(err, integration.ErrRequirements) {
		t.Skip(err.Error())
	}
	require.NoError(t, err)
	target := registry + "/buildx/sbom-provenance-bake:" + identity.NewID()

	dockerfile := []byte(`
FROM busybox:latest AS base
COPY foo /etc/foo
RUN cp /etc/foo /etc/bar

FROM scratch
COPY --from=base /etc/bar /bar
`)
	bakefile := fmt.Appendf(nil, `
target "default" {
  output    = ["type=image,name=%s,push=true"]
  platforms = [%q, %q, %q]
}
`, target, sbomProvenancePlatforms[0], sbomProvenancePlatforms[1], sbomProvenancePlatforms[2])
	dir := tmpdir(t,
		fstest.CreateFile("docker-bake.hcl", bakefile, 0600),
		fstest.CreateFile("Dockerfile", dockerfile, 0600),
		fstest.CreateFile("foo", []byte("foo"), 0600),
	)

	out, err := bakeCmd(sb, withDir(dir), withArgs("--sbom-provenance"))
	require.NoError(t, err, string(out))

	requireSBOMProvenanceAttestations(t, sb, target)
}

// requireSBOMProvenanceAttestations verifies with cosign that every platform
// image in the multi-platform index carries both an SPDX SBOM attestation and
// an in-toto SLSA provenance attestation bound to its own digest.
func requireSBOMProvenanceAttestations(t *testing.T, sb integration.Sandbox, target string) {
	t.Helper()

	desc, provider, err := contentutil.ProviderFromRef(sb.Context(), target)
	require.NoError(t, err)
	imgs, err := testutil.ReadImages(sb.Context(), provider, desc)
	require.NoError(t, err)

	var platformCount int
	for _, manifest := range imgs.Index.Manifests {
		if manifest.Platform == nil || manifest.Annotations["vnd.docker.reference.type"] == "attestation-manifest" {
			continue
		}
		platformCount++
		platform := manifest.Platform.OS + "/" + manifest.Platform.Architecture

		imageRef := target + "@" + string(manifest.Digest)

		sbomStmt := cosignDownloadAttestationByPredicate(t, sb, imageRef, buildflags.PredicateSPDX)
		require.Equal(t, buildflags.PredicateSPDX, sbomStmt.PredicateType,
			"SBOM attestation for %s must use the SPDX predicate", platform)
		requireAttestationSubject(t, sbomStmt, manifest.Digest.String(), platform)

		provStmt := cosignDownloadAttestationByPredicate(t, sb, imageRef, buildflags.PredicateSLSAProvenance)
		require.True(t,
			strings.HasPrefix(provStmt.PredicateType, "https://slsa.dev/provenance/"),
			"provenance attestation for %s must use an in-toto SLSA predicate, got %q",
			platform, provStmt.PredicateType)
		requireAttestationSubject(t, provStmt, manifest.Digest.String(), platform)
	}
	require.Len(t, platformCount, len(sbomProvenancePlatforms), "expected one image per platform")
}

func requireAttestationSubject(t *testing.T, stmt inTotoStatement, wantDigest string, platform string) {
	t.Helper()
	require.NotEmpty(t, stmt.Subject, "attestation for %s must have a subject", platform)
	require.Equal(t, wantDigest, "sha256:"+stmt.Subject[0].Digest.SHA256,
		"attestation for %s must be bound to its platform image digest", platform)
}

// cosignDownloadAttestationByPredicate runs `cosign download attestation`
// against the sandbox registry and returns the in-toto statement matching the
// given predicate type. BuildKit embeds both SBOM and provenance as in-toto
// attestations, so both are fetched through the same cosign subcommand.
func cosignDownloadAttestationByPredicate(t *testing.T, sb integration.Sandbox, ref string, predicateType string) inTotoStatement {
	t.Helper()

	cmd := cosignCmd(sb, "download", "attestation",
		"--allow-http-registry",
		"--predicate-type", predicateType, ref)
	dt, err := cmd.CombinedOutput()
	require.NoError(t, err, string(dt))

	// cosign emits one JSON document per matching attestation, separated by
	// newlines.
	var stmt inTotoStatement
	var matched bool
	for _, line := range strings.Split(strings.TrimSpace(string(dt)), "\n") {
		var candidate inTotoStatement
		require.NoError(t, json.Unmarshal([]byte(line), &candidate))
		if candidate.PredicateType == predicateType {
			stmt = candidate
			matched = true
			break
		}
	}
	require.True(t, matched, "no attestation with predicate %q found for %s", predicateType, ref)
	require.Equal(t, "https://in-toto.io/Statement/v1", stmt.Type)
	return stmt
}

func requireCosign(t *testing.T) {
	t.Helper()
	if _, err := exec.LookPath("cosign"); err != nil {
		t.Skip("cosign binary not found in PATH")
	}
}

func cosignCmd(sb integration.Sandbox, args ...string) *exec.Cmd {
	cmd := exec.Command("cosign", args...)
	cmd.Env = append(cmd.Environ(),
		// keep cosign fully non-interactive against the local registry.
		"COSIGN_YES=true",
	)
	if context := sb.DockerAddress(); context != "" {
		cmd.Env = append(cmd.Env, "DOCKER_CONTEXT="+context)
	}
	return cmd
}
