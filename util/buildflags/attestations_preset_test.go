package buildflags

import (
	"testing"

	"github.com/stretchr/testify/require"
)

func TestSBOMAttestation(t *testing.T) {
	t.Run("default generator", func(t *testing.T) {
		require.Equal(t,
			"type=sbom,generator="+DefaultSBOMGenerator,
			SBOMAttestation(""))
	})
	t.Run("custom generator", func(t *testing.T) {
		require.Equal(t,
			"type=sbom,generator=registry.example.org/sbom-gen:v1",
			SBOMAttestation("registry.example.org/sbom-gen:v1"))
	})
}

func TestProvenanceAttestation(t *testing.T) {
	t.Run("default mode", func(t *testing.T) {
		require.Equal(t, "type=provenance,mode=max", ProvenanceAttestation(""))
	})
	t.Run("explicit mode", func(t *testing.T) {
		require.Equal(t, "type=provenance,mode=min", ProvenanceAttestation("min"))
	})
}

func TestSecurityAttestations(t *testing.T) {
	t.Run("empty input adds both SPDX SBOM and provenance", func(t *testing.T) {
		got, err := SecurityAttestations(nil)
		require.NoError(t, err)
		require.Len(t, got, 2)

		m := got.ToMap()
		require.Contains(t, m, AttestationTypeSBOM)
		require.Contains(t, m, AttestationTypeProvenance)

		sbom := *m[AttestationTypeSBOM]
		require.Contains(t, sbom, "type=sbom")
		require.Contains(t, sbom, "generator="+DefaultSBOMGenerator)

		prov := *m[AttestationTypeProvenance]
		require.Contains(t, prov, "type=provenance")
		require.Contains(t, prov, "mode=max")
	})

	t.Run("user SBOM is preserved", func(t *testing.T) {
		user, err := ParseAttests([]string{"type=sbom,generator=custom/sbom:v2"})
		require.NoError(t, err)

		got, err := SecurityAttestations(user)
		require.NoError(t, err)

		m := got.ToMap()
		require.Equal(t, "type=sbom,generator=custom/sbom:v2", *m[AttestationTypeSBOM])
		require.Contains(t, *m[AttestationTypeProvenance], "type=provenance")
	})

	t.Run("user provenance is preserved", func(t *testing.T) {
		user, err := ParseAttests([]string{"type=provenance,mode=min"})
		require.NoError(t, err)

		got, err := SecurityAttestations(user)
		require.NoError(t, err)

		m := got.ToMap()
		require.Equal(t, "type=provenance,mode=min", *m[AttestationTypeProvenance])
		require.Contains(t, *m[AttestationTypeSBOM], "type=sbom")
	})

	t.Run("disabled attestations stay disabled", func(t *testing.T) {
		user, err := ParseAttests([]string{"type=sbom,disabled=true"})
		require.NoError(t, err)

		got, err := SecurityAttestations(user)
		require.NoError(t, err)

		m := got.ToMap()
		require.Nil(t, m[AttestationTypeSBOM])
		require.Contains(t, *m[AttestationTypeProvenance], "type=provenance")
	})

	t.Run("both provided returns normalized input", func(t *testing.T) {
		user, err := ParseAttests([]string{
			"type=provenance,mode=min",
			"type=sbom,generator=custom/sbom:v2",
		})
		require.NoError(t, err)

		got, err := SecurityAttestations(user)
		require.NoError(t, err)

		m := got.ToMap()
		require.Len(t, m, 2)
		require.Equal(t, "type=provenance,mode=min", *m[AttestationTypeProvenance])
		require.Equal(t, "type=sbom,generator=custom/sbom:v2", *m[AttestationTypeSBOM])
	})

	t.Run("predicate constants are in-toto URIs", func(t *testing.T) {
		require.Equal(t, "https://spdx.dev/Document", PredicateSPDX)
		require.Equal(t, "https://slsa.dev/provenance/v1", PredicateSLSAProvenance)
	})
}
