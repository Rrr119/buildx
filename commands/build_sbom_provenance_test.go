package commands

import (
	"testing"

	"github.com/docker/buildx/util/buildflags"
	"github.com/stretchr/testify/require"
)

func TestBuildOptionsSBOMProvenance(t *testing.T) {
	t.Run("flag adds SPDX SBOM and in-toto provenance", func(t *testing.T) {
		o := buildOptions{sbomProvenance: true}
		opts, err := o.toOptions()
		require.NoError(t, err)

		m := opts.Attests.ToMap()
		require.Len(t, m, 2)
		require.Contains(t, *m[buildflags.AttestationTypeSBOM], "type=sbom")
		require.Contains(t, *m[buildflags.AttestationTypeSBOM], "generator="+buildflags.DefaultSBOMGenerator)
		require.Equal(t, "type=provenance,mode=max", *m[buildflags.AttestationTypeProvenance])
	})

	t.Run("explicit attestations take precedence", func(t *testing.T) {
		o := buildOptions{
			sbomProvenance: true,
			sbom:           "generator=custom/sbom:v9",
		}
		opts, err := o.toOptions()
		require.NoError(t, err)

		m := opts.Attests.ToMap()
		require.Equal(t, "type=sbom,generator=custom/sbom:v9", *m[buildflags.AttestationTypeSBOM])
		require.Equal(t, "type=provenance,mode=max", *m[buildflags.AttestationTypeProvenance])
	})

	t.Run("flag disabled leaves attestations untouched", func(t *testing.T) {
		o := buildOptions{sbom: "true"}
		opts, err := o.toOptions()
		require.NoError(t, err)

		m := opts.Attests.ToMap()
		require.Len(t, m, 1)
		require.Contains(t, *m[buildflags.AttestationTypeSBOM], "type=sbom")
		_, hasProv := m[buildflags.AttestationTypeProvenance]
		require.False(t, hasProv)
	})
}
