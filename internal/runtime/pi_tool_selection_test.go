package runtime

import (
	"encoding/json"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestPiExactNativeTools(t *testing.T) {
	t.Parallel()
	tools, invalid := piToolsFor([]string{"cve", "Read", "cve", "cve*", "mcp__*", "bad,name", "bad/name"})
	assert.Equal(t, []string{"cve", "read"}, tools)
	assert.Equal(t, []string{"cve*", "mcp__*", "bad,name", "bad/name"}, invalid)
	assert.Equal(t, []string{"cve"}, piNativeToolsFor([]string{"Bash", "Skill", "Agent", "cve", "cve", "cve*"}))
	child, unsupported := piPersonaTools([]string{"Read", "cve"})
	assert.Equal(t, []string{"read"}, child)
	assert.Equal(t, []string{"cve"}, unsupported, "native persona tools fail explicitly until child loading is supported")
}

func TestPiToolSelectorBootstrap(t *testing.T) {
	work := t.TempDir()
	store := filepath.Join(work, "store")
	fakeOpenshellPi(t, filepath.Join(work, "openshell.log"), store, "/dev/null")
	input := bootstrapInput{sandboxName: "native-tools-test", agentName: "assess", agentPath: writeAgentFile(t, "---\nname: assess\ntools: [cve]\n---\nAssess the admitted target.")}
	require.NoError(t, PiRuntime{}.Bootstrap(input))
	var manifest piManifest
	require.NoError(t, json.Unmarshal(storedUpload(t, store, PiRuntime{}.piManifestPath()), &manifest))
	assert.True(t, manifest.StrictTools)
	assert.Equal(t, []string{"cve"}, manifest.NativeTools)
	assert.Equal(t, []string{"cve"}, manifest.Tools)
	assert.Equal(t, piToolSelectionExtensionJS, storedUpload(t, store, PiRuntime{}.ConfigDir()+"/"+piToolSelectionExtensionFile))
	input.agentPath = writeAgentFile(t, "---\nname: assess\ntools: ['cve*']\n---\nAssess.")
	require.ErrorContains(t, PiRuntime{}.Bootstrap(input), "exact names")
}

func TestPiToolSelectorGuard(t *testing.T) {
	t.Parallel()
	file := filepath.Join(t.TempDir(), "selector.js")
	guard := piToolSelectionGuard(file)
	for _, bytes := range [][]byte{[]byte("modified"), piToolSelectionExtensionJS} {
		require.NoError(t, os.WriteFile(file, bytes, 0o600))
		err := exec.Command("sh", "-c", guard).Run()
		if string(bytes) == string(piToolSelectionExtensionJS) {
			require.NoError(t, err)
		} else {
			var exit *exec.ExitError
			require.ErrorAs(t, err, &exit)
			assert.Equal(t, piToolSelectionExit, exit.ExitCode())
		}
	}
	require.NoError(t, os.Remove(file))
	require.Error(t, exec.Command("sh", "-c", guard).Run())
}

func TestBuildPiRunCommand_StrictNativeSelection(t *testing.T) {
	// Activation derives from the explicit list, not an editable boolean.
	m := &piManifest{NativeTools: []string{"cve"}, Tools: []string{"cve"}}
	ext := piManifestExtension{Name: "native", Path: "/sandbox/pi-config/extensions/native"}
	cmd := buildPiRunCommand(piTestParams(), m, []piManifestExtension{ext}, "manifest-digest")
	assert.Contains(t, cmd, "--tools 'cve'")
	assert.Contains(t, cmd, piToolSelectionGuard(PiRuntime{}.ConfigDir()+"/"+piToolSelectionExtensionFile))
	assert.Greater(t, strings.Index(cmd, "-e '/sandbox/pi-config/fullsend-tools.js'"), strings.Index(cmd, "-e '/sandbox/pi-config/extensions/native'"))
	assert.NotContains(t, cmd, "--no-builtin-tools")
}
