package main

import "testing"

func TestAppendAgentIdentityReportsRealBuildIdentity(t *testing.T) {
	originalVersion, originalDistribution, originalBuildID := Version, Distribution, BuildID
	t.Cleanup(func() {
		Version, Distribution, BuildID = originalVersion, originalDistribution, originalBuildID
	})
	Version = "2.3.0"
	Distribution = "forwardplus"
	BuildID = "0123456789ab"

	payload := map[string]any{}
	appendAgentIdentity(payload)

	if payload["agentVersion"] != "2.3.0" {
		t.Fatalf("agentVersion = %#v", payload["agentVersion"])
	}
	if payload["agentDistribution"] != "forwardplus" {
		t.Fatalf("agentDistribution = %#v", payload["agentDistribution"])
	}
	if payload["agentBuildId"] != "0123456789ab" {
		t.Fatalf("agentBuildId = %#v", payload["agentBuildId"])
	}
}
