import assert from "node:assert/strict";
import test from "node:test";
import { ENV } from "./env";
import { withGithubAuth } from "./githubAuth";

test("adds the private repository token only to official GitHub hosts", () => {
  const previous = ENV.githubToken;
  ENV.githubToken = "unit-test-token";
  try {
    const github = new Headers(withGithubAuth("https://api.github.com/repos/wzwys9/Forwardplus", {}).headers);
    const accelerator = new Headers(withGithubAuth("https://mirror.example.com/https://api.github.com/repos/wzwys9/Forwardplus", {}).headers);
    const unrelated = new Headers(withGithubAuth("https://example.com/download", {}).headers);
    const plaintext = new Headers(withGithubAuth("http://api.github.com/repos/wzwys9/Forwardplus", {}).headers);
    const nonstandardPort = new Headers(withGithubAuth("https://api.github.com:8443/repos/wzwys9/Forwardplus", {}).headers);

    assert.equal(github.get("Authorization"), "Bearer unit-test-token");
    assert.equal(accelerator.get("Authorization"), null);
    assert.equal(unrelated.get("Authorization"), null);
    assert.equal(plaintext.get("Authorization"), null);
    assert.equal(nonstandardPort.get("Authorization"), null);
  } finally {
    ENV.githubToken = previous;
  }
});
