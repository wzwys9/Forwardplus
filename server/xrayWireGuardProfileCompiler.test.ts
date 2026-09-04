import assert from "node:assert/strict";
import test from "node:test";

import {
  accessSecretPolicyForCredentialType,
  parseStoredXrayAccessSettings,
} from "../shared/xrayAccess";
import {
  findAvailableXrayProfileById,
  findKnownXrayProfileById,
  resolveStoredXrayInboundDefinition,
} from "../shared/xrayProfiles";
import { generateDeterministicXrayConfig, type XrayConfigInboundInput } from "./xrayConfigGenerator";
import {
  createXraySecretKeyring,
  decryptXraySecret,
  encryptXraySecret,
  xrayAccessSecretContext,
  xrayInboundSecretContext,
} from "./xraySecretCrypto";
import {
  buildXrayWireGuardClientConfig,
  deriveXrayWireGuardPublicKey,
  generateXrayWireGuardKeyPair,
  generateXrayWireGuardPreSharedKey,
} from "./xrayWireGuard";

function privateKey(fill: number): string {
  const bytes = Buffer.alloc(32, fill);
  bytes[0] &= 248;
  bytes[31] &= 127;
  bytes[31] |= 64;
  return bytes.toString("base64");
}

test("WireGuard is available after canonical secrets compile to one fixed UDP inbound and standard client config", () => {
  assert.deepEqual(findKnownXrayProfileById("WIREGUARD_UDP_NONE"), {
    id: "WIREGUARD_UDP_NONE",
    status: "AVAILABLE",
    protocol: "WIREGUARD",
    transport: "NONE",
    security: "NONE",
    clientFlow: "NONE",
    listenerNetworks: ["UDP"],
    clientCredentialType: "WIREGUARD_PEER",
    shareFormat: "WIREGUARD_CONFIG",
    testedCoreVersion: "v26.3.27",
    advisoryCode: "WIREGUARD_BLOCKING_RISK",
  });
  assert.equal(findAvailableXrayProfileById("WIREGUARD_UDP_NONE")?.id, "WIREGUARD_UDP_NONE");
  assert.deepEqual(resolveStoredXrayInboundDefinition({
    protocol: "wireguard",
    transport: "none",
    security: "none",
    clientFlow: "",
    profileId: "WIREGUARD_UDP_NONE",
    specVersion: 1,
    specJson: "{}",
  })?.spec, {});

  assert.deepEqual(parseStoredXrayAccessSettings({
    credentialType: "WIREGUARD_PEER",
    settingsJson: JSON.stringify({ schemaVersion: 2, address: "10.0.0.2/32" }),
  }), {
    credentialType: "WIREGUARD_PEER",
    schemaVersion: 2,
    address: "10.0.0.2/32",
  });
  assert.deepEqual(parseStoredXrayAccessSettings({
    credentialType: "WIREGUARD_PEER",
    settingsJson: JSON.stringify({ schemaVersion: 1 }),
  }), { credentialType: "WIREGUARD_PEER", schemaVersion: 1 });
  assert.equal(parseStoredXrayAccessSettings({
    credentialType: "WIREGUARD_PEER",
    settingsJson: JSON.stringify({ schemaVersion: 2, address: "10.0.0.1/32" }),
  }), null);
  assert.deepEqual(accessSecretPolicyForCredentialType("WIREGUARD_PEER"), {
    required: ["PRIVATE_KEY", "PRE_SHARED_KEY"],
    optional: [],
  });

  const generatedPair = generateXrayWireGuardKeyPair();
  const generatedPrivateBytes = Buffer.from(generatedPair.privateKey, "base64");
  assert.equal(generatedPrivateBytes.length, 32);
  assert.equal(generatedPrivateBytes[0] & 7, 0);
  assert.equal(generatedPrivateBytes[31] & 128, 0);
  assert.equal(generatedPrivateBytes[31] & 64, 64);
  assert.equal(generatedPair.publicKey, deriveXrayWireGuardPublicKey(generatedPair.privateKey));
  assert.equal(
    deriveXrayWireGuardPublicKey(Buffer.from(
      "70076d0a7318a57d3c16c17251b26645df4c2f87ebc0992ab177fba51db92c6a",
      "hex",
    ).toString("base64")),
    Buffer.from("8520f0098930a754748b7ddcb43ef75a0dbf3a0d26381af4eba4a98eaa9b4e6a", "hex").toString("base64"),
  );
  const generatedPsk = generateXrayWireGuardPreSharedKey();
  assert.equal(Buffer.from(generatedPsk, "base64").length, 32);
  assert.match(generatedPsk, /^[A-Za-z0-9+/]{43}=$/);

  const serverPrivateKey = privateKey(0x11);
  const firstPrivateKey = privateKey(0x22);
  const secondPrivateKey = privateKey(0x33);
  const firstPsk = Buffer.alloc(32, 0x44).toString("base64");
  const secondPsk = Buffer.alloc(32, 0x55).toString("base64");
  const keyring = createXraySecretKeyring({ currentKeyId: "1", keys: { "1": Buffer.alloc(32, 0x66) } });
  const serverContext = xrayInboundSecretContext("forwardx-wireguard-201", "PRIVATE_KEY");
  const peerContext = xrayAccessSecretContext("forwardx-wireguard-peer-2011", "PRIVATE_KEY");
  const pskContext = xrayAccessSecretContext("forwardx-wireguard-peer-2011", "PRE_SHARED_KEY");
  for (const [secret, context] of [
    [serverPrivateKey, serverContext],
    [firstPrivateKey, peerContext],
    [firstPsk, pskContext],
  ] as const) {
    const envelope = encryptXraySecret(secret, context, keyring);
    assert.equal(envelope.includes(secret), false);
    assert.equal(decryptXraySecret(envelope, context, keyring), secret);
  }
  const peerEnvelope = encryptXraySecret(firstPrivateKey, peerContext, keyring);
  assert.throws(() => decryptXraySecret(peerEnvelope, pskContext, keyring));

  const inbound = {
    id: 201,
    runtimeTag: "forwardx-wireguard-201",
    listenAddress: "0.0.0.0",
    listenPort: 30201,
    protocol: "wireguard",
    transport: "none",
    security: "none",
    profileId: "WIREGUARD_UDP_NONE",
    specVersion: 1,
    specJson: "{}",
    wireguardServerPrivateKey: serverPrivateKey,
    isEnabled: true,
    pendingDelete: false,
    clients: [{
      id: 2012,
      credentialType: "WIREGUARD_PEER",
      privateKey: secondPrivateKey,
      preSharedKey: secondPsk,
      address: "10.0.0.3/32",
      statsKey: "forwardx-wireguard-peer-2012",
      isEnabled: true,
      pendingDelete: false,
      sortOrder: 20,
    }, {
      id: 2011,
      credentialType: "WIREGUARD_PEER",
      privateKey: firstPrivateKey,
      preSharedKey: firstPsk,
      address: "10.0.0.2/32",
      statsKey: "forwardx-wireguard-peer-2011",
      isEnabled: true,
      pendingDelete: false,
      sortOrder: 10,
    }],
  } satisfies XrayConfigInboundInput;
  const generated = generateDeterministicXrayConfig([inbound]);
  const config = JSON.parse(generated.configJson);
  assert.deepEqual(config.inbounds, [{
    tag: "forwardx-wireguard-201",
    listen: "0.0.0.0",
    port: 30201,
    protocol: "wireguard",
    settings: {
      secretKey: serverPrivateKey,
      address: ["10.0.0.1/32"],
      peers: [{
        publicKey: deriveXrayWireGuardPublicKey(firstPrivateKey),
        preSharedKey: firstPsk,
        allowedIPs: ["10.0.0.2/32"],
      }, {
        publicKey: deriveXrayWireGuardPublicKey(secondPrivateKey),
        preSharedKey: secondPsk,
        allowedIPs: ["10.0.0.3/32"],
      }],
      mtu: 1420,
      noKernelTun: true,
    },
  }]);
  assert.deepEqual(generated.expectedListeners, [{
    inboundId: 201,
    runtimeTag: "forwardx-wireguard-201",
    network: "udp",
    listenAddress: "0.0.0.0",
    port: 30201,
  }]);
  assert.equal(generated.configJson.includes(firstPrivateKey), false);
  assert.equal(generated.configJson.includes(secondPrivateKey), false);

  const share = buildXrayWireGuardClientConfig({
    peerPrivateKey: firstPrivateKey,
    peerAddress: "10.0.0.2/32",
    serverPrivateKey,
    preSharedKey: firstPsk,
    publicAddress: "edge.example.com",
    listenPort: 30201,
    displayName: "Edge / Alice",
  });
  assert.deepEqual(share, {
    fileName: "forwardx-edge-alice.conf",
    content: [
      "[Interface]",
      `PrivateKey = ${firstPrivateKey}`,
      "Address = 10.0.0.2/32",
      "DNS = 1.1.1.1, 1.0.0.1",
      "MTU = 1420",
      "",
      "[Peer]",
      `PublicKey = ${deriveXrayWireGuardPublicKey(serverPrivateKey)}`,
      `PresharedKey = ${firstPsk}`,
      "AllowedIPs = 0.0.0.0/0",
      "Endpoint = edge.example.com:30201",
      "PersistentKeepalive = 25",
      "",
    ].join("\n"),
  });
  assert.throws(() => buildXrayWireGuardClientConfig({
    peerPrivateKey: firstPrivateKey,
    peerAddress: "10.0.0.1/32",
    serverPrivateKey,
    preSharedKey: firstPsk,
    publicAddress: "edge.example.com",
    listenPort: 30201,
    displayName: "invalid",
  }));
});
