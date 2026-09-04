import crypto from "crypto";

type TwoFactorSetupChallenge = {
  userId: number;
  secret: string;
  expiresAt: number;
};

const TWO_FACTOR_SETUP_TTL_MS = 5 * 60 * 1000;
const setupChallenges = new Map<string, TwoFactorSetupChallenge>();

function pruneExpired(now = Date.now()) {
  for (const [id, challenge] of setupChallenges) {
    if (challenge.expiresAt <= now) setupChallenges.delete(id);
  }
}

export function createTwoFactorSetupChallenge(input: { userId: number; secret: string }) {
  pruneExpired();
  const setupId = crypto.randomBytes(24).toString("hex");
  const expiresAt = Date.now() + TWO_FACTOR_SETUP_TTL_MS;
  setupChallenges.set(setupId, {
    userId: input.userId,
    secret: input.secret,
    expiresAt,
  });
  return {
    setupId,
    expiresAt: new Date(expiresAt),
    expiresInSeconds: Math.floor(TWO_FACTOR_SETUP_TTL_MS / 1000),
  };
}

export function getTwoFactorSetupChallenge(setupId: string, userId: number) {
  const challenge = setupChallenges.get(setupId);
  if (!challenge) return null;
  if (challenge.userId !== userId || challenge.expiresAt <= Date.now()) {
    setupChallenges.delete(setupId);
    return null;
  }
  return challenge;
}

export function clearTwoFactorSetupChallenge(setupId: string) {
  setupChallenges.delete(setupId);
}

export function clearTwoFactorSetupChallengesForUser(userId: number) {
  for (const [id, challenge] of setupChallenges) {
    if (challenge.userId === userId) setupChallenges.delete(id);
  }
}
