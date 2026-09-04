type MobileTelegramLoginChallenge = {
  expiresAt: number;
};

const challenges = new Map<string, MobileTelegramLoginChallenge>();

function normalizeCode(code: string) {
  return code.trim().toUpperCase();
}

function pruneExpired(now = Date.now()) {
  for (const [code, challenge] of challenges) {
    if (challenge.expiresAt <= now) challenges.delete(code);
  }
}

export function createMobileTelegramLoginChallenge(code: string, ttlMs: number) {
  pruneExpired();
  challenges.set(normalizeCode(code), { expiresAt: Date.now() + ttlMs });
}

export function hasMobileTelegramLoginChallenge(code: string) {
  const normalized = normalizeCode(code);
  const challenge = challenges.get(normalized);
  if (!challenge) return false;
  if (challenge.expiresAt <= Date.now()) {
    challenges.delete(normalized);
    return false;
  }
  return true;
}

export function takeMobileTelegramLoginChallenge(code: string) {
  const normalized = normalizeCode(code);
  if (!hasMobileTelegramLoginChallenge(normalized)) return false;
  challenges.delete(normalized);
  return true;
}

export function clearMobileTelegramLoginChallenge(code: string) {
  challenges.delete(normalizeCode(code));
}
