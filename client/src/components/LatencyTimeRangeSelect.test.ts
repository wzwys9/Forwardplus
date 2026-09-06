import assert from "node:assert/strict";
import test from "node:test";
import { filterLatencySeriesByTimeRange } from "./LatencyTimeRangeSelect";

const now = Date.parse("2026-09-06T12:00:00Z");
const hour = 60 * 60 * 1000;

test("latency time ranges keep both boundaries and reject invalid or future samples", () => {
  const series = [
    { id: "expired", recordedAt: new Date(now - hour - 1) },
    { id: "start", recordedAt: new Date(now - hour) },
    { id: "middle", recordedAt: new Date(now - hour / 2).toISOString() },
    { id: "end", recordedAt: new Date(now) },
    { id: "future", recordedAt: new Date(now + 1) },
    { id: "invalid", recordedAt: "invalid date" },
  ];

  assert.deepEqual(
    filterLatencySeriesByTimeRange(series, 1, now).map((sample) => sample.id),
    ["start", "middle", "end"],
  );
  assert.equal(series.length, 6, "filtering must preserve the cached source series");
});

test("missing latency series are safe before the first metrics response", () => {
  for (const series of [null, undefined, []]) {
    assert.deepEqual(filterLatencySeriesByTimeRange(series, 24, now), []);
  }
});

test("invalid ranges fall back to 24 hours and short ranges retain at least 30 minutes", () => {
  const series = [
    { id: "day", recordedAt: new Date(now - 24 * hour) },
    { id: "half-hour", recordedAt: new Date(now - hour / 2) },
    { id: "recent", recordedAt: new Date(now - 1) },
  ];

  for (const hours of [0, Number.NaN]) {
    assert.deepEqual(filterLatencySeriesByTimeRange(series, hours, now), series);
  }
  for (const hours of [0.1, -1]) {
    assert.deepEqual(filterLatencySeriesByTimeRange(series, hours, now), series.slice(1));
  }
});
