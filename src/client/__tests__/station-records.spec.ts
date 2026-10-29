import { describe, it, expect, vi, afterEach } from "vitest";
import { EufyMega } from "../eufy-mega.js";

/**
 * `getStationRecords` resolves the station and admin id like `getStationFaces`, then pages
 * `P2PSession.queryRecordPage` — whose framing and reply assembly are specced with the transport. These
 * cover the facade's half: the exclusive end date, 20-row pages paged by the oldest row's start time, the row limit,
 * and keeping only the asked device's rows.
 */
const DEVICE = "T8200P0000000000";
const OTHER = "T8200P0000000001";

type Row = { record_id: number; device_sn?: string; start_time: string };

/** A synthetic row `id` minutes after midnight on 2026-10-01, station wall-clock time. */
function row(id: number, device_sn: string | undefined = DEVICE): Row {
  const hh = String(Math.floor(id / 60)).padStart(2, "0");
  const mm = String(id % 60).padStart(2, "0");
  return { record_id: id, device_sn, start_time: `2026-10-01 ${hh}:${mm}:00` };
}

/** The station's reply: rows newest first, grouped under their table with a companion group beside them. */
function page(rows: Row[]): unknown[] {
  return [
    { table_name: "history_record_info", payload: rows },
    { table_name: "event_person_list", payload: [] },
  ];
}

/** Each entry answers one `queryRecordPage` call in turn: a page, or an Error it rejects with. */
function harness(pages: (unknown[] | Error)[], opts: { adminUserId?: string } = {}) {
  const eufy = new EufyMega({ email: "t@example.com", password: "x" });
  const queryRecordPage = vi.fn();
  for (const p of pages) {
    if (p instanceof Error) queryRecordPage.mockRejectedValueOnce(p);
    else queryRecordPage.mockResolvedValueOnce(p);
  }
  queryRecordPage.mockResolvedValue(page([]));

  const internals = eufy as unknown as {
    registry: { list: () => unknown[] };
    p2p: {
      stationKeyOf: (sn: string) => string;
      ensureStation: (sn: string, signal?: AbortSignal) => Promise<void>;
      getSessions: () => Map<string, unknown>;
    };
  };
  vi.spyOn(internals.registry, "list").mockReturnValue([
    { sn: DEVICE, raw: { member: { admin_user_id: opts.adminUserId ?? "ADMIN-0000" } } },
  ]);
  internals.p2p = {
    stationKeyOf: (sn: string) => sn,
    ensureStation: async () => undefined,
    getSessions: () => new Map([[DEVICE, { queryRecordPage }]]),
  };
  return { eufy, queryRecordPage };
}

/** `n` rows newest first, ids `top` down to `top - n + 1`. */
const run = (top: number, n: number) => Array.from({ length: n }, (_, i) => row(top - i));

afterEach(() => vi.useRealTimers());

describe("getStationRecords", () => {
  it("asks up to the day after the last day, scoped to the station's admin id", async () => {
    const { eufy, queryRecordPage } = harness([page([row(2), row(1)])]);
    const rows = await eufy.getStationRecords(DEVICE, { startDate: "20260925", endDate: "20261001" });
    expect(rows.map((r) => r.record_id)).toEqual([2, 1]);
    expect(queryRecordPage).toHaveBeenCalledOnce();
    expect(queryRecordPage).toHaveBeenCalledWith(
      expect.objectContaining({
        accountId: "ADMIN-0000",
        startDate: "20260925",
        endDate: "20261002",
        startTime: "0",
        count: 20,
      }),
    );
  });

  it("rolls the end date over a month boundary", async () => {
    const { eufy, queryRecordPage } = harness([page([])]);
    await eufy.getStationRecords(DEVICE, { startDate: "20261025", endDate: "20261031" });
    expect(queryRecordPage).toHaveBeenCalledWith(expect.objectContaining({ endDate: "20261101" }));
  });

  it("defaults to the seven days ending today on this host's calendar", async () => {
    vi.useFakeTimers({ toFake: ["Date"] });
    vi.setSystemTime(new Date(2026, 9, 3, 12, 0, 0));
    const { eufy, queryRecordPage } = harness([page([])]);
    await eufy.getStationRecords(DEVICE);
    expect(queryRecordPage).toHaveBeenCalledWith(
      expect.objectContaining({ startDate: "20260927", endDate: "20261004" }),
    );
  });

  it("pages back from the oldest row's start time until a short page", async () => {
    const { eufy, queryRecordPage } = harness([page(run(60, 20)), page(run(41, 20)), page(run(22, 5))]);
    const rows = await eufy.getStationRecords(DEVICE, { endDate: "20261001" });
    expect(rows).toHaveLength(43);
    expect(rows[0]?.record_id).toBe(60);
    expect(rows.at(-1)?.record_id).toBe(18);
    expect(queryRecordPage.mock.calls.map(([o]) => o.startTime)).toEqual(["0", "20261001004100", "20261001002200"]);
  });

  it("stops when a page brings no new record, and keeps each record once", async () => {
    const full = page(run(20, 20));
    const { eufy, queryRecordPage } = harness([full, full]);
    const rows = await eufy.getStationRecords(DEVICE, { endDate: "20261001" });
    expect(rows).toHaveLength(20);
    expect(queryRecordPage).toHaveBeenCalledTimes(2);
  });

  it("stops at the limit, keeping the newest rows", async () => {
    const { eufy, queryRecordPage } = harness([page(run(60, 20)), page(run(41, 20))]);
    const rows = await eufy.getStationRecords(DEVICE, { endDate: "20261001", limit: 30 });
    expect(rows.map((r) => r.record_id)).toEqual(run(60, 30).map((r) => r.record_id));
    expect(queryRecordPage).toHaveBeenCalledTimes(2);
  });

  it("leaves out rows naming another device, and keeps rows naming none", async () => {
    const { eufy } = harness([page([row(3), row(2, OTHER), row(1, undefined)])]);
    const rows = await eufy.getStationRecords(DEVICE, { endDate: "20261001" });
    expect(rows.map((r) => r.record_id)).toEqual([3, 1]);
  });

  it("passes the caller's bound and signal to every page", async () => {
    const control = new AbortController();
    const { eufy, queryRecordPage } = harness([page([row(1)])]);
    await eufy.getStationRecords(DEVICE, { timeoutMs: 500, signal: control.signal });
    expect(queryRecordPage).toHaveBeenCalledWith(expect.objectContaining({ timeoutMs: 500, signal: control.signal }));
  });

  it("gives each page five seconds when the caller states no bound", async () => {
    const { eufy, queryRecordPage } = harness([page([row(1)])]);
    await eufy.getStationRecords(DEVICE, { endDate: "20261001" });
    expect(queryRecordPage).toHaveBeenCalledWith(expect.objectContaining({ timeoutMs: 5000 }));
  });

  it("asks a page again when its reply does not arrive whole", async () => {
    const lost = new Error("readDatabase: T8200P0000000000 sent no complete history_record_info");
    const { eufy, queryRecordPage } = harness([page(run(60, 20)), lost, lost, page(run(41, 5))]);
    const rows = await eufy.getStationRecords(DEVICE, { endDate: "20261001" });
    expect(rows).toHaveLength(24);
    expect(queryRecordPage.mock.calls.map(([o]) => o.startTime)).toEqual([
      "0",
      "20261001004100",
      "20261001004100",
      "20261001004100",
    ]);
  });

  it("gives up after a page's third lost reply", async () => {
    const lost = new Error("readDatabase: T8200P0000000000 sent no complete history_record_info");
    const { eufy, queryRecordPage } = harness([lost, lost, lost, page([row(1)])]);
    await expect(eufy.getStationRecords(DEVICE, { endDate: "20261001" })).rejects.toThrow(/sent no complete/);
    expect(queryRecordPage).toHaveBeenCalledTimes(3);
  });

  it("does not ask again once the caller aborts", async () => {
    const control = new AbortController();
    control.abort();
    const { eufy, queryRecordPage } = harness([new Error("readDatabase: aborted"), page([row(1)])]);
    await expect(eufy.getStationRecords(DEVICE, { signal: control.signal })).rejects.toThrow(/aborted/);
    expect(queryRecordPage).toHaveBeenCalledOnce();
  });

  it("refuses a station whose record states no admin id, rather than querying with none", async () => {
    const { eufy, queryRecordPage } = harness([], { adminUserId: "" });
    await expect(eufy.getStationRecords(DEVICE)).rejects.toThrow(/getStationRecords: no admin_user_id/);
    expect(queryRecordPage).not.toHaveBeenCalled();
  });
});
