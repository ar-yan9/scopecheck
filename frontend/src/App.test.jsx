import React from "react";
import { describe, it, expect, vi, afterEach } from "vitest";
import {
  render,
  screen,
  fireEvent,
  waitFor,
  cleanup,
} from "@testing-library/react";
import "@testing-library/jest-dom/vitest";
import { App } from "./App.jsx";
afterEach(() => {
  cleanup();
  vi.unstubAllGlobals();
});
function mockApi(
  scanResponse = { ok: true, data: { id: "job1", port_count: 1 } },
) {
  const f = vi.fn().mockImplementation(async (url, opts) => {
    let data = {};
    let ok = true;
    if (url.endsWith("/local-addresses"))
      data = { addresses: ["127.0.0.1", "192.168.1.25"] };
    else if (url.endsWith("/history")) data = { reports: [] };
    else if (url.endsWith("/health")) data = { status: "ok" };
    else if (url.endsWith("/jobs") && opts) {
      data = scanResponse.data;
      ok = scanResponse.ok;
    } else if (url.endsWith("/jobs/job1"))
      data = { id: "job1", status: "failed", error: "Test completion" };
    return { ok, json: async () => data };
  });
  vi.stubGlobal("fetch", f);
  return f;
}
describe("full-range local workbench", () => {
  it("offers full range and recognized interface addresses", async () => {
    mockApi();
    render(<App />);
    expect(
      screen.getByRole("option", { name: "All TCP · 1-65535" }),
    ).toBeInTheDocument();
    await screen.findByRole("button", { name: "192.168.1.25" });
    fireEvent.click(screen.getByRole("button", { name: "192.168.1.25" }));
    expect(screen.getByLabelText("Hostname or IP")).toHaveValue("192.168.1.25");
    expect(screen.getByText(/Own-machine address/)).toBeInTheDocument();
  });
  it("surfaces rejected external scope without false results", async () => {
    mockApi({
      ok: false,
      data: { detail: "Every non-owned DNS address must be inside scope" },
    });
    render(<App />);
    await screen.findByRole("button", { name: "192.168.1.25" });
    fireEvent.change(screen.getByLabelText("Hostname or IP"), {
      target: { value: "example.test" },
    });
    expect(screen.getByLabelText("Authorized scope")).toBeInTheDocument();
    fireEvent.click(screen.getByRole("button", { name: /Start scope check/ }));
    await waitFor(() =>
      expect(screen.getByRole("alert")).toHaveTextContent(
        "Every non-owned DNS address",
      ),
    );
    expect(
      screen.queryByRole("button", { name: "JSON ↓" }),
    ).not.toBeInTheDocument();
  });
  it("submits all preset and automatic checks, not stale port assumptions", async () => {
    const f = mockApi();
    render(<App />);
    await screen.findByRole("button", { name: "192.168.1.25" });
    fireEvent.change(screen.getByLabelText("Port preset"), {
      target: { value: "all" },
    });
    fireEvent.click(screen.getByRole("button", { name: /Start scope check/ }));
    await waitFor(() =>
      expect(f.mock.calls.some(([u, o]) => u === "/api/jobs" && o)).toBe(true),
    );
    const body = JSON.parse(
      f.mock.calls.find(([u, o]) => u === "/api/jobs" && o)[1].body,
    );
    expect(body.ports).toBe("all");
    expect(body.automatic).toBe(true);
    expect(body.http_ports).toBe("");
    expect(body.authorized).toBe(false);
    await screen.findByRole("alert");
  });
});

it("keeps a fast completed job report through the busy-state transition", async () => {
  const report = {
    scope: {
      target: "127.0.0.1",
      selected_address: "127.0.0.1",
      own_machine: true,
    },
    status: "completed",
    configuration: { ignored_manual_ports: [] },
    summary: { open: 0, closed: 1, timeout: 0, error: 0 },
    coverage: {
      completed: 1,
      requested: 1,
      unscanned: 0,
      open_checks_pending: 0,
    },
    results: [],
    limits: [],
  };
  vi.stubGlobal(
    "fetch",
    vi
      .fn()
      .mockImplementation(async (url, opts) => ({
        ok: true,
        json: async () =>
          url.endsWith("/local-addresses")
            ? { addresses: ["127.0.0.1"] }
            : url.endsWith("/history")
              ? { reports: [] }
              : url.endsWith("/health")
                ? {}
                : url.endsWith("/jobs") && opts
                  ? { id: "fast" }
                  : url.endsWith("/report")
                    ? report
                    : { id: "fast", status: "completed" },
      })),
  );
  render(<App />);
  fireEvent.click(screen.getByRole("button", { name: /Start scope check/ }));
  await screen.findByRole("button", { name: "JSON ↓" });
  expect(
    screen.getByRole("button", { name: /Start scope check/ }),
  ).toBeEnabled();
});
