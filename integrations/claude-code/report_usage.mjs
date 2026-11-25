#!/usr/bin/env node
// Claude Code hook: report the model's token use and cost to the gateway.
//
// The gateway sees tool calls, not model calls, so it cannot count tokens on
// its own. Claude Code writes each model reply, with its token counts, to the
// session transcript. Run as a `Stop` hook, this script reads the replies that
// are new since its last run and sends one `POST /usage` per reply to the
// gateway's MCP proxy, so the dashboard shows model calls, tokens and cost.
//
// Settings (environment):
//   AGENT_GATEWAY_USAGE_URL    the proxy's /usage address, e.g. http://proxy:8090/usage
//   AGENT_GATEWAY_PROXY_TOKEN  the same token the agent sends to the proxy
//   AGENT_GATEWAY_PRICES       optional JSON: {"model": {"in": 4, "out": 20,
//                              "cache_write": 5, "cache_read": 0.2}} in $ per 1M tokens
//   AGENT_GATEWAY_USAGE_STATE  optional folder for the "already sent" list
//                              (default: the system temp folder)
//
// Cost is the API list price for the tokens used. On a Claude subscription
// nothing is billed per token, so read it as "what this would cost on the API".
// A model with no known price is still reported, with tokens and no cost.
//
// The hook never stops Claude Code: any problem is printed to stderr and the
// script exits 0.
import fs from "node:fs";
import os from "node:os";
import path from "node:path";

// $ per 1M tokens. Cache writes are 1.25x input (5-minute cache).
export const PRICES = {
  "claude-fable-5-2": { in: 8, out: 40, cache_write: 10, cache_read: 0.2 },
  "claude-opus-5-5": { in: 4, out: 20, cache_write: 5, cache_read: 0.2 },
  "claude-opus-5": { in: 5, out: 25, cache_write: 6.25, cache_read: 0.5 },
  "claude-sonnet-5-5": { in: 2, out: 10, cache_write: 2.5, cache_read: 0.1 },
  "claude-sonnet-5": { in: 2, out: 10, cache_write: 2.5, cache_read: 0.2 },
  "claude-haiku-5-5": { in: 0.1, out: 0.5, cache_write: 0.125, cache_read: 0.01 },
};

// One entry per model reply. Claude Code may write a reply as several lines
// (one per content block) with the same message id; the last one is complete.
export function replies(lines) {
  const byId = new Map();
  for (const line of lines) {
    if (!line.trim()) continue;
    let entry;
    try { entry = JSON.parse(line); } catch { continue; }
    const message = entry?.message;
    if (entry?.type !== "assistant" || !message?.id || !message.usage) continue;
    if (!message.model || message.model.startsWith("<")) continue;  // "<synthetic>": no API call
    byId.set(message.id, { id: message.id, model: message.model, usage: message.usage });
  }
  return [...byId.values()];
}

// What one reply is sent as: the fields /usage accepts.
export function report(reply, prices = PRICES) {
  const u = reply.usage;
  const n = (v) => (Number.isFinite(v) && v > 0 ? v : 0);
  const fresh = n(u.input_tokens), write = n(u.cache_creation_input_tokens);
  const read = n(u.cache_read_input_tokens), out = n(u.output_tokens);
  const body = { tokens_in: fresh + write + read, tokens_out: out };
  const p = prices[reply.model] ?? prices[reply.model.replace(/-\d{8}$/, "")];
  if (p) {
    const cost = (fresh * p.in + write * p.cache_write + read * p.cache_read + out * p.out) / 1e6;
    body.cost_usd = Math.round(cost * 1e6) / 1e6;
  }
  return body;
}

function loadPrices() {
  const extra = process.env.AGENT_GATEWAY_PRICES;
  if (!extra) return PRICES;
  try { return { ...PRICES, ...JSON.parse(extra) }; }
  catch { console.error("report_usage: AGENT_GATEWAY_PRICES is not JSON; using built-in prices"); return PRICES; }
}

async function main() {
  const url = process.env.AGENT_GATEWAY_USAGE_URL;
  const token = process.env.AGENT_GATEWAY_PROXY_TOKEN;
  if (!url || !token) {
    console.error("report_usage: set AGENT_GATEWAY_USAGE_URL and AGENT_GATEWAY_PROXY_TOKEN");
    return;
  }
  let input = "";
  for await (const chunk of process.stdin) input += chunk;
  const { session_id: session, transcript_path: transcript } = JSON.parse(input || "{}");
  if (!transcript || !fs.existsSync(transcript)) return;

  // Replies already sent, so a later Stop does not send them again.
  const dir = process.env.AGENT_GATEWAY_USAGE_STATE || os.tmpdir();
  const stateFile = path.join(dir, `agw-usage-${String(session || "session").replace(/[^\w-]/g, "_")}.json`);
  let sent = new Set();
  try { sent = new Set(JSON.parse(fs.readFileSync(stateFile, "utf8"))); } catch { /* first run */ }

  const prices = loadPrices();
  for (const reply of replies(fs.readFileSync(transcript, "utf8").split("\n"))) {
    if (sent.has(reply.id)) continue;
    const response = await fetch(url, {
      method: "POST",
      headers: { "Content-Type": "application/json", Authorization: `Bearer ${token}` },
      body: JSON.stringify(report(reply, prices)),
    });
    if (!response.ok) {
      console.error(`report_usage: the gateway answered ${response.status}: ${await response.text()}`);
      break;  // keep the rest for the next run
    }
    sent.add(reply.id);
  }
  fs.mkdirSync(dir, { recursive: true });
  fs.writeFileSync(stateFile, JSON.stringify([...sent]));
}

if (import.meta.url === `file://${process.argv[1]}`) {
  main().catch((err) => console.error(`report_usage: ${err.message}`)).finally(() => process.exit(0));
}
