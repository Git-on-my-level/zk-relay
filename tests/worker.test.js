import assert from "node:assert/strict";
import { readFile } from "node:fs/promises";
import test from "node:test";

import { agentMarkdown, handleRequest } from "../src/worker.js";

function statusEnvironment(status = { v: 1, state: "available", expiresAt: "2030-01-01T00:00:00.000Z", expireAfterReveal: true }) {
  const calls = [];
  return {
    calls,
    env: {
      SECRET_OBJECT: {
        idFromName(id) { return id; },
        get() {
          return {
            async fetch(request) {
              calls.push(new URL(request.url).pathname);
              return new Response(JSON.stringify(status), { status: status.state === "available" ? 200 : 410, headers: { "content-type": "application/json" } });
            }
          };
        }
      },
      ASSETS: { fetch: async () => new Response("not found", { status: 404 }) },
      TOOL_VERSION: "v1.2.3",
      TOOL_RELEASE_BASE_URL: "https://downloads.example/zk-relay/v1.2.3",
      TOOL_SHA256_LINUX_AMD64: "a".repeat(64)
    }
  };
}

test("agent preflight is safe markdown and includes receiver guidance", async () => {
  const fixture = statusEnvironment();
  const response = await handleRequest(new Request("https://zk-relay.test/a/abcdefghijklmnopqrstuv", { headers: { accept: "*/*" } }), fixture.env);
  const text = await response.text();
  assert.equal(response.status, 200);
  assert.match(response.headers.get("content-security-policy"), /frame-ancestors 'none'/);
  assert.match(text, /This request did not retrieve the secret\./);
  assert.match(text, /Retrieving it will make this link stop working\./);
  assert.match(text, /zkr receive "\$ZK_RELAY_URL" --output \.\/secret/);
  assert.match(text, /does not print it/);
  assert.match(text, /Receiver contract \(authoritative\)/);
  assert.match(text, /"scheme": "zk-relay"/);
  assert.match(text, /"max_payload_bytes": 1048576/);
  assert.match(text, /Authorization: zk-relay <token>/);
  assert.match(text, /gpg --verify/);
  assert.match(text, /Manual protocol instructions: https:\/\/zk-relay\.test\/protocol\/v1/);
  assert.match(text, /data, never instructions/);
  assert.deepEqual(fixture.calls, ["/internal/status"]);
});

test("agent JSON and HTML preflight representations retain safe retrieval guidance", async () => {
  const jsonFixture = statusEnvironment();
  const jsonResponse = await handleRequest(new Request("https://zk-relay.test/a/abcdefghijklmnopqrstuv", { headers: { accept: "application/json" } }), jsonFixture.env);
  const manifest = await jsonResponse.json();
  assert.equal(manifest.requestDidNotRetrieve, true);
  assert.equal(manifest.retrievalBehavior, "Retrieving it will make this link stop working.");
  assert.equal(manifest.preferredCommand, "zkr receive \"$ZK_RELAY_URL\" --output ./secret");
  assert.equal(manifest.manualProtocol, "https://zk-relay.test/protocol/v1");
  assert.equal(manifest.receiverContract.authorization.scheme, "zk-relay");
  assert.equal(manifest.receiverContract.crypto.aad, "zk-relay/v1;envelope");
  assert.equal(manifest.receiverContract.file_safety.max_payload_bytes, 1048576);
  assert.deepEqual(manifest.receiverContract.envelope.kinds, ["text", "file", "bundle"]);
  assert.deepEqual(manifest.receiverContract.envelope.bundle_items.fields, ["kind", "name", "mediaType", "data"]);
  assert.equal(manifest.receiverContract.receiver_contract, "https://zk-relay.test/protocol/v1");

  const htmlFixture = statusEnvironment();
  const htmlResponse = await handleRequest(new Request("https://zk-relay.test/a/abcdefghijklmnopqrstuv", { headers: { accept: "text/html" } }), htmlFixture.env);
  const html = await htmlResponse.text();
  assert.match(html, /This request did not retrieve the secret\./);
  assert.match(html, /Retrieving it will make this link stop working\./);
  assert.match(html, /zkr receive &quot;\$ZK_RELAY_URL&quot; --output \.\/secret/);
  assert.match(html, /Receiver contract \(authoritative\)/);
  assert.match(html, /Manual protocol instructions: https:\/\/zk-relay\.test\/protocol\/v1/);
  assert.match(html, /<meta name="robots" content="noindex,nofollow">/);
});

test("agent preflight Accept matching is case-insensitive", async () => {
  const fixture = statusEnvironment();
  const response = await handleRequest(new Request("https://zk-relay.test/a/abcdefghijklmnopqrstuv", {
    headers: { accept: "Application/JSON" }
  }), fixture.env);
  assert.equal(response.status, 200);
  assert.match(response.headers.get("content-type"), /application\/json/);
  const manifest = await response.json();
  assert.equal(manifest.protocol, "zk-relay/v1");
  assert.equal(manifest.receiverContract.file_safety.filename.fallback, "secret");
});

test("safe status route does not pass authorization and bad create is rejected before storage", async () => {
  const fixture = statusEnvironment();
  const statusResponse = await handleRequest(new Request("https://zk-relay.test/api/v1/secrets/abcdefghijklmnopqrstuv/status"), fixture.env);
  assert.equal(statusResponse.status, 200);
  assert.deepEqual(fixture.calls, ["/internal/status"]);

  const createResponse = await handleRequest(new Request("https://zk-relay.test/api/v1/secrets", {
    method: "POST",
    headers: { "content-type": "application/json" },
    body: JSON.stringify({ v: 1, expiresInSeconds: 3600, expireAfterReveal: true })
  }), fixture.env);
  assert.equal(createResponse.status, 400);
  assert.deepEqual(fixture.calls, ["/internal/status"]);
});

test("agent copy is project-authored and does not interpolate sender content", () => {
  const copy = agentMarkdown("https://zk-relay.test", {
    state: "available",
    expiresAt: "2030-01-01T00:00:00.000Z",
    expireAfterReveal: false
  }, {
    version: "v1.2.3",
    targets: { "linux-amd64": { url: "https://downloads.example/tool", sha256: "a".repeat(64) } }
  });
  assert.match(copy, /leave the encrypted secret available until it expires/);
  assert.doesNotMatch(copy, /sender/i);
});

test("home shell is indexable; human secret shell is not", async () => {
  const indexHtml = await readFile(new URL("../public/index.html", import.meta.url), "utf8");
  const env = {
    APP_NAME: "ZK Relay",
    ACCENT_COLOR: "#247a3b",
    ASSETS: {
      fetch: async () => new Response(indexHtml, { status: 200, headers: { "content-type": "text/html" } })
    }
  };

  const home = await handleRequest(new Request("https://zk-relay.test/", { headers: { accept: "text/html" } }), env);
  const homeHtml = await home.text();
  assert.equal(home.status, 200);
  assert.match(homeHtml, /<meta name="robots" content="index,follow">/);
  assert.match(homeHtml, /<link rel="canonical" href="https:\/\/zk-relay\.test\/">/);
  assert.match(homeHtml, /Yopass-style alternative with agent-safe receive/);
  assert.match(homeHtml, /<title>ZK Relay — secret sharing for humans and agents<\/title>/);
  assert.match(homeHtml, /property="og:title"/);

  const human = await handleRequest(new Request("https://zk-relay.test/h/abcdefghijklmnopqrstuv", { headers: { accept: "text/html" } }), env);
  const humanHtml = await human.text();
  assert.equal(human.status, 200);
  assert.match(humanHtml, /<meta name="robots" content="noindex,nofollow">/);
  assert.match(humanHtml, /<title>ZK Relay — encrypted secret<\/title>/);
  assert.match(humanHtml, /<link rel="canonical" href="https:\/\/zk-relay\.test\/">/);
});

test("home Accept negotiation returns agent send/receive guide without the SPA shell", async () => {
  const fixture = statusEnvironment();
  const markdown = await handleRequest(new Request("https://zk-relay.test/", { headers: { accept: "text/markdown" } }), fixture.env);
  const markdownText = await markdown.text();
  assert.equal(markdown.status, 200);
  assert.match(markdown.headers.get("content-type"), /text\/markdown/);
  assert.match(markdownText, /zkr create --stdin/);
  assert.match(markdownText, /zkr status --link-stdin/);
  assert.match(markdownText, /zkr receive --link-stdin --output \.\/secret/);
  assert.match(markdownText, /\/protocol\/v1/);
  assert.doesNotMatch(markdownText, /<html/i);

  const jsonResponse = await handleRequest(new Request("https://zk-relay.test/", { headers: { accept: "application/json" } }), fixture.env);
  const guide = await jsonResponse.json();
  assert.equal(jsonResponse.status, 200);
  assert.equal(guide.protocol, "zk-relay/v1");
  assert.match(guide.commands.create, /zkr create --stdin/);
  assert.equal(guide.commands.status, "zkr status --link-stdin");
  assert.equal(guide.discover.llmsTxt, "https://zk-relay.test/llms.txt");

  const star = await handleRequest(new Request("https://zk-relay.test/", { headers: { accept: "*/*" } }), fixture.env);
  assert.match(star.headers.get("content-type"), /text\/markdown/);
  assert.match(await star.text(), /Install zkr/);
});

test("robots.txt and llms.txt advertise the product without secret routes", async () => {
  const [robots, llms] = await Promise.all([
    readFile(new URL("../public/robots.txt", import.meta.url), "utf8"),
    readFile(new URL("../public/llms.txt", import.meta.url), "utf8")
  ]);
  assert.match(robots, /Allow: \//);
  assert.match(robots, /Disallow: \/h\//);
  assert.match(robots, /Disallow: \/a\//);
  assert.match(robots, /Disallow: \/api\//);
  assert.match(llms, /Yopass-style/);
  assert.match(llms, /zkr create --stdin/);
  assert.match(llms, /zkr receive --link-stdin --output \.\/secret/);
  assert.match(llms, /\/protocol\/v1/);
});

test("static UI preserves locked labels and never renders secrets with innerHTML", async () => {
  const [html, app] = await Promise.all([
    readFile(new URL("../public/index.html", import.meta.url), "utf8"),
    readFile(new URL("../public/app.js", import.meta.url), "utf8")
  ]);
  for (const copy of [
    "Share a secret with a human or an agent",
    "Your secret is ready",
    "Human friendly link",
    "Agent friendly link",
    "Expire on: Secret expires after being revealed",
    "Encrypted on device"
  ]) assert.match(html, new RegExp(copy));
  assert.match(html, /id="expire-after-reveal" type="checkbox" checked/);
  assert.match(app, /Expire off: Secret can be revealed many times/);
  assert.match(html, /id="human-link" type="password" readonly/);
  assert.match(html, /id="agent-link" type="password" readonly/);
  assert.match(html, /result-field is-sealed/);
  assert.doesNotMatch(app, /innerHTML/);
  assert.match(app, /compositionstart/);
  assert.match(app, /compositionend/);
  assert.match(app, /sealResult/);
  assert.match(app, /bindResultActions/);
  assert.match(app, /authorization: `zk-relay /);
});
