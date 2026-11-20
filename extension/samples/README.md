# Sample JS extensions

Load via the Extensions tab or `POST /api/v1/extensions` with the file
contents as `code`. Scripts are pure ECMAScript (no I/O, no network) and
mutate `flow` in place:

```js
function onRequest(flow)  { /* flow.request.*  */ }
function onResponse(flow) { /* flow.response.* */ }
```

## add-header.js — inject a probe header on every request

```js
// extension/samples/add-header.js
function onRequest(flow) {
  flow.request.headers.push({ name: "X-ProxyForge", value: "scripted" });
}
```

## redact-hostnames.js — scrub internal hostnames from responses

```js
// extension/samples/redact-hostnames.js
var INTERNAL = ["db-prod-01", "cache-02", "mq.internal"];
function onResponse(flow) {
  var body = flow.response.body;
  INTERNAL.forEach(function (h) {
    body = body.split(h).join("[internal]");
  });
  flow.response.body = body;
}
```

## json-content-type.js — normalize API responses

```js
function onRequest(flow) {
  if (flow.request.path.indexOf("/api/") === 0) {
    flow.request.headers.push({ name: "Accept", value: "application/json" });
  }
}
```

## see-nothing.js — verify the sandbox (must never error)

```js
function onRequest(flow) {
  if (typeof require !== "undefined") throw new Error("require exists");
  if (typeof process !== "undefined") throw new Error("process exists");
  if (typeof fetch !== "undefined") throw new Error("fetch exists");
}
```
