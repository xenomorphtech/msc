const endpoint = process.env.MAPLE_CDP_ENDPOINT || "http://127.0.0.1:9229";
const targets = await (await fetch(`${endpoint}/json`)).json();
const target = targets.find((entry) => entry.type === "page");
if (!target) throw new Error("No Chromium page target was found");

const socket = new WebSocket(target.webSocketDebuggerUrl);
await new Promise((resolve, reject) => {
  socket.addEventListener("open", resolve, {once: true});
  socket.addEventListener("error", reject, {once: true});
});

let nextId = 1;
const pending = new Map();
socket.addEventListener("message", ({data}) => {
  const message = JSON.parse(data);
  if (!message.id || !pending.has(message.id)) return;
  const {resolve, reject} = pending.get(message.id);
  pending.delete(message.id);
  message.error ? reject(new Error(JSON.stringify(message.error))) : resolve(message.result);
});
function send(method, params = {}) {
  const id = nextId++;
  socket.send(JSON.stringify({id, method, params}));
  return new Promise((resolve, reject) => pending.set(id, {resolve, reject}));
}

await send("Network.enable");
const names = new Set([
  "bfUID", "bfWebToken", "bfTD", "bfEnv", "bfTokenData", "bfSecretCode",
  "ASP.NET_SessionId", "webapi_session", "XSRF-TOKEN",
]);
const {cookies} = await send("Network.getAllCookies");
const selected = cookies.filter(
  (cookie) => names.has(cookie.name) && /(^|\.)((beanfun)|(gamania))\.com$/.test(cookie.domain)
);
for (const cookie of selected) {
  await send("Network.deleteCookies", {
    name: cookie.name,
    domain: cookie.domain,
    path: cookie.path,
  });
}
socket.close();
console.log(JSON.stringify({deleted: selected.length}));
