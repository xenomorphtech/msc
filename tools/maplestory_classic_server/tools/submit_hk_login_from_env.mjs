const account = process.env.MAPLE_ACCOUNT_EMAIL;
const password = process.env.MAPLE_ACCOUNT_PASSWORD;
if (!account || !password) throw new Error("Maple account environment variables are missing");

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

await send("Page.enable");
await send("Runtime.enable");
const {frameTree} = await send("Page.getFrameTree");
const queue = [frameTree];
let loginFrame;
while (queue.length) {
  const node = queue.shift();
  if (node.frame.url.includes("/login/id-pass_form_newBF.aspx")) {
    loginFrame = node.frame;
    break;
  }
  queue.push(...(node.childFrames || []));
}
if (!loginFrame) throw new Error("The HK account/password iframe was not found");
const {executionContextId} = await send("Page.createIsolatedWorld", {
  frameId: loginFrame.id,
  worldName: `hk-login-${loginFrame.id}`,
});
const expression = `((account, password) => {
  document.querySelector('#DivMsgBoxBtn')?.click();
  const accountInput = document.querySelector('#t_AccountID');
  const passwordInput = document.querySelector('#t_Password');
  const submit = document.querySelector('#btn_login');
  if (!accountInput || !passwordInput || !submit) return false;
  for (const [input, value] of [[accountInput, account], [passwordInput, password]]) {
    const setter = Object.getOwnPropertyDescriptor(HTMLInputElement.prototype, 'value').set;
    setter.call(input, value);
    input.dispatchEvent(new Event('input', {bubbles: true}));
    input.dispatchEvent(new Event('change', {bubbles: true}));
  }
  submit.click();
  return true;
})(${JSON.stringify(account)}, ${JSON.stringify(password)})`;
const result = await send("Runtime.evaluate", {
  contextId: executionContextId,
  expression,
  returnByValue: true,
});
socket.close();
if (result.result.value !== true) throw new Error("The HK login form was incomplete");
console.log(JSON.stringify({submitted: true}));
