import {openSync} from "node:fs";
import {spawn} from "node:child_process";

const cdpEndpoint = process.env.MAPLE_CDP_ENDPOINT || "http://127.0.0.1:9229";
const targets = await (await fetch(`${cdpEndpoint}/json`)).json();
const target = targets.find(
  (entry) => entry.type === "page" && entry.url.includes("maplestoryclassic.beanfun.com")
);
if (!target) throw new Error("The authenticated MapleStory browser tab was not found");

const socket = new WebSocket(target.webSocketDebuggerUrl);
await new Promise((resolve, reject) => {
  socket.addEventListener("open", resolve, {once: true});
  socket.addEventListener("error", reject, {once: true});
});

const evaluation = await new Promise((resolve, reject) => {
  const timeout = setTimeout(() => reject(new Error("CDP evaluation timed out")), 5000);
  socket.addEventListener("message", ({data}) => {
    const message = JSON.parse(data);
    if (message.id !== 1) return;
    clearTimeout(timeout);
    if (message.error) reject(new Error(JSON.stringify(message.error)));
    else resolve(message.result);
  });
  socket.send(JSON.stringify({
    id: 1,
    method: "Runtime.evaluate",
    params: {expression: "NgmLayerHelper.argument", returnByValue: true},
  }));
});
socket.close();

const commandLine = evaluation.result.value;
if (typeof commandLine !== "string") {
  throw new Error("The page did not provide an NGM launch command");
}

const passargMatch = commandLine.match(/-passarg:(['"])(.*?)\1(?:\s|$)/);
if (!passargMatch) throw new Error("The NGM launch command did not contain -passarg");
const gameArguments = passargMatch[2].trim().split(/\s+/);
if (gameArguments.length !== 4) {
  throw new Error(`Unexpected game argument count: ${gameArguments.length}`);
}

const prefix = "/home/sdancer/ms/downloads/maplestory_classic_wine_prefix";
const gameDirectory = `${prefix}/drive_c/Program Files/Gamania/maplestory_classic`;
const executable = `${gameDirectory}/Maplestory_Classic.exe`;
const logPath = process.env.MAPLE_WINE_LOG || "/tmp/maple-direct-from-cdp.log";
const log = openSync(logPath, "w");
const display = process.env.MAPLE_TARGET_DISPLAY || ":1";
const networkNamespace = process.env.MAPLE_NETWORK_NAMESPACE || "mapleproxy";
const wineDebug = process.env.MAPLE_WINEDEBUG || "-all";
const dllOverrides = process.env.WINEDLLOVERRIDES || "";
const wineDllPath = process.env.WINEDLLPATH || "";

const child = spawn("sudo", [
  "-n",
  ...(process.env.MAPLE_PATCH_HTTPAPI === "1" ? [
    "unshare", "--mount", "--propagation", "private",
    "/home/sdancer/ms/tools/maplestory_classic_server/tools/run_with_patched_httpapi.sh",
  ] : []),
  "ip", "netns", "exec", networkNamespace,
  "sudo", "-n", "-u", "sdancer", "env",
  `DISPLAY=${display}`,
  "XAUTHORITY=/home/sdancer/.Xauthority",
  `WINEPREFIX=${prefix}`,
  `WINEDEBUG=${wineDebug}`,
  `WINEDLLOVERRIDES=${dllOverrides}`,
  `WINEDLLPATH=${wineDllPath}`,
  "wine", executable, ...gameArguments,
], {
  cwd: gameDirectory,
  detached: true,
  stdio: ["ignore", log, log],
});
child.unref();
console.log(JSON.stringify({started: true, pid: child.pid, argumentCount: gameArguments.length}));
