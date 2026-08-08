#!/usr/bin/env node

import {createHash} from "node:crypto";
import {spawn} from "node:child_process";
import {
  mkdir,
  open,
  readFile,
  rename,
  stat,
  unlink,
  writeFile,
} from "node:fs/promises";
import path from "node:path";
import {inflateSync} from "node:zlib";

const args = process.argv.slice(2);
const option = (name, fallback) => {
  const index = args.indexOf(name);
  return index === -1 ? fallback : args[index + 1];
};

const manifestPath = option("--manifest");
const outputRoot = path.resolve(option("--output", "maplestory_classic_manual"));
const baseUrl = option(
  "--base-url",
  "https://tw-ngm.maplestoryclassic.games.gamania.com",
).replace(/\/$/, "");
const proxy = option("--proxy", "");
const concurrency = Math.max(1, Number(option("--concurrency", "4")) || 4);
const extensions = option("--extensions", "")
  .split(",")
  .map((value) => value.trim().toLowerCase())
  .filter(Boolean)
  .map((value) => (value.startsWith(".") ? value : `.${value}`));

if (!manifestPath) {
  console.error(
    "Usage: manual_ngm_extract.mjs --manifest FILE [--output DIR] " +
      "[--extensions .exe,.dll] [--proxy URL] [--concurrency N]",
  );
  process.exit(2);
}

const manifest = JSON.parse(await readFile(manifestPath, "utf8"));
const objectCache = path.join(outputRoot, ".ngm-objects");
await mkdir(objectCache, {recursive: true});

const sha1 = (value) => createHash("sha1").update(value).digest("hex");
const decodeName = (encodedName) =>
  Buffer.from(encodedName, "base64").toString("utf8").replaceAll("\\", "/");

const files = Object.entries(manifest.files)
  .map(([encodedName, metadata]) => ({
    encodedName,
    relativePath: decodeName(encodedName),
    metadata,
  }))
  .filter(({relativePath}) => {
    if (!extensions.length) return true;
    return extensions.includes(path.extname(relativePath).toLowerCase());
  });

for (const {relativePath} of files) {
  if (
    path.isAbsolute(relativePath) ||
    relativePath.split("/").some((part) => part === "..")
  ) {
    throw new Error(`Unsafe manifest path: ${relativePath}`);
  }
}

const selectedCompressedBytes = files.reduce(
  (sum, {metadata}) => sum + metadata.compressed_size,
  0,
);
console.log(
  `Selected ${files.length} files (${selectedCompressedBytes.toLocaleString()} compressed bytes)`,
);

async function download(url) {
  const curlArgs = [
    "--fail",
    "--silent",
    "--show-error",
    "--location",
    "--retry",
    "3",
    "--retry-all-errors",
    "--connect-timeout",
    "20",
    "--max-time",
    "180",
  ];
  if (proxy) curlArgs.push("--proxy", proxy);
  curlArgs.push(url);

  return await new Promise((resolve, reject) => {
    const child = spawn("curl", curlArgs, {stdio: ["ignore", "pipe", "pipe"]});
    const chunks = [];
    const errors = [];
    child.stdout.on("data", (chunk) => chunks.push(chunk));
    child.stderr.on("data", (chunk) => errors.push(chunk));
    child.on("error", reject);
    child.on("close", (code) => {
      if (code === 0) resolve(Buffer.concat(chunks));
      else reject(new Error(Buffer.concat(errors).toString("utf8").trim() || `curl exited ${code}`));
    });
  });
}

async function readCachedObject(cachePath, expectedSize) {
  try {
    const info = await stat(cachePath);
    if (info.size !== expectedSize) return null;
    return await readFile(cachePath);
  } catch (error) {
    if (error.code === "ENOENT") return null;
    throw error;
  }
}

async function getObject(encodedName, index, objectHash, compressedSize) {
  const cachePath = path.join(objectCache, `${objectHash}.nxgz`);
  let compressed = await readCachedObject(cachePath, compressedSize);
  if (!compressed) {
    const objectName = `${encodedName}.${index}.${objectHash}.nxgz`;
    compressed = await download(`${baseUrl}/${objectName}`);
    if (compressed.length !== compressedSize) {
      throw new Error(
        `${objectName}: expected ${compressedSize} compressed bytes, got ${compressed.length}`,
      );
    }
    const temporaryPath = `${cachePath}.${process.pid}.part`;
    await writeFile(temporaryPath, compressed);
    await rename(temporaryPath, cachePath);
  }

  const uncompressed = inflateSync(compressed);
  const actualHash = sha1(uncompressed);
  if (actualHash !== objectHash) {
    await unlink(cachePath).catch(() => {});
    throw new Error(`${encodedName}.${index}: SHA-1 mismatch`);
  }
  return uncompressed;
}

async function existingFileIsValid(filePath, metadata, orderedObjects) {
  try {
    const info = await stat(filePath);
    if (info.size !== metadata.uncompressed_size) return false;
  } catch (error) {
    if (error.code === "ENOENT") return false;
    throw error;
  }

  const handle = await open(filePath, "r");
  try {
    for (const [index, expectedHash] of orderedObjects) {
      const offset = index * manifest.chunk_size;
      const length = Math.min(manifest.chunk_size, metadata.uncompressed_size - offset);
      const buffer = Buffer.allocUnsafe(length);
      const {bytesRead} = await handle.read(buffer, 0, length, offset);
      if (bytesRead !== length || sha1(buffer) !== expectedHash) return false;
    }
    return true;
  } finally {
    await handle.close();
  }
}

async function extractFile({encodedName, relativePath, metadata}) {
  const orderedObjects = Object.entries(metadata.objects)
    .map(([index, hash]) => [Number(index), hash])
    .sort(([left], [right]) => left - right);
  const objectListHash = sha1(orderedObjects.map(([, hash]) => hash).join(""));
  if (objectListHash !== metadata.hash) {
    throw new Error(`${relativePath}: manifest object-list hash mismatch`);
  }

  const outputPath = path.join(outputRoot, ...relativePath.split("/"));
  if (await existingFileIsValid(outputPath, metadata, orderedObjects)) {
    console.log(`skip ${relativePath}`);
    return;
  }

  await mkdir(path.dirname(outputPath), {recursive: true});
  const temporaryPath = `${outputPath}.part`;
  const handle = await open(temporaryPath, "w");
  let totalBytes = 0;
  try {
    for (const [index, objectHash] of orderedObjects) {
      const compressedSize = metadata.object_sizes[String(index)];
      const chunk = await getObject(encodedName, index, objectHash, compressedSize);
      await handle.write(chunk);
      totalBytes += chunk.length;
    }
  } finally {
    await handle.close();
  }

  if (totalBytes !== metadata.uncompressed_size) {
    throw new Error(
      `${relativePath}: expected ${metadata.uncompressed_size} bytes, wrote ${totalBytes}`,
    );
  }
  await rename(temporaryPath, outputPath);
  console.log(`done ${relativePath}`);
}

let cursor = 0;
let failure;
const workers = Array.from({length: concurrency}, async () => {
  while (!failure) {
    const index = cursor++;
    if (index >= files.length) return;
    try {
      await extractFile(files[index]);
    } catch (error) {
      failure = error;
    }
  }
});
await Promise.all(workers);
if (failure) throw failure;

console.log(`Extraction complete: ${outputRoot}`);
