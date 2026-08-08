"use strict";

const CLASS_NAME =
  "b9e4d430c4a28790f54a8a9fe532d8350c30e9e1a98f418c9035a0543963dbd";
const FIELDS = [
  ["ecb3d34e8cde36985207208f8b876fe9e7734063d80e6d5eaa459428f84074e", 1],
  ["bf399f18fa8f54a7ebc0632f985b7077ee0bf74e31b1c69a396ef59656912d5", 1],
  ["fbdcb21ddbd60e1ad7d516ab7f01d2b7da31d24c44eff30b2495e66c7501ec2", 1],
  ["c580e7accba370372b979ae53076accb4a41dee89b07ae39cfbee759ed565c3", 1],
  ["ef25d1812c7a31dc9364d1063ec19d5238318f914f9c19f3f64161ccd2854ad", 1],
  ["c870d0b355fb42339814f2b305609476df76f5f74ed0bda194d11e80d6c0776", 4],
];

const RVAS = {
  assemblyGetImage: 0x3fd740,
  classFromName: 0x425ec0,
  classGetFieldFromName: 0x425f40,
  classGetName: 0x425f70,
  classGetNamespace: 0x425f80,
  domainAssemblyOpen: 0x426f10,
  domainGet: 0x426f00,
  fieldStaticGetValue: 0x427250,
  imageGetClass: 0x427ca0,
  imageGetClassCount: 0x427c90,
  runtimeClassInit: 0x38e700,
};

function api(base, rva, returnType, argumentTypes) {
  return new NativeFunction(base.add(rva), returnType, argumentTypes, "win64");
}

function requirePointer(value, label) {
  if (value.isNull()) {
    throw new Error(`${label} returned null`);
  }
  return value;
}

function findCipherClass(image, functions) {
  const emptyNamespace = Memory.allocUtf8String("");
  const className = Memory.allocUtf8String(CLASS_NAME);
  let klass = functions.classFromName(image, emptyNamespace, className);
  if (!klass.isNull()) {
    return klass;
  }

  const countValue = functions.imageGetClassCount(image);
  const count = typeof countValue === "number" ? countValue : countValue.toNumber();
  send({ type: "status", message: `direct lookup missed; enumerating ${count} classes` });
  for (let index = 0; index < count; index += 1) {
    const candidate = functions.imageGetClass(image, index);
    if (candidate.isNull()) {
      continue;
    }
    const name = functions.classGetName(candidate).readUtf8String();
    if (name !== CLASS_NAME) {
      continue;
    }
    const namespace = functions.classGetNamespace(candidate).readUtf8String();
    send({ type: "status", message: `enumeration match index=${index} namespace=${JSON.stringify(namespace)}` });
    klass = candidate;
    break;
  }
  return requirePointer(klass, "cipher class lookup and enumeration");
}

function dump() {
  const module = Process.enumerateModules().find(
    (candidate) => candidate.name.toLowerCase() === "gameassembly.dll",
  );
  if (module === undefined) {
    throw new Error("GameAssembly.dll is not loaded");
  }
  const base = module.base;
  const functions = {
    assemblyGetImage: api(base, RVAS.assemblyGetImage, "pointer", ["pointer"]),
    classFromName: api(base, RVAS.classFromName, "pointer", ["pointer", "pointer", "pointer"]),
    classGetFieldFromName: api(base, RVAS.classGetFieldFromName, "pointer", ["pointer", "pointer"]),
    classGetName: api(base, RVAS.classGetName, "pointer", ["pointer"]),
    classGetNamespace: api(base, RVAS.classGetNamespace, "pointer", ["pointer"]),
    domainAssemblyOpen: api(base, RVAS.domainAssemblyOpen, "pointer", ["pointer", "pointer"]),
    domainGet: api(base, RVAS.domainGet, "pointer", []),
    fieldStaticGetValue: api(base, RVAS.fieldStaticGetValue, "void", ["pointer", "pointer"]),
    imageGetClass: api(base, RVAS.imageGetClass, "pointer", ["pointer", "ulong"]),
    imageGetClassCount: api(base, RVAS.imageGetClassCount, "ulong", ["pointer"]),
    runtimeClassInit: api(base, RVAS.runtimeClassInit, "void", ["pointer"]),
  };

  const domain = requirePointer(functions.domainGet(), "il2cpp_domain_get");
  let assembly = NULL;
  let image = NULL;
  let selectedName = "";
  for (const name of ["Framework.dll", "Framework"]) {
    const candidateAssembly = functions.domainAssemblyOpen(
      domain,
      Memory.allocUtf8String(name),
    );
    const candidateImage = candidateAssembly.isNull()
      ? NULL
      : functions.assemblyGetImage(candidateAssembly);
    send({
      type: "status",
      message: `assembly_candidate=${name} assembly=${candidateAssembly} image=${candidateImage}`,
    });
    if (!candidateImage.isNull()) {
      assembly = candidateAssembly;
      image = candidateImage;
      selectedName = name;
      break;
    }
  }
  requirePointer(image, "Framework assembly image lookup");
  const klass = findCipherClass(image, functions);
  functions.runtimeClassInit(klass);
  send({
    type: "status",
    message: `base=${base} assembly_name=${selectedName} domain=${domain} class=${klass}`,
  });

  for (const [fieldName, elementSize] of FIELDS) {
    const field = functions.classGetFieldFromName(
      klass,
      Memory.allocUtf8String(fieldName),
    );
    requirePointer(field, `field lookup ${fieldName}`);
    const output = Memory.alloc(Process.pointerSize);
    output.writePointer(NULL);
    functions.fieldStaticGetValue(field, output);
    const array = requirePointer(output.readPointer(), `static array ${fieldName}`);
    const lengthValue = array.add(0x18).readU64();
    const length = lengthValue.toNumber();
    const byteLength = length * elementSize;
    const data = array.add(0x20).readByteArray(byteLength);
    send(
      {
        type: "array",
        field: fieldName,
        element_size: elementSize,
        elements: length,
        bytes: byteLength,
      },
      data,
    );
  }
  send({ type: "complete" });
}

setImmediate(() => {
  try {
    dump();
  } catch (error) {
    send({ type: "error", message: error.stack || String(error) });
  }
});
