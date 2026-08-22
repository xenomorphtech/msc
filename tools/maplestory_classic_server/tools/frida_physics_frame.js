"use strict";

const TARGETS = [
  ["Msc.Game.Object.Control", "VecCtrl", 1606],
  ["Msc.Game.Object.Control", "VecCtrlUser", 1630],
  ["Msc.Game.Object.Control", "VecCtrlMob", 1621],
];

const NESTED = [
  ["Msc.Game.Object.Control", "VecCtrl", "AbsPos", 1603],
  ["Msc.Game.Object.Control", "VecCtrl", "RelPos", 1604],
  ["Msc.Game.Object.Control", "VecCtrl", "FallDownData", 1605],
  ["Msc.Game.Object.Control", "VecCtrl", "ImpactNext", 1602],
];

const FIELD_STATIC = 0x0010;
const METHOD_STATIC = 0x0010;
const IL2CPP_TYPE_BOOLEAN = 0x02;
const IL2CPP_TYPE_I1 = 0x04;
const IL2CPP_TYPE_U1 = 0x05;
const IL2CPP_TYPE_I2 = 0x06;
const IL2CPP_TYPE_U2 = 0x07;
const IL2CPP_TYPE_I4 = 0x08;
const IL2CPP_TYPE_U4 = 0x09;
const IL2CPP_TYPE_I8 = 0x0a;
const IL2CPP_TYPE_U8 = 0x0b;
const IL2CPP_TYPE_R4 = 0x0c;
const IL2CPP_TYPE_R8 = 0x0d;
const IL2CPP_TYPE_STRING = 0x0e;
const IL2CPP_TYPE_VALUETYPE = 0x11;
const IL2CPP_TYPE_CLASS = 0x12;
const IL2CPP_TYPE_GENERICINST = 0x15;

function api(module, exportName, returnType, argumentTypes) {
  return new NativeFunction(
    module.getExportByName(exportName),
    returnType,
    argumentTypes,
    "win64",
  );
}

function requirePointer(value, label) {
  if (value.isNull()) {
    throw new Error(`${label} returned null`);
  }
  return value;
}

function readCString(pointer) {
  if (pointer.isNull()) {
    return null;
  }
  try {
    return pointer.readUtf8String();
  } catch (error) {
    return null;
  }
}

function typeName(functions, typePointer) {
  if (typePointer.isNull()) {
    return null;
  }
  const allocated = functions.typeGetName(typePointer);
  if (allocated.isNull()) {
    return null;
  }
  const name = readCString(allocated);
  functions.free(allocated);
  return name;
}

function enumerateIterated(getNext, klass) {
  const iter = Memory.alloc(Process.pointerSize);
  iter.writePointer(NULL);
  const items = [];
  while (true) {
    const item = getNext(klass, iter);
    if (item.isNull()) {
      break;
    }
    items.push(item);
  }
  return items;
}

function dumpFields(functions, klass) {
  return enumerateIterated(functions.classGetFields, klass).map((field) => {
    const typePointer = functions.fieldGetType(field);
    return {
      name: readCString(functions.fieldGetName(field)),
      offset: functions.fieldGetOffset(field),
      flags: functions.fieldGetFlags(field) >>> 0,
      type_enum: functions.typeGetType(typePointer),
      type: typeName(functions, typePointer),
    };
  });
}

function methodPointer(method) {
  return method.readPointer();
}

function dumpMethods(functions, klass) {
  return enumerateIterated(functions.classGetMethods, klass).map((method) => {
    const pointer = methodPointer(method);
    const implementationFlags = Memory.alloc(4);
    return {
      name: readCString(functions.methodGetName(method)),
      argc: functions.methodGetParamCount(method),
      flags: functions.methodGetFlags(method, implementationFlags) >>> 0,
      implementation_flags: implementationFlags.readU32(),
      pointer: pointer.isNull() ? null : pointer.toString(),
    };
  });
}

function dumpClass(functions, klass) {
  const parent = functions.classGetParent(klass);
  return {
    namespace: readCString(functions.classGetNamespace(klass)),
    name: readCString(functions.classGetName(klass)),
    parent: parent.isNull()
      ? null
      : `${readCString(functions.classGetNamespace(parent))}.${readCString(functions.classGetName(parent))}`,
    instance_size: functions.classInstanceSize(klass),
    address: klass.toString(),
    fields: dumpFields(functions, klass),
    methods: dumpMethods(functions, klass),
  };
}

function findClass(functions, image, namespaceName, className) {
  const klass = functions.classFromName(
    image,
    Memory.allocUtf8String(namespaceName),
    Memory.allocUtf8String(className),
  );
  return klass.isNull() ? null : klass;
}

function findNested(functions, parent, nestedName) {
  const matches = enumerateIterated(functions.classGetNestedTypes, parent).filter(
    (candidate) => readCString(functions.classGetName(candidate)) === nestedName,
  );
  return matches.length === 0 ? null : matches[0];
}

function isStaticField(field) {
  return (field.flags & FIELD_STATIC) !== 0;
}

function readPrimitive(instance, field) {
  const address = instance.add(field.offset);
  switch (field.type_enum) {
    case IL2CPP_TYPE_BOOLEAN:
    case IL2CPP_TYPE_I1:
      return address.readS8();
    case IL2CPP_TYPE_U1:
      return address.readU8();
    case IL2CPP_TYPE_I2:
      return address.readS16();
    case IL2CPP_TYPE_U2:
      return address.readU16();
    case IL2CPP_TYPE_I4:
      return address.readS32();
    case IL2CPP_TYPE_U4:
      return address.readU32();
    case IL2CPP_TYPE_I8:
      return address.readS64().toString();
    case IL2CPP_TYPE_U8:
      return address.readU64().toString();
    case IL2CPP_TYPE_R4:
      return address.readFloat();
    case IL2CPP_TYPE_R8:
      return address.readDouble();
    default:
      return undefined;
  }
}

function readString(instance, field) {
  const object = instance.add(field.offset).readPointer();
  return readManagedString(object);
}

function readManagedString(object) {
  if (object.isNull()) {
    return null;
  }
  const length = object.add(0x10).readS32();
  if (length <= 0 || length > 256) {
    return null;
  }
  return object.add(0x14).readUtf16String(length);
}

function interestingName(name) {
  if (!name) {
    return false;
  }
  return /pos|vel|speed|jump|fall|climb|fh|foot|hold|state|stance|input|action|move|x$|y$|vx|vy|dir|ladder|rope|knock|impact|abs|rel|tick|elapse|owner|template|object/i.test(
    name,
  );
}

function typeMatchesDump(typeNameValue, classDump) {
  if (!typeNameValue || !classDump) {
    return false;
  }
  return (
    typeNameValue === classDump.name ||
    typeNameValue === `${classDump.namespace}.${classDump.name}` ||
    typeNameValue.endsWith(`.${classDump.name}`) ||
    typeNameValue.endsWith(`+${classDump.name}`)
  );
}

function findClassDump(classByName, typeNameValue) {
  if (!typeNameValue) {
    return null;
  }
  const direct = classByName[typeNameValue];
  if (direct) {
    return direct;
  }
  for (const classDump of Object.values(classByName)) {
    if (typeMatchesDump(typeNameValue, classDump)) {
      return classDump;
    }
  }
  return null;
}

function snapshotObject(instance, classDump, classByName, depth) {
  if (instance.isNull() || depth < 0) {
    return null;
  }
  const values = {};
  for (const field of classDump.fields) {
    if (isStaticField(field) || field.offset < 0x10) {
      continue;
    }
    try {
      const outputName = field.semantic_name || field.name;
      const selected = field.semantic_name || interestingName(field.name);
      if (
        field.type_enum >= IL2CPP_TYPE_BOOLEAN &&
        field.type_enum <= IL2CPP_TYPE_R8
      ) {
        if (selected || field.type_enum >= IL2CPP_TYPE_R4) {
          values[outputName] = readPrimitive(instance, field);
        }
        continue;
      }
      if (field.type_enum === IL2CPP_TYPE_STRING && selected) {
        values[outputName] = readString(instance, field);
        continue;
      }
      if (
        (field.type_enum === IL2CPP_TYPE_CLASS ||
          field.type_enum === IL2CPP_TYPE_VALUETYPE ||
          field.type_enum === IL2CPP_TYPE_GENERICINST) &&
        selected
      ) {
        const childClass = findClassDump(classByName, field.type);
        if (field.type_enum === IL2CPP_TYPE_VALUETYPE && childClass) {
          values[outputName] = snapshotObject(
            // Il2Cpp field offsets for a value type include the 16-byte
            // boxed-object header. Inline structs do not carry that header.
            instance.add(field.offset - 0x10),
            childClass,
            classByName,
            depth - 1,
          );
        } else {
          const child = instance.add(field.offset).readPointer();
          values[outputName] = child.isNull() ? null : child.toString();
          if (!child.isNull() && childClass && depth > 0) {
            values[`${outputName}__fields`] = snapshotObject(
              child,
              childClass,
              classByName,
              depth - 1,
            );
          }
        }
      }
    } catch (error) {
      values[field.semantic_name || field.name] = null;
    }
  }
  return values;
}

function bindApis(module) {
  return {
    domainGet: api(module, "il2cpp_domain_get", "pointer", []),
    domainAssemblyOpen: api(module, "il2cpp_domain_assembly_open", "pointer", [
      "pointer",
      "pointer",
    ]),
    assemblyGetImage: api(module, "il2cpp_assembly_get_image", "pointer", ["pointer"]),
    classFromName: api(module, "il2cpp_class_from_name", "pointer", [
      "pointer",
      "pointer",
      "pointer",
    ]),
    classGetFields: api(module, "il2cpp_class_get_fields", "pointer", [
      "pointer",
      "pointer",
    ]),
    classGetMethods: api(module, "il2cpp_class_get_methods", "pointer", [
      "pointer",
      "pointer",
    ]),
    classGetName: api(module, "il2cpp_class_get_name", "pointer", ["pointer"]),
    classGetNamespace: api(module, "il2cpp_class_get_namespace", "pointer", ["pointer"]),
    classGetParent: api(module, "il2cpp_class_get_parent", "pointer", ["pointer"]),
    classInstanceSize: api(module, "il2cpp_class_instance_size", "int", ["pointer"]),
    classGetNestedTypes: api(module, "il2cpp_class_get_nested_types", "pointer", [
      "pointer",
      "pointer",
    ]),
    imageGetClassCount: api(module, "il2cpp_image_get_class_count", "uint", [
      "pointer",
    ]),
    imageGetClass: api(module, "il2cpp_image_get_class", "pointer", [
      "pointer",
      "uint",
    ]),
    fieldGetName: api(module, "il2cpp_field_get_name", "pointer", ["pointer"]),
    fieldGetOffset: api(module, "il2cpp_field_get_offset", "int", ["pointer"]),
    fieldGetType: api(module, "il2cpp_field_get_type", "pointer", ["pointer"]),
    fieldGetFlags: api(module, "il2cpp_field_get_flags", "int", ["pointer"]),
    methodGetName: api(module, "il2cpp_method_get_name", "pointer", ["pointer"]),
    methodGetParamCount: api(module, "il2cpp_method_get_param_count", "int", ["pointer"]),
    methodGetFlags: api(module, "il2cpp_method_get_flags", "uint", [
      "pointer",
      "pointer",
    ]),
    typeGetName: api(module, "il2cpp_type_get_name", "pointer", ["pointer"]),
    typeGetType: api(module, "il2cpp_type_get_type", "int", ["pointer"]),
    threadAttach: api(module, "il2cpp_thread_attach", "pointer", ["pointer"]),
    runtimeClassInit: api(module, "il2cpp_runtime_class_init", "void", ["pointer"]),
    objectGetClass: api(module, "il2cpp_object_get_class", "pointer", ["pointer"]),
    free: api(module, "il2cpp_free", "void", ["pointer"]),
  };
}

function openImage(functions, domain) {
  for (const name of ["Assembly-CSharp.dll", "Assembly-CSharp"]) {
    const assembly = functions.domainAssemblyOpen(
      domain,
      Memory.allocUtf8String(name),
    );
    if (assembly.isNull()) {
      continue;
    }
    const image = functions.assemblyGetImage(assembly);
    if (!image.isNull()) {
      return { name, image };
    }
  }
  throw new Error("Assembly-CSharp image was not found");
}

function install() {
  const module = Process.enumerateModules().find(
    (candidate) => candidate.name.toLowerCase() === "gameassembly.dll",
  );
  if (module === undefined) {
    throw new Error("GameAssembly.dll is not loaded");
  }
  const functions = bindApis(module);
  const domain = requirePointer(functions.domainGet(), "il2cpp_domain_get");
  functions.threadAttach(domain);
  const opened = openImage(functions, domain);
  const classCount = functions.imageGetClassCount(opened.image);
  const classes = [];
  const klassByKey = {};
  const classDumpByTypeName = {};
  const nestedByOriginalName = {};

  for (const [namespaceName, className, classIndex] of TARGETS) {
    const klass = functions.imageGetClass(opened.image, classIndex);
    if (klass.isNull()) {
      classes.push({
        namespace: namespaceName,
        name: className,
        class_index: classIndex,
        missing: true,
      });
      continue;
    }
    const dumped = dumpClass(functions, klass);
    dumped.original_namespace = namespaceName;
    dumped.original_name = className;
    dumped.class_index = classIndex;
    classes.push(dumped);
    klassByKey[`${namespaceName}.${className}`] = { klass, dumped };
    classDumpByTypeName[`${namespaceName}.${className}`] = dumped;
    classDumpByTypeName[`${dumped.namespace}.${dumped.name}`] = dumped;
    classDumpByTypeName[dumped.name] = dumped;
  }

  for (const [namespaceName, parentName, nestedName, classIndex] of NESTED) {
    const klass = functions.imageGetClass(opened.image, classIndex);
    if (klass.isNull()) {
      classes.push({
        namespace: `${namespaceName}.${parentName}`,
        name: nestedName,
        class_index: classIndex,
        missing: true,
      });
      continue;
    }
    const dumped = dumpClass(functions, klass);
    dumped.original_namespace = `${namespaceName}.${parentName}`;
    dumped.original_name = nestedName;
    dumped.class_index = classIndex;
    classes.push(dumped);
    classDumpByTypeName[`${dumped.namespace}.${dumped.name}`] = dumped;
    classDumpByTypeName[dumped.name] = dumped;
    nestedByOriginalName[nestedName] = dumped;
  }

  const baseEntry = klassByKey["Msc.Game.Object.Control.VecCtrl"];
  const semanticNestedFields = {
    AbsPos: "m_ap",
    RelPos: "m_rp",
    FallDownData: "fall_down",
    ImpactNext: "impact_next",
  };
  if (baseEntry) {
    for (const [originalName, semanticName] of Object.entries(
      semanticNestedFields,
    )) {
      const nestedDump = nestedByOriginalName[originalName];
      if (!nestedDump) {
        continue;
      }
      const matchingFields = baseEntry.dumped.fields
        .filter((field) => typeMatchesDump(field.type, nestedDump))
        .sort((left, right) => left.offset - right.offset);
      for (let index = 0; index < matchingFields.length; index += 1) {
        matchingFields[index].semantic_name =
          originalName === "AbsPos" && index > 0
            ? `m_ap_previous_${index}`
            : semanticName;
      }
    }
  }
  const coordinateFields = {
    AbsPos: ["x", "y", "vx", "vy"],
    RelPos: ["x", "y"],
  };
  for (const [originalName, semanticNames] of Object.entries(coordinateFields)) {
    const nestedDump = nestedByOriginalName[originalName];
    if (!nestedDump) {
      continue;
    }
    const numericFields = nestedDump.fields
      .filter(
        (field) =>
          !isStaticField(field) &&
          field.type_enum >= IL2CPP_TYPE_BOOLEAN &&
          field.type_enum <= IL2CPP_TYPE_R8,
      )
      .sort((left, right) => left.offset - right.offset);
    for (let index = 0; index < semanticNames.length; index += 1) {
      if (numericFields[index]) {
        numericFields[index].semantic_name = semanticNames[index];
      }
    }
  }

  send({
    type: "map",
    base: module.base.toString(),
    image: opened.name,
    class_count: classCount,
    classes,
  });

  const tracked = {
    player: new Map(),
    mob: new Map(),
  };
  let frame = 0;
  let lastEmit = 0;
  const minIntervalMs = 16;

  function classIsOrInherits(candidate, ancestor) {
    let current = candidate;
    for (let depth = 0; !current.isNull() && depth < 32; depth += 1) {
      if (current.equals(ancestor)) {
        return true;
      }
      current = functions.classGetParent(current);
    }
    return false;
  }

  function remember(kind, instance) {
    if (instance.isNull()) {
      return;
    }
    if (kind === "controller") {
      const actualClass = functions.objectGetClass(instance);
      const userEntry = klassByKey["Msc.Game.Object.Control.VecCtrlUser"];
      const mobEntry = klassByKey["Msc.Game.Object.Control.VecCtrlMob"];
      if (userEntry && classIsOrInherits(actualClass, userEntry.klass)) {
        kind = "player";
      } else if (mobEntry && classIsOrInherits(actualClass, mobEntry.klass)) {
        kind = "mob";
      } else {
        return;
      }
    }
    if (kind === "player" && !tracked.player.has(instance.toString())) {
      // A map/portal transition replaces VecCtrlUser. Never keep reading the
      // freed controller after the new live instance has appeared.
      tracked.player.clear();
    }
    tracked[kind].set(instance.toString(), instance);
    if (tracked[kind].size > 256) {
      const first = tracked[kind].keys().next().value;
      tracked[kind].delete(first);
    }
  }

  function emitFrame() {
    const now = Date.now();
    if (now - lastEmit < minIntervalMs) {
      return;
    }
    lastEmit = now;
    frame += 1;
    const playerDump = klassByKey["Msc.Game.Object.Control.VecCtrlUser"];
    const mobDump = klassByKey["Msc.Game.Object.Control.VecCtrlMob"];
    const controllerDump = klassByKey["Msc.Game.Object.Control.VecCtrl"];
    const player = [];
    if (playerDump) {
      for (const instance of tracked.player.values()) {
        player.push({
          ptr: instance.toString(),
          fields: Object.assign(
            {},
            controllerDump
              ? snapshotObject(
                  instance,
                  controllerDump.dumped,
                  classDumpByTypeName,
                  3,
                )
              : {},
            snapshotObject(instance, playerDump.dumped, classDumpByTypeName, 2),
          ),
        });
      }
    }
    const mobs = [];
    if (mobDump) {
      for (const instance of tracked.mob.values()) {
        mobs.push({
          ptr: instance.toString(),
          fields: Object.assign(
            {},
            controllerDump
              ? snapshotObject(
                  instance,
                  controllerDump.dumped,
                  classDumpByTypeName,
                  2,
                )
              : {},
            snapshotObject(instance, mobDump.dumped, classDumpByTypeName, 1),
          ),
        });
      }
    }
    send({
      type: "frame",
      frame,
      timestamp_ns: now * 1000000,
      player: player[0] || null,
      players: player,
      mobs,
    });
  }

  function hookClass(key, kind) {
    const entry = klassByKey[key];
    if (!entry) {
      return 0;
    }
    let hooked = 0;
    for (const method of entry.dumped.methods) {
      if (
        !method.pointer ||
        !method.name ||
        method.name.startsWith(".") ||
        (method.flags & METHOD_STATIC) !== 0
      ) {
        continue;
      }
      if (hookedPointers.has(method.pointer)) {
        continue;
      }
      try {
        let reportedHit = false;
        Interceptor.attach(ptr(method.pointer), {
          onEnter() {
            if (!reportedHit) {
              reportedHit = true;
              send({
                type: "status",
                message: `hook_hit class=${key} method=${method.name}`,
              });
            }
            remember(kind, this.context.rcx);
          },
          onLeave() {
            emitFrame();
          },
        });
        hookedPointers.add(method.pointer);
        hooked += 1;
      } catch (error) {
        hookFailures += 1;
      }
    }
    return hooked;
  }

  const hookedPointers = new Set();
  let hookFailures = 0;
  const hooked = {
    VecCtrlUser: hookClass("Msc.Game.Object.Control.VecCtrlUser", "player"),
    VecCtrlMob: 0,
    VecCtrl: 0,
  };
  send({ type: "hooks", hooked, failures: hookFailures });
}

function waitForGameAssembly() {
  const existing = Process.enumerateModules().find(
    (candidate) => candidate.name.toLowerCase() === "gameassembly.dll",
  );
  if (existing !== undefined) {
    install();
    return;
  }
  const listener = Interceptor.attach(
    Module.getExportByName("kernel32.dll", "LoadLibraryW"),
    {
      onLeave(retval) {
        if (retval.isNull()) {
          return;
        }
        const loaded = Process.enumerateModules().find(
          (candidate) => candidate.name.toLowerCase() === "gameassembly.dll",
        );
        if (loaded === undefined) {
          return;
        }
        listener.detach();
        setTimeout(() => {
          try {
            install();
          } catch (error) {
            send({ type: "error", message: error.stack || String(error) });
          }
        }, 1500);
      },
    },
  );
  send({ type: "status", message: "waiting for GameAssembly.dll" });
}

setImmediate(() => {
  try {
    waitForGameAssembly();
  } catch (error) {
    send({ type: "error", message: error.stack || String(error) });
  }
});
