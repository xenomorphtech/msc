"use strict";

const RVAS = {
  assemblyGetImage: 0x3fd740,
  classFromName: 0x425ec0,
  classGetMethodFromName: 0x425f60,
  domainAssemblyOpen: 0x426f10,
  domainGet: 0x426f00,
};

let installed = false;
let attempts = 0;

function api(base, rva, returnType, argumentTypes) {
  return new NativeFunction(base.add(rva), returnType, argumentTypes, "win64");
}

function tryInstall() {
  if (installed) return;
  attempts += 1;
  try {
    const module = Process.enumerateModules().find(
      (candidate) => candidate.name.toLowerCase() === "gameassembly.dll",
    );
    if (module === undefined) throw new Error("GameAssembly.dll is not loaded");
    const functions = {
      assemblyGetImage: api(module.base, RVAS.assemblyGetImage, "pointer", ["pointer"]),
      classFromName: api(module.base, RVAS.classFromName, "pointer", ["pointer", "pointer", "pointer"]),
      classGetMethodFromName: api(module.base, RVAS.classGetMethodFromName, "pointer", ["pointer", "pointer", "int"]),
      domainAssemblyOpen: api(module.base, RVAS.domainAssemblyOpen, "pointer", ["pointer", "pointer"]),
      domainGet: api(module.base, RVAS.domainGet, "pointer", []),
    };
    const domain = functions.domainGet();
    if (domain.isNull()) throw new Error("IL2CPP domain is not ready");
    const assembly = functions.domainAssemblyOpen(domain, Memory.allocUtf8String("Ngsx.Runtime.dll"));
    if (assembly.isNull()) throw new Error("Ngsx.Runtime assembly is not ready");
    const image = functions.assemblyGetImage(assembly);
    if (image.isNull()) throw new Error("Ngsx.Runtime image is not ready");
    const klass = functions.classFromName(
      image,
      Memory.allocUtf8String("Ngsx.Platform"),
      Memory.allocUtf8String("NgsxWindows"),
    );
    if (klass.isNull()) throw new Error("NgsxWindows class is not ready");
    const methodInfo = functions.classGetMethodFromName(
      klass,
      Memory.allocUtf8String("ReadResult"),
      1,
    );
    if (methodInfo.isNull()) throw new Error("ReadResult method is not ready");
    const method = methodInfo.readPointer();
    if (method.isNull()) throw new Error("ReadResult method pointer is null");
    Interceptor.attach(method, {
      onLeave(retval) {
        if (retval.isNull()) {
          send({type: "result", null_result: true});
          return;
        }
        send({
          type: "result",
          null_result: false,
          is_ok: retval.add(0x10).readU8() !== 0,
          code: retval.add(0x14).readU32(),
        });
      },
    });
    installed = true;
    send({type: "status", message: `ngsx tracer installed after ${attempts} attempt(s)`});
  } catch (error) {
    if (attempts >= 300) {
      send({type: "error", message: error.stack || String(error)});
      return;
    }
    setTimeout(tryInstall, 100);
  }
}

setImmediate(tryInstall);
