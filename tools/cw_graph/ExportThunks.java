// Export known thunk forwarding targets without rerunning analysis/decompilation.
// @category CW.Graph
import ghidra.app.script.GhidraScript;
import ghidra.program.model.listing.*;
import ghidra.program.model.symbol.ExternalLocation;
import com.google.gson.Gson;
import java.io.*;
import java.nio.charset.StandardCharsets;
import java.nio.file.*;
import java.util.*;

public class ExportThunks extends GhidraScript {
    private String binary;
    private String id(Function function) {
        if (!function.isExternal()) return binary + ":0x" + Long.toUnsignedString(
            function.getEntryPoint().subtract(currentProgram.getImageBase()), 16);
        ExternalLocation loc = currentProgram.getExternalManager().getExternalLocation(function.getSymbol());
        String library = loc == null ? "unknown" : loc.getLibraryName();
        String name = loc == null ? function.getName() : loc.getLabel();
        return "external:" + library.toLowerCase(Locale.ROOT) + "!" + name;
    }
    @Override public void run() throws Exception {
        String[] args = getScriptArgs(); binary = args[1];
        Gson gson = new Gson(); int count = 0;
        Path destination = Paths.get(args[0], "thunks.jsonl");
        Path staging = Paths.get(args[0], "thunks.jsonl.partial");
        try (BufferedWriter out = Files.newBufferedWriter(staging, StandardCharsets.UTF_8)) {
            FunctionIterator functions = currentProgram.getFunctionManager().getFunctions(true);
            while (functions.hasNext()) {
                Function f = functions.next();
                if (!f.isThunk()) continue;
                Function target = f.getThunkedFunction(false);
                if (target == null || target.equals(f)) continue;
                out.write(gson.toJson(Map.of("from", id(f), "to", id(target)))); out.newLine(); count++;
            }
        }
        Files.move(staging, destination, StandardCopyOption.REPLACE_EXISTING);
        println("CW_THUNKS count=" + count);
    }
}
