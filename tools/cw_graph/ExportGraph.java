// Export every discovered function, decompile each body, and preserve call sites.
// @category CW.Graph
import ghidra.app.script.GhidraScript;
import ghidra.app.decompiler.*;
import ghidra.program.model.address.*;
import ghidra.program.model.listing.*;
import ghidra.program.model.symbol.*;
import ghidra.util.task.TaskMonitor;
import com.google.gson.Gson;
import java.io.*;
import java.nio.charset.StandardCharsets;
import java.nio.file.*;
import java.util.*;
import java.util.concurrent.*;
import java.util.concurrent.atomic.AtomicInteger;

public class ExportGraph extends GhidraScript {
    private final Gson gson = new Gson();
    private String binary;
    private Address base;
    private String rva(Address address) {
        return "0x" + Long.toUnsignedString(address.subtract(base), 16);
    }
    private String id(Function function) {
        if (!function.isExternal()) return binary + ":" + rva(function.getEntryPoint());
        ExternalLocation loc = currentProgram.getExternalManager().getExternalLocation(function.getSymbol());
        String library = loc == null ? "unknown" : loc.getLibraryName();
        String name = loc == null ? function.getName() : loc.getLabel();
        return "external:" + library.toLowerCase(Locale.ROOT) + "!" + name;
    }
    private Map<String,Object> functionRecord(Function function) {
        Map<String,Object> row = new LinkedHashMap<>();
        row.put("id", id(function)); row.put("binary_id", binary);
        row.put("name", function.getName()); row.put("qualified_name", function.getName(true));
        row.put("address", function.getEntryPoint().toString());
        row.put("rva", function.isExternal() ? "" : rva(function.getEntryPoint()));
        row.put("size", function.getBody().getNumAddresses());
        row.put("signature", function.getSignature().toString());
        row.put("external", function.isExternal()); row.put("thunk", function.isThunk());
        List<List<String>> ranges = new ArrayList<>();
        if (!function.isExternal()) for (AddressRange range : function.getBody().getAddressRanges()) {
            ranges.add(Arrays.asList(rva(range.getMinAddress()), rva(range.getMaxAddress())));
        }
        row.put("ranges", ranges);
        return row;
    }
    private synchronized void emit(BufferedWriter out, Object row) throws IOException {
        out.write(gson.toJson(row)); out.newLine();
    }
    @Override public void run() throws Exception {
        String[] args = getScriptArgs();
        if (args.length < 2) throw new IllegalArgumentException("output_dir binary_sha256 [workers] [timeout]");
        Path output = Paths.get(args[0]); Files.createDirectories(output);
        binary = args[1]; base = currentProgram.getImageBase();
        int workers = args.length > 2 ? Integer.parseInt(args[2]) : 6;
        int timeout = args.length > 3 ? Integer.parseInt(args[3]) : 60;
        FunctionManager fm = currentProgram.getFunctionManager();
        List<Function> functions = new ArrayList<>();
        Set<String> externalIds = new HashSet<>();
        try (BufferedWriter out = Files.newBufferedWriter(output.resolve("external.jsonl"), StandardCharsets.UTF_8)) {
            FunctionIterator external = fm.getExternalFunctions();
            while (external.hasNext()) {
                Function f = external.next();
                if (externalIds.add(id(f))) {
                    Map<String,Object> row = functionRecord(f);
                    row.put("status", "external"); row.put("c", ""); row.put("error", "No body in this module");
                    emit(out, row);
                }
            }
        }
        FunctionIterator iterator = fm.getFunctions(true);
        while (iterator.hasNext()) functions.add(iterator.next());
        try (BufferedWriter out = Files.newBufferedWriter(output.resolve("function-index.jsonl"), StandardCharsets.UTF_8)) {
            for (Function f : functions) {
                Map<String,Object> row = functionRecord(f);
                row.put("status", "pending"); row.put("c", ""); row.put("error", "Decompilation pending");
                emit(out, row);
            }
        }
        try (BufferedWriter out = Files.newBufferedWriter(output.resolve("thunks.jsonl"), StandardCharsets.UTF_8)) {
            for (Function f : functions) {
                if (!f.isThunk()) continue;
                Function target = f.getThunkedFunction(false);
                if (target != null && !target.equals(f)) emit(out, Map.of("from", id(f), "to", id(target)));
            }
        }
        println("CW_EXPORT functions=" + functions.size() + " external=" + externalIds.size());
        long callsites = 0, resolved = 0, unresolved = 0;
        try (BufferedWriter out = Files.newBufferedWriter(output.resolve("calls.jsonl"), StandardCharsets.UTF_8)) {
            for (Function f : functions) {
                monitor.checkCancelled();
                InstructionIterator instructions = currentProgram.getListing().getInstructions(f.getBody(), true);
                while (instructions.hasNext()) {
                    Instruction instruction = instructions.next();
                    FlowType flow = instruction.getFlowType();
                    boolean call = flow.isCall();
                    boolean tail = flow.isJump() && !flow.isConditional() && !flow.isComputed();
                    if (!call && !tail) continue;
                    Map<String,Function> targets = new LinkedHashMap<>();
                    for (Reference ref : instruction.getReferencesFrom()) {
                        Function target = fm.getReferencedFunction(ref.getToAddress());
                        if (target != null && (call || !target.equals(f))) targets.put(id(target), target);
                    }
                    for (Address address : instruction.getFlows()) {
                        Function target = fm.getFunctionAt(address);
                        if (target != null && (call || !target.equals(f))) targets.put(id(target), target);
                    }
                    // Ordinary intra-function jumps are not call edges.
                    if (tail && targets.isEmpty()) continue;
                    Map<String,Object> row = new LinkedHashMap<>();
                    row.put("id", binary + ":call:" + rva(instruction.getAddress()));
                    row.put("binary_id", binary); row.put("caller", id(f));
                    row.put("rva", rva(instruction.getAddress()));
                    row.put("address", instruction.getAddress().toString());
                    row.put("instruction", instruction.toString());
                    row.put("kind", tail ? "tail_call" : flow.isComputed() ? "indirect" : "direct");
                    row.put("targets", new ArrayList<>(targets.keySet()));
                    emit(out, row); callsites++;
                    if (targets.isEmpty()) unresolved++; else resolved++;
                }
            }
        }
        println("CW_CALLS sites=" + callsites + " resolved=" + resolved + " unresolved=" + unresolved);
        final AtomicInteger cursor = new AtomicInteger(), done = new AtomicInteger(), ok = new AtomicInteger();
        final AtomicInteger failed = new AtomicInteger();
        // A partial file is never mistaken for a completed module; summary.json is committed last.
        try (BufferedWriter out = Files.newBufferedWriter(output.resolve("functions.jsonl"), StandardCharsets.UTF_8)) {
            ExecutorService pool = Executors.newFixedThreadPool(workers);
            List<Future<?>> futures = new ArrayList<>();
            for (int worker = 0; worker < workers; worker++) futures.add(pool.submit(() -> {
                DecompInterface decompiler = new DecompInterface();
                DecompileOptions options = new DecompileOptions(); options.grabFromProgram(currentProgram);
                decompiler.setOptions(options); decompiler.toggleCCode(true); decompiler.toggleSyntaxTree(false);
                try {
                    if (!decompiler.openProgram(currentProgram)) throw new IOException(decompiler.getLastMessage());
                    int position;
                    while ((position = cursor.getAndIncrement()) < functions.size()) {
                        Function f = functions.get(position);
                        Map<String,Object> row = functionRecord(f);
                        try {
                            DecompileResults result = decompiler.decompileFunction(f, timeout, TaskMonitor.DUMMY);
                            String c = result.decompileCompleted() && result.getDecompiledFunction() != null
                                ? result.getDecompiledFunction().getC() : "";
                            boolean completed = !c.isEmpty();
                            row.put("status", completed ? "ok" : result.isTimedOut() ? "timeout" : "failed");
                            row.put("c", c); row.put("error", result.getErrorMessage());
                            if (completed) ok.incrementAndGet(); else failed.incrementAndGet();
                        } catch (Exception ex) {
                            row.put("status", "failed"); row.put("c", ""); row.put("error", ex.toString());
                            failed.incrementAndGet();
                        }
                        emit(out, row);
                        int count = done.incrementAndGet();
                        if (count % 1000 == 0 || count == functions.size()) {
                            synchronized (ExportGraph.this) { out.flush(); }
                            println("CW_DECOMPILE done=" + count + "/" + functions.size() + " ok=" + ok.get() + " failed=" + failed.get());
                        }
                        if (count % 100 == 0) decompiler.flushCache();
                    }
                } finally { decompiler.dispose(); }
                return null;
            }));
            pool.shutdown();
            for (Future<?> future : futures) future.get();
        }
        Map<String,Object> summary = new LinkedHashMap<>();
        summary.put("binary_id", binary); summary.put("name", currentProgram.getName());
        summary.put("image_base", base.toString()); summary.put("language", currentProgram.getLanguageID().toString());
        summary.put("functions", functions.size()); summary.put("external_functions", externalIds.size());
        summary.put("decompiled", ok.get()); summary.put("failed", failed.get());
        summary.put("callsites", callsites); summary.put("resolved_callsites", resolved);
        summary.put("unresolved_callsites", unresolved);
        Files.writeString(output.resolve("summary.json"), gson.toJson(summary) + "\n", StandardCharsets.UTF_8);
        println("CW_COMPLETE " + gson.toJson(summary));
    }
}
