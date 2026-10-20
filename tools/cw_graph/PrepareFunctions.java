// Seed native x64 function ranges from the on-disk .pdata section.
// @category CW.Graph
import ghidra.app.script.GhidraScript;
import ghidra.app.cmd.disassemble.DisassembleCommand;
import ghidra.program.model.address.*;
import ghidra.program.model.listing.*;
import ghidra.program.model.mem.MemoryBlock;
import ghidra.program.model.symbol.SourceType;
import java.util.*;

public class PrepareFunctions extends GhidraScript {
    @Override public void run() throws Exception {
        // Never fetch PDBs or modify the supplied binary on disk.
        for (String option : new String[]{"PDB Universal", "Decompiler Parameter ID"}) {
            try { setAnalysisOption(currentProgram, option, "false"); }
            catch (Exception ignored) { }
        }
        MemoryBlock pdata = currentProgram.getMemory().getBlock(".pdata");
        if (pdata == null || currentProgram.getDefaultPointerSize() != 8) return;
        Address base = currentProgram.getImageBase();
        FunctionManager fm = currentProgram.getFunctionManager();
        AddressSet seeds = new AddressSet();
        Map<Long, long[]> records = new LinkedHashMap<>();
        int created = 0, existing = 0, rejected = 0;
        for (long pos = 0; pos + 12 <= pdata.getSize(); pos += 12) {
            monitor.checkCancelled();
            Address at = pdata.getStart().add(pos);
            long begin = Integer.toUnsignedLong(currentProgram.getMemory().getInt(at));
            long end = Integer.toUnsignedLong(currentProgram.getMemory().getInt(at.add(4)));
            long unwind = Integer.toUnsignedLong(currentProgram.getMemory().getInt(at.add(8)));
            if (begin == 0 || begin >= end || end - begin > 0x1000000L) { rejected++; continue; }
            Address entry, last;
            try { entry = base.add(begin); last = base.add(end - 1); }
            catch (Exception ex) { rejected++; continue; }
            MemoryBlock block = currentProgram.getMemory().getBlock(entry);
            if (block == null || !block.isExecute() || !block.isInitialized() ||
                !block.contains(last) || !currentProgram.getMemory().contains(base.add(unwind))) {
                rejected++; continue;
            }
            records.put(begin, new long[]{begin, end, unwind});
        }
        Map<Long, AddressSet> bodies = new LinkedHashMap<>();
        int chained = 0;
        for (long[] record : records.values()) {
            long root = record[0];
            long[] cursor = record;
            Set<Long> seen = new HashSet<>();
            while (seen.add(cursor[0])) {
                Address unwind = base.add(cursor[2]);
                int flags = Byte.toUnsignedInt(currentProgram.getMemory().getByte(unwind)) >>> 3;
                if ((flags & 4) == 0) break;
                int codes = Byte.toUnsignedInt(currentProgram.getMemory().getByte(unwind.add(2)));
                Address chain = unwind.add(4 + ((codes + 1) & ~1) * 2);
                long parent = Integer.toUnsignedLong(currentProgram.getMemory().getInt(chain));
                if (!records.containsKey(parent)) break;
                root = parent; cursor = records.get(parent);
            }
            if (root != record[0]) chained++;
            bodies.computeIfAbsent(root, unused -> new AddressSet()).add(base.add(record[0]), base.add(record[1] - 1));
            seeds.add(base.add(record[0]));
        }
        // Chained unwind ranges are fragments of their parent, not independent functions.
        for (long entry : records.keySet()) {
            if (!bodies.containsKey(entry)) {
                Function fragment = fm.getFunctionAt(base.add(entry));
                if (fragment != null && fragment.getSymbol().getSource() != SourceType.USER_DEFINED)
                    fm.removeFunction(fragment.getEntryPoint());
            }
        }
        for (Map.Entry<Long, AddressSet> item : bodies.entrySet()) {
            Address entry = base.add(item.getKey());
            Function found = fm.getFunctionAt(entry);
            if (found != null) {
                try { found.setBody(found.getBody().union(item.getValue())); }
                catch (Exception ignored) { }
                existing++; continue;
            }
            try {
                fm.createFunction(null, entry, item.getValue(), SourceType.ANALYSIS);
                created++;
            } catch (Exception ex) { rejected++; }
        }
        println("CW_PDATA records=" + records.size() + " chained_fragments=" + chained +
                " created=" + created + " existing=" + existing + " rejected=" + rejected);
        if (!seeds.isEmpty()) {
            DisassembleCommand cmd = new DisassembleCommand(seeds, null, true);
            cmd.applyTo(currentProgram, monitor);
        }
        println("CW_PDATA disassembly seeded; functions=" + fm.getFunctionCount());
    }
}
