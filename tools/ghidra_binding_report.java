//@category GP180
import ghidra.app.decompiler.*;
import ghidra.app.script.GhidraScript;
import ghidra.program.model.address.*;
import ghidra.program.model.listing.*;
import ghidra.program.model.mem.*;
import ghidra.program.model.symbol.*;
import java.util.*;

public class ghidra_binding_report extends GhidraScript {

    public void run() throws Exception {
        String[] needles = {
            "writeParameter",
            "parseParameters",
            "getAlgsByModuleIdAndFxId",
            "getFxIdByModuleIdAndTypeName",
        };
        DecompInterface decomp = new DecompInterface();
        decomp.openProgram(currentProgram);
        Listing listing = currentProgram.getListing();
        for (String needle : needles) {
            println("\n=== " + needle + " ===");
            DataIterator data = listing.getDefinedData(true);
            while (data.hasNext() && !monitor.isCancelled()) {
                Data d = data.next();
                if (!d.hasStringValue()) continue;
                String value = String.valueOf(d.getValue());
                if (!value.contains(needle)) continue;
                println("string " + d.getAddress() + ": " + value);
                Reference[] refs = getReferencesTo(d.getAddress());
                for (Reference ref : refs) {
                    Function f = listing.getFunctionContaining(
                        ref.getFromAddress()
                    );
                    println(
                        "  ref " +
                            ref.getFromAddress() +
                            " function=" +
                            (f == null ? "<none>" : f.getEntryPoint())
                    );
                    if (f != null) {
                        DecompileResults result = decomp.decompileFunction(
                            f,
                            30,
                            monitor
                        );
                        if (result.decompileCompleted()) {
                            println(result.getDecompiledFunction().getC());
                        }
                    }
                }
            }
        }
        decomp.dispose();
    }
}
