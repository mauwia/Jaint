package com.javasecscan.analysis;

import soot.Local;
import soot.Unit;
import soot.Value;
import soot.jimple.AssignStmt;
import soot.jimple.CastExpr;
import soot.jimple.InstanceInvokeExpr;
import soot.jimple.InvokeExpr;
import soot.jimple.InvokeStmt;
import soot.jimple.Stmt;
import soot.toolkits.graph.DirectedGraph;
import soot.toolkits.scalar.ArraySparseSet;
import soot.toolkits.scalar.FlowSet;
import soot.toolkits.scalar.ForwardFlowAnalysis;

import java.util.Set;

/**
 * Intraprocedural forward taint analysis. A local becomes tainted when it is
 * assigned the return value of a source method; taint propagates through copy
 * assignments and casts. Sink detection is handled by the caller after the
 * analysis has converged.
 */
public class TaintFlowAnalysis extends ForwardFlowAnalysis<Unit, FlowSet<Local>> {

    private final Set<String> sourceSignatures;
    private final Set<String> sanitizerSignatures;

    public TaintFlowAnalysis(DirectedGraph<Unit> graph,
                             Set<String> sourceSignatures,
                             Set<String> sanitizerSignatures) {
        super(graph);
        this.sourceSignatures = sourceSignatures;
        this.sanitizerSignatures = sanitizerSignatures;
        doAnalysis();
    }

    @Override
    protected FlowSet<Local> newInitialFlow() {
        return new ArraySparseSet<>();
    }

    @Override
    protected FlowSet<Local> entryInitialFlow() {
        return new ArraySparseSet<>();
    }

    @Override
    protected void merge(FlowSet<Local> in1, FlowSet<Local> in2, FlowSet<Local> out) {
        in1.union(in2, out);
    }

    @Override
    protected void copy(FlowSet<Local> source, FlowSet<Local> dest) {
        source.copy(dest);
    }

    @Override
    protected void flowThrough(FlowSet<Local> in, Unit unit, FlowSet<Local> out) {
        in.copy(out);

        // Standalone sanitizer call (e.g. `validator.sanitize(input)`) — wash
        // the receiver and arguments so subsequent reads of those locals are clean.
        if (unit instanceof InvokeStmt invokeStmt) {
            InvokeExpr invoke = invokeStmt.getInvokeExpr();
            if (sanitizerSignatures.contains(invoke.getMethodRef().getSignature())) {
                applySanitizerScrub(invoke, out);
            }
            return;
        }

        if (!(unit instanceof AssignStmt assign)) return;

        Value lhs = assign.getLeftOp();
        Value rhs = assign.getRightOp();
        if (!(lhs instanceof Local lhsLocal)) return;

        if (rhs instanceof InvokeExpr invoke) {
            String sig = invoke.getMethodRef().getSignature();
            if (sanitizerSignatures.contains(sig)) {
                // Return value is clean and the receiver/args are scrubbed.
                applySanitizerScrub(invoke, out);
                out.remove(lhsLocal);
                return;
            }
            if (sourceSignatures.contains(sig)) {
                out.add(lhsLocal);
                return;
            }
            // Conservative: if any argument is tainted, propagate to return.
            for (Value arg : invoke.getArgs()) {
                if (arg instanceof Local l && in.contains(l)) {
                    out.add(lhsLocal);
                    return;
                }
            }
            // No taint introduced — make sure lhs is cleared.
            out.remove(lhsLocal);
        } else if (rhs instanceof Local rhsLocal) {
            if (in.contains(rhsLocal)) {
                out.add(lhsLocal);
            } else {
                out.remove(lhsLocal);
            }
        } else if (rhs instanceof CastExpr cast && cast.getOp() instanceof Local castLocal) {
            if (in.contains(castLocal)) {
                out.add(lhsLocal);
            } else {
                out.remove(lhsLocal);
            }
        } else {
            // Any other RHS overwrites tainted state.
            out.remove(lhsLocal);
        }
    }

    private void applySanitizerScrub(InvokeExpr invoke, FlowSet<Local> out) {
        for (Value arg : invoke.getArgs()) {
            if (arg instanceof Local l) out.remove(l);
        }
        if (invoke instanceof InstanceInvokeExpr inst
                && inst.getBase() instanceof Local base) {
            out.remove(base);
        }
    }

    @SuppressWarnings("unused")
    public boolean isSinkCall(Stmt stmt) {
        return stmt.containsInvokeExpr();
    }
}
