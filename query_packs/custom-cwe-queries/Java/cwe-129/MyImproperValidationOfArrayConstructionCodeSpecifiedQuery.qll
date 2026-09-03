import MySources
import MySinks
import MySummaries
/** Provides a dataflow configuration to reason about improper validation of code-specified size used for array construction. */

import java
private import semmle.code.java.security.internal.ArraySizing
private import semmle.code.java.dataflow.TaintTracking

/**
 * A dataflow configuration to reason about improper validation of code-specified size used for array construction.
 */
module BoundedFlowSourceConfig implements DataFlow::ConfigSig {






  predicate isSource(DataFlow::Node source) {
    source instanceof BoundedFlowSource and
    // There is not a fixed lower bound which is greater than zero.
    not source.(BoundedFlowSource).lowerBound() > 0
  or isFixSource(source)
}

  predicate isSink(DataFlow::Node sink) {
    any(CheckableArrayAccess caa).canThrowOutOfBoundsDueToEmptyArray(sink.asExpr(), _)
  or isFixSink(sink)
}







predicate isAdditionalFlowStep(DataFlow::Node n1, DataFlow::Node n2) {
  isFixStep(n1, n2)
}




}

/**
 * Dataflow flow for improper validation of code-specified size used for array construction.
 */
module BoundedFlowSourceFlow = DataFlow::Global<BoundedFlowSourceConfig>;
