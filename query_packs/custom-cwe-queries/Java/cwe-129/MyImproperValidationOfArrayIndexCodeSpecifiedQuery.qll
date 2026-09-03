import MySources
import MySinks
import MySummaries
/** Provides a dataflow configuration to reason about improper validation of code-specified array index. */

import java
private import semmle.code.java.security.internal.ArraySizing
private import semmle.code.java.security.internal.BoundingChecks
private import semmle.code.java.dataflow.DataFlow

/**
 * A dataflow configuration to reason about improper validation of code-specified array index.
 */
module BoundedFlowSourceConfig implements DataFlow::ConfigSig {






  predicate isSource(DataFlow::Node source) { source instanceof BoundedFlowSource
  or isFixSource(source)
}

  predicate isSink(DataFlow::Node sink) {
    exists(CheckableArrayAccess arrayAccess | arrayAccess.canThrowOutOfBounds(sink.asExpr()))
  or isFixSink(sink)
}







predicate isAdditionalFlowStep(DataFlow::Node n1, DataFlow::Node n2) {
  isFixStep(n1, n2)
}




}

/**
 * Dataflow flow for improper validation of code-specified array index.
 */
module BoundedFlowSourceFlow = DataFlow::Global<BoundedFlowSourceConfig>;
