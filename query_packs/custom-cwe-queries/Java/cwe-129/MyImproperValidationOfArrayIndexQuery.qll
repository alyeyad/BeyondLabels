import MySources
import MySinks
import MySummaries
/** Provides a taint-tracking configuration to reason about improper validation of user-provided array index. */

import java
private import semmle.code.java.security.internal.ArraySizing
private import semmle.code.java.dataflow.FlowSources

/**
 * A taint-tracking configuration to reason about improper validation
 * of user-provided array index.
 */
module ImproperValidationOfArrayIndexConfig implements DataFlow::ConfigSig {






  predicate isSource(DataFlow::Node source) { source instanceof ThreatModelFlowSource
  or isFixSource(source)
}

  predicate isSink(DataFlow::Node sink) {
    any(CheckableArrayAccess caa).canThrowOutOfBounds(sink.asExpr())
  or isFixSink(sink)
}

predicate isBarrierIn(DataFlow::Node node) { isSource(node) }







predicate isAdditionalFlowStep(DataFlow::Node n1, DataFlow::Node n2) {
  isFixStep(n1, n2)
}




}

/**
 * Taint-tracking flow for improper validation of user-provided array index.
 */
module ImproperValidationOfArrayIndexFlow =
  TaintTracking::Global<ImproperValidationOfArrayIndexConfig>;
