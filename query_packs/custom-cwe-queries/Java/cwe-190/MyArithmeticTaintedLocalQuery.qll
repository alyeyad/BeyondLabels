import MySources
import MySinks
import MySummaries
/** Provides taint-tracking configurations to reason about arithmetic using local-user-controlled data. */

import java
private import semmle.code.java.dataflow.FlowSources
private import semmle.code.java.security.ArithmeticCommon

/**
 * A taint-tracking configuration to reason about arithmetic overflow using local-user-controlled data.
 */
module ArithmeticTaintedLocalOverflowConfig implements DataFlow::ConfigSig {






  predicate isSource(DataFlow::Node source) { source instanceof LocalUserInput
  or isFixSource(source)
}

  predicate isSink(DataFlow::Node sink) { overflowSink(_, sink.asExpr())
  or isFixSink(sink)
}

predicate isBarrierIn(DataFlow::Node node) { isSource(node) }







predicate isAdditionalFlowStep(DataFlow::Node n1, DataFlow::Node n2) {
  isFixStep(n1, n2)
}




}

/**
 * Taint-tracking flow for arithmetic overflow using local-user-controlled data.
 */
module ArithmeticTaintedLocalOverflowFlow =
  TaintTracking::Global<ArithmeticTaintedLocalOverflowConfig>;

/**
 * A taint-tracking configuration to reason about arithmetic underflow using local-user-controlled data.
 */
module ArithmeticTaintedLocalUnderflowConfig implements DataFlow::ConfigSig {






  predicate isSource(DataFlow::Node source) { source instanceof LocalUserInput
  or isFixSource(source)
}

  predicate isSink(DataFlow::Node sink) { underflowSink(_, sink.asExpr())
  or isFixSink(sink)
}

predicate isBarrierIn(DataFlow::Node node) { isSource(node) }







predicate isAdditionalFlowStep(DataFlow::Node n1, DataFlow::Node n2) {
  isFixStep(n1, n2)
}




}

/**
 * Taint-tracking flow for arithmetic underflow using local-user-controlled data.
 */
module ArithmeticTaintedLocalUnderflowFlow =
  TaintTracking::Global<ArithmeticTaintedLocalUnderflowConfig>;
