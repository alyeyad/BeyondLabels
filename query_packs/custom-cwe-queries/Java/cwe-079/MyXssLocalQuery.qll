import MySources
import MySinks
import MySummaries
/** Provides a taint-tracking configuration to reason about cross-site scripting from a local source. */

import java
private import semmle.code.java.dataflow.FlowSources
private import semmle.code.java.dataflow.TaintTracking
private import semmle.code.java.security.XSS

/**
 * A taint-tracking configuration for reasoning about cross-site scripting vulnerabilities from a local source.
 */
module XssLocalConfig implements DataFlow::ConfigSig {






  predicate isSource(DataFlow::Node source) { source instanceof LocalUserInput
  or isFixSource(source)
}

  predicate isSink(DataFlow::Node sink) { sink instanceof XssSink
  or isFixSink(sink)
}

predicate isBarrierOut(DataFlow::Node node) { node instanceof XssSinkBarrier }

  predicate isAdditionalFlowStep(DataFlow::Node node1, DataFlow::Node node2) {
    any(XssAdditionalTaintStep s).step(node1, node2)
  or isFixStep(node1, node2)
}






}

/**
 * Taint-tracking flow for cross-site scripting vulnerabilities from a local source.
 */
module XssLocalFlow = TaintTracking::Global<XssLocalConfig>;
