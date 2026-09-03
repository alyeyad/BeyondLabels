import MySources
import MySinks
import MySummaries
/** Provides a taint-tracking configuration to reason about externally controlled format string vulnerabilities. */

import java
private import semmle.code.java.dataflow.FlowSources
private import semmle.code.java.StringFormat

/**
 * A taint-tracking configuration for externally controlled format string vulnerabilities.
 */
module ExternallyControlledFormatStringConfig implements DataFlow::ConfigSig {






  predicate isSource(DataFlow::Node source) { source instanceof ThreatModelFlowSource
  or isFixSource(source)
}

  predicate isSink(DataFlow::Node sink) {
    sink.asExpr() = any(StringFormat formatCall).getFormatArgument()
  or isFixSink(sink)
}

predicate isAdditionalFlowStep(DataFlow::Node n1, DataFlow::Node n2) {
  isFixStep(n1, n2)
}




}

/**
 * Taint-tracking flow for externally controlled format string vulnerabilities.
 */
module ExternallyControlledFormatStringFlow =
  TaintTracking::Global<ExternallyControlledFormatStringConfig>;
