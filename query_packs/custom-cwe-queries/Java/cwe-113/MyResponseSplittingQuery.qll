import MySources
import MySinks
import MySummaries
/** Provides a taint tracking configuration to reason about response splitting vulnerabilities. */

import java
private import semmle.code.java.dataflow.FlowSources
import semmle.code.java.security.ResponseSplitting

/**
 * A taint-tracking configuration for response splitting vulnerabilities.
 */
module ResponseSplittingConfig implements DataFlow::ConfigSig {






  predicate isSource(DataFlow::Node source) {
    source instanceof ThreatModelFlowSource and
    not source instanceof SafeHeaderSplittingSource
  or isFixSource(source)
}

  predicate isSink(DataFlow::Node sink) { sink instanceof HeaderSplittingSink
  or isFixSink(sink)
}

predicate isAdditionalFlowStep(DataFlow::Node n1, DataFlow::Node n2) {
  isFixStep(n1, n2)
}




}

/**
 * Tracks flow from remote sources to response splitting vulnerabilities.
 */
module ResponseSplittingFlow = TaintTracking::Global<ResponseSplittingConfig>;
