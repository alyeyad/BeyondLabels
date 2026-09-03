import MySources
import MySinks
import MySummaries
/** Provides a taint-tracking configuration to reason about response splitting vulnerabilities from local user input. */

import java
private import semmle.code.java.dataflow.FlowSources
private import semmle.code.java.security.ResponseSplitting

/**
 * A taint-tracking configuration to reason about response splitting vulnerabilities from local user input.
 */
module ResponseSplittingLocalConfig implements DataFlow::ConfigSig {






  predicate isSource(DataFlow::Node source) { source instanceof LocalUserInput
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
 * Taint-tracking flow for response splitting vulnerabilities from local user input.
 */
module ResponseSplittingLocalFlow = TaintTracking::Global<ResponseSplittingLocalConfig>;
