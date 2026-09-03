import MySources
import MySinks
import MySummaries
/** Provides a taint-tracking configuration for reasoning about URL redirections. */

import java
private import semmle.code.java.dataflow.FlowSources
private import semmle.code.java.security.UrlRedirect

/**
 * A taint-tracking configuration for reasoning about URL redirections.
 */
module UrlRedirectConfig implements DataFlow::ConfigSig {






  predicate isSource(DataFlow::Node source) { source instanceof ThreatModelFlowSource
  or isFixSource(source)
}

  predicate isSink(DataFlow::Node sink) { sink instanceof UrlRedirectSink
  or isFixSink(sink)
}







predicate isAdditionalFlowStep(DataFlow::Node n1, DataFlow::Node n2) {
  isFixStep(n1, n2)
}




}

/**
 * Taint-tracking flow for URL redirections.
 */
module UrlRedirectFlow = TaintTracking::Global<UrlRedirectConfig>;
