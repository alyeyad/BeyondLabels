import MySources
import MySinks
import MySummaries
/** Provides classes and modules to reason about SqlInjection vulnerabilities from string concatentation. */

import java
private import semmle.code.java.dataflow.TaintTracking
private import semmle.code.java.security.SqlConcatenatedLib
private import semmle.code.java.security.SqlInjectionQuery

private class UncontrolledStringBuilderSource extends DataFlow::ExprNode {
  UncontrolledStringBuilderSource() {
    exists(StringBuilderVar sbv |
      uncontrolledStringBuilderQuery(sbv, _) and
      this.getExpr() = sbv.getToStringCall()
    )
  }
}

/**
 * A taint-tracking configuration for reasoning about uncontrolled string builders.
 */
module UncontrolledStringBuilderSourceFlowConfig implements DataFlow::ConfigSig {






  predicate isSource(DataFlow::Node src) { src instanceof UncontrolledStringBuilderSource
  or isFixSource(src)
}

  predicate isSink(DataFlow::Node sink) { sink instanceof QueryInjectionSink
  or isFixSink(sink)
}

predicate isAdditionalFlowStep(DataFlow::Node n1, DataFlow::Node n2) {
  isFixStep(n1, n2)
}




}

/**
 * Taint-tracking flow for uncontrolled string builders that are used in a SQL query.
 */
module UncontrolledStringBuilderSourceFlow =
  TaintTracking::Global<UncontrolledStringBuilderSourceFlowConfig>;
