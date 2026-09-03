import MySources
import MySinks
import MySummaries
/** Provides to taint-tracking configuration to reason about the use of broken or risky cryptographic algorithms. */

import java
private import semmle.code.java.security.Encryption
private import semmle.code.java.dataflow.TaintTracking

private class ShortStringLiteral extends StringLiteral {
  ShortStringLiteral() { this.getValue().length() < 100 }
}

/**
 * A string literal that may refer to a broken or risky cryptographic algorithm.
 */
class BrokenAlgoLiteral extends ShortStringLiteral {
  BrokenAlgoLiteral() {
    this.getValue().regexpMatch(getInsecureAlgorithmRegex()) and
    // Exclude German and French sentences.
    not this.getValue().regexpMatch(".*\\p{IsLowercase} des \\p{IsLetter}.*")
  }
}

/**
 * A taint-tracking configuration to reason about the use of broken or risky cryptographic algorithms.
 */
module InsecureCryptoConfig implements DataFlow::ConfigSig {






  predicate isSource(DataFlow::Node n) { n.asExpr() instanceof BrokenAlgoLiteral
  or isFixSource(n)
}

  predicate isSink(DataFlow::Node n) { exists(CryptoAlgoSpec c | n.asExpr() = c.getAlgoSpec())
  or isFixSink(n)
}

predicate isAdditionalFlowStep(DataFlow::Node n1, DataFlow::Node n2) {
  isFixStep(n1, n2)
}




}

/**
 * Taint-tracking flow for use of broken or risky cryptographic algorithms.
 */
module InsecureCryptoFlow = TaintTracking::Global<InsecureCryptoConfig>;
