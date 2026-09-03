import MySources
import MySinks
import MySummaries
/**
 * Provides a taint-tracking configuration for detecting NoSQL injection vulnerabilities
 */

import python
import semmle.python.dataflow.new.DataFlow
import semmle.python.dataflow.new.TaintTracking
import semmle.python.Concepts
private import NoSqlInjectionCustomizations::NoSqlInjection as C

/**
 * A taint-tracking configuration for detecting NoSQL injection vulnerabilities.
 */
module NoSqlInjectionConfig implements DataFlow::StateConfigSig {






  class FlowState = C::FlowState;

  predicate isSource(DataFlow::Node source, FlowState state) {
    source instanceof C::StringSource and
    state instanceof C::String
    or
    source instanceof C::DictSource and
    state instanceof C::Dict
  or isFixSource(source)
}

  predicate isSink(DataFlow::Node sink, FlowState state) {
    sink instanceof C::StringSink and
    (
      state instanceof C::String
      or
      // since Dicts can include strings,
      // e.g. JSON objects can encode strings.
      state instanceof C::Dict
    )
    or
    sink instanceof C::DictSink and
    state instanceof C::Dict
  or isFixSink(sink)
}

predicate isAdditionalFlowStep(
    DataFlow::Node nodeFrom, FlowState stateFrom, DataFlow::Node nodeTo, FlowState stateTo
  ) {
    exists(C::StringToDictConversion c |
      nodeFrom = c.getAnInput() and
      nodeTo = c.getOutput()
    ) and
    stateFrom instanceof C::String and
    stateTo instanceof C::Dict
}

}

module NoSqlInjectionFlow = TaintTracking::GlobalWithState<NoSqlInjectionConfig>;
