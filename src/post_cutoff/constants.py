# =================== ALL ==================================
QL_SUBSET_PREDICATE_JAVA = """\
predicate isFix{kind}Part{part_id}(DataFlow::Node {node}) {{
{body}
}}
"""
CALL_QL_SUBSET_PREDICATE_JAVA = "    isFix{kind}Part{part_id}({node})"

#---------------------------------------------------------------

# =============JAVA ONLY =====================================
QL_SOURCE_PREDICATE_JAVA = """\
import java
import semmle.code.java.dataflow.DataFlow
private import semmle.code.java.dataflow.ExternalFlow

predicate isFixSource(DataFlow::Node src) {{
{body}
}}

{additional}
"""

QL_SINK_PREDICATE_JAVA = """\
import java
import semmle.code.java.dataflow.DataFlow
private import semmle.code.java.dataflow.ExternalFlow

predicate isFixSink(DataFlow::Node snk) {{
{body}
}}

{additional}
"""

QL_STEP_PREDICATE_JAVA = """\
import java
import semmle.code.java.dataflow.DataFlow
private import semmle.code.java.dataflow.ExternalFlow

predicate isFixStep(DataFlow::Node prev, DataFlow::Node next) {{
{body}
}}
"""

QL_METHOD_CALL_SOURCE_BODY_ENTRY_JAVA = """\
    (
        src.asExpr().(Call).getCallee().getName() = "{method}" and
        src.asExpr().(Call).getCallee().getDeclaringType().getSourceDeclaration().hasQualifiedName("{package}", "{clazz}")
    )\
"""

# HUNK_SRC_ENTRY_API_JAVA = """\
#     (
#         src.asExpr().(Call).getCallee().getName() = "{method}" and
#         (
#             src.asExpr().(Call).getCallee().getFile().getRelativePath().matches("%{file_path}%")
#             or
#             src.asExpr().(Call).getLocation().getFile().getRelativePath().matches("%{file_path}%")
#         )
#     )\
# """
HUNK_SRC_ENTRY_API_JAVA_FULL = """\
    (
        {method_part} and
        {file_part}
    )\
"""
HUNK_SRC_ENTRY_API_JAVA_NO_METHOD = """\
    (
        {file_part}
    )\
"""
HUNK_SRC_ENTRY_API_JAVA_METHOD = """\
    src.asExpr().(Call).getCallee().getName() = "{method}"
"""
HUNK_SRC_ENTRY_API_JAVA_FILE = """\
    (
        src.asExpr().(Call).getCallee().getFile().getRelativePath().matches("%{file_path}%")
        or
        src.asExpr().(Call).getLocation().getFile().getRelativePath().matches("%{file_path}%")
    )
"""

HUNK_SINK_BODY_ENTRY_JAVA_FULL = """\
    exists(Call c |
            {method_part} and
            {file_part}
            and
            ({args})
    )\
"""
HUNK_SINK_BODY_ENTRY_JAVA_METHOD_PART = """\
c.getCallee().getName() = "{method}"
"""
HUNK_SINK_BODY_ENTRY_JAVA_FILE_PART = """\
     (
         c.getCallee().getFile().getRelativePath().matches("%{file_path}%")
         or
         c.getLocation().getFile().getRelativePath().matches("%{file_path}%")
     )\
"""

HUNK_SINK_BODY_ENTRY_JAVA_METHOD_NO_ARGS = """\
    exists(Call c |
            {method_name} and
            {file_part}
    )\
"""

HUNK_SINK_BODY_ENTRY_JAVA_NO_METHOD = """\
    exists(Call c |
            {file_part}
    )\
"""

# HUNK_SINK_BODY_ENTRY_JAVA = """\
#     exists(Call c |
#         c.getCallee().getName() = "{method}" and
#         (
#             c.getCallee().getFile().getRelativePath().matches("%{file_path}%")
#             or
#             c.getLocation().getFile().getRelativePath().matches("%{file_path}%")
#         )
#         and
#         ({args})
#     )\
# """

HUNK_FUNC_PARAM_SOURCE_ENTRY_JAVA_WITH_METHOD = """\
    exists(Parameter p |
        src.asParameter() = p and
        p.getCallable().getName() = "{method}" and
        p.getCallable().getFile().getRelativePath().matches("%{file_path}%")
    )\
"""
HUNK_FUNC_PARAM_SOURCE_ENTRY_JAVA_NO_METHOD = """\
    exists(Parameter p |
        src.asParameter() = p and
        p.getCallable().getFile().getRelativePath().matches("%{file_path}%")
    )\
"""


HUNK_SUMMARY_ENTRY_JAVA = """\
    exists(Call c |
        (c.getArgument(_) = prev.asExpr() or c.getQualifier() = prev.asExpr())
        and
       c.getFile().getRelativePath().matches("%{file_path}%")
       and
       ({funcs})
       and c = next.asExpr()
    )\
"""

HUNK_SUMMARY_ENTRY_NOFUNC_JAVA = """\
    exists(Call c |
        (c.getArgument(_) = prev.asExpr() or c.getQualifier() = prev.asExpr())
        and
       c.getFile().getRelativePath().matches("%{file_path}%")
       and c = next.asExpr()
    )\
"""




HUNK_SUMMARY_FUNC_ENTRY_JAVA=""" c.getCallee().getName().matches("{method}") """

# ================================== Python Hunk Predicates =================================================
QL_SOURCE_PREDICATE_PY = """\
import python
import semmle.python.dataflow.new.DataFlow 
import semmle.python.dataflow.new.internal.DataFlowPublic as DF


predicate isFixSource(DataFlow::Node src) {{
{body}
}}

{additional}
"""

QL_SINK_PREDICATE_PY = """\
import python
import semmle.python.dataflow.new.DataFlow

predicate isFixSink(DataFlow::Node snk) {{
{body}
}}

{additional}
"""

QL_SUBSET_PREDICATE_PY = """\
predicate isFix{kind}Part{part_id}(DataFlow::Node {node}) {{
{body}
}}
"""

CALL_QL_SUBSET_PREDICATE_PY = "    isFix{kind}Part{part_id}({node})"

QL_STEP_PREDICATE_PY = """\
import python
import semmle.python.dataflow.new.DataFlow

predicate isFixStep(DataFlow::Node prev, DataFlow::Node next) {{
{body}
}}
"""
# HUNK_SRC_ENTRY_API_PY = """\
#     (
#         (
#             (src.asExpr().(Call).getFunc() instanceof Name and src.asExpr().(Call).getFunc().(Name).getId() = "{method}")
#             or
#             (src.asExpr().(Call).getFunc() instanceof Attribute and src.asExpr().(Call).getFunc().(Attribute).getAttr() = "{method}")
#         )
#         and
#         (
#             src.asExpr().(Call).getLocation().getFile().getRelativePath().matches("%{file_path}%")
#             or
#             src.asExpr().(Call).getFunc().getLocation().getFile().getRelativePath().matches("%{file_path}%")
#         )
#     )\
# """

HUNK_SRC_ENTRY_API_PY_FULL = """\
    (
        {method_part}
        and
        {file_part}
    )\
"""
HUNK_SRC_ENTRY_API_PY_NO_METHOD = """\
    (
        {file_part}
    )\
"""

HUNK_SRC_ENTRY_API_PY_FILE = """\
    (
        src.asExpr().(Call).getLocation().getFile().getRelativePath().matches("%{file_path}%")
        or
        src.asExpr().(Call).getFunc().getLocation().getFile().getRelativePath().matches("%{file_path}%")
    )\
"""
HUNK_SRC_ENTRY_API_PY_METHOD = """\
     (
         (src.asExpr().(Call).getFunc() instanceof Name and src.asExpr().(Call).getFunc().(Name).getId() = "{method}")
         or
         (src.asExpr().(Call).getFunc() instanceof Attribute and src.asExpr().(Call).getFunc().(Attribute).getAttr() = "{method}")
     )\
"""
HUNK_FUNC_PARAM_SOURCE_ENTRY_PY_WITH_METHOD = """\
    exists(DF::ParameterNode pn |
        src = pn and
        pn.getEnclosingCallable().getQualifiedName() = "{method}" and
        pn.getEnclosingCallable().getLocation().getFile().getRelativePath().matches("%{file_path}%")
    )\
"""

HUNK_FUNC_PARAM_SOURCE_ENTRY_PY_NO_METHOD = """\
    exists(DF::ParameterNode pn |
        src = pn and
        pn.getEnclosingCallable().getLocation().getFile().getRelativePath().matches("%{file_path}%")
    )\
"""

# HUNK_SINK_BODY_ENTRY_PY = """\
#     exists(Call c |
#         (
#             (c.getFunc() instanceof Name and c.getFunc().(Name).getId() = "{method}")
#             or
#             (c.getFunc() instanceof Attribute and c.getFunc().(Attribute).getAttr() = "{method}")
#         )
#         and
#         (
#             c.getLocation().getFile().getRelativePath().matches("%{file_path}%")
#             or
#             c.getFunc().getLocation().getFile().getRelativePath().matches("%{file_path}%")
#         )
#         and
#         ({args})
#     )\
# """
HUNK_SINK_BODY_ENTRY_PY_FULL = """\
    exists(Call c |
        {method_part}
        and
        {file_part}
        and
        ({args})
    )\
"""

HUNK_SINK_BODY_ENTRY_PY_NO_METHOD = """\
    exists(Call c |
        {file_part}
    )\
"""

HUNK_SINK_BODY_ENTRY_PY_METHOD_NO_ARGS = """\
    exists(Call c |
        {method_part}
        and
        {file_part}
    )\
"""

HUNK_SINK_BODY_ENTRY_PY_METHOD_PART = """\
    (
         (c.getFunc() instanceof Name and c.getFunc().(Name).getId() = "{method}")
         or
         (c.getFunc() instanceof Attribute and c.getFunc().(Attribute).getAttr() = "{method}")
     )\
"""

HUNK_SINK_BODY_ENTRY_PY_FILE_PART = """\
    (
         c.getLocation().getFile().getRelativePath().matches("%{file_path}%")
         or
         c.getFunc().getLocation().getFile().getRelativePath().matches("%{file_path}%")
    )\
"""



QL_SINK_ARG_NAME_ENTRY_PY = """ c.getArg({arg_id}) = snk.asExpr() """

HUNK_SUMMARY_ENTRY_PY = """\
    exists(Call c |
        (c.getAnArg() = prev.asExpr() or exists(Attribute a | c.getFunc() = a and prev.asExpr() = a.getObject()))
        and
       c.getLocation().getFile().getRelativePath().matches("%{file_path}%")
       and
       ({funcs})
       and c = next.asExpr()
    )\
"""

HUNK_SUMMARY_ENTRY_NOFUNC_PY = """\
    exists(Call c |
        (c.getAnArg() = prev.asExpr() or exists(Attribute a | c.getFunc() = a and prev.asExpr() = a.getObject()))
        and
       c.getLocation().getFile().getRelativePath().matches("%{file_path}%")
       and c = next.asExpr()
    )\
"""

HUNK_SUMMARY_FUNC_ENTRY_PY="""\
        (
            (c.getFunc() instanceof Name and c.getFunc().(Name).getId() = "{method}")
            or
            (c.getFunc() instanceof Attribute and c.getFunc().(Attribute).getAttr() = "{method}")
        )\
"""


# ------------------------------------------------------------------------------------------------------------
# QL_FUNC_PARAM_NAME_ENTRY = """ p.getName() = "{arg_name}" """
#
# QL_SUMMARY_BODY_ENTRY = """\
#     exists(Call c |
#         (c.getArgument(_) = prev.asExpr() or c.getQualifier() = prev.asExpr())
#         and c.getCallee().getDeclaringType().hasQualifiedName("{package}", "{clazz}")
#         and c.getCallee().getName() = "{method}"
#         and c = next.asExpr()
#     )\
# """
#
# QL_SINK_BODY_ENTRY = """\
#     exists(Call c |
#         c.getCallee().getName() = "{method}" and
#         c.getCallee().getDeclaringType().getSourceDeclaration().hasQualifiedName("{package}", "{clazz}") and
#         ({args})
#     )\
# """



#
#
QL_SINK_ARG_NAME_ENTRY_JAVA = """ c.getArgument({arg_id}) = snk.asExpr().(Argument) """
#
#
QL_SINK_ARG_THIS_ENTRY = """ c.getQualifier() = snk.asExpr() """

QL_BODY_OR_SEPARATOR = "\n    or\n"

# EXTENSION_YML_TEMPLATE_JAVA = """\
# extensions:
#   - addsTo:
#       pack: codeql/java-all
#       extensible: sinkModel
#     data:
# {sinks}
#   - addsTo:
#       pack: codeql/java-all
#       extensible: sourceModel
#     data:
# {sources}
# """

# QL_FUNC_PARAM_SOURCE_ENTRY = """\
#     exists(Parameter p |
#         src.asParameter() = p and
#         p.getCallable().getName() = "{method}" and
#         p.getCallable().getDeclaringType().getSourceDeclaration().hasQualifiedName("{package}", "{clazz}") and
#         ({params})
#     )\
# """
# EXTENSION_SRC_SINK_YML_ENTRY = """\
#       - ["{package}", "{clazz}", True, "{method}", "", "", "{access}", "{tag}", "manual"]\
# """
#
# EXTENSION_SUMMARY_YML_ENTRY = """\
#       - ["{package}", "{clazz}", True, "{method}", "", "", "{access_in}", "{access_out}", "{tag}", "manual"]\
# """

PREDICATES = {
    "Java": {
        "QL_SOURCE_PREDICATE": QL_SOURCE_PREDICATE_JAVA,
        "QL_SINK_PREDICATE": QL_SINK_PREDICATE_JAVA,
        "QL_SUBSET_PREDICATE": QL_SUBSET_PREDICATE_JAVA,
        "CALL_QL_SUBSET_PREDICATE": CALL_QL_SUBSET_PREDICATE_JAVA,
        "QL_STEP_PREDICATE": QL_STEP_PREDICATE_JAVA,


        "HUNK_SRC_ENTRY_API_FULL": HUNK_SRC_ENTRY_API_JAVA_FULL,
        "HUNK_SRC_ENTRY_API_NO_METHOD": HUNK_SRC_ENTRY_API_JAVA_NO_METHOD,
        "HUNK_SRC_ENTRY_API_FILE": HUNK_SRC_ENTRY_API_JAVA_FILE,
        "HUNK_SRC_ENTRY_API_METHOD": HUNK_SRC_ENTRY_API_JAVA_METHOD,
        "HUNK_FUNC_PARAM_SOURCE_ENTRY_NO_METHOD": HUNK_FUNC_PARAM_SOURCE_ENTRY_JAVA_NO_METHOD,
        "HUNK_FUNC_PARAM_SOURCE_ENTRY_WITH_METHOD": HUNK_FUNC_PARAM_SOURCE_ENTRY_JAVA_WITH_METHOD,


        "HUNK_SINK_BODY_ENTRY_FULL": HUNK_SINK_BODY_ENTRY_JAVA_FULL,
        "HUNK_SINK_BODY_ENTRY_NO_METHOD": HUNK_SINK_BODY_ENTRY_JAVA_NO_METHOD,
        "HUNK_SINK_BODY_ENTRY_METHOD_NO_ARGS": HUNK_SINK_BODY_ENTRY_JAVA_METHOD_NO_ARGS,
        "HUNK_SINK_BODY_ENTRY_METHOD_PART": HUNK_SINK_BODY_ENTRY_JAVA_METHOD_PART,
        "HUNK_SINK_BODY_ENTRY_FILE_PART": HUNK_SINK_BODY_ENTRY_JAVA_FILE_PART,
        "QL_SINK_ARG_NAME_ENTRY": QL_SINK_ARG_NAME_ENTRY_JAVA,


        "HUNK_SUMMARY_ENTRY": HUNK_SUMMARY_ENTRY_JAVA,
        "HUNK_SUMMARY_ENTRY_NOFUNC": HUNK_SUMMARY_ENTRY_NOFUNC_JAVA,
        "HUNK_SUMMARY_FUNC_ENTRY": HUNK_SUMMARY_FUNC_ENTRY_JAVA,
        "QL_BODY_OR_SEPARATOR": QL_BODY_OR_SEPARATOR,
        "QL_SINK_ARG_THIS_ENTRY": QL_SINK_ARG_THIS_ENTRY,
    },
    "Python": {
        "QL_SOURCE_PREDICATE": QL_SOURCE_PREDICATE_PY,
        "QL_SINK_PREDICATE": QL_SINK_PREDICATE_PY,
        "QL_SUBSET_PREDICATE": QL_SUBSET_PREDICATE_PY,
        "CALL_QL_SUBSET_PREDICATE": CALL_QL_SUBSET_PREDICATE_PY,
        "QL_STEP_PREDICATE": QL_STEP_PREDICATE_PY,

        "HUNK_SRC_ENTRY_API_FULL": HUNK_SRC_ENTRY_API_PY_FULL,
        "HUNK_SRC_ENTRY_API_NO_METHOD": HUNK_SRC_ENTRY_API_PY_NO_METHOD,
        "HUNK_SRC_ENTRY_API_FILE": HUNK_SRC_ENTRY_API_PY_FILE,
        "HUNK_SRC_ENTRY_API_METHOD": HUNK_SRC_ENTRY_API_PY_METHOD,
        "HUNK_FUNC_PARAM_SOURCE_ENTRY_NO_METHOD": HUNK_FUNC_PARAM_SOURCE_ENTRY_PY_NO_METHOD,
        "HUNK_FUNC_PARAM_SOURCE_ENTRY_WITH_METHOD": HUNK_FUNC_PARAM_SOURCE_ENTRY_PY_WITH_METHOD,


        "HUNK_SINK_BODY_ENTRY_FULL": HUNK_SINK_BODY_ENTRY_PY_FULL,
        "HUNK_SINK_BODY_ENTRY_NO_METHOD": HUNK_SINK_BODY_ENTRY_PY_NO_METHOD,
        "HUNK_SINK_BODY_ENTRY_METHOD_NO_ARGS": HUNK_SINK_BODY_ENTRY_PY_METHOD_NO_ARGS,
        "HUNK_SINK_BODY_ENTRY_METHOD_PART": HUNK_SINK_BODY_ENTRY_PY_METHOD_PART,
        "HUNK_SINK_BODY_ENTRY_FILE_PART": HUNK_SINK_BODY_ENTRY_PY_FILE_PART,
        "QL_SINK_ARG_NAME_ENTRY": QL_SINK_ARG_NAME_ENTRY_PY,


        "HUNK_SUMMARY_ENTRY": HUNK_SUMMARY_ENTRY_PY,
        "HUNK_SUMMARY_ENTRY_NOFUNC": HUNK_SUMMARY_ENTRY_NOFUNC_PY,
        "HUNK_SUMMARY_FUNC_ENTRY": HUNK_SUMMARY_FUNC_ENTRY_PY,
        "QL_BODY_OR_SEPARATOR": QL_BODY_OR_SEPARATOR,
        "QL_SINK_ARG_THIS_ENTRY": QL_SINK_ARG_THIS_ENTRY,
    }
    #HUNK_SINK_BODY_ENTRY_PY_FULL,HUNK_SINK_BODY_ENTRY_PY_NO_METHOD,HUNK_SINK_BODY_ENTRY_PY_METHOD_NO_ARGS
}
