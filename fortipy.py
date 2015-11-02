from xml.etree import cElementTree
from collections import namedtuple
from os.path import exists, splitext
from zipfile import ZipFile
from tempfile import mkdtemp
from shutil import rmtree

# Data Structures
File = namedtuple("File", "size timestamp type encoding name loc")
Build = namedtuple("Build", "build_id number_of_files loc java_class_path source_base_path scan_time source_files")
ClassInfo = namedtuple("ClassInfo", "class_id kingdom type subtype analyzer_name default_severity")
InstanceInfo = namedtuple("InstanceInfo", "instance_id confidence instance_severity")
Vulnerability = namedtuple("Vulnerability", "class_info instance_info analysis_info")
Location = namedtuple("Location", "path line_start line_end col_start col_end")
Context = namedtuple("Context", "function_name namespace enclosing_class decl_location")
ReplacementDefs = namedtuple("ReplacementDefinitions", "items location")
AnalysisInfo = namedtuple("AnalysisInfo", "context replacement_defs trace")
NodeRef = namedtuple("NodeRef", "id")
Node = namedtuple("Node", "is_default snippet_id source_location action reason knowledge")
Trace = namedtuple("Trace", "nodes nodes_ref")
KeyValue = namedtuple("KeyValue", "key value")
TypeValue = namedtuple("TypeValue", "type value")


def _xpath(path):
    return path.strip().replace("/", "/{%s}" % "xmlns://www.fortifysoftware.com/schema/fvdl")


def _get_nodes(root, p, fn=lambda node: node):
    out = []
    try:
        for item in root.findall(_xpath(p)):
            out.append(fn(item))
        return out
    except:
        return None


def _get_node(root, p, fn=lambda node: node.text):
    try:
        return fn(root.findall(_xpath(p))[0])
    except:
        return None


def _get_attr(name):
    return lambda node: node.attrib.get(name, None)


def _make_node_ref(root):
    return NodeRef(id=root.attrib.get("id", None))


def _make_node(root):
    return Node(
        is_default=root.attrib.get("isDefault", "false") == "true",
        source_location=_get_node(root, "./SourceLocation", _make_location),
        snippet_id=_get_node(root, "./SourceLocation", _get_attr("snippet")),
        action=_get_node(root, "./Action",
                         lambda node: TypeValue(type=node.attrib.get("type", None), value=node.text)),
        reason=_get_node(root, "./Reason/Rule", _get_attr("ruleID")),
        knowledge=_get_nodes(root, "./Knowledge", lambda node: (node.attrib.get("primary", None),
                                                                node.attrib.get("type", None), node.text)))


def _make_file(root):
    return File(
        size=root.attrib.get("size", None),
        timestamp=root.attrib.get("timestamp", None),
        type=root.attrib.get("type", None),
        encoding=root.attrib.get("encoding", None),
        name=_get_node(root, "./Name"),
        loc=_get_nodes(root, "./LOC",
                       lambda node: TypeValue(type=node.attrib.get("type", None), value=node.text)))


def _make_build(root):
    return Build(
        build_id=_get_node(root, "./Build/BuildID"),
        number_of_files=_get_node(root, "./Build/NumberFiles"),
        loc=_get_nodes(root, "./Build/LOC",
                       lambda node: TypeValue(type=node.attrib.get("type", None), value=node.text)),
        java_class_path=_get_node(root, "./Build/JavaClasspath"),
        source_base_path=_get_node(root, "./Build/SourceBasePath"),
        scan_time=_get_node(root, "./Build/ScanTime"),
        source_files=_get_nodes(root, "./Build/SourceFiles/File", _make_file))


def _make_class_info(root):
    return ClassInfo(
        class_id=_get_node(root, "./ClassID"),
        kingdom=_get_node(root, "./Kingdom"),
        type=_get_node(root, "./Type"),
        subtype=_get_node(root, "./Subtype"),
        analyzer_name=_get_node(root, "./AnalyzerName"),
        default_severity=_get_node(root, "./DefaultSeverity"))


def _make_instance_info(root):
    return InstanceInfo(
        instance_id=_get_node(root, "./InstanceID"),
        confidence=_get_node(root, "./Confidence"),
        instance_severity=_get_node(root, "./InstanceSeverity"))


def _make_vulnerability(root):
    return Vulnerability(
        class_info=_get_node(root, "./ClassInfo", _make_class_info),
        instance_info=_get_node(root, "./InstanceInfo", _make_instance_info),
        analysis_info=_get_node(root, "./AnalysisInfo", _make_analysis_info))


def _make_vulnerabilities(root):
    return _get_nodes(root, "./Vulnerabilities/Vulnerability", _make_vulnerability)


def _make_location(root):
    return Location(
        path=root.attrib.get("path", None),
        line_start=root.attrib.get("line", None),
        line_end=root.attrib.get("lineEnd", None),
        col_start=root.attrib.get("colStart", None),
        col_end=root.attrib.get("colEnd", None))


def _make_context(root):
    return Context(
        function_name=_get_node(root, "./Function", _get_attr("name")),
        namespace=_get_node(root, "./Function", _get_attr("namespace")),
        enclosing_class=_get_node(root, "./Function", _get_attr("enclosingClass")),
        decl_location=_get_node(root, "./FunctionDeclarationSourceLocation", _make_location))


# TODO: thinkg about unpacking these values
# <Def key="EnclosingFunction.name" value="jointOperationSignatures()"/>
# <Def key="PrimaryCall.name" value="error()"/>
# <Def key="PrimaryLocation.file" value="MultipleSignServiceImpl.java"/>
# <Def key="PrimaryLocation.line" value="221"/>
def _make_replacement_defs(root):
    return ReplacementDefs(
        location=_get_node(root, "./LocationDef", _make_location),
        items=_get_nodes(root, "./Def",
                         lambda node: KeyValue(key=node.attrib.get("key", None), value=node.attrib.get("value", None))))


def _make_trace(root):
    return Trace(
        nodes=_get_nodes(root, "./Entry/Node", _make_node),
        nodes_ref=_get_nodes(root, "./Entry/NodeRef", _make_node_ref))


def _make_analysis_info(root):
    return AnalysisInfo(
        context=_get_node(root, "./Unified/Context", _make_context),
        replacement_defs=_get_node(root, "./Unified/ReplacementDefinitions", _make_replacement_defs),
        trace=_get_node(root, "./Unified/Trace/Primary", _make_trace))


class FPR(object):
    def __init__(self, filename=None):
        if not exists(filename):
            raise Exception("{} does not exists!".format(filename))

        ext = splitext(filename)[1].lower()

        self.temppath = mkdtemp("fvdl") if ext == "fpr" else None
        self.files = {}

        if self.temppath is not None:
            with ZipFile(filename, "r") as f:
                f.extractall(self.temppath)

            xml = cElementTree.parse("{}/src-archive/index.xml".format(self.temppath)).getroot()
            self.files = dict((entry.attrib["key"].strip().lower(), "{}/{}".format(self.temppath, entry.text.strip()))
                              for entry in xml.findall("entry"))
            root = cElementTree.parse("{}/audit.fvdl".format(self.temppath)).getroot()
        else:
            root = cElementTree.parse(filename).getroot()

        self.Vulnerabilities = _make_vulnerabilities(root)
        self.Build = _make_build(root)

    def __enter__(self):
        return self

    def __exit__(self, exc_type, exc_val, exc_tb):
        self.close()

    def close(self, clean=True):
        if self.temppath is None:
            return

        if clean:
            rmtree(self.temppath)

        self.temppath = None

    def get_types_of_vulns(self):
        return set([x.class_info.type for x in self.Vulnerabilities if x is not None and
                    x.class_info is not None and x.class_info.type is not None])

    def get_vulns_of_type(self, vtype):
        return [x for x in self.Vulnerabilities if x is not None and x.class_info is not None and
                x.class_info.type.strip().lower() == vtype.lower().strip()]

    def get_code_for(self, filename):
        fname = self.files.get(filename.lower().strip(), "")

        if not exists(fname):
            raise Exception("{} does not exists!".format(fname))

        with open(fname, "r") as f:
            return f.read()

if __name__ == "__main__":
    fpr = FPR("test/audit.fvdl")
    print fpr.get_types_of_vulns()
    print fpr.get_vulns_of_type("dead code")
