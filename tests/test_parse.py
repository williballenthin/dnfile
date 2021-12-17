import pytest
import fixtures

import dnfile
from dnfile.mdtable import TypeRefRow, AssemblyRefRow


def test_metadata():
    path = fixtures.get_data_path_by_name("hello-world.exe")

    dn = dnfile.dnPE(path)
    assert dn.net is not None
    assert dn.net.metadata is not None

    dn.net.metadata.struct.Signature == 0x424A5342
    dn.net.metadata.struct.MajorVersion == 1
    dn.net.metadata.struct.MinorVersion == 1
    dn.net.metadata.struct.Version == "v4.0.30319"
    dn.net.metadata.struct.Flags == 0x0
    dn.net.metadata.struct.NumberOfStreams == 5


def test_streams():
    path = fixtures.get_data_path_by_name("hello-world.exe")

    dn = dnfile.dnPE(path)
    assert dn.net is not None
    assert dn.net.metadata is not None

    assert b"#~" in dn.net.metadata.streams
    assert hasattr(dn.net, "metadata")

    # strings used by #~
    assert b"#Strings" in dn.net.metadata.streams
    assert hasattr(dn.net, "strings")

    # "user strings"
    assert b"#US" in dn.net.metadata.streams
    assert hasattr(dn.net, "user_strings")

    assert b"#GUID" in dn.net.metadata.streams
    assert hasattr(dn.net, "guids")

    assert b"#Blob" in dn.net.metadata.streams
    assert hasattr(dn.net, "blobs")

    assert b"#Foo" not in dn.net.metadata.streams
    assert not hasattr(dn.net, "foo")


def test_tables():
    path = fixtures.get_data_path_by_name("hello-world.exe")

    dn = dnfile.dnPE(path)
    assert dn.net is not None

    for table in ["Module", "TypeRef", "TypeDef", "MethodDef", "Param", "MemberRef", "CustomAttribute", "Assembly", "AssemblyRef"]:
        assert hasattr(dn.net.mdtables, table)

    assert not hasattr(dn.net.mdtables, "foo")


def test_module():
    path = fixtures.get_data_path_by_name("hello-world.exe")

    dn = dnfile.dnPE(path)
    assert dn.net is not None

    assert dn.net.mdtables.Module[0].Name == "1-hello-world.exe"


def test_typedef_extends():
    path = fixtures.get_data_path_by_name("hello-world.exe")

    dn = dnfile.dnPE(path)
    assert dn.net is not None

    typedefs = dn.net.mdtables.TypeDef
    assert typedefs[0].TypeName == "<Module>"
    assert typedefs[1].TypeName == "HelloWorld"

    #   .class public auto ansi beforefieldinit HelloWorld
    #      extends [mscorlib]System.Object

    extends = typedefs[1].Extends
    assert extends.table is not None
    assert extends.table.name == "TypeRef"
    assert extends.row_index == 5

    superclass = extends.row
    assert isinstance(superclass, TypeRefRow)
    assert superclass.TypeNamespace == "System"
    assert superclass.TypeName == "Object"

    assert superclass.ResolutionScope.table is not None
    assert superclass.ResolutionScope.table.name == "AssemblyRef"
    assembly = superclass.ResolutionScope.row
    assert isinstance(assembly, AssemblyRefRow)
    assert assembly.Name == "mscorlib"


def test_typedef_members():
    path = fixtures.get_data_path_by_name("hello-world.exe")

    dn = dnfile.dnPE(path)
    assert dn.net is not None

    typedefs = dn.net.mdtables.TypeDef
    assert typedefs[0].TypeName == "<Module>"
    assert typedefs[1].TypeName == "HelloWorld"

    # neither class has fields
    assert len(typedefs[0].FieldList) == 0
    assert len(typedefs[1].FieldList) == 0

    # <Module> has no methods
    assert len(typedefs[0].MethodList) == 0
    # HelloWorld has two methods: Main and .ctor
    assert len(typedefs[1].MethodList) == 2

    assert typedefs[1].MethodList[0].row.Name == "Main"
    assert typedefs[1].MethodList[1].row.Name == ".ctor"


def test_method_params():
    path = fixtures.get_data_path_by_name("hello-world.exe")

    dn = dnfile.dnPE(path)
    assert dn.net is not None

    methods = dn.net.mdtables.MethodDef
    assert methods[0].Name == "Main"
    assert methods[1].Name == ".ctor"

    # default void Main (string[] args)  cil managed
    assert len(methods[0].ParamList) == 1
    # instance default void '.ctor' ()  cil managed
    assert len(methods[1].ParamList) == 0

    assert methods[0].ParamList[0].row is not None
    assert methods[0].ParamList[0].row.Name == "args"


def test_ignore_NumberOfRvaAndSizes():
    # .NET loaders ignores NumberOfRvaAndSizes, so attempt to parse anyways
    path = fixtures.DATA / "1d41308bf4148b4c138f9307abc696a6e4c05a5a89ddeb8926317685abb1c241"
    if not path.exists():
        raise pytest.xfail("test file 1d41308bf41... (DANGER: malware) not found in test fixtures")

    dn = dnfile.dnPE(path)
    assert hasattr(dn, "net") and dn.net is not None
    assert hasattr(dn.net, "metadata") and dn.net.metadata is not None


def test_flags():
    path = fixtures.get_data_path_by_name("hello-world.exe")

    dn = dnfile.dnPE(path)
    assert dn.net is not None

    # class HelloWorld
    cls = dn.net.mdtables.TypeDef.get_with_row_index(2)

    # these are enums from CorTypeSemantics
    assert cls.Flags.tdClass is True
    assert cls.Flags.tdInterface is False

    # these are flags from CorTypeAttrFlags
    assert cls.Flags.tdBeforeFieldInit is True
    assert cls.Flags.tdAbstract is False
