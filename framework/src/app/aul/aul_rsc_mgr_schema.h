#ifndef __AUL_RSC_MGR_SCHEMA_H__
#define __AUL_RSC_MGR_SCHEMA_H__

static const char res_schema[] =
"<?xml version=\"1.0\" encoding=\"UTF-8\"?>"
"<xs:schema xmlns:xs=\"http://www.w3.org/2001/XMLSchema\" elementFormDefault=\"qualified\" targetNamespace=\"http://tizen.org/ns/rm\" xmlns:packages=\"http://tizen.org/ns/rm\">"
"  <xs:import namespace=\"http://www.w3.org/XML/1998/namespace\"/>"
"  <xs:element name=\"res\">"
"    <xs:complexType>"
"      <xs:all>"
"        <xs:element name=\"group-image\" type=\"packages:GroupContainer\" maxOccurs=\"1\" minOccurs=\"0\"/>"
"        <xs:element name=\"group-layout\" type=\"packages:GroupContainer\" maxOccurs=\"1\" minOccurs=\"0\"/>"
"        <xs:element name=\"group-sound\" type=\"packages:GroupContainer\" maxOccurs=\"1\" minOccurs=\"0\"/>"
"        <xs:element name=\"group-bin\" type=\"packages:GroupContainer\" maxOccurs=\"1\" minOccurs=\"0\"/>"
"      </xs:all>"
"    </xs:complexType>"
"  </xs:element>"
"  <xs:complexType name=\"GroupContainer\">"
"    <xs:sequence>"
"      <xs:element name=\"node\" maxOccurs=\"unbounded\" minOccurs=\"0\">"
"        <xs:complexType>"
"          <xs:attribute name=\"folder\" type=\"xs:string\" use=\"required\"/>"
"          <xs:attribute name=\"screen-dpi\" type=\"xs:integer\"/>"
"          <xs:attribute name=\"screen-dpi-range\" type=\"xs:string\"/>"
"          <xs:attribute name=\"screen-width-range\" type=\"xs:string\"/>"
"          <xs:attribute name=\"screen-large\" type=\"xs:boolean\"/>"
"          <xs:attribute name=\"screen-bpp\" type=\"xs:integer\"/>"
"          <xs:attribute name=\"platform-version\" type=\"xs:string\"/>"
"          <xs:attribute name=\"language\" type=\"xs:string\"/>"
"        </xs:complexType>"
"      </xs:element>"
"    </xs:sequence>"
"    <xs:attribute name=\"folder\" type=\"xs:string\" use=\"required\"/>"
"  </xs:complexType>"
"</xs:schema>";

#endif
