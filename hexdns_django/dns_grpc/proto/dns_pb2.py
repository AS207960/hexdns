# -*- coding: utf-8 -*-
# Generated by the protocol buffer compiler.  DO NOT EDIT!
# source: dns.proto

from google.protobuf import descriptor as _descriptor
from google.protobuf import message as _message
from google.protobuf import reflection as _reflection
from google.protobuf import symbol_database as _symbol_database
# @@protoc_insertion_point(imports)

_sym_db = _symbol_database.Default()




DESCRIPTOR = _descriptor.FileDescriptor(
  name='dns.proto',
  package='coredns.dns',
  syntax='proto3',
  serialized_options=b'Z\002pb',
  serialized_pb=b'\n\tdns.proto\x12\x0b\x63oredns.dns\"\x18\n\tDnsPacket\x12\x0b\n\x03msg\x18\x01 \x01(\x0c\x32\x84\x01\n\nDnsService\x12\x37\n\x05Query\x12\x16.coredns.dns.DnsPacket\x1a\x16.coredns.dns.DnsPacket\x12=\n\tAXFRQuery\x12\x16.coredns.dns.DnsPacket\x1a\x16.coredns.dns.DnsPacket0\x01\x42\x04Z\x02pbb\x06proto3'
)




_DNSPACKET = _descriptor.Descriptor(
  name='DnsPacket',
  full_name='coredns.dns.DnsPacket',
  filename=None,
  file=DESCRIPTOR,
  containing_type=None,
  fields=[
    _descriptor.FieldDescriptor(
      name='msg', full_name='coredns.dns.DnsPacket.msg', index=0,
      number=1, type=12, cpp_type=9, label=1,
      has_default_value=False, default_value=b"",
      message_type=None, enum_type=None, containing_type=None,
      is_extension=False, extension_scope=None,
      serialized_options=None, file=DESCRIPTOR),
  ],
  extensions=[
  ],
  nested_types=[],
  enum_types=[
  ],
  serialized_options=None,
  is_extendable=False,
  syntax='proto3',
  extension_ranges=[],
  oneofs=[
  ],
  serialized_start=26,
  serialized_end=50,
)

DESCRIPTOR.message_types_by_name['DnsPacket'] = _DNSPACKET
_sym_db.RegisterFileDescriptor(DESCRIPTOR)

DnsPacket = _reflection.GeneratedProtocolMessageType('DnsPacket', (_message.Message,), {
  'DESCRIPTOR' : _DNSPACKET,
  '__module__' : 'dns_pb2'
  # @@protoc_insertion_point(class_scope:coredns.dns.DnsPacket)
  })
_sym_db.RegisterMessage(DnsPacket)


DESCRIPTOR._options = None

_DNSSERVICE = _descriptor.ServiceDescriptor(
  name='DnsService',
  full_name='coredns.dns.DnsService',
  file=DESCRIPTOR,
  index=0,
  serialized_options=None,
  serialized_start=53,
  serialized_end=185,
  methods=[
  _descriptor.MethodDescriptor(
    name='Query',
    full_name='coredns.dns.DnsService.Query',
    index=0,
    containing_service=None,
    input_type=_DNSPACKET,
    output_type=_DNSPACKET,
    serialized_options=None,
  ),
  _descriptor.MethodDescriptor(
    name='AXFRQuery',
    full_name='coredns.dns.DnsService.AXFRQuery',
    index=1,
    containing_service=None,
    input_type=_DNSPACKET,
    output_type=_DNSPACKET,
    serialized_options=None,
  ),
])
_sym_db.RegisterServiceDescriptor(_DNSSERVICE)

DESCRIPTOR.services_by_name['DnsService'] = _DNSSERVICE

# @@protoc_insertion_point(module_scope)
