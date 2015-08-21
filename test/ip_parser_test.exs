defmodule IpParserTest do
  use ExUnit.Case

  setup do
    bits = File.read!("./sample_packet.bits")
    # Get a record destructured out of the binary
    packet = IPPacket.Record.from_bits(bits)
    {:ok, packet: packet}
  end

  test "getting protocol version", meta do
    assert meta[:packet].protocol_version == 4
  end

  test "getting header length in bytes", meta do
    assert meta[:packet].header_length_in_bytes == 20
  end

  test "getting type of service", meta do
    assert meta[:packet].type_of_service == :unspecified
  end

  test "getting total length in bytes", meta do
    assert meta[:packet].total_length_in_bytes == 44
  end

  test "getting the identification", meta do
    assert meta[:packet].identification == 9394
  end

  test "getting the flags", meta do
    assert meta[:packet].flags == 0
  end

  test "getting the fragmentation_offset", meta do
    assert meta[:packet].fragmentation_offset == 0
  end

  test "getting the TTL (Time to Live)", meta do
    assert meta[:packet].ttl == 64
  end

  test "getting the network protocol", meta do
    assert meta[:packet].network_protocol == :tcp
  end

  test "getting the header checksum", meta do
    assert meta[:packet].header_checksum == 64991
  end

  test "getting the source ip address", meta do
    assert meta[:packet].source_ip_address == "172.16.0.9"
  end

  test "getting the destination ip address", meta do
    assert meta[:packet].destination_ip_address == "172.16.0.1"
  end

  test "getting the options brah", meta do
    assert meta[:packet].options == 35040
  end

  test "getting the payload", meta do
    assert meta[:packet].payload == <<2, 236, 24, 219, 242, 0, 0, 0, 0, 12, 0, 64, 64, 31, 40, 192, 0, 0, 64, 128, 182, 4::size(3)>>
  end
end
