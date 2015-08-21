defmodule IPPacket.Record do

  defstruct protocol_version: nil, header_length_in_bytes: nil,
    type_of_service: nil, total_length_in_bytes: nil, identification: nil,
    flags: nil, fragmentation_offset: nil, ttl: nil, network_protocol: nil,
    header_checksum: nil, source_ip_address: nil, destination_ip_address: nil,
    options: nil, payload: nil

  def from_bits(bits) do
    <<protocol_version :: size(4),
      header_words :: size(4),
      _type_of_service_legacy :: size(4),
      type_of_service_int :: size(4),
      total_length :: size(16),
      identification :: size(16),
      flags :: size(3),
      fragmentation_offset :: size(13),
      ttl :: size(8),
      network_protocol_int :: size(8),
      header_checksum :: size(16),
      source_ip_address :: size(32),
      destination_ip_address :: size(32),
      rest :: bitstring>> = bits

    options_size = calculate_options_size({total_length, header_words, rest})

    <<options :: size(options_size),
      payload :: bitstring>> = rest

    %IPPacket.Record{
      protocol_version: protocol_version,
      header_length_in_bytes: header_words * (32 / 8),
      type_of_service: type_of_service_for(type_of_service_int),
      total_length_in_bytes: total_length,
      identification: identification,
      flags: flags,
      fragmentation_offset: fragmentation_offset,
      ttl: ttl,
      network_protocol: type_of_network_protocol_for(network_protocol_int),
      header_checksum: header_checksum,
      source_ip_address: ip_string(source_ip_address),
      destination_ip_address: ip_string(destination_ip_address),
      options: options,
      payload: payload
    }
  end

  defp calculate_options_size({total_length, header_words, rest}) do
    byte_size(rest) - div((total_length - (header_words * 4)), 8)
  end

  defp ip_string(ip) do
    <<first, second, third, fourth>> = <<ip :: size(32)>>
    "#{first}.#{second}.#{third}.#{fourth}"
  end

  defp type_of_service_for(type_of_service_int) do
    case type_of_service_int do
      8 -> :minimize_delay
      4 -> :maximize_throughput
      2 -> :maximize_reliability
      1 -> :minimize_monetary_cost
      0 -> :unspecified
    end
  end

  defp type_of_network_protocol_for(network_protocol_int) do
    case network_protocol_int do
      1  -> :icmp
      2  -> :igmp
      6  -> :tcp
      17 -> :udp
      _  -> :unknown
    end
  end
end
