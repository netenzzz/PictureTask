#include "Reader.h"
#include <bitset>
#include <cmath>
#include <exception>
#include <fstream>
#include <iostream>
#include <sstream>

struct PcapGlobHeader {
  uint32_t magic_number;  
  uint16_t version_major;
  uint16_t version_minor; 
  int32_t thiszone;     
  uint32_t sigfigs;    
  uint32_t snaplen;   
  uint32_t network;    
};

struct PcapLocalHeader {
  uint32_t ts_sec;   
  uint32_t ts_usec; 
  uint32_t incl_len;
  uint32_t orig_len; 
};

// Ethernet packet structure
#pragma pack(push, 1)
struct EthernetFront {
  int mac_port_1;
  int mac_port_1_and_2;
  int mac_port_2;
  char type_begin;
  char type_end;
};
#pragma pack(pop)

struct IPHeader {
  uint16_t first_16_bytes;
  uint16_t length;
  uint16_t id;
  int16_t len;
  uint32_t not_used_1;
  uint32_t not_used_2;
  uint32_t not_used_3;
};

struct TCPHeader {
  uint16_t src_port;  
  uint16_t dst_port;  
  uint32_t seq_n;    
  uint32_t ack_n;    
  uint16_t offset;  
  uint16_t win;    
  uint16_t crc;   
  uint16_t ptr;  
};

template <int T>
void TransformValue(const std::bitset<T> &input, std::bitset<T> &output) {
  const int bytes_number = input.size() / 8;
  std::string bit_string;
  for (int i = 0; i < bytes_number; ++i) {
    for (int j = 8 * (i + 1) - 1; j >= 8 * (i); --j) {
      std::ostringstream str;
      str << input[j];
      bit_string += str.str();
    }
  }
  output = std::bitset<T>(bit_string);
}

void ParsePorts(const std::bitset<16> &cliet_reverse,
                const std::bitset<16> &server_reverse, uint16_t *client,
                uint16_t *server) {
  std::bitset<16> normal_client;
  std::bitset<16> normal_server;
  TransformValue<16>(cliet_reverse, normal_client);
  TransformValue<16>(server_reverse, normal_server);
  *client = (uint16_t)normal_client.to_ulong();
  *server = (uint16_t)normal_server.to_ulong();
}

Reader::Reader(const std::string &path_to_search,
               const std::string &path_to_save)
    : search_path_(path_to_search),
      save_path_(path_to_save),
      first_packet(true),
      http_content_length(100000) {
  file.open(search_path_, std::ifstream::in | std::ifstream::binary);
  if (!file.is_open()) throw std::runtime_error("File not exist");

  output_file.open(save_path_, std::ofstream::out | std::ofstream::binary);
  if (!output_file.is_open())
    throw std::runtime_error("File couldnt be create");
};

void Reader::LoadPicture() {
  ParsePcapGlobalHeader();
  const int triple_handshake = 3;
  for (size_t i = 0; i < triple_handshake; ++i) {
    OnePacketParse();
  }

  counter = 0;
  while (http_content_length != 0) {
    OnePacketParse();
    ++counter;
  }
}

void Reader::OnePacketParse() {
  ParsePcapLocalHeader();
  ParseEthernetTopHeader();
  ParseIPHeader();
  ParseTCPHeader();
}

void Reader::SkipPadding(const int &real_size, const int &actual_size) {
  const int diff = std::fabs(actual_size - real_size);
  char not_used[6];
  file.read((char *)&not_used, 6);
}

void Reader::ParseHTTPRequest() {
  const int size_of_field = 15;
  const size_t begin = http_request_buffer.find("Content-Length:");
  const size_t end = http_request_buffer.find("Content-Type:");
  std::string number(http_request_buffer.begin() + begin + 15,
                     http_request_buffer.begin() + end - 1);
  std::istringstream str(number);
  str >> http_content_length;
}

void Reader::ParseEthernetTopHeader() {
  EthernetFront ethernt_hdr;
  size_t ethernt_hdr_size = sizeof(ethernt_hdr);
  file.read((char *)&ethernt_hdr, ethernt_hdr_size);
}

void Reader::ParseIPHeader() {
  IPHeader ip_hdr;
  size_t ip_hdr_size = sizeof(ip_hdr);
  file.read((char *)&ip_hdr, ip_hdr_size);
  std::bitset<16> length_bits_reverse(ip_hdr.length);
  std::bitset<16> length_bits_normal;
  TransformValue<16>(length_bits_reverse, length_bits_normal);
  packet_length = (uint16_t)length_bits_normal.to_ulong();
}

void Reader::ParseTCPHeader() {
  TCPHeader tcp_hdr;
  int tcp_hdr_size = sizeof(tcp_hdr);
  file.read((char *)&tcp_hdr, tcp_hdr_size);

  std::bitset<16> client_bits_reverse(tcp_hdr.src_port);
  std::bitset<16> server_bits_reverse(tcp_hdr.dst_port);

  ParsePorts(client_bits_reverse, server_bits_reverse, &source_port,
             &dest_port);
  if (first_packet) {
    initial_client_port = source_port;
    initial_server_port = dest_port;
    first_packet = false;
  }

  std::bitset<16> offset_bits{tcp_hdr.offset};
  int offset_int = 0;
  for (int i = 4, counter = 0; i < 8; ++i) {
    offset_int += offset_bits[i] * std::pow(2, counter);
    ++counter;
  }
  offset_int = offset_int * 4;
  int read_length = sizeof(tcp_hdr) + 20;

  char buffer[100];
  if (sizeof(tcp_hdr) < offset_int) {
    file.read(buffer, fabs(tcp_hdr_size - offset_int));
    read_length += fabs(tcp_hdr_size - offset_int);
  }

  if ((read_length - packet_length) < 0) {
    while (read_length < packet_length) {
      char buffer[100];
      if (std::fabs(read_length - packet_length) >= 100) {
        file.read(buffer, 100);
        if (initial_server_port == source_port) {
          if (counter != 2)
            output_file.write(buffer, 100);
          else
            http_request_buffer += buffer;

          if (counter >= 3) http_content_length -= 100;
        }

        read_length += 100;
      } else {
        const int diff = std::fabs(read_length - packet_length);
        file.read(buffer, diff);
        if (initial_server_port == source_port) {
          if (counter != 2)
            output_file.write(buffer, diff);
          else {
            http_request_buffer += std::string(buffer, buffer + diff);
          }

          if (counter >= 3) http_content_length -= diff;
        }
        read_length += diff;
      }
    }
  }

  if (initial_server_port == source_port && read_length + 14 < 60  )
  {
    SkipPadding(read_length + 14, 60);
  }

  if (counter == 2) {
    ParseHTTPRequest();
  }
}

void Reader::ParsePcapLocalHeader() {
  PcapLocalHeader pcap_hdr_loc;
  size_t pcap_hdr_loc_size = sizeof(pcap_hdr_loc);
  file.read((char *)&pcap_hdr_loc, pcap_hdr_loc_size);
}

void Reader::ParsePcapGlobalHeader() {
  PcapGlobHeader pcap_hdr_global;
  size_t pcap_hdr_global_size = sizeof(pcap_hdr_global);
  file.read((char *)&pcap_hdr_global, pcap_hdr_global_size);
}
