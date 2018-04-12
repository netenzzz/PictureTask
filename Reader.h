#include <fstream>
#include <string>
class Reader {
 public:
  Reader(const std::string &path_to_search, const std::string &path_to_save);
  void LoadPicture();

 private:
  void ParsePcapGlobalHeader();
  void ParsePcapLocalHeader();
  void ParseEthernetTopHeader();
  void SkipPadding(const int &read_size, const int &actual_size);
  void ParseIPHeader();
  void ParseTCPHeader();
  void OnePacketParse();
  void ParseHTTPRequest();
  std::string search_path_;
  std::string save_path_;
  std::ifstream file;
  std::ofstream output_file;
  uint16_t source_port;
  uint16_t dest_port;
  uint16_t initial_client_port;
  uint16_t initial_server_port;
  int tcp_header_size;
  bool first_packet;
  uint16_t packet_length;
  int http_content_length;
  int counter;
  std::string http_request_buffer;
};
