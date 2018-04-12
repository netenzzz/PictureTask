#include <iostream>
#include "Reader.h"

int main(int argc, char *argv[]) {
  try {
    Reader reader(argv[1], argv[2]);
    reader.LoadPicture();
  } catch (std::exception &err) {
    std::cout << err.what() << std::endl;
  }
  return 0;
}