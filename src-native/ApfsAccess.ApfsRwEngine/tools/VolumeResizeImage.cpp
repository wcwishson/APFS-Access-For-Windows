#include "VolumeResizeCli.h"
int wmain(int argc, wchar_t** argv) { return apfsaccess::rw::volume_image_cli::Run(argc, argv, false); }
