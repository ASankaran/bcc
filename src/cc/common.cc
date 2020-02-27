/*
 * Copyright (c) 2016 Catalysts GmbH
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
#include <fstream>
#include <sstream>

#include "common.h"
#include "vendor/tinyformat.hpp"

#include <llvm/DebugInfo/Symbolize/Symbolize.h>
#include <llvm/Object/ObjectFile.h>


namespace ebpf {

std::vector<int> read_cpu_range(std::string path) {
  std::ifstream cpus_range_stream { path };
  std::vector<int> cpus;
  std::string cpu_range;

  while (std::getline(cpus_range_stream, cpu_range, ',')) {
    std::size_t rangeop = cpu_range.find('-');
    if (rangeop == std::string::npos) {
      cpus.push_back(std::stoi(cpu_range));
    }
    else {
      int start = std::stoi(cpu_range.substr(0, rangeop));
      int end = std::stoi(cpu_range.substr(rangeop + 1));
      for (int i = start; i <= end; i++)
        cpus.push_back(i);
    }
  }
  return cpus;
}

std::vector<int> get_online_cpus() {
  return read_cpu_range("/sys/devices/system/cpu/online");
}

std::vector<int> get_possible_cpus() {
  return read_cpu_range("/sys/devices/system/cpu/possible");
}

std::string get_pid_exe(pid_t pid) {
  char exe_path[4096];
  int res;

  std::string exe_link = tfm::format("/proc/%d/exe", pid);
  res = readlink(exe_link.c_str(), exe_path, sizeof(exe_path));
  if (res == -1)
    return "";
  if (res >= static_cast<int>(sizeof(exe_path)))
    res = sizeof(exe_path) - 1;
  exe_path[res] = '\0';
  return std::string(exe_path);
}

std::string get_debug_line_info(std::string module_name, uint64_t addr) {
	llvm::symbolize::LLVMSymbolizer::Options opts;
	llvm::symbolize::LLVMSymbolizer symbolizer(opts);
	auto res = symbolizer.symbolizeInlinedCode(module_name, addr);
	if(!res) {
		return "[UNKNOWN]:??";
	}
	auto line_info = res.get();
	std::string debug_info("");
	for(uint32_t i = 0; i < line_info.getNumberOfFrames(); i++) {
		debug_info += line_info.getFrame(i).FileName + ":" + std::to_string(line_info.getFrame(i).Line);
		if(i != line_info.getNumberOfFrames() - 1) {
			debug_info += ";";
		}
	}
	return debug_info;
}

} // namespace ebpf
