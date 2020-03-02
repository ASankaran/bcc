/*
 * Copyright (c) 2015 PLUMgrid, Inc.
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

#pragma once

#include <memory>
#include <string>
#include <unistd.h>
#include <vector>

namespace ebpf {

#ifdef __cpp_lib_make_unique
using std::make_unique;
#else
template <class T, class... Args>
typename std::enable_if<!std::is_array<T>::value, std::unique_ptr<T>>::type
make_unique(Args &&... args) {
  return std::unique_ptr<T>(new T(std::forward<Args>(args)...));
}
#endif

std::vector<int> get_online_cpus();

std::vector<int> get_possible_cpus();

std::string get_pid_exe(pid_t pid);

struct DebugLineInfo {
	DebugLineInfo(std::string file_name, int line_number)
		: file_name(file_name), line_number(line_number){};

	std::string to_string() {
		return file_name + ":" + std::to_string(line_number);
	}

	friend bool operator==(const DebugLineInfo& x, const DebugLineInfo& y) {
		return x.file_name == y.file_name && x.line_number == y.line_number;
	}

	std::string file_name;
	int line_number;
};

std::vector<DebugLineInfo> get_debug_line_info(std::string module_name, uint64_t addr);

}  // namespace ebpf
