package recovery

import _ "embed"

//go:generate clang -g -O2 -target bpf -D__TARGET_ARCH_arm64 -I /usr/include/aarch64-linux-gnu -c bpf/faults.c -o faults_arm64.o
//go:embed faults_arm64.o
var faultProgram []byte
