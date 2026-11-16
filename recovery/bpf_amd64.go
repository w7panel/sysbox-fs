package recovery

import _ "embed"

//go:generate clang -g -O2 -target bpf -D__TARGET_ARCH_x86 -I /usr/include/x86_64-linux-gnu -c bpf/faults.c -o faults_amd64.o
//go:embed faults_amd64.o
var faultProgram []byte
