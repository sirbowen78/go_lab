package main

/*
This is a re-write of the original program I have attempted to learn Go.
The original code is here: https://github.com/sirbowen78/go_lab/blob/main/learnSSH.go
This re-write helps me understand about pointer receiver, it is much more complicated
than the original.
*/

import (
	"bufio"
	"encoding/base64"
	"fmt"
	"io"
	"log"
	"net"
	"os"
	"strings"

	"golang.org/x/crypto/ssh"
	"golang.org/x/crypto/ssh/terminal"
)

type sshConfig struct {
	// configuration template for creating ssh client.
	username  string
	password  string
	ipAddr    string
	ignoreKey bool
}

type sshclient struct {
	client *ssh.Client
}

// Reference: http://networkbit.ch/golang-ip-address-manipulation/#net_ip_ipmask_methods
func v4maskTocidr(mask string) (cidr int) {
	// argument has to be a ipv4 netmask
	m := net.IPMask(net.ParseIP(mask).To4())
	cidr, _ = m.Size()
	return
}

func cidrTov4mask(subnet string) string {
	// argument must be a subnet eg. 192.168.1.0/24
	var m []byte // Use to store Mask.
	_, ipv4net, err := net.ParseCIDR(subnet)
	if err != nil {
		log.Fatalln(err)
	}
	m = ipv4net.Mask
	return fmt.Sprintf("%d.%d.%d.%d", m[0], m[1], m[2], m[3])
}

func isIPv4Address(addr string) bool {
	/*
		addr is an address without the "/" eg. 10.10.10.1 not 10.10.10.1/24
		net.ParseIP.To4() method returns back the address if valid, otherwise is nil if address is invalid.
	*/
	if net.ParseIP(addr).To4() == nil {
		return false
	}
	return true
}

func parseCmd() (cmd string) {
	/*
		Have to use bufio.NewScanner to scan the text (with spaces) from stdin.
		fmt.Scanln() and Scanf() cannot fulfil this requirement because the text
		will be truncated when there is a space or newline.
	*/
	scan := bufio.NewScanner(os.Stdin)
	fmt.Println("\nCommand: ")
	if scan.Scan() {
		cmd = scan.Text()
	}
	return
}

func getPassword() string {
	fmt.Println("Password: ")
	passwd, _ := terminal.ReadPassword(int(os.Stdin.Fd()))
	// convert byte slice to string
	return string(passwd)
}

func hostKeyString(k ssh.PublicKey) string {
	return k.Type() + " " + base64.StdEncoding.EncodeToString(k.Marshal())
}

func hKeyCallBack(c *sshConfig) ssh.HostKeyCallback {
	if c.ignoreKey {
		return ssh.InsecureIgnoreHostKey()
	}
	return ssh.HostKeyCallback(func(_ string, _ net.Addr, pubKey ssh.PublicKey) error {
		log.Printf("Warning: %s is not in trusted key, add this public key to trusted key: %q", c.ipAddr, hostKeyString(pubKey))
		return nil
	})
}

func (c *sshConfig) sshClient() (conn sshclient, err error) {
	config := &ssh.ClientConfig{
		User: c.username,
		Auth: []ssh.AuthMethod{
			ssh.Password(c.password)},
		HostKeyCallback: hKeyCallBack(c),
	}
	// ssh.Dial needs to have ipaddress:port as full address.
	addr := fmt.Sprintf("%s:22", c.ipAddr)
	conn.client, err = ssh.Dial("tcp", addr, config)
	return
}

func (c *sshConfig) getSSHConfig() {
	var ignoreKeyOpt string
	fmt.Println("\nIPv4 address: ")
	fmt.Scanln(&c.ipAddr)
	if !isIPv4Address(c.ipAddr) {
		log.Fatalln("Invalid IPv4 address!")
	}
	fmt.Println("\nUsername: ")
	fmt.Scanln(&c.username)
	c.password = getPassword()
	fmt.Println("\nIgnore host key? [Y/N]: ")
	fmt.Scanln(&ignoreKeyOpt)
	if strings.ToUpper(ignoreKeyOpt) == "Y" {
		c.ignoreKey = true
	} else if strings.ToUpper(ignoreKeyOpt) == "N" {
		c.ignoreKey = false
	} else if ignoreKeyOpt == "" {
		c.ignoreKey = false
		log.Println("No option chosen, default N is chosen.")
	} else {
		log.Fatalln("Invalid choice, must be either Y or N.")
	}
}

func (conn sshclient) cmd() {
	session, err := conn.client.NewSession()
	if err != nil {
		log.Fatalln(err)
	}
	defer session.Close()

	sessStdOut, err := session.StdoutPipe()
	if err != nil {
		log.Fatalln(err)
	}
	go io.Copy(os.Stdout, sessStdOut)

	sessStdErr, err := session.StderrPipe()
	if err != nil {
		log.Fatalln(err)
	}
	go io.Copy(os.Stderr, sessStdErr)
	cmd := parseCmd()
	if cmd == "" {
		log.Fatalln("Command cannot be left blank.")
	}
	if err := session.Run(cmd); err != nil {
		log.Fatalln(err)
	}
}

func main() {
	var (
		cfg  sshConfig
		conn sshclient
		e    error
	)
	cfg.getSSHConfig()
	conn, e = cfg.sshClient()
	if e != nil {
		log.Fatalln(e)
	}
	conn.cmd()
}
