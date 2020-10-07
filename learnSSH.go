package main

/*
I am learning how to use the ssh module and also to practise golang with things I do in work,
One of them is doing ssh to devices.
*/
import (
	"encoding/base64"
	"fmt"
	"io"
	"log"
	"net"
	"os"

	"golang.org/x/crypto/ssh"
	"golang.org/x/crypto/ssh/terminal" // Require go get golang.org/x/sys/windows
)

// See reference: https://medium.com/tarkalabs/ssh-recipes-in-go-part-one-5f5a44417282 for basic usage.

func hKeyString(k ssh.PublicKey) string {
	// Reference: https://stackoverflow.com/questions/44269142/golang-ssh-getting-must-specify-hoskeycallback-error-despite-setting-it-to-n/63308243#63308243
	return k.Type() + " " + base64.StdEncoding.EncodeToString(k.Marshal())
}

func callBack(ignoreKey bool) ssh.HostKeyCallback {
	/*
		This is a callback function required by ssh.ClientConfig, if ignoreKey is true then ssh.InsecureIgnoreHostKey() is used,
		otherwise ssh.HostKeyCallBack is used and an anonymous function is called, this ensures there is host key verification check,
		if key does not exist as trusted host then a warning is displayed to advise user.
		With this callback I do not need to write two functions that only the HostKeyCallback is different.
	*/
	if ignoreKey {
		return ssh.InsecureIgnoreHostKey()
	}
	// Reference: https://stackoverflow.com/questions/44269142/golang-ssh-getting-must-specify-hoskeycallback-error-despite-setting-it-to-n/63308243#63308243
	return ssh.HostKeyCallback(func(_ string, _ net.Addr, pubKey ssh.PublicKey) error {
		log.Printf("Warning: There is no trusted key in effect, add this %q", hKeyString(pubKey))
		return nil
	})
}

func passwdSSH(addr, username, password string, ignoreKey bool) (c *ssh.Client, err error) {
	config := &ssh.ClientConfig{
		User: username,
		Auth: []ssh.AuthMethod{
			ssh.Password(password)},
		// Reference: https://github.com/helloyi/go-sshclient/blob/master/sshclient.go
		// only the pubkey is an interesting item, see: https://stackoverflow.com/questions/44269142/golang-ssh-getting-must-specify-hoskeycallback-error-despite-setting-it-to-n
		// If there is no trustedkey found for the target host, log a warning to advise user.
		// The warning looks like this:
		// 2020/10/07 15:11:07 Warning: There is no trusted key in effect, add this "ecdsa-sha2-nistp256 AAAAE2VjZHNhLXNoYTItbmlzdHAyNTYAAAAIbmlzdHAyNTYAAABBBMria+C+ScdBZ6JuCAa+oeu+DiS3Z9uj4PobRtWogWDBlL2GKYqKZHzgSTN3iLpGX4d9AIAMpsqEKCyfUUyP+kA="
		HostKeyCallback: callBack(ignoreKey),
	}
	c, err = ssh.Dial("tcp", addr, config)
	return
}

func cmd(command string, conn *ssh.Client) {
	// Create a new session from the ssh client.
	session, err := conn.NewSession()
	// Error in creating session
	if err != nil {
		log.Fatalln(err)
	}
	defer session.Close()

	// This portion output to stdout
	sessStdOut, err := session.StdoutPipe()
	if err != nil {
		log.Fatalln(err)
	}
	go io.Copy(os.Stdout, sessStdOut)

	// If there is error, the output is displayed in stderr.
	sessStdErr, err := session.StderrPipe()
	if err != nil {
		log.Fatalln(err)
	}
	go io.Copy(os.Stderr, sessStdErr)
	if err := session.Run(command); err != nil {
		log.Fatalln(err)
	}
}

func askForInfo() (string, string, string) {
	var username, addr, ipAddress string
	fmt.Println("\nUsername: ")
	fmt.Scanln(&username)
	fmt.Println("Password: ")
	// Do not use \n in fmt.Println() because \n is ignored by terminal.ReadPassword() method.
	// https://godoc.org/golang.org/x/crypto/ssh/terminal#ReadPassword
	// The return value is a byte slice, hence must convert to string with string().
	password, _ := terminal.ReadPassword(int(os.Stdin.Fd()))
	fmt.Println("\nServer ip address: ")
	fmt.Scanln(&ipAddress)

	// fmt.Sprintf formats the string and return the formatted string.
	addr = fmt.Sprintf("%s:22", ipAddress)
	return addr, username, string(password)
}

func main() {
	// Test the functions here.
	addr, username, password := askForInfo()
	conn, err := passwdSSH(addr, username, password, false)
	if err != nil {
		log.Fatalln(err)
	}
	defer conn.Close()
	cmd("ls -lAhF", conn)
}
