package scers

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"golang.org/x/crypto/ssh"
	"golang.org/x/crypto/ssh/agent"
	"io"
	"math/rand"
	"net"
	"os"
	"os/exec"
	"strings"
	"sync"
	"sync/atomic"
	"time"
)

const (
	maxSSHAgentConn         = 128
	defaultPort             = "22"
	chunkSize               = 65536
	throughputSleepInterval = 100
	minChunks               = 10
	minThroughput           = chunkSize * minChunks * (1000 / throughputSleepInterval)
)

var maxThroughput uint64

//----------------------------------------------

type connHostsMap struct {
	mu sync.Mutex
	v  map[string]*ssh.Client
}

func (c *connHostsMap) get(hostname string) (v *ssh.Client, ok bool) {
	c.mu.Lock()
	v, ok = c.v[hostname]
	c.mu.Unlock()
	return v, ok
}

func (c *connHostsMap) set(hostname string, v *ssh.Client) {
	c.mu.Lock()
	c.v[hostname] = v
	c.mu.Unlock()
}

func (c *connHostsMap) close(hostname string) error {
	c.mu.Lock()
	v, ok := c.v[hostname]
	delete(c.v, hostname)
	c.mu.Unlock()
	if !ok {
		return nil
	}

	return v.Close()
}

//----------------------------------------------

// Config - configuration for setting up a new SSH client.
//
// SSHAgentPath - the value of the SSH_AUTH_SOCK variable
//
// Keys - map, key - file name, value - password, if any.
//
// DisConnAfterUse - close the connection after execution.
type Config struct {
	GeneralUser          string
	GeneralPort          string
	GeneralPass          string
	SSHAgentPath         string
	MaxSimultaneousConn  uint
	MaxSSHAgentConn      uint
	GeneralMaxThroughput uint64
	Keys                 map[string]string
	DisConnAfterUse      bool
}

type Client struct {
	GeneralUser          string
	GeneralPass          string
	GeneralPort          string
	MaxSimultaneousConn  uint
	MaxThroughputCh      chan bool
	Signers              []ssh.Signer
	DisConnAfterUse      bool
	TimedOutHosts        map[string]bool
	ConnectedHosts       connHostsMap
	SSHAgentPath         string
	SSHAgentMaxConn      uint
	SSHAgentConnChan     chan chan bool
	SSHAgentConnFreeChan chan bool
	Result               chan *Result
}

// NewClient - creates a session for parallel execution of commands on remote servers.
func NewClient(conf Config) (*Client, error) {
	var client Client

	client.GeneralUser = conf.GeneralUser
	client.GeneralPass = conf.GeneralPass
	client.GeneralPort = conf.GeneralPort
	if conf.GeneralPort == "" {
		client.GeneralPort = defaultPort
	}

	client.SSHAgentPath = conf.SSHAgentPath
	if client.SSHAgentPath != "" {
		client.SSHAgentConnChan = make(chan chan bool)
		client.SSHAgentConnFreeChan = make(chan bool, 10)
		client.SSHAgentMaxConn = conf.MaxSSHAgentConn
		if client.SSHAgentMaxConn == 0 {
			client.SSHAgentMaxConn = maxSSHAgentConn
		}
		go client.sshAgentThreadControl(client.SSHAgentMaxConn)
	}

	if len(conf.Keys) != 0 {
		client.makeSigners(conf.Keys)
	}

	client.MaxSimultaneousConn = conf.MaxSimultaneousConn

	client.DisConnAfterUse = conf.DisConnAfterUse
	client.TimedOutHosts = make(map[string]bool)
	client.ConnectedHosts = connHostsMap{v: make(map[string]*ssh.Client)}

	client.MaxThroughputCh = make(chan bool, minChunks)
	maxThroughput = conf.GeneralMaxThroughput
	go client.controlMaxThroughputThread()

	return &client, nil
}

//----------------------------------------------

func (c *Client) controlMaxThroughputThread() {
	for {
		throughput := atomic.LoadUint64(&maxThroughput)

		chunks := throughput / chunkSize * throughputSleepInterval / 1000

		if chunks < minChunks {
			chunks = minChunks
		}

		for i := uint64(0); i < chunks; i++ {
			c.MaxThroughputCh <- true
		}

		if throughput > 0 {
			time.Sleep(throughputSleepInterval * time.Millisecond)
		}
	}
}

//----------------------------------------------

func (c *Client) sshAgentThreadControl(maxConn uint) {
	freeConn := maxConn
	for {
		reqCh := c.SSHAgentConnChan
		freeCh := c.SSHAgentConnFreeChan

		if freeConn <= 0 {
			reqCh = nil
		}

		select {
		case respChan := <-reqCh:
			freeConn--
			respChan <- true
		case <-freeCh:
			freeConn++
		}
	}
}

func (c *Client) makeSigners(keys map[string]string) {
	for path, pass := range keys {
		signer, err := makeSigner(path, pass)
		if err == nil {
			c.Signers = append(c.Signers, signer)
		}
	}
}

func makeSigner(path, pass string) (ssh.Signer, error) {
	fp, err := os.Open(path)
	if err != nil {
		if !os.IsNotExist(err) {
			return nil, fmt.Errorf("Could not parse %s: %v", path, err)
		}

	}
	defer fp.Close()

	buf, err := io.ReadAll(fp)
	if err != nil {
		return nil, fmt.Errorf("Could not read %s: %v", path, err)
	}

	if bytes.Contains(buf, []byte("ENCRYPTED")) {
		var (
			tmpfp *os.File
			out   []byte
		)

		tmpfp, err = os.CreateTemp("", "key")
		if err != nil {
			return nil, fmt.Errorf("Could not create temporary file: %v", err)
		}

		tmpName := tmpfp.Name()

		defer func() { tmpfp.Close(); os.Remove(tmpName) }()

		_, err = tmpfp.Write(buf)
		if err != nil {
			return nil, fmt.Errorf("Could not write encrypted key contents to temporary file: %v", err)
		}

		err = tmpfp.Close()
		if err != nil {
			return nil, fmt.Errorf("Could not close temporary file: %v", err)
		}

		cmd := exec.Command("ssh-keygen", "-f", tmpName, "-N", "", "-P", pass, "-p")
		out, err = cmd.CombinedOutput()
		if err != nil {
			return nil, fmt.Errorf(string(out))
		}

		tmpfp, err = os.Open(tmpName)
		if err != nil {
			return nil, fmt.Errorf("Cannot open back %v", err)
		}

		buf, err = io.ReadAll(tmpfp)
		if err != nil {
			return nil, fmt.Errorf("Could not read %s: %v", path, err)
		}

		tmpfp.Close()
		os.Remove(tmpName)
	}

	signer, err := ssh.ParsePrivateKey(buf)
	if err != nil {
		return nil, fmt.Errorf("Could not parse %s: %v", path, err)
	}

	return signer, nil
}

// ----------------------------------------------

// SSHTask - data for executing a command on a remote server.
type SSHTask struct {
	User string
	Pass string
	Host string
	Port string
	Cmd  string
}

// ExecuteCmd - executes commands on remote servers according to the SSHTask array.
func (c *Client) ExecuteCmd(ctx context.Context, tasks []SSHTask) {

	responseCh := make(chan *Result, len(tasks))
	defer close(responseCh)

	c.Result = make(chan *Result, len(tasks))
	defer close(c.Result)

	maxSimultaneousConn := uint(len(tasks))
	if c.MaxSimultaneousConn > 0 {
		maxSimultaneousConn = c.MaxSimultaneousConn
	}
	maxSimultaneousCh := make(chan struct{}, maxSimultaneousConn)
	defer close(maxSimultaneousCh)

	for _, t := range tasks {
		go func(task SSHTask) {
			maxSimultaneousCh <- struct{}{}
			defer func() { <-maxSimultaneousCh }()
			responseCh <- c.executeCmd(task)
		}(t)
	}

	for i := 0; i < len(tasks); i++ {
		select {
		case <-ctx.Done():
			goto finish
		case msg := <-responseCh:
			delete(c.TimedOutHosts, msg.Host)
			c.Result <- msg
		}
	}
finish:
	for hostname := range c.TimedOutHosts {
		c.ConnectedHosts.close(hostname)
	}
}

func (c *Client) executeCmd(t SSHTask) *Result {
	err := c.checkSSHTaskFields(&t)
	if err != nil {
		return &Result{Host: t.Host, Cmd: t.Cmd, Err: err}
	}

	conn, err := c.getConnection(t.Host, t.Port, t.User, t.Pass)
	if err != nil {
		return &Result{Host: t.Host, Cmd: t.Cmd, Err: err}
	}

	session, err := conn.NewSession()
	if err != nil {
		return &Result{Host: t.Host, Cmd: t.Cmd, Err: err}
	}
	if c.DisConnAfterUse {
		defer c.ConnectedHosts.close(t.Host)
	}
	defer session.Close()

	var (
		stdoutBuf bytes.Buffer
		stderrBuf bytes.Buffer
	)

	session.Stdout = &stdoutBuf
	session.Stderr = &stderrBuf

	startTime := time.Now()
	err = session.Run(t.Cmd)
	endTime := time.Now()

	elapsedTime := endTime.Sub(startTime).Seconds()

	return &Result{
		Host:        t.Host,
		Cmd:         t.Cmd,
		Stdout:      stdoutBuf.String(),
		Stderr:      stderrBuf.String(),
		Err:         err,
		ElapsedTime: elapsedTime,
	}
}

func (c *Client) checkSSHTaskFields(t *SSHTask) error {
	if t.Host == "" {
		return fmt.Errorf("Empty 'Host'")
	}
	if t.Cmd == "" {
		return fmt.Errorf("Empty 'Cmd'")
	}
	if t.User == "" {
		t.User = c.GeneralUser
	}
	if t.Pass == "" {
		t.Pass = c.GeneralPass
	}
	if t.Port == "" {
		t.Port = c.GeneralPort
	}
	return nil
}

//----------------------------------------------

// CSPTask - data for transferring a file to a remote server.
type CSPTask struct {
	User          string
	Pass          string
	Host          string
	Port          string
	Source        string
	Target        string
	MaxThroughput uint64
}

// UploadFile - sends files to remote servers according to the CSPTask array.
func (c *Client) UploadFile(ctx context.Context, tasks []CSPTask) {

	responseCh := make(chan *Result, len(tasks))
	defer close(responseCh)

	c.Result = make(chan *Result, len(tasks))
	defer close(c.Result)

	maxSimultaneousConn := uint(len(tasks))
	if c.MaxSimultaneousConn > 0 {
		maxSimultaneousConn = c.MaxSimultaneousConn
	}
	maxSimultaneousCh := make(chan struct{}, maxSimultaneousConn)
	defer close(maxSimultaneousCh)

	for _, t := range tasks {
		go func(task CSPTask) {
			maxSimultaneousCh <- struct{}{}
			defer func() { <-maxSimultaneousCh }()
			responseCh <- c.uploadFile(task)
		}(t)
	}

	for i := 0; i < len(tasks); i++ {
		select {
		case <-ctx.Done():
			goto finish
		case msg := <-responseCh:
			delete(c.TimedOutHosts, msg.Host)
			c.Result <- msg
		}
	}
finish:
	for hostname := range c.TimedOutHosts {
		c.ConnectedHosts.close(hostname)
	}
}

func (c *Client) uploadFile(t CSPTask) *Result {
	err := c.checkCSPTaskFields(&t)
	if err != nil {
		return &Result{Host: t.Host, Source: t.Source, Target: t.Target, Err: err}
	}

	file, err := os.Open(t.Source)
	if err != nil {
		return &Result{Host: t.Host, Source: t.Source, Target: t.Target, Err: err}
	}
	defer file.Close()

	contents, err := io.ReadAll(file)
	if err != nil {
		return &Result{
			Host:   t.Host,
			Source: t.Source,
			Target: t.Target,
			Err:    fmt.Errorf(fmt.Sprint("Cannot read %s contents: %v", t.Source, err)),
		}
	}

	conn, err := c.getConnection(t.Host, t.Port, t.User, t.Pass)
	if err != nil {
		return &Result{Host: t.Host, Source: t.Source, Target: t.Target, Err: err}
	}

	session, err := conn.NewSession()
	if err != nil {
		return &Result{Host: t.Host, Source: t.Source, Target: t.Target, Err: err}
	}
	if c.DisConnAfterUse {
		defer c.ConnectedHosts.close(t.Host)
	}
	defer session.Close()

	startTime := time.Now()
	cmd := fmt.Sprintf("cat >'%s'", strings.Replace(t.Target, "'", "'\\''", -1))
	stdinPipe, err := session.StdinPipe()
	if err != nil {
		return &Result{Host: t.Host, Source: t.Source, Target: t.Target, Err: err}
	}

	var stdoutBuf bytes.Buffer
	var stderrBuf bytes.Buffer
	session.Stdout = &stdoutBuf
	session.Stderr = &stderrBuf

	err = session.Start(cmd)
	if err != nil {
		return &Result{Host: t.Host, Source: t.Source, Target: t.Target, Err: err}
	}

	for start, maxEnd := 0, len(contents); start < maxEnd; start += chunkSize {
		<-c.MaxThroughputCh

		end := start + chunkSize
		if end > maxEnd {
			end = maxEnd
		}
		_, err = stdinPipe.Write(contents[start:end])
		if err != nil {
			return &Result{Host: t.Host, Source: t.Source, Target: t.Target, Err: err}
		}
	}

	err = stdinPipe.Close()
	if err != nil {
		return &Result{Host: t.Host, Source: t.Source, Target: t.Target, Err: err}
	}

	err = session.Wait()
	endTime := time.Now()

	elapsedTime := endTime.Sub(startTime).Seconds()

	return &Result{
		Host:        t.Host,
		Source:      t.Source,
		Target:      t.Target,
		Stdout:      stdoutBuf.String(),
		Stderr:      stderrBuf.String(),
		ElapsedTime: elapsedTime,
		Err:         err,
	}
}

func (c *Client) checkCSPTaskFields(t *CSPTask) error {
	if t.Host == "" {
		return fmt.Errorf("Empty 'Host'")
	}
	if t.Source == "" {
		return fmt.Errorf("Empty 'Source'")
	}
	if t.Target == "" {
		return fmt.Errorf("Empty 'Target'")
	}
	if t.MaxThroughput != 0 {
		atomic.StoreUint64(&t.MaxThroughput, maxThroughput)
	}
	if t.MaxThroughput > 0 && t.MaxThroughput < minThroughput {
		return fmt.Errorf(fmt.Sprint("Minimal supported throughput is ", minThroughput, " Bps"))
	}
	if t.User == "" {
		t.User = c.GeneralUser
	}
	if t.Pass == "" {
		t.Pass = c.GeneralPass
	}
	if t.Port == "" {
		t.Port = c.GeneralPort
	}
	return nil
}

//----------------------------------------------

func (c *Client) getConnection(host, port, user, pass string) (*ssh.Client, error) {
	var err error

	conn, ok := c.ConnectedHosts.get(host)
	if ok {
		return conn, nil
	}

	defer func() {
		if msg := recover(); msg != nil {
			err = errors.New("Panic: " + fmt.Sprint(msg))
		}
	}()

	c.waitAgent()
	conf, agentConn, err := c.makeConfig(user, pass)
	if agentConn != nil {
		defer agentConn.Close()
	}
	if err != nil {
		return conn, err
	}

	defer c.releaseAgent()

	conn, err = ssh.Dial("tcp", fmt.Sprintf("%s:%s", host, port), conf)
	if err != nil {
		return conn, err
	}

	c.ConnectedHosts.set(host, conn)
	return conn, err
}

func (c *Client) waitAgent() {
	if c.SSHAgentPath != "" {
		respChan := make(chan bool)
		c.SSHAgentConnChan <- respChan
		<-respChan
	}
}

func (c *Client) makeConfig(user, pass string) (*ssh.ClientConfig, net.Conn, error) {
	var (
		clientAuth    = []ssh.AuthMethod{}
		agentUnixSock net.Conn
		err           error
	)

	if c.SSHAgentPath != "" {
		for {
			agentUnixSock, err = net.Dial("unix", c.SSHAgentPath)

			if err != nil {
				netErr := err.(net.Error)
				if netErr.Timeout() {
					time.Sleep(time.Duration(rand.Intn(100)) * time.Millisecond)
					continue
				}
				return nil, nil, fmt.Errorf("Cannot open connection to SSH agent: %v", netErr.Error())
			} else {
				authAgent := ssh.PublicKeysCallback(agent.NewClient(agentUnixSock).Signers)
				clientAuth = append(clientAuth, authAgent)
			}
			break
		}
	}

	if len(c.Signers) > 0 {
		clientAuth = append(clientAuth, ssh.PublicKeys(c.Signers...))
	}

	clientAuth = append(clientAuth, ssh.Password(pass))

	return &ssh.ClientConfig{
		User:            user,
		Auth:            clientAuth,
		HostKeyCallback: ssh.InsecureIgnoreHostKey(),
	}, agentUnixSock, nil
}

func (c *Client) releaseAgent() {
	if c.SSHAgentPath != "" {
		c.SSHAgentConnFreeChan <- true
	}
}

//----------------------------------------------

// Result - the result of executing ExecuteCmd or UploadFile.
type Result struct {
	Host        string
	Cmd         string
	Source      string
	Target      string
	Stdout      string
	Stderr      string
	Err         error
	ElapsedTime float64
}

// GetResult - returns the result of the last execution of ExecuteCmd or UploadFile.
func (c *Client) GetResult() []Result {
	var results []Result
	for result := range c.Result {
		results = append(results, *result)
	}
	return results
}

//----------------------------------------------

// Close - closes all previously created connections and channels.
//
// After using Close the client created by NewClient is not valid.
func (c *Client) Close() {
	for hostname := range c.TimedOutHosts {
		c.ConnectedHosts.close(hostname)
	}
	close(c.MaxThroughputCh)
	close(c.SSHAgentConnFreeChan)
	close(c.SSHAgentConnChan)
}
