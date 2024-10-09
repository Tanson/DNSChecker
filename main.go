package main

import (
	"bufio"
	"bytes"
	"flag"
	"fmt"
	"github.com/miekg/dns"
	"log"
	"math/big"
	"math/rand"
	"net"
	"os"
	"strings"
	"sync"
	"time"
)

// 颜色常量
const (
	Reset = "\033[0m"
	Red   = "\033[31m"
	Green = "\033[32m"
)

var (
	// Command-line flags
	input      string
	timeout    int
	semaphoreC int
	showHelp   bool
)

func generateTransactionID() uint16 {
	return uint16(rand.Intn(0xFFFF)) // 生成随机的 Transaction ID
}

// 使用方法
// 创建 DNS 查询数据包
var dnsQuery = []byte{
	byte(generateTransactionID() >> 8), byte(generateTransactionID() & 0xFF),
	0x01, 0x00, // Flags (RD = 1, 希望递归)
	0x00, 0x01, // Question Count
	0x00, 0x00, // Answer Count
	0x00, 0x00, // Authority Count
	0x00, 0x00, // Additional Count
	0x03, 'w', 'w', 'w', // www
	0x05, 'b', 'a', 'i', 'd', 'u', // baidu
	0x03, 'c', 'o', 'm', // com
	0x00,       // End of the domain name
	0x00, 0x01, // Type A
	0x00, 0x01, // Class IN
}

// 将 IP 转换为 big.Int 类型，方便数值计算
func ipToBigInt(ip net.IP) *big.Int {
	ip = ip.To4() // 只支持 IPv4
	if ip == nil {
		return nil
	}
	result := big.NewInt(0)
	result.SetBytes(ip)
	return result
}

// 将 big.Int 转换回 IP 地址
func bigIntToIP(ipInt *big.Int) net.IP {
	return net.IP(ipInt.Bytes()).To4()
}

// 解析 IP 列表输入，可以是文件名、单个 IP、多个 IP 或 IP 范围
func parseIPs(input string) ([]string, error) {
	if input == "" {
		return nil, fmt.Errorf("no input provided")
	}

	var ips []string

	// Check if input is a filename
	if fileExists(input) {
		fileIps, err := parseIPList(input)
		if err != nil {
			return nil, fmt.Errorf("failed to parse IP list from file: %v", err)
		}
		ips = append(ips, fileIps...)
	} else {
		// Assume input is a comma-separated list
		entries := strings.Split(input, ",")
		for _, entry := range entries {
			entry = strings.TrimSpace(entry)
			if entry == "" {
				continue
			}
			if strings.Contains(entry, "-") {
				// IP range
				rangeIPs, err := parseIPRange(entry)
				if err != nil {
					log.Printf("Error parsing IP range '%s': %v", entry, err)
					continue
				}
				ips = append(ips, rangeIPs...)
			} else if strings.Contains(entry, "/") {
				// CIDR notation
				cidrIPs := parseCIDR(entry)
				ips = append(ips, cidrIPs...)
			} else {
				// Single IP
				if net.ParseIP(entry) != nil {
					ips = append(ips, entry)
				} else {
					log.Printf("Invalid IP address: %s", entry)
				}
			}
		}
	}

	return ips, nil
}

// 解析 IP 段，CIDR 和单个 IP 的函数
func parseIPList(filename string) ([]string, error) {
	file, err := os.Open(filename)
	if err != nil {
		return nil, err
	}
	defer file.Close()

	var ips []string
	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if strings.Contains(line, "-") {
			// 解析 IP 区间
			ipRange, err := parseIPRange(line)
			if err != nil {
				log.Printf("Error parsing IP range %s: %v", line, err)
				continue
			}
			ips = append(ips, ipRange...)
		} else if strings.Contains(line, "/") {
			// 解析 CIDR
			cidr := parseCIDR(line)
			ips = append(ips, cidr...)
		} else {
			// 单个 IP
			ips = append(ips, line)
		}
	}
	if err := scanner.Err(); err != nil {
		return nil, err
	}
	return ips, nil
}

// 解析 IP 区间，如 "58.59.128.0-58.59.131.255"
func parseIPRange(rangeStr string) ([]string, error) {
	ips := []string{}

	// 分割起始和结束 IP
	parts := strings.Split(rangeStr, "-")
	if len(parts) != 2 {
		return nil, fmt.Errorf("Invalid IP range format: %s", rangeStr)
	}

	startIP := net.ParseIP(strings.TrimSpace(parts[0]))
	endIP := net.ParseIP(strings.TrimSpace(parts[1]))
	if startIP == nil || endIP == nil {
		return nil, fmt.Errorf("Invalid IP address: %s or %s", parts[0], parts[1])
	}

	// 遍历范围内的所有 IP
	start := ipToBigInt(startIP)
	end := ipToBigInt(endIP)

	// 遍历范围内的所有 IP
	for ip := new(big.Int).Set(start); ip.Cmp(end) <= 0; ip.Add(ip, big.NewInt(1)) {
		ips = append(ips, bigIntToIP(ip).String())
	}

	return ips, nil
}

// 解析 CIDR 格式，如 "116.1.73.1/24"
func parseCIDR(cidr string) []string {
	ip, ipnet, err := net.ParseCIDR(cidr)
	if err != nil {
		log.Fatalf("Invalid CIDR: %v", err)
	}

	var ips []string
	for ip := ip.Mask(ipnet.Mask); ipnet.Contains(ip); inc(ip) {
		ips = append(ips, ip.String())
	}
	return ips
}

// 增加 IP 地址的辅助函数
func inc(ip net.IP) {
	for j := len(ip) - 1; j >= 0; j-- {
		ip[j]++
		if ip[j] > 0 {
			break
		}
	}
}

// 检查文件是否存在
func fileExists(filename string) bool {
	info, err := os.Stat(filename)
	return err == nil && !info.IsDir()
}

func checkDNS(ip string, wg *sync.WaitGroup, semaphore chan struct{}, results chan<- string, timeoutDuration time.Duration) {
	defer wg.Done()
	defer func() { <-semaphore }() // 释放信号量

	conn, err := net.DialTimeout("udp", ip+":53", timeoutDuration)
	if err != nil {
		return
	}
	defer conn.Close()

	_, err = conn.Write(dnsQuery)
	if err != nil {
		return
	}

	buf := make([]byte, 512)
	conn.SetReadDeadline(time.Now().Add(timeoutDuration))
	n, err := conn.Read(buf)
	if err != nil || n == 0 {
		return
	}
	// 检查递归可用性
	if buf[3]&0x80 != 0 {
		result := fmt.Sprintf("%s supports recursive queries", ip)
		results <- result
		fmt.Printf(Green+"%s supports recursive queries"+Reset+"\n", ip)
	} else {
		result := fmt.Sprintf("%s does NOT support recursive queries", ip)
		results <- result
		fmt.Printf(Red+"%s does NOT support recursive queries"+Reset+"\n", ip)
	}
}

// 高并发扫描和测试递归查询功能
// 解析响应包头部（Recursion Available位是否为1）
// 0 0 0 0 0 0 0 0
// | | | | | | | |
// 7 6 5 4 3 2 1 0
// 第 7 位（QR）:查询/响应标志位。0 表示查询，1 表示响应。
// 第 6-3 位（OPCODE）:操作码，指示查询的类型。
// 第 2 位（AA）:权威回答标志。1 表示该响应是来自权威 DNS 服务器，0 表示不是。
// 第 1 位（TC）:截断标志。1 表示消息被截断。
// 第 0 位（RD）:
// 递归查询标志。1 表示请求支持递归，0 表示不支持。
//
// Questions: n 表示该 DNS 查询请求中包含 n 个问题。
// Answers: 3 表示 DNS 响应中包含 3 个答案。
// : false 表示该 DNS 响应不是来自权威 DNS 服务器。
// Truncated: false 表示该 DNS 响应没有被截断，意味着完整的数据可以被接收。
// Recursion Available: true 表示该 DNS 服务器支持递归查询。
// Recursion Desired: true 表示查询请求中希望服务器执行递归查询。
// 检查 DNS 响应并打印详细信息
func checkDNSWithDetails(ip string, wg *sync.WaitGroup, semaphore chan struct{}, results chan<- string, duration time.Duration) {
	defer wg.Done()
	defer func() { <-semaphore }() // 释放信号量

	m := new(dns.Msg)
	m.SetQuestion("www.baidu.com.", dns.TypeA)
	m.RecursionDesired = true

	c := new(dns.Client)
	c.Net = "udp"
	c.Timeout = duration
	r, _, err := c.Exchange(m, ip+":53")
	if err != nil {
		//results <- fmt.Sprintf("%s: %v", ip, err)
		return
	}

	var output bytes.Buffer
	output.WriteString(fmt.Sprintf("Response from %s:\n", ip))
	output.WriteString(fmt.Sprintf("ID: %d\n", r.Id))
	output.WriteString(fmt.Sprintf("RecursionDesired: %s\n", r.RecursionDesired))
	output.WriteString(fmt.Sprintf("Opcode: %d\n", r.Opcode))
	output.WriteString(fmt.Sprintf("Rcode: %d\n", r.Rcode))
	output.WriteString(fmt.Sprintf("Flags: %s\n", r.String()))
	output.WriteString(fmt.Sprintf("Questions: %d\n", len(r.Question)))
	output.WriteString(fmt.Sprintf("Answers: %d\n", len(r.Answer)))
	output.WriteString(fmt.Sprintf("Authoritative: %v\n", r.Authoritative))
	output.WriteString(fmt.Sprintf("Truncated: %v\n", r.Truncated))
	output.WriteString(fmt.Sprintf("Recursion Available: %v\n", r.RecursionAvailable))
	output.WriteString(fmt.Sprintf("Recursion Desired: %v\n", r.RecursionDesired))

	// 打印问题部分
	for _, q := range r.Question {
		output.WriteString(fmt.Sprintf("Question: %s %d\n", q.Name, q.Qtype))
	}
	var isRecursion bool = false
	// 打印回答部分
	for _, a := range r.Answer {
		switch rr := a.(type) {
		case *dns.A:
			isRecursion = true
			output.WriteString(fmt.Sprintf("Answer (A): %s -> %s\n", rr.Header().Name, rr.A))
		case *dns.CNAME:
			isRecursion = true
			output.WriteString(fmt.Sprintf("Answer (CNAME): %s -> %s\n", rr.Header().Name, rr.Target))
		// 可以添加更多类型的处理
		default:
			output.WriteString(fmt.Sprintf("Answer: %v\n", rr))
		}
	}
	fmt.Println(output.String())

	// 检查递归可用性
	if r.RecursionAvailable && len(r.Answer) > 0 {
		results <- fmt.Sprintf("%s (UDP) supports recursive queries", ip)
		fmt.Printf(Green+"%s (UDP) supports recursive queries"+Reset+"\n", ip)
	} else {
		if isRecursion {
			results <- fmt.Sprintf("%s (UDP) support domain name resolution", ip)
			fmt.Printf(Green+"%s (UDP) support domain name resolution"+Reset+"\n", ip)
		} else {
			results <- fmt.Sprintf("%s (UDP) does NOT support recursive queries", ip)
			fmt.Printf(Red+"%s (UDP) does NOT support recursive queries"+Reset+"\n", ip)
		}

	}
	fmt.Println(strings.Repeat("-", 60))
}
func checkDNSTCPWithDetails(ip string, wg *sync.WaitGroup, semaphore chan struct{}, results chan<- string, duration time.Duration) {
	defer wg.Done()
	defer func() { <-semaphore }() // 释放信号量

	m := new(dns.Msg)
	m.SetQuestion("www.baidu.com.", dns.TypeA)
	m.RecursionDesired = true

	c := new(dns.Client)
	c.Net = "tcp"
	c.Timeout = duration
	r, _, err := c.Exchange(m, ip+":53")
	if err != nil {
		// 可以选择记录错误信息
		return
	}

	var output bytes.Buffer
	output.WriteString(fmt.Sprintf("TCP Response from %s:\n", ip))
	output.WriteString(fmt.Sprintf("ID: %d\n", r.Id))
	output.WriteString(fmt.Sprintf("RecursionDesired: %s\n", r.RecursionDesired))
	output.WriteString(fmt.Sprintf("Opcode: %d\n", r.Opcode))
	output.WriteString(fmt.Sprintf("Rcode: %d\n", r.Rcode))
	output.WriteString(fmt.Sprintf("Flags: %s\n", r.String()))
	output.WriteString(fmt.Sprintf("Questions: %d\n", len(r.Question)))
	output.WriteString(fmt.Sprintf("Answers: %d\n", len(r.Answer)))
	output.WriteString(fmt.Sprintf("Authoritative: %v\n", r.Authoritative))
	output.WriteString(fmt.Sprintf("Truncated: %v\n", r.Truncated))
	output.WriteString(fmt.Sprintf("Recursion Available: %v\n", r.RecursionAvailable))
	output.WriteString(fmt.Sprintf("Recursion Desired: %v\n", r.RecursionDesired))

	// 打印问题部分
	for _, q := range r.Question {
		output.WriteString(fmt.Sprintf("Question: %s %d\n", q.Name, q.Qtype))
	}
	var isRecursion bool = false
	// 打印回答部分
	for _, a := range r.Answer {
		switch rr := a.(type) {
		case *dns.A:
			isRecursion = true
			output.WriteString(fmt.Sprintf("Answer (A): %s -> %s\n", rr.Header().Name, rr.A))
		case *dns.CNAME:
			isRecursion = true
			output.WriteString(fmt.Sprintf("Answer (CNAME): %s -> %s\n", rr.Header().Name, rr.Target))
		// 可以添加更多类型的处理
		default:
			output.WriteString(fmt.Sprintf("Answer: %v\n", rr))
		}
	}
	fmt.Println(output.String())

	// 检查递归可用性
	if r.RecursionAvailable && len(r.Answer) > 0 {
		results <- fmt.Sprintf("%s (TCP) supports recursive queries", ip)
		fmt.Printf(Green+"%s (TCP) supports recursive queries"+Reset+"\n", ip)
	} else {
		if isRecursion {
			results <- fmt.Sprintf("%s (TCP) support domain name resolution", ip)
			fmt.Printf(Green+"%s (TCP) support domain name resolution"+Reset+"\n", ip)
		} else {
			results <- fmt.Sprintf("%s (TCP) does NOT support recursive queries", ip)
			fmt.Printf(Red+"%s (TCP) does NOT support recursive queries"+Reset+"\n", ip)
		}
	}
	fmt.Println(strings.Repeat("-", 60))
}
func init() {
	// 自定义帮助信息
	flag.Usage = func() {
		helpText := `DNS Recursive Query Checker

用法:
  dns_checker -i <input> [-t <timeout>] [-c <concurrency>] [-h]

选项:
  -i string
    	输入 IP 的方式，可以是文件名、单个 IP、多个 IP 以逗号分隔，或 IP 范围。
    	例如:
    	  -i "ip_list.txt"
    	  -i "192.168.1.1"
    	  -i "192.168.1.1,192.168.1.2"
    	  -i "192.168.1.1-192.168.1.10"
    	  -i "192.168.1.1,192.168.1.5-192.168.1.10,10.0.0.0/24"
  -t int
    	DNS 查询的超时时间（秒），默认值为 2 秒。
  -c int
    	并发限制，默认值为 2000。
  -h	显示帮助信息

功能:
  本工具现在支持通过 UDP 和 TCP 两种协议进行 DNS 递归查询检查。

示例:
  # 从文件读取 IP
  dns_checker -i "ip_list.txt"

  # 直接输入多个 IP 和 IP 范围
  dns_checker -i "8.8.8.8,8.8.4.4,1.1.1.1-1.1.1.5" -t 3

  # 使用 CIDR
  dns_checker -i "10.0.0.0/24" -t 1
`
		fmt.Fprintf(flag.CommandLine.Output(), helpText)
	}

	// 定义命令行标志
	flag.StringVar(&input, "i", "", "输入 IP 的方式，可以是文件名、单个 IP、多个 IP 以逗号分隔，或 IP 范围。")
	flag.IntVar(&timeout, "t", 2, "DNS 查询的超时时间（秒），默认值为 2 秒。")
	flag.IntVar(&semaphoreC, "c", 2000, "并发限制，默认值为 2000。")
	flag.BoolVar(&showHelp, "h", false, "显示帮助信息")

	// Seed the random number generator
	rand.Seed(time.Now().UnixNano())
}
func main() {
	// 解析命令行标志
	flag.Parse()

	if showHelp {
		flag.Usage()
		return
	}

	startTime := time.Now() // 记录开始时间

	if input == "" {
		log.Fatalf("请用-h查看帮助.")
	}

	// Parse IPs based on input
	ips, err := parseIPs(input)
	if err != nil {
		log.Fatalf("Failed to parse IPs: %v\n", err)
	}

	if len(ips) == 0 {
		log.Fatalf("No valid IPs to process.")
	}

	var wg sync.WaitGroup
	semaphore := make(chan struct{}, semaphoreC) // 并发限制
	results := make(chan string, len(ips))       // 用于存储结果

	timeoutDuration := time.Duration(timeout) * time.Second

	for _, ip := range ips {
		wg.Add(1)
		semaphore <- struct{}{} // 占用信号量
		go checkDNSWithDetails(ip, &wg, semaphore, results, timeoutDuration)

		// TCP 检查
		wg.Add(1)
		semaphore <- struct{}{} // 占用信号量
		go checkDNSTCPWithDetails(ip, &wg, semaphore, results, timeoutDuration)
	}
	// 如果你 prefer 使用 checkDNS 而不是 checkDNSWithDetails, you can uncomment below:
	/*
		for _, ip := range ips {
			wg.Add(1)
			semaphore <- struct{}{} // 占用信号量
			go checkDNS(ip, &wg, semaphore, results, timeoutDuration)
		}
	*/

	go func() {
		wg.Wait()
		close(results)
	}()

	// 将结果保存到文件
	outputFile, err := os.Create("dns_results.txt")
	if err != nil {
		log.Fatalf("Failed to create output file: %v\n", err)
	}
	defer outputFile.Close()

	writer := bufio.NewWriter(outputFile)
	for result := range results {
		_, err := writer.WriteString(result + "\n")
		if err != nil {
			log.Printf("Failed to write result to file: %v\n", err)
		}
		fmt.Println(result) // 输出结果到屏幕
	}
	writer.Flush()

	// 打印耗时
	elapsedTime := time.Since(startTime)
	fmt.Printf("Scanning completed. Results saved to dns_results.txt. Total time taken: %v\n", elapsedTime)
}
