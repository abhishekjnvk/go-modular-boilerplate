package middleware

import (
	"crypto/sha256"
	"fmt"
	"net"
	"net/http"
	"regexp"
	"strings"
	"time"
	// "github.com/oschwald/geoip2-golang"
)

// DeviceInfo represents comprehensive device information
type DeviceInfo struct {
	// Basic device info
	UserAgent  string `json:"user_agent"`
	IPAddress  string `json:"ip_address"`
	DeviceType string `json:"device_type"` // desktop, mobile, tablet, bot
	OS         string `json:"os"`          // windows, macos, linux, ios, android
	OSVersion  string `json:"os_version"`
	Browser    string `json:"browser"` // chrome, firefox, safari, edge
	BrowserVer string `json:"browser_version"`

	// Hardware info
	DeviceModel string `json:"device_model,omitempty"` // iPhone, Galaxy, etc.
	ScreenRes   string `json:"screen_resolution,omitempty"`

	// Network info
	ASN      string `json:"asn,omitempty"`
	ISP      string `json:"isp,omitempty"`
	Country  string `json:"country,omitempty"`
	City     string `json:"city,omitempty"`
	Region   string `json:"region,omitempty"`
	Timezone string `json:"timezone,omitempty"`

	// Security info
	IsVPN     bool `json:"is_vpn"`
	IsProxy   bool `json:"is_proxy"`
	IsTor     bool `json:"is_tor"`
	IsBot     bool `json:"is_bot"`
	RiskScore int  `json:"risk_score"` // 0-100, higher = more suspicious

	// Session info
	Fingerprint string    `json:"fingerprint,omitempty"`
	DetectedAt  time.Time `json:"detected_at"`
}

// DeviceDetector provides comprehensive device detection capabilities
type DeviceDetector struct {
	// geoIPDB *geoip2.Reader // Uncomment when geoip2-golang is available
}

// NewDeviceDetector creates a new device detector
func NewDeviceDetector(geoIPPath string) (*DeviceDetector, error) {
	// var geoIPDB *geoip2.Reader
	// if geoIPPath != "" {
	// 	db, err := geoip2.Open(geoIPPath)
	// 	if err != nil {
	// 		logger.New().Warn("Failed to open GeoIP database, continuing without geolocation",
	// 			"path", geoIPPath,
	// 			"error", err)
	// 	} else {
	// 		geoIPDB = db
	// 	}
	// }

	return &DeviceDetector{
		// geoIPDB: geoIPDB,
	}, nil
}

// DetectDevice extracts comprehensive device information from HTTP request
func (d *DeviceDetector) DetectDevice(r *http.Request) *DeviceInfo {
	userAgent := r.Header.Get("User-Agent")
	ipAddress := d.getClientIP(r)

	deviceInfo := &DeviceInfo{
		UserAgent:  userAgent,
		IPAddress:  ipAddress,
		DetectedAt: time.Now(),
	}

	// Parse user agent
	d.parseUserAgent(deviceInfo)

	// Get geolocation data
	// if d.geoIPDB != nil {
	// 	d.enrichWithGeoIP(deviceInfo)
	// }

	// Detect security risks
	d.detectSecurityRisks(deviceInfo)

	// Generate device fingerprint
	deviceInfo.Fingerprint = d.generateFingerprint(deviceInfo)

	return deviceInfo
}

// getClientIP extracts the real client IP from various headers
func (d *DeviceDetector) getClientIP(r *http.Request) string {
	// Check X-Forwarded-For header (most common)
	xff := r.Header.Get("X-Forwarded-For")
	if xff != "" {
		// Take the first IP (original client)
		ips := strings.Split(xff, ",")
		if len(ips) > 0 {
			ip := strings.TrimSpace(ips[0])
			if net.ParseIP(ip) != nil {
				return ip
			}
		}
	}

	// Check X-Real-IP header
	xri := r.Header.Get("X-Real-IP")
	if xri != "" && net.ParseIP(xri) != nil {
		return xri
	}

	// Check CF-Connecting-IP (Cloudflare)
	cfip := r.Header.Get("CF-Connecting-IP")
	if cfip != "" && net.ParseIP(cfip) != nil {
		return cfip
	}

	// Check X-Client-IP
	xcip := r.Header.Get("X-Client-IP")
	if xcip != "" && net.ParseIP(xcip) != nil {
		return xcip
	}

	// Fallback to RemoteAddr
	host, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		return r.RemoteAddr
	}
	return host
}

// parseUserAgent parses the User-Agent string to extract device information
func (d *DeviceDetector) parseUserAgent(info *DeviceInfo) {
	ua := strings.ToLower(info.UserAgent)

	// Detect bots first
	if d.isBot(ua) {
		info.IsBot = true
		info.DeviceType = "bot"
		info.Browser = "bot"
		return
	}

	// Detect device type
	if d.isMobile(ua) {
		info.DeviceType = "mobile"
	} else if d.isTablet(ua) {
		info.DeviceType = "tablet"
	} else {
		info.DeviceType = "desktop"
	}

	// Detect OS
	info.OS = d.detectOS(ua)
	info.OSVersion = d.detectOSVersion(ua, info.OS)

	// Detect browser
	info.Browser = d.detectBrowser(ua)
	info.BrowserVer = d.detectBrowserVersion(ua, info.Browser)

	// Detect device model
	info.DeviceModel = d.detectDeviceModel(ua)
}

// isBot checks if the user agent is from a bot
func (d *DeviceDetector) isBot(ua string) bool {
	botPatterns := []string{
		"bot", "crawler", "spider", "scraper", "indexer",
		"googlebot", "bingbot", "yahoo", "duckduckbot",
		"facebookexternalhit", "twitterbot", "linkedinbot",
		"whatsapp", "telegrambot", "discordbot",
	}

	for _, pattern := range botPatterns {
		if strings.Contains(ua, pattern) {
			return true
		}
	}
	return false
}

// isMobile checks if the user agent is from a mobile device
func (d *DeviceDetector) isMobile(ua string) bool {
	mobilePatterns := []string{
		"mobile", "android", "iphone", "ipad", "ipod",
		"blackberry", "windows phone", "opera mini",
		"iemobile", "webos", "palm", "symbian",
	}

	for _, pattern := range mobilePatterns {
		if strings.Contains(ua, pattern) {
			return true
		}
	}
	return false
}

// isTablet checks if the user agent is from a tablet
func (d *DeviceDetector) isTablet(ua string) bool {
	tabletPatterns := []string{
		"ipad", "tablet", "kindle", "playbook",
		"silk", "xoom", "transformer",
	}

	for _, pattern := range tabletPatterns {
		if strings.Contains(ua, pattern) {
			return true
		}
	}
	return false
}

// detectOS detects the operating system from user agent
func (d *DeviceDetector) detectOS(ua string) string {
	osPatterns := map[string][]string{
		"windows":  {"windows nt", "win32", "win64"},
		"macos":    {"macintosh", "mac os x", "macos"},
		"linux":    {"linux", "ubuntu", "fedora", "centos", "debian"},
		"ios":      {"iphone", "ipad", "ipod"},
		"android":  {"android"},
		"chromeos": {"cros"},
	}

	for os, patterns := range osPatterns {
		for _, pattern := range patterns {
			if strings.Contains(ua, pattern) {
				return os
			}
		}
	}
	return "unknown"
}

// detectOSVersion extracts OS version from user agent
func (d *DeviceDetector) detectOSVersion(ua, os string) string {
	switch os {
	case "windows":
		if match := regexp.MustCompile(`windows nt (\d+\.\d+)`).FindStringSubmatch(ua); len(match) > 1 {
			return match[1]
		}
	case "macos":
		if match := regexp.MustCompile(`mac os x (\d+[_\d]+)`).FindStringSubmatch(ua); len(match) > 1 {
			return strings.ReplaceAll(match[1], "_", ".")
		}
	case "ios":
		if match := regexp.MustCompile(`os (\d+[_\d]+)`).FindStringSubmatch(ua); len(match) > 1 {
			return strings.ReplaceAll(match[1], "_", ".")
		}
	case "android":
		if match := regexp.MustCompile(`android (\d+\.\d+)`).FindStringSubmatch(ua); len(match) > 1 {
			return match[1]
		}
	}
	return ""
}

// detectBrowser detects the browser from user agent
func (d *DeviceDetector) detectBrowser(ua string) string {
	browserPatterns := map[string][]string{
		"chrome":  {"chrome", "chromium"},
		"firefox": {"firefox", "fxios"},
		"safari":  {"safari", "webkit"},
		"edge":    {"edg", "edge"},
		"opera":   {"opera", "opr"},
		"ie":      {"msie", "trident"},
	}

	for browser, patterns := range browserPatterns {
		for _, pattern := range patterns {
			if strings.Contains(ua, pattern) {
				return browser
			}
		}
	}
	return "unknown"
}

// detectBrowserVersion extracts browser version from user agent
func (d *DeviceDetector) detectBrowserVersion(ua, browser string) string {
	switch browser {
	case "chrome":
		if match := regexp.MustCompile(`chrome/(\d+\.\d+)`).FindStringSubmatch(ua); len(match) > 1 {
			return match[1]
		}
	case "firefox":
		if match := regexp.MustCompile(`firefox/(\d+\.\d+)`).FindStringSubmatch(ua); len(match) > 1 {
			return match[1]
		}
	case "safari":
		if match := regexp.MustCompile(`version/(\d+\.\d+)`).FindStringSubmatch(ua); len(match) > 1 {
			return match[1]
		}
	case "edge":
		if match := regexp.MustCompile(`edg/(\d+\.\d+)`).FindStringSubmatch(ua); len(match) > 1 {
			return match[1]
		}
	}
	return ""
}

// detectDeviceModel extracts device model from user agent
func (d *DeviceDetector) detectDeviceModel(ua string) string {
	// iPhone models
	if strings.Contains(ua, "iphone") {
		if match := regexp.MustCompile(`iphone(?:\s|;)(\w+)`).FindStringSubmatch(ua); len(match) > 1 {
			return "iPhone " + match[1]
		}
		return "iPhone"
	}

	// iPad models
	if strings.Contains(ua, "ipad") {
		return "iPad"
	}

	// Android devices
	if strings.Contains(ua, "android") {
		if match := regexp.MustCompile(`;\s*([^;)]+)\s*build`).FindStringSubmatch(ua); len(match) > 1 {
			return strings.TrimSpace(match[1])
		}
	}

	return ""
}

// // enrichWithGeoIP adds geolocation data using MaxMind GeoIP database
// func (d *DeviceDetector) enrichWithGeoIP(info *DeviceInfo) {
// 	// if d.geoIPDB == nil {
// 	// 	return
// 	// }

// 	// ip := net.ParseIP(info.IPAddress)
// 	// if ip == nil {
// 	// 	return
// 	// }

// 	// // Get city data
// 	// city, err := d.geoip2.City(ip)
// 	// if err != nil {
// 	// 	logger.New().Debug("Failed to get city data from GeoIP",
// 	// 		"ip", info.IPAddress,
// 	// 		"error", err)
// 	// 	return
// 	// }

// 	// if city.Country.Names != nil {
// 	// 	info.Country = city.Country.Names["en"]
// 	// }

// 	// if city.City.Names != nil {
// 	// 	info.City = city.City.Names["en"]
// 	// }

// 	// if len(city.Subdivisions) > 0 {
// 	// 	info.Region = city.Subdivisions[0].Names["en"]
// 	// }

// 	// if city.Location.TimeZone != "" {
// 	// 	info.Timezone = city.Location.TimeZone
// 	// }

// 	// // Get ASN data
// 	// asn, err := d.geoIPDB.ASN(ip)
// 	// if err == nil && asn.AutonomousSystemNumber > 0 {
// 	// 	info.ASN = fmt.Sprintf("AS%d", asn.AutonomousSystemNumber)
// 	// 	info.ISP = asn.AutonomousSystemOrganization
// 	// }
// }

// detectSecurityRisks analyzes the device info for security risks
func (d *DeviceDetector) detectSecurityRisks(info *DeviceInfo) {
	riskScore := 0

	// Check for VPN patterns in IP
	if d.isVPNIP(info.IPAddress) {
		info.IsVPN = true
		riskScore += 20
	}

	// Check for proxy headers
	if d.hasProxyHeaders(info) {
		info.IsProxy = true
		riskScore += 15
	}

	// Check for Tor exit nodes
	if d.isTorIP(info.IPAddress) {
		info.IsTor = true
		riskScore += 30
	}

	// Check for suspicious user agents
	if d.isSuspiciousUA(info.UserAgent) {
		riskScore += 25
	}

	// Check for bot behavior
	if info.IsBot {
		riskScore += 10
	}

	// Cap risk score at 100
	if riskScore > 100 {
		riskScore = 100
	}

	info.RiskScore = riskScore
}

// isVPNIP checks if IP is likely from a VPN
func (d *DeviceDetector) isVPNIP(ip string) bool {
	// This is a simplified check - in production, you'd use a VPN detection service
	vpnPatterns := []string{
		"10.", "172.16.", "192.168.", // Private networks
	}

	for _, pattern := range vpnPatterns {
		if strings.HasPrefix(ip, pattern) {
			return true
		}
	}
	return false
}

// hasProxyHeaders checks for proxy-related headers
func (d *DeviceDetector) hasProxyHeaders(info *DeviceInfo) bool {
	// This would check for various proxy headers in the original request
	// For now, we'll use a simple heuristic
	return strings.Contains(strings.ToLower(info.UserAgent), "proxy")
}

// isTorIP checks if IP is a Tor exit node
func (d *DeviceDetector) isTorIP(ip string) bool {
	// In production, you would maintain a cached list of Tor exit nodes
	// This could be updated periodically from https://check.torproject.org/exit-addresses
	// For now, we'll implement a basic check using known Tor exit node patterns

	// Parse IP address
	if net.ParseIP(ip) == nil {
		return false
	}

	// Check against known Tor exit node ranges (simplified example)
	// In production, you'd load this from a database or API
	torRanges := []string{
		"185.220.100.0/24", // Example Tor exit node range
		"185.220.101.0/24",
		"185.220.102.0/24",
		"199.249.223.0/24",
		"199.249.224.0/24",
		// Add more ranges as needed
	}

	for _, cidr := range torRanges {
		_, network, err := net.ParseCIDR(cidr)
		if err != nil {
			continue
		}
		if network.Contains(net.ParseIP(ip)) {
			return true
		}
	}

	return false
}

// isSuspiciousUA checks for suspicious user agent patterns
func (d *DeviceDetector) isSuspiciousUA(ua string) bool {
	suspiciousPatterns := []string{
		"curl", "wget", "python", "java", "go-http-client",
		"postman", "insomnia", "paw", "httpie",
	}

	uaLower := strings.ToLower(ua)
	for _, pattern := range suspiciousPatterns {
		if strings.Contains(uaLower, pattern) {
			return true
		}
	}
	return false
}

// generateFingerprint creates a unique fingerprint for the device
func (d *DeviceDetector) generateFingerprint(info *DeviceInfo) string {
	// Create a fingerprint based on device characteristics
	fingerprint := fmt.Sprintf("%s|%s|%s|%s|%s",
		info.OS,
		info.Browser,
		info.DeviceType,
		info.IPAddress,
		info.UserAgent)

	// In production, you'd hash this with a salt
	return fmt.Sprintf("%x", sha256.Sum256([]byte(fingerprint)))
}

// Close closes the GeoIP database
func (d *DeviceDetector) Close() error {
	// if d.geoIPDB != nil {
	// 	return d.geoIPDB.Close()
	// }
	return nil
}
