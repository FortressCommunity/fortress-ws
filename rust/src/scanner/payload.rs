use regex::Regex;

/// Result of scanning a payload for threats.
#[derive(Debug, Clone)]
pub struct ScanResult {
    pub is_threat: bool,
    pub threat_type: String,
    pub confidence: f32,
}

/// Scans WebSocket payloads for common attack patterns using regex.
#[derive(Debug)]
pub struct PayloadScanner {
    patterns: Vec<(Regex, String)>,
}

impl PayloadScanner {
    /// Creates a new `PayloadScanner` with pre-compiled threat patterns.
    pub fn new() -> Self {
        let patterns = vec![
            // XSS patterns
            (
                Regex::new(r"(?i)<script|javascript:\s*|on\w+\s*=").unwrap(),
                "xss".to_string(),
            ),
            // SQL injection patterns
            (
                Regex::new(r"(?i)(union\s+select|drop\s+table|insert\s+into)").unwrap(),
                "sql_injection".to_string(),
            ),
            // Command injection patterns
            (
                Regex::new(r"(?i)(;|\||`)\s*(ls|cat|rm|wget|curl)").unwrap(),
                "command_injection".to_string(),
            ),
        ];
        PayloadScanner { patterns }
    }

    /// Scans the given payload bytes for known threat patterns.
    ///
    /// Returns a `ScanResult` indicating whether a threat was detected,
    /// the threat type, and a confidence score (1.0 if matched, 0.0 if not).
    pub fn scan(&self, payload: &[u8]) -> ScanResult {
        let payload_str = String::from_utf8_lossy(payload);
        for (re, threat_type) in &self.patterns {
            if re.is_match(&payload_str) {
                return ScanResult {
                    is_threat: true,
                    threat_type: threat_type.clone(),
                    confidence: 1.0,
                };
            }
        }
        ScanResult {
            is_threat: false,
            threat_type: String::new(),
            confidence: 0.0,
        }
    }
}

impl Default for PayloadScanner {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn scanner() -> PayloadScanner {
        PayloadScanner::new()
    }

    #[test]
    fn test_detect_xss_script_tag() {
        let result = scanner().scan(b"<script>alert(1)</script>");
        assert!(result.is_threat);
        assert_eq!(result.threat_type, "xss");
        assert_eq!(result.confidence, 1.0);
    }

    #[test]
    fn test_detect_xss_javascript_url() {
        let result = scanner().scan(b"javascript:void(0)");
        assert!(result.is_threat);
        assert_eq!(result.threat_type, "xss");
    }

    #[test]
    fn test_detect_xss_event_handler() {
        let result = scanner().scan(b"onclick=alert(1)");
        assert!(result.is_threat);
        assert_eq!(result.threat_type, "xss");
    }

    #[test]
    fn test_detect_sql_injection_union() {
        let result = scanner().scan(b"SELECT * FROM users UNION SELECT * FROM admins");
        assert!(result.is_threat);
        assert_eq!(result.threat_type, "sql_injection");
    }

    #[test]
    fn test_detect_sql_injection_drop() {
        let result = scanner().scan(b"DROP table users");
        assert!(result.is_threat);
        assert_eq!(result.threat_type, "sql_injection");
    }

    #[test]
    fn test_detect_command_injection() {
        let result = scanner().scan(b"; ls -la");
        assert!(result.is_threat);
        assert_eq!(result.threat_type, "command_injection");
    }

    #[test]
    fn test_clean_payload() {
        let result = scanner().scan(b"Hello, world!");
        assert!(!result.is_threat);
        assert_eq!(result.confidence, 0.0);
    }
}
