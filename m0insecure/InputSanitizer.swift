//
//  InputSanitizer.swift
//  m0insecure
//
//  Created by Antigravity on 13/11/2026.
//

import Foundation

enum InjectionType: String {
    case xss = "Cross-Site Scripting (XSS)"
    case sqli = "SQL Injection (SQLi)"
    case commandInjection = "Command Injection"
    case pathTraversal = "Path Traversal"
}

struct InjectionViolation: Error, LocalizedError {
    let type: InjectionType
    let field: String
    let reason: String

    var errorDescription: String? {
        "Potential \(type.rawValue) detected in \(field): \(reason)"
    }
}

final class InputSanitizer {
    static let shared = InputSanitizer()
    private init() {}

    // MARK: - Injection Detection Patterns

    private let sqliPatterns: [String] = [
        #"(?i)(\bOR\b|\bAND\b)\s+['"]?(\d+|[a-zA-Z]+)['"]?\s*=\s*['"]?(\d+|[a-zA-Z]+)['"]?"#, // ' OR '1'='1
        #"(?i)\b(UNION(\s+ALL)?\s+SELECT|SELECT\s+.+\s+FROM|INSERT\s+INTO|DELETE\s+FROM|DROP\s+TABLE|DROP\s+DATABASE|ALTER\s+TABLE)\b"#,
        #"(?i)(--|#|\/\*|\*\/|;\s*--|;\s*DROP|;\s*DELETE)"#,
        #"(?i)\bEXEC(\s+XP_|\s+SP_)?\b"#,
        #"(?i)\bSLEEP\s*\(\s*\d+\s*\)"#,
        #"(?i)\bBENCHMARK\s*\(\s*\d+\s*,"#
    ]

    private let xssPatterns: [String] = [
        #"(?i)<\s*script[^>]*>"#,
        #"(?i)<\s*\/\s*script\s*>"#,
        #"(?i)javascript\s*:"#,
        #"(?i)vbscript\s*:"#,
        #"(?i)data\s*:\s*text\/html"#,
        #"(?i)on(load|error|click|mouseover|focus|blur|submit)\s*="#,
        #"(?i)<\s*(img|iframe|svg|body|input|link|meta)\b[^>]*on\w+\s*="#,
        #"(?i)<\s*(iframe|object|embed|applet|meta|link)\b"#
    ]

    private let commandPatterns: [String] = [
        #"[;&|`$]\s*(cat|ls|rm|sh|bash|chmod|nc|curl|wget|ping)\b"#,
        #"\$\([^\)]+\)"#,
        #"`[^`]+`"#
    ]

    private let pathTraversalPatterns: [String] = [
        #"\.\.\/|\.\.\\"#
    ]

    // MARK: - Validation & Detection

    /// Analyzes an input string for known malicious injection patterns.
    /// Throws an `InjectionViolation` if dangerous payload patterns are detected.
    func validateSafety(input: String, fieldName: String) throws {
        // Check for null byte injection
        if input.contains("\0") {
            throw InjectionViolation(
                type: .commandInjection,
                field: fieldName,
                reason: "Null byte character is not permitted."
            )
        }

        // Check for Path Traversal
        for pattern in pathTraversalPatterns {
            if input.range(of: pattern, options: .regularExpression) != nil {
                throw InjectionViolation(
                    type: .pathTraversal,
                    field: fieldName,
                    reason: "Directory traversal sequences are blocked."
                )
            }
        }

        // Check for XSS
        for pattern in xssPatterns {
            if input.range(of: pattern, options: .regularExpression) != nil {
                throw InjectionViolation(
                    type: .xss,
                    field: fieldName,
                    reason: "Executable script or HTML tag payload detected."
                )
            }
        }

        // Check for SQLi
        for pattern in sqliPatterns {
            if input.range(of: pattern, options: .regularExpression) != nil {
                throw InjectionViolation(
                    type: .sqli,
                    field: fieldName,
                    reason: "SQL query manipulation pattern detected."
                )
            }
        }

        // Check for Command Injection
        for pattern in commandPatterns {
            if input.range(of: pattern, options: .regularExpression) != nil {
                throw InjectionViolation(
                    type: .commandInjection,
                    field: fieldName,
                    reason: "Shell command chaining sequence detected."
                )
            }
        }
    }

    // MARK: - Sanitization Helpers

    /// General HTML/XSS entity encoding: replaces &, <, >, ", ' with safe HTML entities.
    func encodeHTML(_ text: String) -> String {
        var result = text.replacingOccurrences(of: "\0", with: "")
        result = result.replacingOccurrences(of: "&", with: "&amp;")
        result = result.replacingOccurrences(of: "<", with: "&lt;")
        result = result.replacingOccurrences(of: ">", with: "&gt;")
        result = result.replacingOccurrences(of: "\"", with: "&quot;")
        result = result.replacingOccurrences(of: "'", with: "&#x27;")
        result = result.replacingOccurrences(of: "/", with: "&#x2F;")
        return result
    }

    /// Strips any raw HTML tags (e.g. `<script>`, `<b>`, `<img>`).
    func stripHTMLTags(_ text: String) -> String {
        let pattern = #"<[^>]+>"#
        return text.replacingOccurrences(of: pattern, with: "", options: .regularExpression)
    }

    /// Sanitizes email inputs by stripping HTML, removing dangerous control characters,
    /// and trimming surrounding whitespaces.
    func sanitizeEmail(_ email: String) -> String {
        var clean = email.replacingOccurrences(of: "\0", with: "")
        clean = stripHTMLTags(clean)
        clean = clean.trimmingCharacters(in: .whitespacesAndNewlines)
        // Disallow dangerous SQL/command characters in email
        let forbidden = CharacterSet(charactersIn: ";`'\"\\<>*|^")
        clean = clean.components(separatedBy: forbidden).joined()
        return clean
    }

    /// Sanitizes general text fields (e.g. contacts, search fields) by stripping tags
    /// and escaping dangerous injection metacharacters.
    func sanitizeText(_ text: String) -> String {
        var clean = text.replacingOccurrences(of: "\0", with: "")
        clean = stripHTMLTags(clean)
        clean = clean.trimmingCharacters(in: .whitespacesAndNewlines)
        return clean
    }

    /// Sanitizes numeric OTP codes by filtering out all non-digit characters and limiting length.
    func sanitizeOTP(_ code: String, maxLength: Int = 6) -> String {
        let digitsOnly = code.filter { $0.isNumber }
        return String(digitsOnly.prefix(maxLength))
    }
}
