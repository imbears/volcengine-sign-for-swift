import Foundation
import CryptoSwift

struct VolcengineCredential {
    internal let accessKey: String
    internal let secretKey: String
    
    internal init(accessKey: String, secretKey: String) {
        self.accessKey = accessKey
        self.secretKey = secretKey
    }
}

class VolcengineSign {
    internal let credential: VolcengineCredential
    internal let service: String
    internal let region: String
    
    internal init(credential: VolcengineCredential, service: String, region: String) {
        self.credential = credential
        self.service = service
        self.region = region
    }
    
    internal func signRequest(_ request: URLRequest) throws -> String {
        guard let url = request.url else {
            throw NSError(domain: "volcengine", code: -10001)
        }
        let xDate: String
        if let value = request.value(forHTTPHeaderField: "X-Date") {
            xDate = value
        } else {
            let formatter = DateFormatter()
            formatter.timeZone = .init(secondsFromGMT: 0)
            formatter.dateFormat = "yyyyMMdd'T'HHmmss'Z'"
            xDate = formatter.string(from: Date())
        }
        let allHTTPHeaderFields = request.allHTTPHeaderFields ?? [:]
        // 步骤1：创建规范请求
        let httpMethod = request.httpMethod!
        let path: String = url.path()
        let query: String = url.query() ?? ""
        let contentSha256 = (request.httpBody ?? Data()).sha256().toHexString()
        let canonicalRequest = canonicalizedRequest(httpMethod, path, query, allHTTPHeaderFields, contentSha256)

        // 步骤2：创建待签字符串
        let scope = "\(String(xDate.prefix(8)))/\(region)/\(service)/request"
        let stringToSign = String(format: "HMAC-SHA256\n%@\n%@\n%@", xDate, scope, canonicalRequest.sha256())
        
        // 步骤3：构建签名
        let kDate = try hmac(credential.secretKey.bytes, String(xDate.prefix(8)))
        let kRegion = try hmac(kDate, region)
        let kService = try hmac(kRegion, service)
        let kSigning = try hmac(kService, "request")
        let signature = try hmac(kSigning, stringToSign).toHexString()
        
        // 步骤4：将签名添加到请求当中
        let authorization = String(format: "HMAC-SHA256 Credential=%@/%@, SignedHeaders=%@, Signature=%@",
                                   credential.accessKey,
                                   scope,
                                   allHTTPHeaderFields.sorted(by: {$0.key < $1.key}).map({$0.key.lowercased()}).joined(separator: ";"),
                                   signature
        )
        
        
        return authorization
    }
    
    /// canonicalizedRequest
    /// - Parameters:
    ///   - httpMethod: String
    ///   - path: String
    ///   - query: String
    ///   - headers: [String: String]
    ///   - contentSha256: String
    /// - Returns: String
    private func canonicalizedRequest(_ httpMethod: String, _ path: String, _ query: String, _ headers: [String: String], _ contentSha256: String) -> String {
        var result = ""
        // request method
        result.append(httpMethod)
        result.append("\n")
        // canonical uri
        result.append(path)
        result.append("\n")
        // canonical query String
        result.append(query)
        result.append("\n")
        // canonical header
        result.append(headers.sorted(by: {$0.key < $1.key}).map({"\($0.key.lowercased()):\($0.value)"}).joined(separator: "\n").appending("\n"))
        result.append("\n")
        // sign header
        result.append(headers.sorted(by: {$0.key < $1.key}).map({$0.key.lowercased()}).joined(separator: ";"))
        result.append("\n")
        // content sha256
        result.append(contentSha256)
        return result
    }
    
    /// hmac
    /// - Parameters:
    ///   - key: Array<UInt8>
    ///   - message: String
    /// - Returns: Array<UInt8>
    private func hmac(_ key: Array<UInt8>, _ message: String) throws -> Array<UInt8> {
        let hmac = HMAC(key: key, variant: .sha2(.sha256))
        return try hmac.authenticate(message.bytes)
    }
    
    /// formatterDate
    /// - Parameter date: Date
    /// - Returns: String
    internal func formatterDate(_ date: Date, _ dateFormat: String = "yyyyMMdd'T'HHmmss'Z'") -> String {
        let formatter: DateFormatter = .init()
        formatter.timeZone = .init(secondsFromGMT: 0)
        formatter.dateFormat = dateFormat
        return formatter.string(from: date)
    }
}
