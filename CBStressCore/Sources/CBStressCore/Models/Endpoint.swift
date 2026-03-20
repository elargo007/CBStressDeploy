///  Endpoint.swift
///  CBStress
///
///  Created by Steven Petteruti on 1/16/26.
///  1-24-26 Holds authentication material (Bearer token / cookies) in a reusable, non-UI model. No scanner logic here.
///  2-17-26 Make struct public for web app

import Foundation

public struct Endpoint: Identifiable, Hashable, Codable {
    public enum HTTPMethod: String, CaseIterable, Codable {
        case GET, POST, PUT, PATCH, DELETE, HEAD, OPTIONS
    }

    public var id: String { url + "|\(method.rawValue)" }

    public var url: String
    public var method: HTTPMethod
    public var headers: [String: String]
    public var body: String?

    public init(url: String,
                method: HTTPMethod = .GET,
                headers: [String: String] = [:],
                body: String? = nil) {
        self.url = url
        self.method = method
        self.headers = headers
        self.body = body
    }

    public func applying(auth: AuthContext?) -> Endpoint {
        guard let auth else { return self }
        var copy = self
        if let token = auth.bearerToken, !token.isEmpty {
            copy.headers["Authorization"] = "Bearer \(token)"
        }
        if let cookie = auth.cookieHeader, !cookie.isEmpty {
            copy.headers["Cookie"] = cookie
        }
        return copy
    }
}
