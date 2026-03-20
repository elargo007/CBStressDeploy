//  AnyCodable.swift
//  CBStressCore
//
//  Lightweight AnyCodable implementation to support Codable/Hashable metadata.
//

import Foundation

public enum AnyCodable: Codable, Hashable, Sendable {
    case bool(Bool)
    case int(Int)
    case double(Double)
    case string(String)
    case array([AnyCodable])
    case dictionary([String: AnyCodable])

    // MARK: - Initializers
    public init(from decoder: Decoder) throws {
        let container = try decoder.singleValueContainer()

        if container.decodeNil() {
            // Represent `nil` by throwing and letting the caller use Optional<AnyCodable>
            throw DecodingError.valueNotFound(AnyCodable.self, DecodingError.Context(codingPath: decoder.codingPath, debugDescription: "nil is not representable directly; use Optional<AnyCodable>"))
        } else if let b = try? container.decode(Bool.self) {
            self = .bool(b)
        } else if let i = try? container.decode(Int.self) {
            self = .int(i)
        } else if let d = try? container.decode(Double.self) {
            self = .double(d)
        } else if let s = try? container.decode(String.self) {
            self = .string(s)
        } else if let a = try? container.decode([AnyCodable].self) {
            self = .array(a)
        } else if let dict = try? container.decode([String: AnyCodable].self) {
            self = .dictionary(dict)
        } else {
            throw DecodingError.dataCorruptedError(in: container, debugDescription: "Unsupported AnyCodable value")
        }
    }

    public func encode(to encoder: Encoder) throws {
        var container = encoder.singleValueContainer()
        switch self {
        case .bool(let b):
            try container.encode(b)
        case .int(let i):
            try container.encode(i)
        case .double(let d):
            try container.encode(d)
        case .string(let s):
            try container.encode(s)
        case .array(let a):
            try container.encode(a)
        case .dictionary(let dict):
            try container.encode(dict)
        }
    }
}

// Convenience initializers for common literal conversions
extension AnyCodable: ExpressibleByBooleanLiteral, ExpressibleByIntegerLiteral, ExpressibleByFloatLiteral, ExpressibleByStringLiteral, ExpressibleByArrayLiteral, ExpressibleByDictionaryLiteral {
    public init(booleanLiteral value: Bool) { self = .bool(value) }
    public init(integerLiteral value: Int) { self = .int(value) }
    public init(floatLiteral value: Double) { self = .double(value) }
    public init(stringLiteral value: String) { self = .string(value) }

    public init(arrayLiteral elements: AnyCodable...) { self = .array(elements) }

    public init(dictionaryLiteral elements: (String, AnyCodable)...) {
        var dict: [String: AnyCodable] = [:]
        for (k, v) in elements { dict[k] = v }
        self = .dictionary(dict)
    }
}

// Helpers to expose unboxed values if needed
public extension AnyCodable {
    var boolValue: Bool? { if case let .bool(v) = self { return v } else { return nil } }
    var intValue: Int? { if case let .int(v) = self { return v } else { return nil } }
    var doubleValue: Double? { if case let .double(v) = self { return v } else { return nil } }
    var stringValue: String? { if case let .string(v) = self { return v } else { return nil } }
    var arrayValue: [AnyCodable]? { if case let .array(v) = self { return v } else { return nil } }
    var dictionaryValue: [String: AnyCodable]? { if case let .dictionary(v) = self { return v } else { return nil } }
}
