import Foundation

struct DemoError: Error, CustomStringConvertible {
    let description: String
}

/// Minimal JSON plumbing for routing protocol messages between parties.
enum MpcJson {

    static func array(_ objects: [String]) -> String {
        "[" + objects.joined(separator: ",") + "]"
    }

    /// Splits a JSON array into its raw top-level elements without re-encoding them.
    static func split(_ json: String) -> [String] {
        var items: [String] = []
        var depth = 0
        var inString = false
        var escaped = false
        var start: String.Index?

        for index in json.indices {
            let char = json[index]
            if escaped { escaped = false; continue }
            if char == "\\" { escaped = true; continue }
            if char == "\"" { inString.toggle(); continue }
            if inString { continue }
            if char == "{" {
                if depth == 0 { start = index }
                depth += 1
            } else if char == "}" {
                depth -= 1
                if depth == 0, let begin = start {
                    items.append(String(json[begin...index]))
                }
            }
        }
        return items
    }

    static func int(_ json: String, _ key: String) -> Int? {
        object(json)?[key] as? Int
    }

    static func string(_ json: String, _ key: String) -> String? {
        object(json)?[key] as? String
    }

    static func raw(_ json: String, _ key: String) -> String? {
        guard let value = object(json)?[key],
              let data = try? JSONSerialization.data(withJSONObject: value) else { return nil }
        return String(data: data, encoding: .utf8)
    }

    private static func object(_ json: String) -> [String: Any]? {
        (try? JSONSerialization.jsonObject(with: Data(json.utf8))) as? [String: Any]
    }
}

extension Data {
    var hexString: String { map { String(format: "%02x", $0) }.joined() }
}
