public enum VisibleText {
    public static func title(_ input: String) -> String { render(input, preserveLines: false) }
    public static func secret(_ input: String) -> String { render(input, preserveLines: true) }

    private static func render(_ input: String, preserveLines: Bool) -> String {
        input.unicodeScalars.map { scalar in
            let permittedLine = preserveLines && (scalar == "\n" || scalar == "\t")
            if (scalar.properties.generalCategory == .control && !permittedLine) || scalar.properties.generalCategory == .format {
                return "\\u{" + String(scalar.value, radix: 16) + "}"
            }
            return String(scalar)
        }.joined()
    }
}
