interface AirFieldMetadata {
  elementKind: "input" | "textarea" | "contenteditable" | "unknown";
  inputType?: string;
  autocomplete?: string;
  descriptor?: string;
  pageContext?: string;
}

type AirFieldClassification =
  | { capture: "content"; reason: "ordinary-text-field" }
  | { capture: "metadata-only"; reason: "authentication-field" | "payment-field" | "unsupported-or-unknown-field" };

namespace AirFieldPolicy {
  export function classify(metadata: AirFieldMetadata): AirFieldClassification {
    const descriptor = `${metadata.descriptor ?? ""} ${metadata.autocomplete ?? ""} ${metadata.pageContext ?? ""}`.toLowerCase();
    const authentication = /(?:password|passcode|one[- ]?time|\botp\b|\btotp\b|\bpin\b|credential|secret|security.?code|webauthn|sign.?in|log.?in|authenticate|verification.?code|account.?number|username)/i;
    const payment = /(?:credit.?card|debit.?card|card.?number|\bcvv\b|\bcvc\b|payment|checkout|billing|bank.?account|transaction|cc-number|cc-csc|cc-exp)/i;
    if (payment.test(descriptor)) return { capture: "metadata-only", reason: "payment-field" };
    if (authentication.test(descriptor)) return { capture: "metadata-only", reason: "authentication-field" };
    if (metadata.elementKind === "textarea" || metadata.elementKind === "contenteditable") {
      return { capture: "content", reason: "ordinary-text-field" };
    }
    if (metadata.elementKind === "input" && ["text", "search", "url"].includes((metadata.inputType ?? "").toLowerCase())) {
      return { capture: "content", reason: "ordinary-text-field" };
    }
    return { capture: "metadata-only", reason: "unsupported-or-unknown-field" };
  }
}
