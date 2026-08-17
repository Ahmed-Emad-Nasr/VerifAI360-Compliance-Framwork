"""
scoping_data.py
-----------------
SAQ (Self-Assessment Questionnaire) type catalog for VerifAI 360.

WHY THIS EXISTS
----------------
Real PCI DSS self-assessment starts with picking the right SAQ type
(A, A-EP, B, B-IP, C, C-VT, D-Merchant, D-Service Provider, ...) based on
*how* the merchant/service provider handles cardholder data. The SAQ type
determines which of the 12 top-level PCI DSS requirements are actually
in scope — a merchant on SAQ A does not need to satisfy the same set of
controls as one on SAQ D. Treating every merchant as if all 12
requirements apply (the previous behaviour of this tool) overstates the
work required for smaller merchants and, worse, makes the compliance %
misleading for anyone who isn't on SAQ D.

IMPORTANT ACCURACY NOTE — READ BEFORE TRUSTING THIS FOR A REAL ASSESSMENT
--------------------------------------------------------------------------
The requirement-to-SAQ mapping below is a **simplified approximation**,
expressed at the level of the 12 top-level PCI DSS requirements (this
tool's data model does not carry the official, question-by-question SAQ
text). The official, authoritative, question-level mapping lives in each
SAQ's own PDF, published by the PCI Security Standards Council at
https://www.pcisecuritystandards.org/document_library/ (search "SAQ").
Eligibility criteria and exact applicable requirements can also depend on
things this tool cannot see (e.g. whether a service provider is genuinely
isolated, whether paper records exist, acquirer/card-brand-specific
rules). Always confirm the correct SAQ type and its exact applicable
requirements with your acquirer and a Qualified Security Assessor (QSA)
before submitting anything based on this tool's output.

Sources consulted for the general shape of this mapping (all secondary/
explanatory, not the primary SAQ text itself):
  - PCI Security Standards Council, "PCI DSS v4: What's New with
    Self-Assessment Questionnaires" (blog.pcisecuritystandards.org)
  - PCI DSS v4.0 SAQ A (official PDF, listings.pcisecuritystandards.org)
  - Secureframe, SecurityMetrics, Thoropass, FRSecure SAQ overview articles
"""

SAQ_TYPES = {
    "A": {
        "label": "SAQ A — Card-not-present, fully outsourced",
        "description": (
            "E-commerce or mail/telephone-order merchants that have fully outsourced all "
            "cardholder data handling to PCI DSS-compliant third parties, with no electronic "
            "storage, processing, or transmission of cardholder data on the merchant's own "
            "systems (no redirect/iframe control over the payment page)."
        ),
        "applicable_requirements": ["2", "8", "9", "12"],
        "notes": "Shortest SAQ (~31 questions in the official form). Requirement 12.8/12.9 "
                 "(service-provider management) applies because everything is outsourced.",
    },
    "A-EP": {
        "label": "SAQ A-EP — Card-not-present, partially outsourced (e-commerce)",
        "description": (
            "E-commerce merchants who outsource payment processing to a PCI DSS-validated "
            "third party but whose own web server controls or impacts how the customer is "
            "redirected to that third party (e.g. hosts the checkout page that loads a "
            "payment iframe/script). No cardholder data is stored on the merchant's systems."
        ),
        "applicable_requirements": ["1", "2", "4", "6", "8", "9", "10", "11", "12"],
        "notes": "Substantially larger than SAQ A — includes ASV external scanning and "
                 "penetration testing (Req 11) and secure-development controls (Req 6) "
                 "because the merchant's web server can affect payment-page security.",
    },
    "B": {
        "label": "SAQ B — Imprint machines / standalone dial-out terminals",
        "description": (
            "Merchants using only standalone, dial-out terminals or manual imprint machines "
            "with no internet connection and no electronic cardholder data storage. Not for "
            "e-commerce."
        ),
        "applicable_requirements": ["3", "4", "9", "12"],
        "notes": "Very limited technical scope since terminals are not network-connected.",
    },
    "C": {
        "label": "SAQ C — Internet-connected payment application",
        "description": (
            "Merchants processing cardholder data through an internet-connected payment "
            "application (POS/virtual terminal/mobile app), with no electronic cardholder "
            "data storage and the payment system isolated from other systems/networks."
        ),
        "applicable_requirements": ["1", "2", "3", "4", "6", "7", "8", "9", "10", "11", "12"],
        "notes": "Broader than A/A-EP because the merchant directly operates a network-"
                 "connected system that touches cardholder data.",
    },
    "D-Merchant": {
        "label": "SAQ D — Merchant (catch-all)",
        "description": (
            "Any merchant that doesn't qualify for a more limited SAQ type — e.g. stores "
            "cardholder data electronically, or has a payment environment that doesn't "
            "cleanly fit A/A-EP/B/C. Covers the full PCI DSS requirement set."
        ),
        "applicable_requirements": ["1", "2", "3", "4", "5", "6", "7", "8", "9", "10", "11", "12"],
        "notes": "Longest SAQ (~251 questions in the official form). All 12 requirements apply.",
    },
    "D-Service Provider": {
        "label": "SAQ D — Service Provider",
        "description": (
            "The only SAQ type available to service providers (entities that store, process, "
            "or transmit cardholder data, or manage CDE components, on behalf of others). "
            "Covers the full PCI DSS requirement set, including service-provider-specific "
            "sub-requirements."
        ),
        "applicable_requirements": ["1", "2", "3", "4", "5", "6", "7", "8", "9", "10", "11", "12"],
        "notes": "Longest SAQ (~269 questions in the official form). All 12 requirements apply; "
                 "some individual questions are merchant-only and reported N/A for service "
                 "providers, which this simplified requirement-level mapping cannot represent.",
    },
    "Not yet determined": {
        "label": "Not yet determined — show all 12 requirements",
        "description": "No SAQ type selected yet. All 12 requirements are shown as in scope "
                        "until a type is chosen on the SAQ Scoping page.",
        "applicable_requirements": [str(i) for i in range(1, 13)],
        "notes": "Default state — pick a SAQ type on the SAQ Scoping page for an accurate scope.",
    },
}

DEFAULT_SAQ_TYPE = "Not yet determined"


def get_saq_definition(saq_type: str) -> dict:
    return SAQ_TYPES.get(saq_type, SAQ_TYPES[DEFAULT_SAQ_TYPE])


def applicable_requirement_ids(saq_type: str):
    return set(get_saq_definition(saq_type)["applicable_requirements"])
