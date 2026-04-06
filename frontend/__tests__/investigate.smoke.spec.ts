import { expect, test, type Page } from "@playwright/test";

const auditId = "smoke-audit-123";
const rulesetId = "smoke-ruleset-123";
const findingId = "smoke-finding-123";
const ruleId = "smoke-rule-123";
const findingTitle = "Unrestricted inbound access from internet";

const auditResponse = {
  id: auditId,
  ruleset_id: rulesetId,
  filename: "nsg-prod-eastus-export.json",
  vendor: "azure_nsg",
  rule_count: 1,
  status: "completed",
  summary:
    "Audit of nsg-prod-eastus identified one critical finding tied to a permissive inbound rule.",
  error_message: null,
  findings: [
    {
      id: findingId,
      severity: "critical",
      category: "overly_permissive",
      title: findingTitle,
      description:
        "Rule 'Allow-All-Inbound' permits all inbound traffic from 0.0.0.0/0.",
      recommendation:
        "Remove the allow-all rule and replace it with source-restricted allow rules.",
      confidence: 0.99,
      source: "llm",
      affected_rule_ids: [ruleId],
    },
  ],
  total_findings: 1,
  critical_count: 1,
  high_count: 0,
  medium_count: 0,
  low_count: 0,
  created_at: "2026-04-06T20:57:14.360968Z",
  completed_at: "2026-04-06T21:00:14.360968Z",
} as const;

const rulesResponse = [
  {
    id: ruleId,
    original_id: "Allow-All-Inbound",
    name: "Allow-All-Inbound",
    vendor: "azure_nsg",
    action: "allow",
    direction: "inbound",
    protocol: "*",
    source_addresses: ["0.0.0.0/0"],
    source_ports: ["*"],
    destination_addresses: ["10.1.0.0/24"],
    destination_ports: ["*"],
    priority: 500,
    collection_name: null,
    collection_priority: null,
    description: "Temporary migration rule",
    enabled: true,
    risk_score: 99,
    tags: {},
  },
] as const;

const complianceResponse = [
  {
    framework: "cis_azure_v2",
    total_controls: 1,
    passed: 0,
    failed: 1,
    not_applicable: 0,
    checks: [
      {
        id: "cis-check-1",
        framework: "cis_azure_v2",
        control_id: "NSG-1",
        control_title: "Restrict inbound access from the internet",
        status: "fail",
        evidence: "Allow-All-Inbound permits 0.0.0.0/0.",
        affected_rule_ids: [ruleId],
      },
    ],
  },
] as const;

async function mockAuditApi(page: Page) {
  await page.addInitScript(
    ({ auditId, rulesetId, auditResponse, complianceResponse, rulesResponse }) => {
      const originalFetch = window.fetch.bind(window);

      const jsonResponse = (body: unknown, status = 200) =>
        new Response(JSON.stringify(body), {
          status,
          headers: {
            "Content-Type": "application/json",
          },
        });

      window.fetch = async (input, init) => {
        const request = input instanceof Request ? input : new Request(input, init);
        const url = new URL(request.url, window.location.origin);
        const path = url.pathname;

        if (!path.includes("/api/v1/")) {
          return originalFetch(input, init);
        }

        if (request.method.toUpperCase() !== "GET") {
          return jsonResponse({ detail: "Method Not Allowed" }, 405);
        }

        if (path.endsWith("/api/v1/audits")) {
          return jsonResponse([auditResponse]);
        }

        if (path.endsWith(`/api/v1/audit/${auditId}`)) {
          return jsonResponse(auditResponse);
        }

        if (path.endsWith(`/api/v1/audit/${auditId}/compliance`)) {
          return jsonResponse(complianceResponse);
        }

        if (path.endsWith(`/api/v1/rulesets/${rulesetId}/rules`)) {
          return jsonResponse(rulesResponse);
        }

        return jsonResponse({ detail: "Not Found" }, 404);
      };
    },
    { auditId, rulesetId, auditResponse, complianceResponse, rulesResponse },
  );
}

test("dashboard Investigate opens findings without client-side exceptions", async ({ page }) => {
  const pageErrors: string[] = [];
  page.on("pageerror", (error) => pageErrors.push(error.message));

  await mockAuditApi(page);
  await page.goto("/");
  await expect(
    page.getByText("Priority queue from the current focus audit"),
  ).toBeVisible();

  const investigateLink = page.getByRole("link", { name: "Investigate" }).first();
  await expect(investigateLink).toHaveAttribute(
    "href",
    new RegExp(`/audit/${auditId}\\?tab=findings&finding=${findingId}$`),
  );

  await investigateLink.click();

  await expect(page).toHaveURL(
    new RegExp(`/audit/${auditId}\\?tab=findings&finding=${findingId}$`),
  );
  await expect(page.getByText("Audit Investigation")).toBeVisible();
  await expect(page.getByRole("tab", { name: /Findings \(1\)/i })).toHaveAttribute(
    "aria-selected",
    "true",
  );
  await expect(page.getByText(findingTitle).first()).toBeVisible();
  await expect(
    page.getByText(/Application error: a client-side exception/i),
  ).toHaveCount(0);

  expect(pageErrors).toEqual([]);
});