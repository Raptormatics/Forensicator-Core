/**
 * GET /api/pcap-analysis/uploads/[id]/export — full PCAP result set as a
 * multi-sheet Excel workbook (Conversations, DNS, Findings, IOCs). Unlike
 * the paginated detail GET, this fetches every row for the upload.
 */
import { NextRequest, NextResponse } from "next/server";
import { prisma } from "@/lib/db/prisma";
import { requireAuth } from "@/lib/auth/api-guard";
import { buildXlsxBuffer } from "@/lib/reports/xlsx-export";

type Params = { params: Promise<{ id: string }> };

export async function GET(req: NextRequest, props: Params) {
  const params = await props.params;
  try {
    await requireAuth(req);
    const { id } = params;

    const upload = await prisma.pcapUpload.findUnique({ where: { id }, select: { id: true, filename: true } });
    if (!upload) return NextResponse.json({ error: "not_found" }, { status: 404 });

    const [conversations, dnsQueries, findings, iocs] = await Promise.all([
      prisma.pcapConversation.findMany({ where: { uploadId: id }, orderBy: [{ bytesAtoB: "desc" }] }),
      prisma.pcapDnsQuery.findMany({ where: { uploadId: id }, orderBy: [{ count: "desc" }] }),
      prisma.pcapFinding.findMany({ where: { uploadId: id }, orderBy: { matchCount: "desc" }, include: { rule: { select: { name: true } } } }),
      prisma.pcapIoc.findMany({ where: { uploadId: id }, orderBy: [{ count: "desc" }] }),
    ]);

    const buffer = await buildXlsxBuffer([
      {
        name: "Conversations",
        columns: [
          { header: "Protocol", key: "protocol", width: 10 },
          { header: "Endpoint A", key: "addrA", width: 20 },
          { header: "Port A", key: "portA", width: 10 },
          { header: "Endpoint B", key: "addrB", width: 20 },
          { header: "Port B", key: "portB", width: 10 },
          { header: "Packets A->B", key: "packetsAtoB", width: 14 },
          { header: "Packets B->A", key: "packetsBtoA", width: 14 },
          { header: "Bytes A->B", key: "bytesAtoB", width: 14 },
          { header: "Bytes B->A", key: "bytesBtoA", width: 14 },
          { header: "TLS SNI", key: "tlsSni", width: 30 },
          { header: "First Seen", key: "firstSeen", width: 22 },
          { header: "Last Seen", key: "lastSeen", width: 22 },
        ],
        rows: conversations.map((c) => ({
          protocol: c.protocol.toUpperCase(),
          addrA: c.addrA, portA: c.portA, addrB: c.addrB, portB: c.portB,
          packetsAtoB: c.packetsAtoB, packetsBtoA: c.packetsBtoA,
          bytesAtoB: Number(c.bytesAtoB), bytesBtoA: Number(c.bytesBtoA),
          tlsSni: c.tlsSni ?? "",
          firstSeen: c.firstSeen ? c.firstSeen.toISOString() : "",
          lastSeen: c.lastSeen ? c.lastSeen.toISOString() : "",
        })),
      },
      {
        name: "DNS",
        columns: [
          { header: "Query", key: "queryName", width: 35 },
          { header: "Type", key: "queryType", width: 10 },
          { header: "Response IPs", key: "responseIps", width: 35 },
          { header: "Count", key: "count", width: 10 },
          { header: "First Seen", key: "firstSeen", width: 22 },
          { header: "Last Seen", key: "lastSeen", width: 22 },
        ],
        rows: dnsQueries.map((d) => ({
          queryName: d.queryName, queryType: d.queryType ?? "",
          responseIps: d.responseIps.join(", "), count: d.count,
          firstSeen: d.firstSeen ? d.firstSeen.toISOString() : "",
          lastSeen: d.lastSeen ? d.lastSeen.toISOString() : "",
        })),
      },
      {
        name: "Findings",
        columns: [
          { header: "Title", key: "title", width: 30 },
          { header: "Severity", key: "severity", width: 12 },
          { header: "Description", key: "description", width: 40 },
          { header: "Match Count", key: "matchCount", width: 12 },
          { header: "Matched Field", key: "matchedField", width: 20 },
          { header: "Matched Value", key: "matchedValue", width: 30 },
          { header: "Rule", key: "rule", width: 25 },
          { header: "First Seen", key: "firstSeen", width: 22 },
          { header: "Last Seen", key: "lastSeen", width: 22 },
        ],
        rows: findings.map((f) => ({
          title: f.title, severity: f.severity, description: f.description ?? "",
          matchCount: f.matchCount, matchedField: f.matchedField ?? "", matchedValue: f.matchedValue ?? "",
          rule: f.rule?.name ?? "",
          firstSeen: f.firstSeen ? f.firstSeen.toISOString() : "",
          lastSeen: f.lastSeen ? f.lastSeen.toISOString() : "",
        })),
      },
      {
        name: "IOCs",
        columns: [
          { header: "Type", key: "type", width: 12 },
          { header: "Value", key: "value", width: 40 },
          { header: "Count", key: "count", width: 10 },
        ],
        rows: iocs.map((i) => ({ type: i.type, value: i.value, count: i.count })),
      },
    ]);

    const filename = `pcap-analysis-${upload.filename.replace(/[^a-zA-Z0-9._-]/g, "_")}.xlsx`;
    return new NextResponse(new Uint8Array(buffer), {
      headers: {
        "Content-Type": "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet",
        "Content-Disposition": `attachment; filename="${filename}"`,
        "Content-Length": String(buffer.length),
      },
    });
  } catch (err: unknown) {
    if (err && typeof err === "object" && "toResponse" in err) return (err as { toResponse(): Response }).toResponse();
    return NextResponse.json({ error: "server_error" }, { status: 500 });
  }
}
