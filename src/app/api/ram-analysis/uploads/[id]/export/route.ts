/**
 * GET /api/ram-analysis/uploads/[id]/export — full RAM result set as a
 * multi-sheet Excel workbook (Processes, Connections, Findings, IOCs).
 * Unlike the paginated detail GET, this fetches every row for the upload.
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

    const upload = await prisma.ramUpload.findUnique({ where: { id }, select: { id: true, filename: true } });
    if (!upload) return NextResponse.json({ error: "not_found" }, { status: 404 });

    const [processes, connections, findings, iocs] = await Promise.all([
      prisma.ramProcess.findMany({ where: { uploadId: id }, orderBy: [{ pid: "asc" }] }),
      prisma.ramNetworkConnection.findMany({ where: { uploadId: id }, orderBy: [{ createdAt: "asc" }] }),
      prisma.ramFinding.findMany({ where: { uploadId: id }, orderBy: { matchCount: "desc" }, include: { rule: { select: { name: true } } } }),
      prisma.ramIoc.findMany({ where: { uploadId: id }, orderBy: [{ count: "desc" }] }),
    ]);

    const buffer = await buildXlsxBuffer([
      {
        name: "Processes",
        columns: [
          { header: "PID", key: "pid", width: 10 },
          { header: "PPID", key: "ppid", width: 10 },
          { header: "Name", key: "name", width: 25 },
          { header: "Path", key: "path", width: 40 },
          { header: "Command Line", key: "commandLine", width: 50 },
          { header: "Create Time", key: "createTime", width: 22 },
          { header: "Exit Time", key: "exitTime", width: 22 },
          { header: "Session", key: "sessionId", width: 10 },
          { header: "Threads", key: "threads", width: 10 },
          { header: "Handles", key: "handles", width: 10 },
        ],
        rows: processes.map((p) => ({
          pid: p.pid, ppid: p.ppid, name: p.name, path: p.path ?? "", commandLine: p.commandLine ?? "",
          createTime: p.createTime ? p.createTime.toISOString() : "",
          exitTime: p.exitTime ? p.exitTime.toISOString() : "",
          sessionId: p.sessionId, threads: p.threads, handles: p.handles,
        })),
      },
      {
        name: "Connections",
        columns: [
          { header: "Protocol", key: "protocol", width: 10 },
          { header: "Local Address", key: "localAddr", width: 20 },
          { header: "Local Port", key: "localPort", width: 10 },
          { header: "Foreign Address", key: "foreignAddr", width: 20 },
          { header: "Foreign Port", key: "foreignPort", width: 10 },
          { header: "State", key: "state", width: 12 },
          { header: "PID", key: "pid", width: 10 },
          { header: "Process", key: "processName", width: 25 },
          { header: "Created", key: "created", width: 22 },
        ],
        rows: connections.map((c) => ({
          protocol: c.protocol ?? "", localAddr: c.localAddr ?? "", localPort: c.localPort,
          foreignAddr: c.foreignAddr ?? "", foreignPort: c.foreignPort, state: c.state ?? "",
          pid: c.pid, processName: c.processName ?? "",
          created: c.created ? c.created.toISOString() : "",
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

    const filename = `ram-analysis-${upload.filename.replace(/[^a-zA-Z0-9._-]/g, "_")}.xlsx`;
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
