/**
 * Shared multi-sheet Excel (.xlsx) workbook builder, used by the per-module
 * result-page export routes (PCAP/Log/RAM analysis, IOC intelligence).
 */
import ExcelJS from "exceljs";

export type XlsxColumn = { header: string; key: string; width?: number };
export type XlsxSheet = { name: string; columns: XlsxColumn[]; rows: Record<string, unknown>[] };

export async function buildXlsxBuffer(sheets: XlsxSheet[]): Promise<Buffer> {
  const workbook = new ExcelJS.Workbook();
  workbook.creator = "Forensicator Enterprise";
  workbook.created = new Date();

  for (const sheet of sheets) {
    // Sheet names are capped at 31 chars and can't contain []:*?/\ — none of
    // ours do, but truncate defensively since it's a hard Excel limit.
    const ws = workbook.addWorksheet(sheet.name.slice(0, 31));
    ws.columns = sheet.columns.map((c) => ({ header: c.header, key: c.key, width: c.width ?? 20 }));
    ws.getRow(1).font = { bold: true };
    ws.views = [{ state: "frozen", ySplit: 1 }];
    for (const row of sheet.rows) ws.addRow(row);
  }

  // addWorksheet requires at least one sheet — guard callers that pass none.
  if (sheets.length === 0) workbook.addWorksheet("Empty");

  const arrayBuffer = await workbook.xlsx.writeBuffer();
  return Buffer.from(arrayBuffer);
}
