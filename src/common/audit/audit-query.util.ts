import { AuditQueryDto } from "@/common/audit/audit-query.dto";

/**
 * Per-log-type field accessors so the same filter/pagination logic works for
 * both the data-plane log and the admin-action log (which have different
 * shapes for the same logical fields).
 */
export interface AuditFieldAccessors<T> {
	ts: (e: T) => string | undefined;
	cn?: (e: T) => string | undefined;
	event?: (e: T) => string | undefined;
	level?: (e: T) => string | undefined;
}

/**
 * Parse NDJSON content into objects, skipping blank/malformed lines.
 */
export function parseNdjson<T>(content: string): T[] {
	const out: T[] = [];
	for (const line of content.split("\n")) {
		if (!line.trim()) continue;
		try {
			out.push(JSON.parse(line) as T);
		} catch {
			// Skip malformed line – tamper/partial-write tolerant.
		}
	}
	return out;
}

/**
 * Filter and paginate parsed NDJSON entries server-side.
 *
 * Order is chronological (oldest→newest), matching the file order.
 *   - Filters (cn/event/level/since/until) apply first.
 *   - If `offset`/`limit` are set, they slice the filtered list.
 *   - Otherwise the last `lines` entries are returned (default 100),
 *     preserving the original tail behaviour.
 */
export function queryAuditEntries<T>(
	all: T[],
	q: AuditQueryDto,
	acc: AuditFieldAccessors<T>
): T[] {
	const sinceMs = q.since ? Date.parse(q.since) : undefined;
	const untilMs = q.until ? Date.parse(q.until) : undefined;

	let filtered = all.filter(e => {
		if (q.cn && acc.cn) {
			if (acc.cn(e) !== q.cn) return false;
		}
		if (q.event && acc.event) {
			if (acc.event(e) !== q.event) return false;
		}
		if (q.level && acc.level) {
			if (acc.level(e) !== q.level) return false;
		}
		if (sinceMs !== undefined || untilMs !== undefined) {
			const tsRaw = acc.ts(e);
			const tsMs = tsRaw ? Date.parse(tsRaw) : NaN;
			if (Number.isNaN(tsMs)) return false;
			if (sinceMs !== undefined && tsMs < sinceMs) return false;
			if (untilMs !== undefined && tsMs > untilMs) return false;
		}
		return true;
	});

	if (q.offset !== undefined || q.limit !== undefined) {
		const offset = q.offset ?? 0;
		const limit = q.limit ?? filtered.length;
		filtered = filtered.slice(offset, offset + limit);
	} else {
		const lines = q.lines ?? 100;
		filtered = filtered.slice(Math.max(filtered.length - lines, 0));
	}

	return filtered;
}
