import * as crypto from "crypto";
import * as fs from "fs";
import * as path from "path";

import { Injectable, Logger } from "@nestjs/common";

import {
	AdminActionEntry,
	AdminActionResult,
	AdminActor,
} from "@/admin-audit/dto/admin-action.dto";
import { sanitizeParams } from "@/admin-audit/sanitize.util";
import { AuditQueryDto } from "@/common/audit/audit-query.dto";
import {
	parseNdjson,
	queryAuditEntries,
} from "@/common/audit/audit-query.util";
import { PKI_CONFIG } from "@/common/config/pki.config";

/** Genesis prev_hash for the first entry in the chain. */
const ZERO_HASH = "0".repeat(64);

export interface AppendAction {
	action: string;
	actor: AdminActor | null;
	target?: string | null;
	params?: Record<string, unknown>;
	result: AdminActionResult;
}

/**
 * AdminAuditService – tamper-evident record of who performed control-plane
 * mutations.
 *
 * Entries are appended as NDJSON to ADMIN_AUDIT_LOG on the writable app volume
 * (/var/lib/pqc-mgmt). Each entry carries a SHA-256 hash chain (`prev_hash` →
 * `hash`), so any retroactive edit or
 * deletion breaks the chain and is detectable.
 *
 * Appends are serialized through an internal promise queue so concurrent
 * mutations cannot interleave sequence numbers or race the chain head. The
 * head (seq + last hash) is recovered from the file on first use so the chain
 * survives process restarts.
 */
@Injectable()
export class AdminAuditService {
	private readonly logger = new Logger(AdminAuditService.name);
	private readonly logPath = PKI_CONFIG.adminAuditLogPath;

	private lastSeq = 0;
	private lastHash = ZERO_HASH;
	private initialized = false;
	/** Serializes appends (and lazy init) to keep the chain consistent. */
	private queue: Promise<unknown> = Promise.resolve();

	/**
	 * Deterministic serialization for hashing: keys sorted recursively so the
	 * hash is reproducible regardless of property insertion order.
	 */
	private canonical(value: unknown): string {
		if (value === null || typeof value !== "object") {
			return JSON.stringify(value);
		}
		if (Array.isArray(value)) {
			return "[" + value.map(v => this.canonical(v)).join(",") + "]";
		}
		const obj = value as Record<string, unknown>;
		const keys = Object.keys(obj).sort();
		return (
			"{" +
			keys
				.map(k => JSON.stringify(k) + ":" + this.canonical(obj[k]))
				.join(",") +
			"}"
		);
	}

	/** Compute the chain hash over every field except `hash` itself. */
	private computeHash(entry: Omit<AdminActionEntry, "hash">): string {
		return crypto
			.createHash("sha256")
			.update(this.canonical(entry))
			.digest("hex");
	}

	/** Recover the chain head (seq + last hash) from the existing log file. */
	private recoverHead(): void {
		if (this.initialized) return;
		this.initialized = true;
		try {
			if (!fs.existsSync(this.logPath)) return;
			const content = fs.readFileSync(this.logPath, "utf8");
			const entries = parseNdjson<AdminActionEntry>(content);
			const last = entries[entries.length - 1];
			if (last && typeof last.seq === "number" && last.hash) {
				this.lastSeq = last.seq;
				this.lastHash = last.hash;
			}
		} catch (e) {
			this.logger.error(
				`Could not recover admin-audit chain head from ${this.logPath}: ${(e as Error).message}`
			);
		}
	}

	/**
	 * Append one action to the audit log. Serialized; never throws into the
	 * caller (a failed audit write is logged but does not fail the operation –
	 * the chain-break is itself detectable on read).
	 */
	append(action: AppendAction): Promise<AdminActionEntry | null> {
		const run = this.queue.then(() => this.doAppend(action));
		// Keep the queue alive even if this append rejects internally.
		this.queue = run.catch(() => undefined);
		return run;
	}

	private async doAppend(
		action: AppendAction
	): Promise<AdminActionEntry | null> {
		this.recoverHead();

		const actor: AdminActor = action.actor ?? {
			sub: null,
			fpr: null,
			role: null,
		};

		const base: Omit<AdminActionEntry, "hash"> = {
			seq: this.lastSeq + 1,
			ts: new Date().toISOString(),
			actor,
			action: action.action,
			target: action.target ?? null,
			params: (sanitizeParams(action.params ?? {}) ?? {}) as Record<
				string,
				unknown
			>,
			result: action.result,
			prev_hash: this.lastHash,
		};
		const entry: AdminActionEntry = {
			...base,
			hash: this.computeHash(base),
		};

		try {
			fs.mkdirSync(path.dirname(this.logPath), { recursive: true });
			await fs.promises.appendFile(
				this.logPath,
				JSON.stringify(entry) + "\n",
				{ mode: 0o640 }
			);
			this.lastSeq = entry.seq;
			this.lastHash = entry.hash;
			return entry;
		} catch (e) {
			this.logger.error(
				`Failed to append admin-audit entry (action=${action.action}): ${(e as Error).message}`
			);
			return null;
		}
	}

	/** Read, filter, and paginate admin-action entries for the API. */
	async query(q: AuditQueryDto): Promise<AdminActionEntry[]> {
		if (!fs.existsSync(this.logPath)) {
			return [];
		}
		const content = await fs.promises.readFile(this.logPath, "utf8");
		const all = parseNdjson<AdminActionEntry>(content);
		return queryAuditEntries(all, q, {
			ts: e => e.ts,
			// admin-actions have no client CN; expose actor.sub under `cn` filter
			// is misleading, so leave cn unsupported here.
			event: e => e.action,
			level: e => e.result?.status,
		});
	}
}
