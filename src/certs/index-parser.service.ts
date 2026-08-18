import * as fs from "fs";
import * as readline from "readline";

import { Injectable, Logger } from "@nestjs/common";

export interface CertEntry {
	status: "V" | "R" | "E"; // Valid, Revoked, Expired
	expirationDate: Date;
	revocationDate?: Date;
	serialNumber: string;
	filename?: string;
	subject: string;
}

@Injectable()
export class IndexParserService {
	private readonly logger = new Logger(IndexParserService.name);

	/**
	 * Parses the OpenSSL index.txt file
	 * @param filePath Path to the index.txt file
	 * @returns Array of parsed certificate entries
	 */
	async parseIndexFile(filePath: string): Promise<CertEntry[]> {
		this.logger.debug(`Parsing index file at ${filePath}`);
		const entries: CertEntry[] = [];

		if (!fs.existsSync(filePath)) {
			this.logger.warn(`Index file not found at ${filePath}`);
			return entries;
		}

		const fileStream = fs.createReadStream(filePath);
		const rl = readline.createInterface({
			input: fileStream,
			crlfDelay: Infinity,
		});

		for await (const line of rl) {
			if (!line.trim()) continue;

			const parts = line.split("\t");
			if (parts.length < 6) {
				this.logger.warn(`Skipping invalid line: ${line}`);
				continue;
			}

			const status = parts[0] as "V" | "R" | "E";
			const expirationDateStr = parts[1];
			const revocationDateStr = parts[2];
			const serialNumber = parts[3];
			const filename = parts[4];
			const subject = parts[5];

			// OpenSSL dates are in YYMMDDHHMMSSZ format
			let expirationDate = new Date();
			if (expirationDateStr.length === 13) {
				const year = parseInt(
					"20" + expirationDateStr.substring(0, 2),
					10
				);
				const month =
					parseInt(expirationDateStr.substring(2, 4), 10) - 1;
				const day = parseInt(expirationDateStr.substring(4, 6), 10);
				const hour = parseInt(expirationDateStr.substring(6, 8), 10);
				const minute = parseInt(expirationDateStr.substring(8, 10), 10);
				const second = parseInt(
					expirationDateStr.substring(10, 12),
					10
				);
				expirationDate = new Date(
					Date.UTC(year, month, day, hour, minute, second)
				);
			}

			let revocationDate: Date | undefined;
			if (revocationDateStr && revocationDateStr.length >= 13) {
				// It might have a reason appended e.g. YYMMDDHHMMSSZ,reason
				const datePart = revocationDateStr.split(",")[0];
				const year = parseInt("20" + datePart.substring(0, 2), 10);
				const month = parseInt(datePart.substring(2, 4), 10) - 1;
				const day = parseInt(datePart.substring(4, 6), 10);
				const hour = parseInt(datePart.substring(6, 8), 10);
				const minute = parseInt(datePart.substring(8, 10), 10);
				const second = parseInt(datePart.substring(10, 12), 10);
				revocationDate = new Date(
					Date.UTC(year, month, day, hour, minute, second)
				);
			}

			entries.push({
				status,
				expirationDate,
				revocationDate,
				serialNumber,
				filename: filename !== "unknown" ? filename : undefined,
				subject,
			});
		}

		return entries;
	}
}
