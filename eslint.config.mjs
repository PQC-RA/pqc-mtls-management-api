import path from "node:path";
import { fileURLToPath } from "node:url";

import { fixupConfigRules, fixupPluginRules } from "@eslint/compat";
import { FlatCompat } from "@eslint/eslintrc";
import js from "@eslint/js";
import typescriptEslintEslintPlugin from "@typescript-eslint/eslint-plugin";
import * as tsParser from "@typescript-eslint/parser";
import _import from "eslint-plugin-import";
import globals from "globals";

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);
const compat = new FlatCompat({
	baseDirectory: __dirname,
	recommendedConfig: js.configs.recommended,
	allConfig: js.configs.all,
});

export default [
	{
		ignores: ["**/eslint.config.mjs", "**/dist", "**/node_modules"],
	},
	...fixupConfigRules(
		compat.extends(
			"plugin:@typescript-eslint/recommended",
			"plugin:prettier/recommended",
			"plugin:import/recommended",
			"plugin:import/typescript"
		)
	),
	{
		plugins: {
			"@typescript-eslint": fixupPluginRules(
				typescriptEslintEslintPlugin
			),
			"import": fixupPluginRules(_import),
		},

		languageOptions: {
			globals: {
				...globals.node,
				...globals.jest,
			},

			parser: tsParser,
			ecmaVersion: 5,
			sourceType: "module",

			parserOptions: {
				project: "tsconfig.json",
			},
		},

		settings: {
			"import/resolver": {
				typescript: {
					alwaysTryTypes: true,
					extensions: [".js", ".jsx", ".ts", ".tsx"],
					project: "tsconfig.json",
				},
			},
		},

		rules: {
			"@typescript-eslint/interface-name-prefix": "off",
			"@typescript-eslint/explicit-function-return-type": "off",
			"@typescript-eslint/explicit-module-boundary-types": "off",
			"@typescript-eslint/no-explicit-any": "off",
			"@typescript-eslint/no-unused-vars": [
				"error",
				{
					argsIgnorePattern: "^_",
					varsIgnorePattern: "^_",
					caughtErrorsIgnorePattern: "^_",
				},
			],

			// Sort named imports alphabetically
			"sort-imports": [
				"error",
				{
					ignoreCase: true, // Case-insensitive sorting
					ignoreDeclarationSort: true, // Let `import/order` handle the overall import order
					ignoreMemberSort: false, // Ensure named imports are sorted
					memberSyntaxSortOrder: [
						"none",
						"all",
						"multiple",
						"single",
					], // Sort order for import syntax
				},
			],

			"import/no-duplicates": "error",

			"import/order": [
				"error",
				{
					"groups": [
						"builtin",
						"external",
						"internal",
						["parent", "sibling", "index"],
					],

					"pathGroups": [
						{
							pattern: "@/tracing",
							group: "builtin",
							position: "after",
						},
						{
							pattern: "@/**",
							group: "internal",
							position: "before",
						},
					],

					"pathGroupsExcludedImportTypes": [],

					"newlines-between": "always",

					"alphabetize": {
						order: "asc",
						caseInsensitive: true,
					},
				},
			],
		},
	},
	// Test files: allow jest.mock() require() patterns and Function type in spies
	{
		files: ["**/*.spec.ts", "**/*.e2e-spec.ts"],
		rules: {
			"@typescript-eslint/no-require-imports": "off",
			"@typescript-eslint/no-unsafe-function-type": "off",
		},
	},
];
