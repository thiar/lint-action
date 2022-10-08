const core = require("@actions/core");

const { run } = require("../utils/action");
const commandExists = require("../utils/command-exists");
const { initLintResult } = require("../utils/lint-result");
const { removeTrailingPeriod } = require("../utils/string");

/** @typedef {import('../utils/lint-result').LintResult} LintResult */

/**
 * https://github.com/enlightn/security-checker
 */
class PHPSecurityChecker {
	static get name() {
		return "security-checker";
	}

	/**
	 * Verifies that all required programs are installed. Throws an error if programs are missing
	 * @param {string} dir - Directory to run the linting program in
	 * @param {string} prefix - Prefix to the lint command
	 */
	static async verifySetup(dir, prefix = "") {
		// Verify that PHP is installed (required to execute security-checker)
		if (!(await commandExists("php"))) {
			throw new Error("PHP is not installed");
		}

		// Verify that security-checker is installed
		try {
			run(`${prefix} security-checker --version`, { dir });
		} catch (err) {
			throw new Error(`${this.name} is not installed`);
		}
	}

	/**
	 * Runs the linting program and returns the command output
	 * @param {string} dir - Directory to run the linter in
	 * @param {string[]} extensions - File extensions which should be linted
	 * @param {string} args - Additional arguments to pass to the linter
	 * @param {boolean} fix - Whether the linter should attempt to fix code style issues automatically
	 * @param {string} prefix - Prefix to the lint command
	 * @returns {{status: number, stdout: string, stderr: string}} - Output of the lint command
	 */
	static lint(dir, extensions, args = "", fix = false, prefix = "") {
		const extensionsArg = extensions.join(",");
		if (fix) {
			core.warning(`${this.name} does not support auto-fixing ${extensionsArg}`);
		}
		return run(`${prefix} security-checker security:check composer.lock ${args} --no-dev --format=json`, {
			dir,
			ignoreErrors: true,
		});
	}

	/**
	 * Parses the output of the lint command. Determines the success of the lint process and the
	 * severity of the identified code style violations
	 * @param {string} dir - Directory in which the linter has been run
	 * @param {{status: number, stdout: string, stderr: string}} output - Output of the lint command
	 * @returns {LintResult} - Parsed lint result
	 */
	static parseOutput(dir, output) {
		const lintResult = initLintResult();
		lintResult.isSuccess = output.status === 0;

		let outputJson;
		try {
			outputJson = JSON.parse(output.stdout);
		} catch (err) {
			throw Error(
				`Error parsing ${this.name} JSON output: ${err.message}. Output: "${output.stdout}"`,
			);
		}
		for(const [dependency, advisories] of Object.entries(outputJson)){
			for(const advisor of advisories.advisories){
					const { cve, link, title,  } = advisor;
					const entry = {
							path: `${dependency} version: ${advisories.version} `,
							firstLine: cve,
							lastLine: cve,
							message: `${title} (${link})`,
					};
					lintResult.error.push(entry);
			}

	}


		return lintResult;
	}
}

module.exports = PHPSecurityChecker;
