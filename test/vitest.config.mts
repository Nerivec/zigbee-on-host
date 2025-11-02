import { defineConfig } from "vitest/config";

export default defineConfig({
    plugins: [],
    test: {
        typecheck: {
            enabled: true,
        },
        mockReset: true,
        onConsoleLog() {
            return false;
        },
        coverage: {
            enabled: false,
            provider: "v8",
            include: ["src/**"],
            exclude: ["src/dev/**"],
            extension: [".ts"],
            // exclude: [],
            clean: true,
            cleanOnRerun: true,
            reportsDirectory: "coverage",
            reporter: ["text", "html"],
            reportOnFailure: false,
            thresholds: {
                /** current dev status, should maintain above this */
                statements: 85,
                functions: 85,
                branches: 85,
                lines: 85,
            },
        },
    },
});
