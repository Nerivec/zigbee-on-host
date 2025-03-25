import { defineConfig } from "vitest/config";

export default defineConfig({
    test: {
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
                statements: 70,
                functions: 75,
                branches: 75,
                lines: 70,
            },
        },
    },
});
