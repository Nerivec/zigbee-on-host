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
                100: true,
            },
        },
    },
});
