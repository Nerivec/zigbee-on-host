"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
exports.logger = void 0;
exports.setLogger = setLogger;
/* v8 ignore next -- @preserve */
exports.logger = {
    debug: (messageOrLambda, namespace) => console.debug(`[${new Date().toISOString()}] ${namespace}: ${messageOrLambda()}`),
    info: (messageOrLambda, namespace) => console.info(`[${new Date().toISOString()}] ${namespace}: ${typeof messageOrLambda === "function" ? messageOrLambda() : messageOrLambda}`),
    warning: (messageOrLambda, namespace) => console.warn(`[${new Date().toISOString()}] ${namespace}: ${typeof messageOrLambda === "function" ? messageOrLambda() : messageOrLambda}`),
    error: (message, namespace) => console.error(`[${new Date().toISOString()}] ${namespace}: ${message}`),
};
/* v8 ignore next -- @preserve */
function setLogger(l) {
    exports.logger = l;
}
//# sourceMappingURL=logger.js.map