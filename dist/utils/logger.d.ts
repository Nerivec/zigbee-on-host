export interface Logger {
    debug: (messageOrLambda: () => string, namespace: string) => void;
    info: (messageOrLambda: string | (() => string), namespace: string) => void;
    warning: (messageOrLambda: string | (() => string), namespace: string) => void;
    error: (messageOrLambda: string, namespace: string) => void;
}
export declare let logger: Logger;
export declare function setLogger(l: Logger): void;
