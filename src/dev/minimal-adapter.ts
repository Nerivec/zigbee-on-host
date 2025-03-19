import { type Socket as DgramSocket, createSocket } from "node:dgram";
import { Socket } from "node:net";
import { SerialPort } from "serialport";
import { type NetworkParameters, OTRCPDriver } from "../drivers/ot-rcp-driver.js";
import type { StreamRawConfig } from "../spinel/spinel.js";
import { logger } from "../utils/logger.js";
import type { ZigbeeAPSHeader, ZigbeeAPSPayload } from "../zigbee/zigbee-aps.js";
import { DEFAULT_WIRESHARK_IP, DEFAULT_ZEP_UDP_PORT, createWiresharkZEPFrame } from "./wireshark.js";

const NS = "minimal-adapter";

export function isTcpPath(path: string): boolean {
    // tcp path must be: tcp://<host>:<port>
    return /^(?:tcp:\/\/)[\w.-]+[:][\d]+$/gm.test(path);
}

/**
 * Example:
 * ```ts
 * {
 *     path: 'COM4',
 *     baudRate: 460800,
 *     rtscts: true,
 * }
 * ```
 */
type PortOptions = {
    path: string;
    //---- serial only
    baudRate?: number;
    rtscts?: boolean;
};

/**
 * Minimal adapter using the OT RCP Driver that can be started via `cli.ts` and outputs to both the console, and Wireshark (MAC frames).
 */
export class MinimalAdapter {
    public readonly driver: OTRCPDriver;
    private readonly portOptions: PortOptions;
    private serialPort?: SerialPort;
    private socketPort?: Socket;
    /** True when serial/socket is currently closing */
    private closing: boolean;

    private wiresharkSeqNum: number;
    private wiresharkPort: number;
    private wiresharkAddress: string;
    private readonly wiresharkSocket: DgramSocket;

    constructor(portOptions: PortOptions, streamRawConfig: StreamRawConfig, netParams: NetworkParameters, sendMACToZEP: boolean) {
        this.wiresharkSeqNum = 0; // start at 1
        this.wiresharkSocket = createSocket("udp4");
        this.wiresharkPort = process.env.WIRESHARK_ZEP_PORT ? Number.parseInt(process.env.WIRESHARK_ZEP_PORT) : DEFAULT_ZEP_UDP_PORT;
        this.wiresharkAddress = process.env.WIRESHARK_ADDRESS ? process.env.WIRESHARK_ADDRESS : DEFAULT_WIRESHARK_IP;
        this.wiresharkSocket.bind(this.wiresharkPort);

        this.driver = new OTRCPDriver(streamRawConfig, netParams, ".", sendMACToZEP);

        this.portOptions = portOptions;
        this.closing = false;

        if (sendMACToZEP) {
            this.driver.on("macFrame", (payload, rssi) => {
                const wsZEPFrame = createWiresharkZEPFrame(this.driver.netParams.channel, 1, 0, rssi ?? 0, this.nextWiresharkSeqNum(), payload);

                this.wiresharkSocket.send(wsZEPFrame, this.wiresharkPort, this.wiresharkAddress);
            });
        }

        // noop logger as needed
        // setLogger({ debug: () => {}, info: () => {}, warning: () => {}, error: () => {}});
    }

    /**
     * Check if port is valid, open, and not closing.
     */
    get portOpen(): boolean {
        if (this.closing) {
            return false;
        }

        if (isTcpPath(this.portOptions.path!)) {
            return this.socketPort ? !this.socketPort.closed : false;
        }

        return this.serialPort ? this.serialPort.isOpen : false;
    }

    private nextWiresharkSeqNum(): number {
        this.wiresharkSeqNum = (this.wiresharkSeqNum + 1) & 0xffffffff;

        return this.wiresharkSeqNum + 1;
    }

    /**
     * Init the serial or socket port and hook parser/writer.
     */
    public async initPort(): Promise<void> {
        await this.closePort(); // will do nothing if nothing's open

        if (isTcpPath(this.portOptions.path!)) {
            const pathUrl = new URL(this.portOptions.path!);
            const hostname = pathUrl.hostname;
            const port = Number.parseInt(pathUrl.port, 10);

            logger.debug(() => `Opening TCP socket with ${hostname}:${port}`, NS);

            this.socketPort = new Socket();

            this.socketPort.setNoDelay(true);
            this.socketPort.setKeepAlive(true, 15000);
            this.driver.writer.pipe(this.socketPort);
            this.socketPort.pipe(this.driver.parser);
            this.driver.parser.on("data", this.driver.onFrame.bind(this.driver));

            return await new Promise((resolve, reject): void => {
                const openError = async (err: Error): Promise<void> => {
                    await this.stop();

                    reject(err);
                };

                this.socketPort!.on("connect", () => {
                    logger.debug(() => "Socket connected", NS);
                });
                this.socketPort!.on("ready", (): void => {
                    logger.info("Socket ready", NS);
                    this.socketPort!.removeListener("error", openError);
                    this.socketPort!.once("close", this.onPortClose.bind(this));
                    this.socketPort!.on("error", this.onPortError.bind(this));

                    resolve();
                });
                this.socketPort!.once("error", openError);

                this.socketPort!.connect(port, hostname);
            });
        }

        const serialOpts = {
            path: this.portOptions.path!,
            baudRate: typeof this.portOptions.baudRate === "number" ? this.portOptions.baudRate : 115200,
            rtscts: typeof this.portOptions.rtscts === "boolean" ? this.portOptions.rtscts : false,
            autoOpen: false,
            parity: "none" as const,
            stopBits: 1 as const,
            xon: false,
            xoff: false,
        };

        // enable software flow control if RTS/CTS not enabled in config
        if (!serialOpts.rtscts) {
            logger.info("RTS/CTS config is off, enabling software flow control.", NS);
            serialOpts.xon = true;
            serialOpts.xoff = true;
        }

        logger.debug(() => `Opening serial port with [path=${serialOpts.path} baudRate=${serialOpts.baudRate} rtscts=${serialOpts.rtscts}]`, NS);
        this.serialPort = new SerialPort(serialOpts);

        this.driver.writer.pipe(this.serialPort);
        this.serialPort.pipe(this.driver.parser);
        this.driver.parser.on("data", this.driver.onFrame.bind(this.driver));

        try {
            await new Promise<void>((resolve, reject): void => {
                this.serialPort!.open((err) => (err ? reject(err) : resolve()));
            });

            logger.info("Serial port opened", NS);

            this.serialPort.once("close", this.onPortClose.bind(this));
            this.serialPort.on("error", this.onPortError.bind(this));
        } catch (error) {
            await this.stop();

            throw error;
        }
    }

    /**
     * Handle port closing
     * @param err A boolean for Socket, an Error for serialport
     */
    private onPortClose(error: boolean | Error): void {
        if (error) {
            logger.error("Port closed unexpectedly.", NS);
        } else {
            logger.info("Port closed.", NS);
        }
    }

    /**
     * Handle port error
     * @param error
     */
    private onPortError(error: Error): void {
        logger.error(`Port ${error}`, NS);

        throw new Error("Port error");
    }

    public async start(): Promise<void> {
        await this.initPort();

        if (!this.portOpen) {
            throw new Error("Invalid call to start");
        }

        if (this.serialPort) {
            // try clearing read/write buffers
            try {
                await new Promise<void>((resolve, reject): void => {
                    this.serialPort!.flush((err) => (err ? reject(err) : resolve()));
                });
            } catch (err) {
                logger.error(`Error while flushing serial port before start: ${err}`, NS);
            }
        }

        await this.driver.start();
        await this.driver.formNetwork();
        // allow joins on start for 254 seconds
        this.driver.allowJoins(0xfe, true);

        this.driver.on("frame", this.onFrame.bind(this));
        this.driver.on("deviceJoined", this.onDeviceJoined.bind(this));
        this.driver.on("deviceRejoined", this.onDeviceRejoined.bind(this));
        this.driver.on("deviceLeft", this.onDeviceLeft.bind(this));
    }

    public async stop(): Promise<void> {
        this.closing = true;

        await this.driver.stop();
        this.wiresharkSocket.close();
        await this.closePort();
    }

    public async closePort(): Promise<void> {
        if (this.serialPort?.isOpen) {
            try {
                await new Promise<void>((resolve, reject): void => {
                    this.serialPort!.flush((err) => (err ? reject(err) : resolve()));
                });

                await new Promise<void>((resolve, reject): void => {
                    this.serialPort!.close((err) => (err ? reject(err) : resolve()));
                });
            } catch (err) {
                logger.error(`Failed to close serial port ${err}.`, NS);
            }

            this.serialPort.removeAllListeners();

            this.serialPort = undefined;
        } else if (this.socketPort != null && !this.socketPort.closed) {
            this.socketPort.destroy();
            this.socketPort.removeAllListeners();

            this.socketPort = undefined;
        }
    }

    private onFrame(_sender16: number | undefined, _sender64: bigint | undefined, _apsHeader: ZigbeeAPSHeader, _apsPayload: ZigbeeAPSPayload): void {
        // as needed for testing
    }

    private onDeviceJoined(_source16: number, _source64: bigint | undefined): void {
        // as needed for testing
    }

    private onDeviceRejoined(_source16: number, _source64: bigint | undefined): void {
        // as needed for testing
    }

    private onDeviceLeft(_source16: number, _source64: bigint): void {
        // as needed for testing
    }
}
