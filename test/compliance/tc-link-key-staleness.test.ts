/**
 * Zigbee Specification Compliance Tests — stale trust centre link keys
 *
 * 05-3474-23 #4.7.3.1 step 2b, #4.7.3.11.1
 *
 * The defect this pins down, end to end:
 *
 * A unique trust centre link key issued to one incarnation of an IEEE survives
 * that device's departure. When the device comes back factory reset it holds
 * only the well-known key, so that is what it proves in VERIFY_KEY — the
 * correct proof for a device with no unique key. The trust centre, still
 * holding the stale entry, compares that proof against the OLD key and answers
 * SECURITY_FAILURE. The device is then unjoinable, and nothing in the exchange
 * says why: the joiner's proof is right, the comparison is right, and only the
 * key the trust centre reaches for is stale.
 *
 * This test drives the real StackContext and APSHandler — no mocked associate,
 * no mocked key table — so it fails on a tree without the fix and passes on one
 * with it. It deliberately uses no API the fix introduces, so the same file
 * compiles and runs on both.
 */

import { mkdirSync, rmSync } from "node:fs";
import { join } from "node:path";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { MACAssociationStatus, type MACCapabilities, type MACHeader } from "../../src/zigbee/mac.js";
import { makeKeyedHashByType, registerDefaultHashedKeys, ZigbeeKeyType } from "../../src/zigbee/zigbee.js";
import { ZigbeeAPSConsts, type ZigbeeAPSHeader } from "../../src/zigbee/zigbee-aps.js";
import type { ZigbeeNWKHeader } from "../../src/zigbee/zigbee-nwk.js";
import { APSHandler, type APSHandlerCallbacks } from "../../src/zigbee-stack/aps-handler.js";
import { MACHandler, type MACHandlerCallbacks } from "../../src/zigbee-stack/mac-handler.js";
import { NWKHandler, type NWKHandlerCallbacks } from "../../src/zigbee-stack/nwk-handler.js";
import { type NetworkParameters, StackContext, type StackContextCallbacks } from "../../src/zigbee-stack/stack-context.js";
import { NETDEF_EXTENDED_PAN_ID, NETDEF_NETWORK_KEY, NETDEF_PAN_ID, NETDEF_TC_KEY } from "../data.js";
import { NO_ACK_CODE } from "./utils.js";

describe("Stale trust centre link keys", () => {
    let netParams: NetworkParameters;
    let saveDir: string;
    let context: StackContext;
    let macHandler: MACHandler;
    let apsHandler: APSHandler;

    const capabilities: MACCapabilities = {
        alternatePANCoordinator: false,
        deviceType: 1,
        powerSource: 1,
        rxOnWhenIdle: true,
        securityCapability: true,
        allocateAddress: true,
    };

    beforeEach(async () => {
        netParams = {
            eui64: 0x00124b0012345678n,
            panId: NETDEF_PAN_ID,
            extendedPanId: NETDEF_EXTENDED_PAN_ID.readBigUInt64LE(),
            channel: 15,
            nwkUpdateId: 0,
            txPower: 5,
            networkKey: Buffer.from(NETDEF_NETWORK_KEY),
            networkKeyFrameCounter: 0,
            networkKeySequenceNumber: 0,
            tcKey: Buffer.from(NETDEF_TC_KEY),
            tcKeyFrameCounter: 0,
        };
        saveDir = `temp_STALEKEY_${Math.floor(Math.random() * 1000000)}`;
        mkdirSync(saveDir, { recursive: true });

        registerDefaultHashedKeys(
            makeKeyedHashByType(ZigbeeKeyType.LINK, Buffer.from(NETDEF_TC_KEY)),
            makeKeyedHashByType(ZigbeeKeyType.NWK, Buffer.from(NETDEF_NETWORK_KEY)),
            makeKeyedHashByType(ZigbeeKeyType.TRANSPORT, Buffer.from(NETDEF_TC_KEY)),
            makeKeyedHashByType(ZigbeeKeyType.LOAD, Buffer.from(NETDEF_TC_KEY)),
        );

        const stackContextCallbacks: StackContextCallbacks = { onDeviceLeft: vi.fn() };
        const macCallbacks: MACHandlerCallbacks = {
            onFrame: vi.fn(),
            onSendFrame: vi.fn(),
            onAPSSendTransportKeyNWK: vi.fn(),
            onMarkRouteSuccess: vi.fn(),
            onMarkRouteFailure: vi.fn(),
        };
        const nwkCallbacks: NWKHandlerCallbacks = { onAPSSendTransportKeyNWK: vi.fn() };
        const apsCallbacks: APSHandlerCallbacks = {
            onFrame: vi.fn(),
            onDeviceJoined: vi.fn(),
            onDeviceRejoined: vi.fn(),
            onDeviceAuthorized: vi.fn(),
        };

        context = new StackContext(stackContextCallbacks, join(saveDir, "zoh.save"), netParams);
        await context.loadState();

        macHandler = new MACHandler(context, macCallbacks, NO_ACK_CODE);
        const nwkHandler = new NWKHandler(context, macHandler, nwkCallbacks);
        apsHandler = new APSHandler(context, macHandler, nwkHandler, apsCallbacks);
    });

    afterEach(() => {
        apsHandler.stop();
        rmSync(saveDir, { force: true, recursive: true });
    });

    /** What the trust centre answered, from the CONFIRM_KEY it sent. */
    const verifyAsFactoryResetDevice = async (device16: number, device64: bigint): Promise<number> => {
        // A device holding no unique key proves the well-known one. That is
        // precisely `tcVerifyKeyHash`.
        const data = Buffer.alloc(1 + 8 + ZigbeeAPSConsts.CMD_KEY_LENGTH);
        let offset = 0;
        data.writeUInt8(ZigbeeAPSConsts.CMD_KEY_TC_LINK, offset);
        offset += 1;
        data.writeBigUInt64LE(device64, offset);
        offset += 8;
        context.tcVerifyKeyHash.copy(data, offset);

        const macHeader = { frameControl: {}, source16: device16, source64: device64 } as MACHeader;
        const nwkHeader = { frameControl: {}, source16: device16, source64: device64 } as ZigbeeNWKHeader;
        const apsHeader = { frameControl: {} } as ZigbeeAPSHeader;

        const sendSpy = vi.spyOn(apsHandler, "sendConfirmKey").mockResolvedValue(true);

        try {
            await apsHandler.processVerifyKey(data, 0, macHeader, nwkHeader, apsHeader);

            expect(sendSpy).toHaveBeenCalledTimes(1);

            return sendSpy.mock.calls[0][1];
        } finally {
            sendSpy.mockRestore();
        }
    };

    it("accepts a factory-reset device's well-known-key proof after a previous incarnation held a unique key", async () => {
        const device64 = 0x00124b00ffee0404n;

        context.trustCenterPolicies.issueUniqueTCLinkKeys = true;

        // The unique key issued to the PREVIOUS incarnation of this IEEE.
        context.setAppLinkKey(device64, netParams.eui64, Buffer.from("0f0e0d0c0b0a09080706050403020100", "hex"));

        expect(context.getAppLinkKey(device64, netParams.eui64)).toBeDefined();

        // The device is factory reset, and joins anew: an unsecured INITIAL
        // join, not a rejoin.
        context.allowJoins(60, true);

        const [status, assigned16] = await context.associate(undefined, device64, true, capabilities, true);

        expect(status).toStrictEqual(MACAssociationStatus.SUCCESS);

        // 0x00 SUCCESS -- the stale entry is gone, so the correct well-known
        // proof is compared against the well-known key.
        // 0xad SECURITY_FAILURE is the defect: the correct proof compared
        // against the stale unique key.
        expect(await verifyAsFactoryResetDevice(assigned16, device64)).toStrictEqual(0x00);
    });

    it("accepts the proof when the previous incarnation is still recorded as authorized", async () => {
        const device64 = 0x00124b00ffee0606n;
        const previous16 = 0x2468;

        context.trustCenterPolicies.issueUniqueTCLinkKeys = true;

        // The device left without the trust centre hearing it: its entry is
        // still there, authorized, the network key marked as delivered, and
        // its unique key kept.
        context.deviceTable.set(device64, {
            address16: previous16,
            capabilities,
            authorized: true,
            neighbor: true,
            lastTransportedNetworkKeySeq: netParams.networkKeySequenceNumber,
            recentLQAs: [],
            incomingNWKFrameCounter: undefined,
            endDeviceTimeout: undefined,
            linkStatusMisses: 0,
        });
        context.address16ToAddress64.set(previous16, device64);
        context.setAppLinkKey(device64, netParams.eui64, Buffer.from("0f0e0d0c0b0a09080706050403020100", "hex"));

        // Factory reset, it associates with the coordinator as its parent.
        context.allowJoins(60, true);

        const macHeader = { frameControl: {}, source64: device64 } as MACHeader;

        await macHandler.processAssocReq(Buffer.from([0x8e]), 0, macHeader);

        // 0xad SECURITY_FAILURE is the defect: the association was taken for a
        // rejoin, so the stale unique key survived it.
        expect(await verifyAsFactoryResetDevice(previous16, device64)).toStrictEqual(0x00);

        const device = context.deviceTable.get(device64)!;

        expect(device.address16).toStrictEqual(previous16);
        expect(device.authorized).toStrictEqual(false);
    });

    it("still accepts the proof when no previous key was ever issued", async () => {
        const device64 = 0x00124b00ffee0505n;

        context.trustCenterPolicies.issueUniqueTCLinkKeys = true;
        context.allowJoins(60, true);

        const [status, assigned16] = await context.associate(undefined, device64, true, capabilities, true);

        expect(status).toStrictEqual(MACAssociationStatus.SUCCESS);
        // Control: this passes on both trees. It is what proves the test above
        // isolates the stale entry and nothing else about the join.
        expect(await verifyAsFactoryResetDevice(assigned16, device64)).toStrictEqual(0x00);
    });
});
