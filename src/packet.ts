import { AddressInfo } from "net";
import { DEFAULT_IP, DEFAULT_MAC } from "./const";
import { IpConverter, MacConverter } from "./converters";
import { BOOTMessageType, DHCPMessageType, DHCPOptions } from "./enum";
import { Option } from "./option";
import * as Options from "./option";

/**
 * 0                   1                   2                   3
 * 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
 * +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 * |     op (1)    |   htype (1)   |   hlen (1)    |   hops (1)    |
 * +---------------+---------------+---------------+---------------+
 * |                            xid (4)                            |
 * +-------------------------------+-------------------------------+
 * |           secs (2)            |           flags (2)           |
 * +-------------------------------+-------------------------------+
 * |                          ciaddr  (4)                          |
 * +---------------------------------------------------------------+
 * |                          yiaddr  (4)                          |
 * +---------------------------------------------------------------+
 * |                          siaddr  (4)                          |
 * +---------------------------------------------------------------+
 * |                          giaddr  (4)                          |
 * +---------------------------------------------------------------+
 * |                                                               |
 * |                          chaddr  (16)                         |
 * |                                                               |
 * |                                                               |
 * +---------------------------------------------------------------+
 * |                                                               |
 * |                          sname   (64)                         |
 * +---------------------------------------------------------------+
 * |                                                               |
 * |                          file    (128)                        |
 * +---------------------------------------------------------------+
 * |                                                               |
 * |                          options (variable)                   |
 * +---------------------------------------------------------------+
 */

function stripBinNull(str: string) {
    const pos = str.indexOf("\u0000");
    let res = str;
    if (pos !== -1) {
        res = str.substr(0, pos);
    }
    return res;
}

export type PacketOptions = Array<Option<any>>;

export class Packet {

    /**
     * Creates new DHCP Packet from Buffer
     *
     * @static
     * @param {Buffer} buffer
     * @returns
     *
     * @memberOf Packet
     */
    public static fromBuffer(buffer: Buffer) {
        const packet = new Packet();
        packet.fromBuffer(buffer);
        return packet;
    }

    public op: BOOTMessageType = BOOTMessageType.request;
    public htype: number = 1;
    public hlen: number = 6;
    public hops: number = 0;
    public xid: number = 0;
    public secs: number = 0;
    public flags: number = 0;
    public ciaddr: string = DEFAULT_IP;
    public yiaddr: string = DEFAULT_IP;
    public siaddr: string = DEFAULT_IP;
    public giaddr: string = DEFAULT_IP;
    public chaddr: string = DEFAULT_MAC;
    public sname: string = "";
    public file: string = "";
    public options: PacketOptions = [];
    public reinfo?: AddressInfo;

    /**
     * Returns DHCPMessageType of DHCP packet
     *
     * @readonly
     * @type {number}
     * @memberOf Packet
     */
    get type(): number {
        let dhcpType: number = 0;
        this.options.some((option) => {
            if (option.type === DHCPOptions.DhcpMessageType) {
                dhcpType = option.value;
            }
            return !!dhcpType;
        });
        return dhcpType;
    }

    /**
     * Encodes DHCP packet to Buffer
     *
     * @returns {Buffer}
     *
     * @memberOf Packet
     */
    public toBuffer(): Buffer {
        const buffer = Buffer.alloc(576);
        buffer.fill(0);

        buffer[0] = this.op;
        buffer[1] = this.htype;
        buffer[2] = this.hlen;
        buffer[3] = this.hops;

        buffer.writeUIntBE(this.xid, 4, 4);

        buffer.writeUIntBE(this.secs, 8, 2);
        buffer.writeUIntBE(this.flags, 10, 2);

        buffer.write(IpConverter.encode(this.ciaddr).toString("binary"), 12, 16, "binary");
        buffer.write(IpConverter.encode(this.yiaddr).toString("binary"), 16, 20, "binary");
        buffer.write(IpConverter.encode(this.siaddr).toString("binary"), 20, 24, "binary");
        buffer.write(IpConverter.encode(this.giaddr).toString("binary"), 24, 28, "binary");

        const chaddr = MacConverter.encode(this.chaddr, this.hlen).toString("binary");
        buffer.write(chaddr, 28, chaddr.length, "binary");

        buffer.write(this.sname, 44, 64, "ascii");
        buffer.write(this.file, 108, 128, "ascii");

        // this.options.sort((a, b) => a.type > b.type ? 1 : a.type < b.type ? -1 : 0);
        const lastOption = this.options[this.options.length - 1];
        if (lastOption && lastOption.type !== DHCPOptions.End) {
            this.options.push(new Options.EndOption());
        }

        buffer.write(Buffer.from([99, 130, 83, 99]).toString("binary"), 236, 4, "binary"); // magic cookie RFC2132

        const options = this.options.map((option) => option.toBuffer());
        const raw = Buffer.concat(options).toString("binary");

        buffer.write(raw, 240, raw.length, "binary");

        return buffer.slice(0, 240 + raw.length);
    }

    /**
     * Decodes Buffer to DHCP Packet
     *
     * @param {Buffer} buffer
     *
     * @memberOf Packet
     */
    public fromBuffer(buffer: Buffer) {
        this.op = buffer[0];
        this.htype = buffer[1];
        this.hlen = buffer[2];
        this.hops = buffer[3];

        this.xid = buffer.readUIntBE(4, 4);

        this.secs = buffer.readUIntBE(8, 2);
        this.flags = buffer.readUIntBE(10, 2);

        this.ciaddr = IpConverter.decode(buffer.slice(12, 16));
        this.yiaddr = IpConverter.decode(buffer.slice(16, 20));
        this.siaddr = IpConverter.decode(buffer.slice(20, 24));
        this.giaddr = IpConverter.decode(buffer.slice(24, 28));

        this.chaddr = MacConverter.decode(buffer.slice(28, 28 + this.hlen));

        this.sname = stripBinNull(buffer.toString("ascii", 44, 108));
        this.file = stripBinNull(buffer.toString("ascii", 108, 236));

        const optionsBuffer = buffer.slice(240);
        let pos = 0;
        let loop = true;
        while (loop) {
            if (optionsBuffer[pos] === 255 || pos >= optionsBuffer.length) { // End
                this.options.push(new Options.EndOption());
                loop = false;
            } else {
                const tag = optionsBuffer[pos];
                const len = optionsBuffer[pos + 1];
                const data = optionsBuffer.slice(pos, pos + 2 + len);
                const OptionClass = Option.create(tag) as any;
                const option = OptionClass.fromBuffer(data);
                this.options.push(option);
                pos += len + 2;
            }
        }
    }

    /**
     * Converts DHCP Packet to String
     *
     * @returns
     *
     * @memberOf Packet
     */
    public toString() {

        const str: string[] = [];
        str.push(`DHCP: ${DHCPMessageType[this.type] || "UNKNOWN"}`);
        str.push(`=====================================`);
        str.push(`Message type (op): ${BOOTMessageType[this.op]}`);
        str.push(`Hardware address type (htype): ${this.htype}`);
        str.push(`hops: ${this.hops}`);
        str.push(`Transaction ID (xid): ${this.xid}`);
        str.push(`Seconds (secs): ${this.secs}`);
        str.push(`Flags: ${this.flags}`);
        str.push(`Client IP (ciaddr): ${this.ciaddr}`);
        str.push(`Your IP (yiaddr): ${this.yiaddr}`);
        str.push(`Server IP (siaddr): ${this.siaddr}`);
        str.push(`Relay agent IP (giaddr): ${this.giaddr}`);
        str.push(`Client hardware address (chaddr): ${this.chaddr}`);
        str.push(`Server host name (sname): ${this.sname}`);
        str.push(`Boot file name (file): ${this.file}`);
        str.push(`Options:`);

        this.options.map((option) => {
            let item = "UNKNOWN";
            const val = option.value;
            if (Buffer.isBuffer(val)) {
                item = val.toString("hex");
            } else if (Array.isArray(val)) {
                item = `[${val.join(", ")}]`;
                 } else if (typeof val === "object") {
                item = JSON.stringify(val);
                 } else {
                item = `${val}`;
                 }
            str.push(`  ${DHCPOptions[option.type]}(${option.type}): ${item}`);
        });

        return str.join("\n");
    }

    /**
     * Returns first DHCP Option matched to type
     * - if Option not found returns null
     *
     * @param {DHCPOptions} type
     * @returns
     *
     * @memberOf Packet
     */
    public find(type: DHCPOptions) {
        let res: Option<any> | null = null;
        const options = this.options.filter((o) => o.type === type);
        if (options.length) {
            res = options[0];
        }
        return res;
    }

}
