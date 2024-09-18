import {
	App,
	Editor,
	MarkdownView,
	Notice,
	Plugin,
	PluginSettingTab,
	Setting,
	TFile,
	TFolder,
	Vault,
} from "obsidian";
import { spawn, spawnSync } from "child_process";
import { createInterface } from "readline";
import * as crypto from "crypto";
import * as net from "net";

interface IvrePluginSettings {
	use_data: boolean;
	use_subdomains: boolean;
	db_url_data: string;
	db_url_view: string;
	base_directory: string;
}

interface IvreHostname {
	name: string;
	type: string;
	domains: string[];
}

interface IvreCertificateSubject {
	[field: string]: string;
}

interface IvreCertificate {
	md5?: string;
	sha1?: string;
	sha256?: string;
	subject_text: string;
	subject: IvreCertificateSubject;
	issuer_text: string;
	issuer: IvreCertificateSubject;
	self_signed: boolean;
	not_before: string;
	not_after: string;
	pubkey: IvrePubkey;
}

interface IvreJa3 {
	md5: string;
	sha1?: string;
	sha256?: string;
	raw?: string;
}

interface IvreJa3Server extends IvreJa3 {
	client?: IvreJa3;
}

interface IvrePubkey {
	md5?: string;
	sha1?: string;
	sha256?: string;
	type: string;
	bits?: number;
	exponent?: number;
	modulus?: string;
	raw: string;
}

interface IvreSshPubkey {
	fingerprint?: string;
	key: string;
	type: string;
	bits?: number;
}

interface IvreScript {
	// @ts-ignore
	id: string;
	// @ts-ignore
	output: string;
	// @ts-ignore
	"ssl-cert"?: IvreCertificate[];
	// @ts-ignore
	"ssl-ja3-client"?: IvreJa3[];
	// @ts-ignore
	"ssl-ja3-server"?: IvreJa3Server[];
	// @ts-ignore
	"http-user-agent"?: string[];
	// @ts-ignore
	"ssh-hostkey"?: IvreSshPubkey[];
	[structured: string]: JSON;
}

interface IvrePort {
	port: number;
	protocol: string;
	scripts: IvreScript[];
	state_state: string;
	service_name?: string;
	service_product?: string;
	service_version?: string;
	service_extrainfo?: string;
	screenshot?: string;
	screendata?: string;
}

interface IvreTag {
	value: string;
	type: string;
	info: string[];
}

interface IvreIpInfo {
	as_num?: number;
	as_name?: string;
	continent_code?: string;
	continent_name?: string;
	country_code?: string;
	country_name?: string;
	registered_country_code?: string;
	registered_country_name?: string;
	region_code?: string[];
	region_name?: string[];
	postal_code?: string;
	city?: string;
	coordinates?: [number, number];
	coordinates_accuracy_radius?: number;
}

interface IvreHost {
	addr: string;
	addresses: {
		mac: string[];
	};
	infos?: IvreIpInfo;
	categories: string[];
	tags: IvreTag[];
	hostnames: IvreHostname[];
	ports: IvrePort[];
}

interface IvreViewEntry {
	address: string;
	filename: string;
}

const DEFAULT_SETTINGS: IvrePluginSettings = {
	use_data: true,
	use_subdomains: true,
	db_url_data: "",
	db_url_view: "",
	base_directory: "IVRE",
};

enum ElementType {
	IpAddress,
	IpNetwork,
	HostName,
	MacAddress,
	AsNum,

	IvreLink,
	Unknown,
}

const MAC_ADDRESS =
	/^[0-9a-f]{1,2}:[0-9a-f]{1,2}:[0-9a-f]{1,2}:[0-9a-f]{1,2}:[0-9a-f]{1,2}:[0-9a-f]{1,2}$/i;

const AS_NUM = /^AS-?[0-9]+/;

function ivre_guess_type(element: string, base_directory: string): ElementType {
	if (net.isIP(element)) {
		return ElementType.IpAddress;
	}
	if (/[^/]+\/\d+$/.test(element)) {
		const [addr, mask] = element.split("/", 2);
		const mask_n = parseInt(mask);
		if (0 <= mask_n) {
			if (net.isIPv4(addr) && mask_n <= 32) {
				return ElementType.IpNetwork;
			}
			if (net.isIPv6(addr) && mask_n <= 128) {
				return ElementType.IpNetwork;
			}
		}
	}
	if (isValidHostname(element)) {
		return ElementType.HostName;
	}
	if (MAC_ADDRESS.test(element)) {
		return ElementType.MacAddress;
	}
	if (AS_NUM.test(element)) {
		return ElementType.AsNum;
	}
	const ivre_link = new RegExp(
		`^\\[\\[${base_directory}/(IP|AS|Network|Hostname|MAC)/[^|\\]]+\\|[^\\]]+\\]\\]$`,
	);
	if (ivre_link.test(element)) {
		return ElementType.IvreLink;
	}
	return ElementType.Unknown;
}

function create_folder(vault: Vault, folder: string) {
	vault.createFolder(folder).catch((e) => {
		/* continue regardless of File already exists error */
		if (e.message !== "Folder already exists.") {
			throw e;
		}
	});
}
function create_note(vault: Vault, fname: string, content: string) {
	vault.create(fname, content).catch((e) => {
		if (e.message === "File already exists.") {
			// file already exists
			const file = vault.getAbstractFileByPath(fname);
			if (!(file instanceof TFile)) {
				console.log(`[IVRE] Cannot recreate ${fname}`);
			} else {
				vault.modify(file, content);
			}
		} else {
			throw e;
		}
	});
}
function flag_emoji(country_code: string): string {
	return country_code
		.toUpperCase()
		.replace(/[A-Z]/g, (char) =>
			String.fromCodePoint(127397 + char.charCodeAt(0)),
		);
}
function tag_type(tag: IvreTag): string {
	switch (tag.type) {
		case "info":
		case "warning":
		case "danger": {
			return tag.type.toUpperCase();
		}
		default: {
			return "EXAMPLE";
		}
	}
}

// adapted from https://stackoverflow.com/a/2532344
const ALLOWED_HOSTNAME_LABEL = /^(?!-)[a-z\d-]{1,63}(?<!-)$/i;
function isValidHostname(value: string): boolean {
	if (value.endsWith(".")) {
		value = value.slice(0, -1);
	}
	if (value.length > 253) {
		return false;
	}
	if (value.indexOf(".") === -1) {
		return false;
	}
	return value.split(".").every(function (label) {
		return label && ALLOWED_HOSTNAME_LABEL.test(label);
	});
}

function ivre_create_as(
	num: number,
	name: string,
	vault: Vault,
	base_directory: string,
) {
	const base = `${base_directory}/AS`;
	create_folder(vault, base);
	const fname = `${base}/AS${num}.md`;
	create_note(vault, fname, `AS${num} - ${name}\n`);
}
function ivre_create_country(
	code: string,
	name: string,
	vault: Vault,
	base_directory: string,
) {
	const base = `${base_directory}/Country`;
	create_folder(vault, base);
	const fname = `${base}/${code}.md`;
	create_note(vault, fname, `${flag_emoji(code)} - ${code} - ${name}\n`);
}
function ivre_create_category(
	category: string,
	vault: Vault,
	base_directory: string,
) {
	const base = `${base_directory}/Category`;
	create_folder(vault, base);
	const fname = `${base}/${category}.md`;
	create_note(vault, fname, `Category ${category}\n`);
}
function ivre_create_mac(mac: string, vault: Vault, base_directory: string) {
	const base = `${base_directory}/MAC`;
	create_folder(vault, base);
	const fname = `${base}/${mac.toLowerCase().replace(/:/g, "")}.md`;
	const ivre_macdata = spawnSync("ivre", ["macdata", "--json", mac]);
	let content = `MAC ${mac.toLowerCase()}\n`;
	const data = JSON.parse(ivre_macdata.stdout.toString());
	if ("manufacturer_code" in data) {
		content += `- Manufacturer code: ${data.manufacturer_code}\n`;
	}
	if ("manufacturer_name" in data) {
		content += `- Manufacturer name: ${data.manufacturer_name}\n`;
	}
	create_note(vault, fname, content);
}
function ivre_create_hostname(
	name: string,
	vault: Vault,
	base_directory: string,
) {
	const base = `${base_directory}/Hostname`;
	create_folder(vault, base);
	const fname = `${base}/${name}.md`;
	let answer = `- Hostname ${name}\n`;
	const dot_index = name.indexOf(".");
	if (dot_index > -1) {
		const parent = name.slice(dot_index + 1);
		ivre_create_hostname(parent, vault, base_directory);
		answer += `- Parent: [[${base_directory}/Hostname/${parent}|${parent}]]\n`;
	}
	create_note(vault, fname, answer);
}
function ivre_create_hash(hash: string, vault: Vault, base_directory: string) {
	const base = `${base_directory}/Hash`;
	create_folder(vault, base);
	const fname = `${base}/${hash}.md`;
	create_note(vault, fname, `${hash}`);
}
function ivre_create_pubkey(
	pubkey: IvrePubkey,
	vault: Vault,
	base_directory: string,
) {
	const base = `${base_directory}/Pubkey`;
	create_folder(vault, base);
	const fname = `${base}/${pubkey.sha256}.md`;
	let answer = "Public key\n";
	answer += "\n# Information #\n";
	answer += `- Type: ${pubkey.type}\n`;
	answer += `- Key: ${pubkey.raw}\n`;
	if (pubkey.bits) {
		answer += `- Bits: ${pubkey.bits}\n`;
	}
	if (pubkey.exponent) {
		answer += `- Exponent: ${pubkey.exponent}\n`;
	}
	if (pubkey.modulus) {
		answer += `- Modulus: ${pubkey.modulus}\n`;
	}
	answer += "\n# Hashes #\n";
	for (const hashtype of ["md5", "sha1", "sha256"]) {
		const hash_value = pubkey[hashtype];
		ivre_create_hash(hash_value, vault, base_directory);
		answer += `- ${hashtype.toUpperCase()}: [[${base_directory}/Hash/${hash_value}.md|${hash_value}]]\n`;
	}
	create_note(vault, fname, answer);
}
function ivre_create_pubkey_ssh(
	pubkey: IvreSshPubkey,
	vault: Vault,
	base_directory: string,
) {
	const raw = Buffer.from(pubkey.key, "base64");
	const sha256 = crypto.createHash("sha256").update(raw).digest("hex");
	ivre_create_pubkey(
		{
			type: pubkey.type.startsWith("ssh-")
				? pubkey.type.substring(4)
				: pubkey.type,
			raw: pubkey.key,
			md5: crypto.createHash("md5").update(raw).digest("hex"),
			sha1: crypto.createHash("sha1").update(raw).digest("hex"),
			sha256: sha256,
			bits: pubkey.bits,
		},
		vault,
		base_directory,
	);
	return sha256;
}
function ivre_create_certificate(
	cert: IvreCertificate,
	vault: Vault,
	base_directory: string,
) {
	const base = `${base_directory}/Certificate`;
	create_folder(vault, base);
	const fname = `${base}/${cert.sha256}.md`;
	let answer = "Certificate\n";
	answer += "\n# Subject & Issuer #\n";
	answer += `- Subject: ${cert.subject_text}`;
	answer += `- Issuer: ${cert.issuer_text}`;
	answer += "\n# Hashes #\n";
	for (const hashtype of ["md5", "sha1", "sha256"]) {
		const hash_value = cert[hashtype];
		ivre_create_hash(hash_value, vault, base_directory);
		answer += `- ${hashtype.toUpperCase()}: [[${base_directory}/Hash/${hash_value}.md|${hash_value}]]\n`;
	}
	if (cert.pubkey) {
		ivre_create_pubkey(cert.pubkey, vault, base_directory);
		answer += `- Public key: [[${base_directory}/Pubkey/${cert.pubkey.sha256}.md|${cert.pubkey.sha256}]]\n`;
	}
	create_note(vault, fname, answer);
}
function ivre_create_ja3(ja3: IvreJa3, vault: Vault, base_directory: string) {
	const base = `${base_directory}/JA3`;
	create_folder(vault, base);
	const fname = `${base}/${ja3.md5}.md`;
	let answer = "JA3\n";
	answer += "\n# Raw value #\n";
	answer += `\`\`\`\n${ja3.raw}\n\`\`\`\n`;
	answer += "\n# Hashes #\n";
	for (const hashtype of ["md5", "sha1", "sha256"]) {
		if (ja3[hashtype]) {
			const hash_value = ja3[hashtype];
			ivre_create_hash(hash_value, vault, base_directory);
			answer += `- ${hashtype.toUpperCase()}: [[${base_directory}/Hash/${hash_value}.md|${hash_value}]]\n`;
		}
	}
	create_note(vault, fname, answer);
}
function ivre_handle_address(
	address: string,
	vault: Vault,
	settings: IvrePluginSettings,
): string {
	const inst = new IvreSearchView();
	inst.process_ipaddress(address, vault, settings, undefined, (code) => {
		if (code === 0) {
			new Notice(`🍸 ✅ IP address ${address} processed!`);
		}
	});
	return `${settings.base_directory}/IP/${address.replace(/:/g, "_")}.md`;
}
function ivre_handle_hostname(
	hostname: string,
	vault: Vault,
	settings: IvrePluginSettings,
): string {
	const inst = new IvreSearchView();
	hostname = hostname.toLowerCase().replace(/\.$/, "");
	inst.process_hostname(hostname, vault, settings, undefined, (code) => {
		if (code === 0) {
			new Notice(`🍸 ✅ hostname ${hostname} processed!`);
		}
	});
	return `${settings.base_directory}/Hostname/${hostname}.md`;
}
function ivre_handle_network(
	network: string,
	vault: Vault,
	settings: IvrePluginSettings,
): string {
	const inst = new IvreSearchView();
	const results: IvreViewEntry[] = [];
	const base = `${settings.base_directory}/Network`;
	const fname = `${base}/${network.replace(/[/:]/g, "_")}.md`;
	inst.process_network(
		network,
		vault,
		settings,
		(result) => {
			results.push(result);
		},
		(code) => {
			create_folder(vault, base);
			const addr_list = results
				.map(
					(result) =>
						`- [[${result.filename.replace(/\.md$/, "")}|${result.address}]]`,
				)
				.join("\n");
			create_note(vault, fname, `Network: ${network}\n${addr_list}\n`);
			if (code === 0) {
				new Notice(`🍸 ✅ network ${network} processed!`);
			}
		},
	);
	return fname;
}
function ivre_handle_asnum(
	as_num: number,
	vault: Vault,
	settings: IvrePluginSettings,
): string | undefined {
	const inst = new IvreSearchView();
	inst.process_asnum(as_num, vault, settings, undefined, (code) => {
		if (code === 0) {
			new Notice(`🍸 ✅ AS AS${as_num} processed!`);
		}
	});
	return `${settings.base_directory}/AS/AS${as_num}.md`;
}
function ivre_handle_mac(
	mac: string,
	vault: Vault,
	settings: IvrePluginSettings,
): string {
	const inst = new IvreSearchView();
	mac = mac.toLowerCase();
	inst.process_mac(mac, vault, settings, undefined, (code) => {
		if (code === 0) {
			new Notice(`🍸 ✅ MAC address ${mac} processed!`);
		}
	});
	return `${settings.base_directory}/MAC/${mac.replace(/:/g, "")}.md`;
}
function ivre_refresh_data(vault: Vault, settings: IvrePluginSettings) {
	const base = vault.getAbstractFileByPath(settings.base_directory);
	if (!(base instanceof TFolder)) {
		new Notice(`🍸 ⚠️ Base [${base}] is not a folder`);
		return;
	}
	const sub_dirs = Object.fromEntries(base.children.map((x) => [x.name, x]));
	if (sub_dirs.IP instanceof TFolder) {
		for (const subf of sub_dirs.IP.children) {
			if (subf instanceof TFile) {
				ivre_handle_address(
					subf.basename
						.replace(/_([0-9]+)$/, "/$1")
						.replace(/_/g, ":"),
					vault,
					settings,
				);
			}
		}
	}
}

class IvreSearch {}

class IvreSearchView extends IvreSearch {
	process_line(
		line: string,
		vault: Vault,
		settings: IvrePluginSettings,
	): IvreViewEntry | undefined {
		if (!line) {
			return;
		}
		const data: IvreHost = JSON.parse(line);
		if (!data) {
			return;
		}
		let answer = "";
		let tmp_answer = "";
		let info: IvreIpInfo | undefined;
		if ((info = data.infos)) {
			if (info.as_num) {
				ivre_create_as(
					info.as_num,
					info.as_name || "-",
					vault,
					settings.base_directory,
				);
				tmp_answer += `> ## Autonomous System ##\n> [[${
					settings.base_directory
				}/AS/AS${info.as_num}|AS${info.as_num} - ${
					info.as_name || "-"
				}]]\n`;
			}
			if (info.country_code) {
				ivre_create_country(
					info.country_code,
					info.country_name || "-",
					vault,
					settings.base_directory,
				);
				tmp_answer += `> ## Geography ##\n> Country: [[${
					settings.base_directory
				}/Country/${info.country_code}|${flag_emoji(info.country_code)} - ${
					info.country_code
				} - ${info.country_name || "-"}]]\n`;
				(info.region_code || []).forEach(
					(code: string, index: number) => {
						tmp_answer += `> Region: ${code} - ${
							(info.region_name || [])[index] || "-"
						}\n`;
					},
				);
			}
			if (info.city) {
				tmp_answer += `> City: ${info.city} - ${info.postal_code || "-"}\n`;
			}
			if (tmp_answer) {
				answer += `> [!ABSTRACT]- IP Data\n${tmp_answer}\n`;
			}
		}
		tmp_answer = "";
		(data.tags || []).forEach((tag: IvreTag) => {
			tmp_answer += `> [!${tag_type(tag)}]- ${
				tag.value
			}\n> #${tag.value.replace(/ /g, "_")}\n> ${tag.info.join(
				"\n> ",
			)}\n\n`;
		});
		if (tmp_answer) {
			answer += tmp_answer;
		}
		tmp_answer = "";
		(data.categories || []).forEach((category: string) => {
			tmp_answer += `- [[${settings.base_directory}/Category/${category}|${category}]]\n`;
			ivre_create_category(category, vault, settings.base_directory);
		});
		if (tmp_answer) {
			answer += `\n# Categories #\n${tmp_answer}`;
		}
		tmp_answer = "";
		((data.addresses || {}).mac || []).forEach((addr: string) => {
			ivre_create_mac(addr, vault, settings.base_directory);
			tmp_answer += `- [[${settings.base_directory}/MAC/${addr
				.toLowerCase()
				.replace(/:/g, "")}|${addr}]]\n`;
		});
		if (tmp_answer) {
			answer += `\n# MAC addresses #\n${tmp_answer}`;
		}
		tmp_answer = "";
		(data.hostnames || []).forEach((hname: IvreHostname) => {
			tmp_answer += `- [[${settings.base_directory}/Hostname/${hname.name}|${hname.name}]] (${hname.type})\n`;
			ivre_create_hostname(hname.name, vault, settings.base_directory);
		});
		if (tmp_answer) {
			answer += `\n# Hostnames #\n${tmp_answer}`;
		}
		tmp_answer = "";
		let tmp_answer_host = "";
		(data.ports || []).forEach((port: IvrePort) => {
			if (port.port === -1) {
				(port.scripts || []).forEach((script: IvreScript) => {
					if (
						script.id == "ssl-ja3-client" &&
						script["ssl-ja3-client"] &&
						script["ssl-ja3-client"].length
					) {
						tmp_answer_host += "\n## JA3 Client fingerprints ##\n";
						script["ssl-ja3-client"].forEach((ja3: IvreJa3) => {
							if (ja3.raw) {
								ivre_create_ja3(
									ja3,
									vault,
									settings.base_directory,
								);
							} else {
								// TODO: test if JA3 exists
								ivre_create_hash(
									ja3.md5,
									vault,
									settings.base_directory,
								);
							}
							tmp_answer_host += `- [[${settings.base_directory}/JA3/${ja3.md5}.md|${ja3.md5}]]\n`;
						});
					}
					if (
						script.id == "http-user-agent" &&
						script["http-user-agent"] &&
						script["http-user-agent"].length
					) {
						tmp_answer_host += "\n## HTTP User-Agents ##\n";
						script["http-user-agent"].forEach(
							(useragent: string) => {
								tmp_answer_host += `- \`${useragent}\`\n`;
							},
						);
					}
				});
				return;
			}
			tmp_answer += `\n## ${port.protocol}/${port.port} ##\n`;
			tmp_answer += `- ${
				port.state_state.startsWith("open") ? "✅" : "❌"
			} Status: ${port.state_state}\n`;
			if (port.service_name) {
				tmp_answer += `- Service: ${port.service_name}`;
				if (port.service_product) {
					tmp_answer += ` ${port.service_product}`;
					if (port.service_version) {
						tmp_answer += ` ${port.service_version}`;
					}
				}
				if (port.service_extrainfo) {
					tmp_answer += ` (${port.service_extrainfo})`;
				}
				tmp_answer += "\n";
			}
			(port.scripts || []).forEach((script: IvreScript) => {
				if (script.id == "ssl-cert" || script.id == "ssl-cacert") {
					(script["ssl-cert"] || []).forEach(
						(cert: IvreCertificate) => {
							tmp_answer += `- ${
								script["id"] == "ssl-cacert"
									? "CA"
									: "Certificate"
							} [[${settings.base_directory}/Certificate/${
								cert.sha256
							}|${cert.subject_text}]]\n`;
							ivre_create_certificate(
								cert,
								vault,
								settings.base_directory,
							);
						},
					);
				} else if (
					script.id == "ssl-ja3-server" &&
					script["ssl-ja3-server"] &&
					script["ssl-ja3-server"].length
				) {
					tmp_answer += "\n### JA3 Server fingerprints ###\n";
					script["ssl-ja3-server"].forEach((ja3: IvreJa3Server) => {
						if (ja3.raw) {
							ivre_create_ja3(
								ja3,
								vault,
								settings.base_directory,
							);
						} else {
							// TODO: test if JA3 exists
							ivre_create_hash(
								ja3.md5,
								vault,
								settings.base_directory,
							);
						}
						if (ja3.client) {
							if (ja3.client.raw) {
								ivre_create_ja3(
									ja3.client,
									vault,
									settings.base_directory,
								);
							} else {
								// TODO: test if JA3 exists
								ivre_create_hash(
									ja3.client.md5,
									vault,
									settings.base_directory,
								);
							}
							tmp_answer += `- [[${settings.base_directory}/JA3/${ja3.md5}.md|${ja3.md5}]] - [[${settings.base_directory}/JA3/${ja3.client.md5}.md|${ja3.client.md5}]]\n`;
						} else {
							tmp_answer += `- [[${settings.base_directory}/JA3/${ja3.md5}.md|${ja3.md5}]]\n`;
						}
					});
				} else if (
					script.id == "ssh-hostkey" &&
					script["ssh-hostkey"] &&
					script["ssh-hostkey"].length
				) {
					tmp_answer += "\n### SSH Host keys ###\n";
					script["ssh-hostkey"].forEach((key: IvreSshPubkey) => {
						const sha256 = ivre_create_pubkey_ssh(
							key,
							vault,
							settings.base_directory,
						);
						tmp_answer += `- [[${settings.base_directory}/Pubkey/${sha256}.md|${sha256}]]\n`;
					});
				}
			});
			if (port.screenshot === "field" && port.screendata) {
				tmp_answer += `\n![](data:image/png;base64,${port.screendata})\n`;
			}
			tmp_answer += "\n";
		});
		if (tmp_answer) {
			answer += `\n# Ports #\n${tmp_answer.substring(
				0,
				tmp_answer.length - 1,
			)}`;
		}
		if (tmp_answer_host) {
			answer += `\n# Host details #\n${tmp_answer_host.substring(
				0,
				tmp_answer_host.length - 1,
			)}`;
		}
		if (data.addr && answer) {
			const base = `${settings.base_directory}/IP`;
			create_folder(vault, base);
			const fname = `${base}/${data.addr.replace(/:/g, "_")}.md`;
			create_note(vault, fname, answer);
			return { address: data.addr, filename: fname };
		}
	}
	exec_and_process(
		options: string[],
		vault: Vault,
		settings: IvrePluginSettings,
		on_result?: ((entry: IvreViewEntry) => void) | undefined,
		on_close?: ((code: number | null) => void) | undefined,
	): void {
		const ivre_view = spawn("ivre", options);
		const ivre_view_lines = createInterface(ivre_view.stdout);
		ivre_view_lines.on("line", (line) => {
			const result = this.process_line(line, vault, settings);
			if (on_result && result) {
				on_result(result);
			}
		});
		ivre_view.on("close", function (code) {
			if (code) {
				new Notice(
					`🍸 ⚠️ Command ivre [${options}] failed with code ${code}`,
				);
			} else {
				console.log(`IVRE: Command ivre [${options}] succeeded!`);
			}
			if (on_close) {
				on_close(code);
			}
		});
	}
	process_ipaddress(
		address: string,
		vault: Vault,
		settings: IvrePluginSettings,
		on_result?: ((entry: IvreViewEntry) => void) | undefined,
		on_close?: ((code: number | null) => void) | undefined,
	): void {
		const options = ["view", "--json", "--limit", "1"];
		if (settings.db_url_view) {
			options.push("--from-db", settings.db_url_view);
		}
		options.push(address);
		this.exec_and_process(options, vault, settings, on_result, on_close);
	}
	process_hostname(
		hostname: string,
		vault: Vault,
		settings: IvrePluginSettings,
		on_result?: ((entry: IvreViewEntry) => void) | undefined,
		on_close?: ((code: number | null) => void) | undefined,
	): void {
		const options = ["view", "--json"];
		if (settings.db_url_view) {
			options.push("--from-db", settings.db_url_view);
		}
		options.push(
			settings.use_subdomains ? "--domain" : "--hostname",
			hostname,
		);
		this.exec_and_process(options, vault, settings, on_result, on_close);
	}
	process_network(
		network: string,
		vault: Vault,
		settings: IvrePluginSettings,
		on_result?: ((entry: IvreViewEntry) => void) | undefined,
		on_close?: ((code: number | null) => void) | undefined,
	): void {
		const options = ["view", "--json"];
		if (settings.db_url_view) {
			options.push("--from-db", settings.db_url_view);
		}
		options.push(network);
		this.exec_and_process(options, vault, settings, on_result, on_close);
	}
	process_asnum(
		as_num: number,
		vault: Vault,
		settings: IvrePluginSettings,
		on_result?: ((entry: IvreViewEntry) => void) | undefined,
		on_close?: ((code: number | null) => void) | undefined,
	): void {
		const options = ["view", "--json", "--asnum", as_num.toString()];
		if (settings.db_url_view) {
			options.push("--from-db", settings.db_url_view);
		}
		this.exec_and_process(options, vault, settings, on_result, on_close);
	}
	process_mac(
		mac: string,
		vault: Vault,
		settings: IvrePluginSettings,
		on_result?: ((entry: IvreViewEntry) => void) | undefined,
		on_close?: ((code: number | null) => void) | undefined,
	): void {
		const options = ["view", "--json"];
		if (settings.db_url_view) {
			options.push("--from-db", settings.db_url_view);
		}
		options.push("--mac", mac);
		this.exec_and_process(options, vault, settings, on_result, on_close);
	}
}

function ivre_analyze_selection(
	settings: IvrePluginSettings,
	editor: Editor,
	vault: Vault,
	active_file: TFile | null,
) {
	const links: { element: string; link: string }[] = [];
	let content_data = editor.getSelection();
	content_data.split(/\s+/).forEach((element) => {
		switch (ivre_guess_type(element, settings.base_directory)) {
			case ElementType.IpAddress: {
				new Notice(`🍸 Processing IP address: ${element}`);
				const fname = ivre_handle_address(element, vault, settings);
				if (fname) {
					links.push({ element: element, link: fname.slice(0, -3) });
				}
				break;
			}
			case ElementType.IpNetwork: {
				new Notice(`🍸 Processing network: ${element}`);
				const fname = ivre_handle_network(element, vault, settings);
				if (fname) {
					links.push({ element: element, link: fname.slice(0, -3) });
				}
				break;
			}
			case ElementType.AsNum: {
				new Notice(`🍸 Processing AS: ${element}`);
				const fname = ivre_handle_asnum(
					parseInt(element.slice(2)),
					vault,
					settings,
				);
				if (fname) {
					links.push({ element: element, link: fname.slice(0, -3) });
				}
				break;
			}
			case ElementType.HostName: {
				new Notice(`🍸 Processing hostname: ${element}`);
				const fname = ivre_handle_hostname(element, vault, settings);
				if (fname) {
					links.push({ element: element, link: fname.slice(0, -3) });
				}
				break;
			}
			case ElementType.MacAddress: {
				new Notice(`🍸 Processing MAC address: ${element}`);
				const fname = ivre_handle_mac(element, vault, settings);
				if (fname) {
					links.push({ element: element, link: fname.slice(0, -3) });
				}
				break;
			}
			case ElementType.IvreLink: {
				// This is already an IVRE link; just process the element again
				// without adding it to `links`
				const data = element.match(/\[\[[^|]+\|([^\]]+)\]\]/);
				if (data !== null) {
					switch (ivre_guess_type(data[1], settings.base_directory)) {
						case ElementType.IpAddress: {
							new Notice(`🍸 Processing IP address: ${data[1]}`);
							ivre_handle_address(data[1], vault, settings);
							break;
						}
						case ElementType.IpNetwork: {
							new Notice(`🍸 Processing network: ${data[1]}`);
							ivre_handle_network(data[1], vault, settings);
							break;
						}
						case ElementType.AsNum: {
							new Notice(`🍸 Processing AS: ${data[1]}`);
							ivre_handle_asnum(
								parseInt(data[1].slice(2)),
								vault,
								settings,
							);
							break;
						}
						case ElementType.HostName: {
							new Notice(`🍸 Processing hostname: ${data[1]}`);
							ivre_handle_hostname(data[1], vault, settings);
							break;
						}
						case ElementType.MacAddress: {
							new Notice(`🍸 Processing MAC address: ${data[1]}`);
							ivre_handle_mac(data[1], vault, settings);
							break;
						}
						default: {
							console.log(
								`[IVRE] Element in link ignored: ${data[1]}`,
							);
						}
					}
				}
				break;
			}
			default: {
				if (element) {
					console.log(`[IVRE] Element ignored: ${element}`);
				}
			}
		}
	});
	if (
		active_file &&
		!active_file.path.startsWith(settings.base_directory) &&
		links.length > 0
	) {
		links.forEach((replacement) => {
			const expr = new RegExp(
				`(\\s|^)${replacement.element.replace(
					/[.*+?^${}()|[\]\\]/g,
					"\\$&",
				)}(\\s|$)`,
				"g",
			);
			content_data = content_data.replace(
				expr,
				`$1[[${replacement.link}|${replacement.element}]]$2`,
			);
		});
		editor.replaceSelection(content_data);
	}
}

export default class IvrePlugin extends Plugin {
	settings: IvrePluginSettings;

	async onload() {
		await this.loadSettings();

		// This creates an icon in the left ribbon.
		const ribbonIconEl = this.addRibbonIcon(
			"martini",
			"IVRE: analyze selection",
			(evt: MouseEvent) => {
				// Called when the user clicks the icon.
				const view =
					this.app.workspace.getActiveViewOfType(MarkdownView);
				if (!view) {
					new Notice("🍸 ⚠️ Call me from a MarkdownView!");
				} else {
					const view_mode = view.getMode(); // "preview" or "source" (can also be "live" but I don't know when that happens)
					switch (view_mode) {
						case "preview":
							new Notice(
								"🍸 ⚠️ Call me from a MarkdownView in source mode!",
							);
							break;
						case "source":
							// Ensure that view.editor exists!
							if ("editor" in view) {
								// @ts-ignore We already know that view.editor exists.
								ivre_analyze_selection(
									this.settings,
									view.editor,
									this.app.vault,
									view.file,
								);
							} else {
								new Notice(
									"🍸 ⚠️ Cannot find .editor in current view!",
								);
							}
							break;
						default:
							new Notice(
								"🍸 ⚠️ Call me from a MarkdownView in source mode!",
							);
							break;
					}
				}
			},
		);
		// Perform additional things with the ribbon
		ribbonIconEl.addClass("my-plugin-ribbon-class");

		// Add IVRE version in a status bar item.
		const statusBarItemEl = this.addStatusBarItem();
		const ivre_version = spawn("ivre", ["--version"]);
		ivre_version.stdout.on("data", (data: Buffer) => {
			data.toString()
				.split(/\r?\n/)
				.forEach((line) => {
					if (line.startsWith("Version ")) {
						statusBarItemEl.setText(`🍸 IVRE v${line.slice(8)}`);
						return;
					}
				});
		});
		ivre_version.on("close", (code: number) => {
			if (code !== 0) {
				statusBarItemEl.setText(
					`🍸 ⚠️ IVRE --version exited with code ${code}`,
				);
			}
		});
		ivre_version.on("error", (err: number) => {
			statusBarItemEl.setText(
				`🍸 ⚠️ IVRE --version exited with error ${err}`,
			);
		});

		// This adds an editor command that can perform some operation on the current editor instance
		this.addCommand({
			id: "analyze-selection",
			name: "Analyze selection with IVRE",
			editorCallback: (editor: Editor, view: MarkdownView) => {
				ivre_analyze_selection(
					this.settings,
					editor,
					this.app.vault,
					view.file,
				);
			},
		});

		this.addCommand({
			id: "refresh-data",
			name: "Refresh IVRE data",
			callback: () => {
				ivre_refresh_data(this.app.vault, this.settings);
			},
		});

		// This adds a settings tab so the user can configure various aspects of the plugin
		this.addSettingTab(new IvreSettingTab(this.app, this));
	}

	onunload() {}

	async loadSettings() {
		this.settings = Object.assign(
			{},
			DEFAULT_SETTINGS,
			await this.loadData(),
		);
	}

	async saveSettings() {
		await this.saveData(this.settings);
	}
}

class IvreSettingTab extends PluginSettingTab {
	plugin: IvrePlugin;

	constructor(app: App, plugin: IvrePlugin) {
		super(app, plugin);
		this.plugin = plugin;
	}

	display(): void {
		const { containerEl } = this;

		containerEl.empty();

		containerEl.createEl("h2", { text: "Settings for IVRE plugin." });

		new Setting(containerEl)
			.setName("Use data (Maxmind)")
			.setDesc('Enable the use of results from "ivre ipdata"')
			.addToggle((toggle) =>
				toggle
					.setValue(this.plugin.settings.use_data)
					.onChange(async (value) => {
						this.plugin.settings.use_data = value;
						await this.plugin.saveSettings();
					}),
			);
		new Setting(containerEl)
			.setName("Use subdomains")
			.setDesc("Include subdomains in domain enumerations.")
			.addToggle((toggle) =>
				toggle
					.setValue(this.plugin.settings.use_subdomains)
					.onChange(async (value) => {
						setting_url_view.setDisabled(!value);
						this.plugin.settings.use_subdomains = value;
						await this.plugin.saveSettings();
					}),
			);
		new Setting(containerEl)
			.setName("URL for data")
			.setDesc(
				"URL for IVRE database for data (Maxmind GeoIP). Leave empty to use the system default.",
			)
			.addText((text) =>
				text
					.setPlaceholder("maxmind:///usr/share/ivre/geoip")
					.setDisabled(!this.plugin.settings.use_data)
					.setValue(this.plugin.settings.db_url_data)
					.onChange(async (value) => {
						this.plugin.settings.db_url_data = value;
						await this.plugin.saveSettings();
					}),
			);
		const setting_url_view = new Setting(containerEl)
			.setName("URL for view")
			.setDesc(
				"URL for IVRE database for view (mixed from passive & scan). Leave empty to use the system default.",
			)
			.addText((text) =>
				text
					.setPlaceholder("mongodb://example/ivre")
					.setValue(this.plugin.settings.db_url_view)
					.onChange(async (value) => {
						this.plugin.settings.db_url_view = value;
						await this.plugin.saveSettings();
					}),
			);
		new Setting(containerEl)
			.setName("Base directory")
			.setDesc("Base directory for pages created by this plugin.")
			.addText((text) =>
				text
					.setPlaceholder("directory")
					.setValue(this.plugin.settings.base_directory)
					.onChange(async (value) => {
						this.plugin.settings.base_directory = value;
						await this.plugin.saveSettings();
					}),
			);
	}
}
