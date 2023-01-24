import {
	App,
	Editor,
	MarkdownView,
	Notice,
	Plugin,
	PluginSettingTab,
	Setting,
	TFile,
	Vault,
} from "obsidian";
import {
	isIPAddress,
	isIPV4Address,
	isIPV6Address,
} from "ip-address-validator";
import { spawn, spawnSync } from "child_process";

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

interface IvreScript {
	// @ts-ignore
	id: string;
	// @ts-ignore
	output: string;
	// @ts-ignore
	"ssl-cert"?: IvreCertificate[];

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
}

interface IvreTag {
	value: string;
	type: string;
	info: string[];
}

interface IvreHost {
	addr: string;
	addresses: {
		mac: string[];
	};
	categories: string[];
	tags: IvreTag[];
	hostnames: IvreHostname[];
	ports: IvrePort[];
}

interface IvreMarkdownResult {
	address: string;
	data: string;
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

	IvreLink,
	Unknown,
}

const MAC_ADDRESS =
	/^[0-9a-f]{1,2}:[0-9a-f]{1,2}:[0-9a-f]{1,2}:[0-9a-f]{1,2}:[0-9a-f]{1,2}:[0-9a-f]{1,2}$/i;

function ivre_guess_type(element: string, base_directory: string): ElementType {
	if (isIPAddress(element)) {
		return ElementType.IpAddress;
	}
	if (/[^/]+\/\d+$/.test(element)) {
		const [addr, mask] = element.split("/", 2);
		const mask_n = parseInt(mask);
		if (0 <= mask_n) {
			if (isIPV4Address(addr) && mask_n <= 32) {
				return ElementType.IpNetwork;
			}
			if (isIPV6Address(addr) && mask_n <= 128) {
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
	const ivre_link = new RegExp(
		`^\\[\\[${base_directory}/(IP|Network|Hostname|MAC)/[^|\\]]+\\|[^\\]]+\\]\\]$`
	);
	if (ivre_link.test(element)) {
		return ElementType.IvreLink;
	}
	return ElementType.Unknown;
}

function create_folder(vault: Vault, base: string) {
	try {
		vault.createFolder(base);
	} catch (e) {
		/* continue regardless of error */
	}
}
// https://dev.to/jorik/country-code-to-flag-emoji-a21
function flag_emoji(country_code: string): string {
	const codePoints = country_code
		.toUpperCase()
		.split("")
		.map((char) => 127397 + char.charCodeAt(0));
	return String.fromCodePoint(...codePoints);
}
function tag_emoji(tag: IvreTag): string | undefined {
	switch (tag.type) {
		case "info": {
			return "ℹ️";
		}
		case "warning": {
			return "⚠️";
		}
		case "danger": {
			return "🚨";
		}
		default: {
			return undefined;
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
	base_directory: string
) {
	const base = `${base_directory}/AS`;
	create_folder(vault, base);
	const fname = `${base}/AS${num}.md`;
	vault.create(fname, `AS${num} - ${name}\n`);
}
function ivre_create_country(
	code: string,
	name: string,
	vault: Vault,
	base_directory: string
) {
	const base = `${base_directory}/Country`;
	create_folder(vault, base);
	const fname = `${base}/${code}.md`;
	vault.create(fname, `${flag_emoji(code)} - ${code} - ${name}\n`);
}
function ivre_create_category(
	category: string,
	vault: Vault,
	base_directory: string
) {
	const base = `${base_directory}/Category`;
	create_folder(vault, base);
	const fname = `${base}/${category}.md`;
	vault.create(fname, `Category ${category}\n`);
}
function ivre_create_mac(mac: string, vault: Vault, base_directory: string) {
	const base = `${base_directory}/MAC`;
	create_folder(vault, base);
	const fname = `${base}/${mac.toLowerCase().replace(/:/g, "")}.md`;
	const ivre_ipdata = spawnSync("ivre", ["macdata", "--json", mac]);
	let content = `MAC ${mac.toLowerCase()}\n`;
	const data = JSON.parse(ivre_ipdata.stdout.toString());
	if ("manufacturer_code" in data) {
		content += `- Manufacturer code: ${data.manufacturer_code}\n`;
	}
	if ("manufacturer_name" in data) {
		content += `- Manufacturer name: ${data.manufacturer_name}\n`;
	}
	vault.create(fname, content);
}
function ivre_create_hostname(
	name: string,
	vault: Vault,
	base_directory: string
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
	vault.create(fname, answer);
}
function ivre_create_hash(hash: string, vault: Vault, base_directory: string) {
	const base = `${base_directory}/Hash`;
	create_folder(vault, base);
	const fname = `${base}/${hash}.md`;
	vault.create(fname, `${hash}`);
}
function ivre_create_pubkey(
	pubkey: IvrePubkey,
	vault: Vault,
	base_directory: string
) {
	const base = `${base_directory}/Pubkey`;
	create_folder(vault, base);
	const fname = `${base}/${pubkey.sha256}.md`;
	let answer = "Public key\n";
	answer += "\n# Information #\n";
	answer += `- Type: ${pubkey.type}\n`;
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
	vault.create(fname, answer);
}
function ivre_create_certificate(
	cert: IvreCertificate,
	vault: Vault,
	base_directory: string
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
	vault.create(fname, answer);
}
function ivre_handle_address(
	address: string,
	vault: Vault,
	settings: IvrePluginSettings
): string | undefined {
	const data = [];
	if (settings.use_data) {
		const inst = new IvreSearchData();
		const result = inst.process_ipaddress(address, vault, settings);
		if (result) {
			data.push(result);
		}
	}
	const inst = new IvreSearchView();
	const result = inst.process_ipaddress(address, vault, settings);
	if (result) {
		data.push(result);
	}
	if (data.length > 0) {
		const base = `${settings.base_directory}/IP`;
		create_folder(vault, base);
		const fname = `${base}/${address.replace(/:/g, "_")}.md`;
		vault.create(fname, data.join("\n"));
		return fname;
	}
	return undefined;
}
function ivre_handle_hostname(
	hostname: string,
	vault: Vault,
	settings: IvrePluginSettings
): string | undefined {
	const inst = new IvreSearchView();
	let one_answer = false;
	hostname = hostname.toLowerCase().replace(/\.$/, "");
	if (settings.use_data) {
		const inst_data = new IvreSearchData();
		for (const result of inst.process_hostname(hostname, vault, settings)) {
			const data = [];
			const data_result = inst_data.process_ipaddress(
				result.address,
				vault,
				settings
			);
			if (data_result) {
				data.push(data_result);
			}
			data.push(result.data);
			const base = `${settings.base_directory}/IP`;
			create_folder(vault, base);
			vault.create(
				`${base}/${result.address.replace(/:/g, "_")}.md`,
				data.join("\n")
			);
			one_answer = true;
		}
	} else {
		for (const result of inst.process_hostname(hostname, vault, settings)) {
			const base = `${settings.base_directory}/IP`;
			create_folder(vault, base);
			vault.create(
				`${base}/${result.address.replace(/:/g, "_")}.md`,
				result.data
			);
			one_answer = true;
		}
	}
	if (one_answer) {
		return `${settings.base_directory}/Hostname/${hostname}.md`;
	}
	return undefined;
}
function ivre_handle_network(
	network: string,
	vault: Vault,
	settings: IvrePluginSettings
): string | undefined {
	const inst = new IvreSearchView();
	const answers = [];
	if (settings.use_data) {
		const inst_data = new IvreSearchData();
		const data = [];
		for (const result of inst.process_network(network, vault, settings)) {
			const data_result = inst_data.process_ipaddress(
				result.address,
				vault,
				settings
			);
			if (data_result) {
				data.push(data_result);
			}
			data.push(result.data);
			const base = `${settings.base_directory}/IP`;
			create_folder(vault, base);
			vault.create(
				`${base}/${result.address.replace(/:/g, "_")}.md`,
				data.join("\n")
			);
			answers.push(result.address);
		}
	} else {
		for (const result of inst.process_network(network, vault, settings)) {
			const base = `${settings.base_directory}/IP`;
			create_folder(vault, base);
			vault.create(
				`${base}/${result.address.replace(/:/g, "_")}.md`,
				result.data
			);
			answers.push(result.address);
		}
	}
	if (answers.length > 0) {
		const base = `${settings.base_directory}/Network`;
		create_folder(vault, base);
		const fname = `${base}/${network.replace(/[/:]/g, "_")}.md`;
		const addr_list = answers
			.map((addr) => {
				return `- [[${settings.base_directory}/IP/${addr.replace(
					/:/g,
					"_"
				)}|${addr}]]`;
			})
			.join("\n");
		vault.create(fname, `Network: ${network}\n${addr_list}\n`);
		return fname;
	}
	return undefined;
}
function ivre_handle_mac(
	mac: string,
	vault: Vault,
	settings: IvrePluginSettings
): string | undefined {
	const inst = new IvreSearchView();
	let one_answer = false;
	mac = mac.toLowerCase();
	if (settings.use_data) {
		const inst_data = new IvreSearchData();
		for (const result of inst.process_mac(mac, vault, settings)) {
			const data = [];
			const data_result = inst_data.process_ipaddress(
				result.address,
				vault,
				settings
			);
			if (data_result) {
				data.push(data_result);
			}
			data.push(result.data);
			const base = `${settings.base_directory}/IP`;
			create_folder(vault, base);
			vault.create(
				`${base}/${result.address.replace(/:/g, "_")}.md`,
				data.join("\n")
			);
			one_answer = true;
		}
	} else {
		for (const result of inst.process_mac(mac, vault, settings)) {
			const base = `${settings.base_directory}/IP`;
			create_folder(vault, base);
			vault.create(
				`${base}/${result.address.replace(/:/g, "_")}.md`,
				result.data
			);
			one_answer = true;
		}
	}
	if (one_answer) {
		return `${settings.base_directory}/MAC/${mac.replace(/:/g, "")}.md`;
	}
	return undefined;
}

class IvreSearch {}

class IvreSearchData extends IvreSearch {
	process_ipaddress(
		address: string,
		vault: Vault,
		settings: IvrePluginSettings
	): string | undefined {
		const options = ["ipdata", "--json"];
		if (settings.db_url_data) {
			options.push("--from-db", settings.db_url_data);
		}
		options.push(address);
		const ivre_ipdata = spawnSync("ivre", options);
		const data = JSON.parse(ivre_ipdata.stdout.toString());
		let answer = "\n# IP Data #\n";
		if ("as_num" in data) {
			ivre_create_as(
				data.as_num,
				data.as_name || "-",
				vault,
				settings.base_directory
			);
			answer += `\n## Autonomous System ##\n[[${
				settings.base_directory
			}/AS/AS${data.as_num}|AS${data.as_num} - ${
				data.as_name || "-"
			}]]\n`;
		}
		if ("country_code" in data) {
			ivre_create_country(
				data.country_code,
				data.country_name || "-",
				vault,
				settings.base_directory
			);
			answer += `\n## Geography ##\n\n### Country ###\n[[${
				settings.base_directory
			}/Country/${data.country_code}|${flag_emoji(data.country_code)} - ${
				data.country_code
			} - ${data.country_name || "-"}]]\n`;
			if ("region_code" in data) {
				answer += "\n### Region ###\n";
				data.region_code.forEach((code: string, index: number) => {
					answer += `${code} - ${data.region_name[index] || "-"}\n`;
				});
			}
			if ("city" in data) {
				answer += `\n### City ###\n${data.city} - ${
					data.postal_code || "-"
				}\n`;
			}
		}
		if ("address_type" in data) {
			answer += `\n## Address type ##\n${data.address_type}\n`;
		}
		return answer;
	}
}

class IvreSearchView extends IvreSearch {
	process_line(
		line: string,
		vault: Vault,
		settings: IvrePluginSettings
	): string | undefined {
		if (!line) {
			return;
		}
		const data: IvreHost = JSON.parse(line);
		if (!data) {
			return;
		}
		let answer = "";
		let tmp_answer = "";
		(data.tags || []).forEach((tag: IvreTag) => {
			tmp_answer += `${tag_emoji(tag)} #${tag.value.replace(
				/ /g,
				"_"
			)}\n`;
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
			answer += `\n## Categories ##\n${tmp_answer}`;
		}
		tmp_answer = "";
		((data.addresses || {}).mac || []).forEach((addr: string) => {
			ivre_create_mac(addr, vault, settings.base_directory);
			tmp_answer += `- [[${settings.base_directory}/MAC/${addr
				.toLowerCase()
				.replace(/:/g, "")}|${addr}]]\n`;
		});
		if (tmp_answer) {
			answer += `\n## MAC addresses ##\n${tmp_answer}`;
		}
		tmp_answer = "";
		(data.hostnames || []).forEach((hname: IvreHostname) => {
			tmp_answer += `- [[${settings.base_directory}/Hostname/${hname.name}|${hname.name}]] (${hname.type})\n`;
			ivre_create_hostname(hname.name, vault, settings.base_directory);
		});
		if (tmp_answer) {
			answer += `\n## Hostnames ##\n${tmp_answer}`;
		}
		tmp_answer = "";
		(data.ports || []).forEach((port: IvrePort) => {
			if (port.port === -1) {
				return;
			}
			tmp_answer += `\n### ${port.protocol}/${port.port} ###\n`;
			tmp_answer += `- Status: ${port.state_state}\n`;
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
								settings.base_directory
							);
						}
					);
				}
			});
		});
		if (tmp_answer) {
			answer += `\n## Ports ##\n${tmp_answer}`;
		}
		return answer;
	}
	process_ipaddress(
		address: string,
		vault: Vault,
		settings: IvrePluginSettings
	): string | undefined {
		const options = ["view", "--json", "--limit", "1"];
		if (settings.db_url_view) {
			options.push("--from-db", settings.db_url_view);
		}
		options.push(address);
		const ivre_view = spawnSync("ivre", options);
		for (const line of ivre_view.stdout.toString().split(/\r?\n/)) {
			const data = this.process_line(line, vault, settings);
			if (data) {
				return `\n# View #\n${data}`;
			}
		}
		return undefined;
	}
	*process_hostname(
		hostname: string,
		vault: Vault,
		settings: IvrePluginSettings
	): Generator<IvreMarkdownResult, void, unknown> {
		const options = ["view", "--json"];
		if (settings.db_url_view) {
			options.push("--from-db", settings.db_url_view);
		}
		options.push(
			settings.use_subdomains ? "--domain" : "--hostname",
			hostname
		);
		const ivre_view = spawnSync("ivre", options);
		for (const line of ivre_view.stdout.toString().split(/\r?\n/)) {
			const data = this.process_line(line, vault, settings);
			if (data) {
				yield {
					address: JSON.parse(line).addr,
					data: `\n# View #\n${data}`,
				};
			}
		}
	}
	*process_network(
		network: string,
		vault: Vault,
		settings: IvrePluginSettings
	): Generator<IvreMarkdownResult, void, unknown> {
		const options = ["view", "--json"];
		if (settings.db_url_view) {
			options.push("--from-db", settings.db_url_view);
		}
		options.push(network);
		const ivre_view = spawnSync("ivre", options);
		for (const line of ivre_view.stdout.toString().split(/\r?\n/)) {
			const data = this.process_line(line, vault, settings);
			if (data) {
				yield {
					address: JSON.parse(line).addr,
					data: `\n# View #\n${data}`,
				};
			}
		}
	}
	*process_mac(
		mac: string,
		vault: Vault,
		settings: IvrePluginSettings
	): Generator<IvreMarkdownResult, void, unknown> {
		const options = ["view", "--json"];
		if (settings.db_url_view) {
			options.push("--from-db", settings.db_url_view);
		}
		options.push("--mac", mac);
		const ivre_view = spawnSync("ivre", options);
		for (const line of ivre_view.stdout.toString().split(/\r?\n/)) {
			const data = this.process_line(line, vault, settings);
			if (data) {
				yield {
					address: JSON.parse(line).addr,
					data: `\n# View #\n${data}`,
				};
			}
		}
	}
}

function ivre_analyze_selection(
	settings: IvrePluginSettings,
	editor: Editor,
	vault: Vault,
	active_file: TFile | null
) {
	const links: { element: string; link: string }[] = [];
	let content_data = editor.getSelection();
	content_data.split(/\s+/).forEach((element) => {
		switch (ivre_guess_type(element, settings.base_directory)) {
			case ElementType.IpAddress: {
				new Notice(`Processing IP address: ${element}`);
				const fname = ivre_handle_address(element, vault, settings);
				if (fname) {
					links.push({ element: element, link: fname.slice(0, -3) });
				}
				break;
			}
			case ElementType.IpNetwork: {
				new Notice(`Processing network: ${element}`);
				const fname = ivre_handle_network(element, vault, settings);
				if (fname) {
					links.push({ element: element, link: fname.slice(0, -3) });
				}
				break;
			}
			case ElementType.HostName: {
				new Notice(`Processing hostname: ${element}`);
				const fname = ivre_handle_hostname(element, vault, settings);
				if (fname) {
					links.push({ element: element, link: fname.slice(0, -3) });
				}
				break;
			}
			case ElementType.MacAddress: {
				new Notice(`Processing MAC address: ${element}`);
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
							new Notice(`Processing IP address: ${data[1]}`);
							ivre_handle_address(data[1], vault, settings);
							break;
						}
						case ElementType.IpNetwork: {
							new Notice(`Processing network: ${data[1]}`);
							ivre_handle_network(data[1], vault, settings);
							break;
						}
						case ElementType.HostName: {
							new Notice(`Processing hostname: ${data[1]}`);
							ivre_handle_hostname(data[1], vault, settings);
							break;
						}
						case ElementType.MacAddress: {
							new Notice(`Processing MAC address: ${data[1]}`);
							ivre_handle_mac(data[1], vault, settings);
							break;
						}
						default: {
							new Notice(`Element ignored: ${data[1]}`);
						}
					}
				}
				break;
			}
			default: {
				if (element) {
					new Notice(`Element ignored: ${element}`);
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
					"\\$&"
				)}(\\s|$)`,
				"g"
			);
			content_data = content_data.replace(
				expr,
				`$1[[${replacement.link}|${replacement.element}]]$2`
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
					new Notice("Call me from a MarkdownView!");
				} else {
					const view_mode = view.getMode(); // "preview" or "source" (can also be "live" but I don't know when that happens)
					switch (view_mode) {
						case "preview":
							new Notice(
								"Call me from a MarkdownView in source mode!"
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
									this.app.workspace.getActiveFile()
								);
							} else {
								new Notice(
									"Cannot find .editor in current view!"
								);
							}
							break;
						default:
							new Notice(
								"Call me from a MarkdownView in source mode!"
							);
							break;
					}
				}
			}
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
						statusBarItemEl.setText(`IVRE v${line.slice(8)}`);
						return;
					}
				});
		});
		ivre_version.on("close", (code: number) => {
			if (code !== 0) {
				statusBarItemEl.setText(
					`IVRE --version exited with code ${code}`
				);
			}
		});
		ivre_version.on("error", (err: number) => {
			statusBarItemEl.setText(`IVRE --version exited with error ${err}`);
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
					this.app.workspace.getActiveFile()
				);
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
			await this.loadData()
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
					})
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
					})
			);
		new Setting(containerEl)
			.setName("URL for data")
			.setDesc(
				"URL for IVRE database for data (Maxmind GeoIP). Leave empty to use the system default."
			)
			.addText((text) =>
				text
					.setPlaceholder("maxmind:///usr/share/ivre/geoip")
					.setDisabled(!this.plugin.settings.use_data)
					.setValue(this.plugin.settings.db_url_data)
					.onChange(async (value) => {
						this.plugin.settings.db_url_data = value;
						await this.plugin.saveSettings();
					})
			);
		const setting_url_view = new Setting(containerEl)
			.setName("URL for view")
			.setDesc(
				"URL for IVRE database for view (mixed from passive & scan). Leave empty to use the system default."
			)
			.addText((text) =>
				text
					.setPlaceholder("mongodb://example/ivre")
					.setValue(this.plugin.settings.db_url_view)
					.onChange(async (value) => {
						this.plugin.settings.db_url_view = value;
						await this.plugin.saveSettings();
					})
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
					})
			);
	}
}
