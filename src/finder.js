import batchPromises from "batch-promises";
import axios from "redaxios";
import WhoisParser from "bulk-whois-parser";
import LongestPrefixMatch from "longest-prefix-match";
import CsvParser from "./csvParser";
import md5 from "md5";
import fs from "fs";
import moment from "moment";
import ipUtils from "ip-sub";
import {explicitTransferCheck, lessSpecific} from "whois-wrapper";
import {execFile} from "child_process";

require("events").EventEmitter.defaultMaxListeners = 200;

export default class Finder {
    constructor(params) {
        const defaults = {
            cacheDir: ".cache/",
            whoisCacheDays: 3,
            geofeedCacheDays: 7,
            af: [4, 6],
            includeZip: false,
            silent: false,
            keepNonIso: false,
            keepInvalidSubdivisions: false,
            removeInvalidSubdivisions: false,
            disableProcessing: false,
            customFeedsFile: null,
            include: ["ripe", "afrinic", "apnic", "arin", "lacnic"],
            output: "result.csv",
            test: null,
            downloadTimeout: 14,
            referralDepthLimit: 10,
            referralConcurrency: 10,
            referralTimeout: 10,
            referralFailFast: false,
            arinLiveReferrals: false,
            daysWhoisSuballocationsCache: 7, // Cannot be less than this
            skipSuballocations: false,
            compileSuballocationLocally: false
        };
        this.params = {
            ...defaults,
            ...(params ?? {})
        };
        this.logger = this.params.logger;
        this.cacheDir = this.params.cacheDir.split("/").filter(i => !!i).join("/") + "/";
        this.csvParser = new CsvParser();
        this.startTime = moment();
        this.referralQueryCache = {};
        this.discoveryStats = {
            bulkPairs: 0,
            referralPairs: 0,
            livePairs: 0,
            bulkUniqueGeofeeds: 0,
            referralLiveUniqueGeofeeds: 0,
            totalUniqueGeofeeds: 0
        };

        this.cacheHeadersIndexFileName = this.cacheDir + "cache-index.json";
        this._importCacheHeaderIndex();

        this.connectors = defaults.include.filter(key => this.params.include.includes(key));

        this.whois = new WhoisParser({
            cacheDir: this.cacheDir,
            repos: this.connectors,
            daysWhoisSuballocationsCache: this.params.daysWhoisSuballocationsCache,
            skipSuballocations: this.params.skipSuballocations,
            defaultCacheDays: this.params.whoisCacheDays,
            compileSuballocationLocally: this.params.compileSuballocationLocally,
            userAgent: "geofeed-finder",
            deleteCorruptedCacheFile: true
        });

        // ARIN referral records are mostly in the RR dump (NetRange objects), not in ARIN's RDAP-derived inetnum list.
        this.arinWhois = this.params.include.includes("arin")
            ? new WhoisParser({
                cacheDir: this.cacheDir,
                repos: ["arin"],
                daysWhoisSuballocationsCache: this.params.daysWhoisSuballocationsCache,
                skipSuballocations: this.params.skipSuballocations,
                defaultCacheDays: this.params.whoisCacheDays,
                compileSuballocationLocally: this.params.compileSuballocationLocally,
                userAgent: "geofeed-finder",
                deleteCorruptedCacheFile: true
            })
            : null;
    };


    _toArray = (value) => {
        if (Array.isArray(value)) {
            return value;
        }

        if (value === null || value === undefined) {
            return [];
        }

        return [value];
    };

    _cleanString = (value) => {
        return `${value ?? ""}`.trim();
    };

    _getObjectValuesByKeys = (object, keys = []) => {
        const keySet = new Set(keys.map(i => i.toLowerCase()));
        const out = [];

        for (let [key, value] of Object.entries(object ?? {})) {
            if (keySet.has(key.toLowerCase())) {
                out.push(...this._toArray(value).map(this._cleanString).filter(Boolean));
            }
        }

        return out;
    };

    _getObjectTextValues = (object) => {
        const out = [];

        for (let value of Object.values(object ?? {})) {
            out.push(...this._toArray(value).map(this._cleanString).filter(Boolean));
        }

        return out;
    };

    _getRemarksAndComments = (object) => {
        return this._getObjectValuesByKeys(object, ["remarks", "comment", "comments", "descr"]);
    };

    _getLastUpdate = (object) => {
        const rawDate = object?.["last-updated"] || object?.["last-modified"] || object?.["updated"] || object?.["changed"] || null;
        const parsed = moment(rawDate);
        return parsed.isValid() ? parsed : moment(0);
    };

    _extractInetnums = (object) => {
        const inetnum = object?.inetnum || object?.inet6num;

        if (!inetnum) {
            return [];
        }

        try {
            if (!inetnum.includes("/")) {
                const ips = inetnum.split("-").map(ip => ip.trim());
                return ipUtils.ipRangeToCidr(ips[0], ips[1]);
            }
        } catch (error) {
            return [];
        }

        return [inetnum];
    };

    _toReferralProtocol = (protocol, port) => {
        const proto = `${protocol ?? ""}`.trim().toLowerCase();

        if (proto === "rwhois" || parseInt(port) === 4321) {
            return "rwhois";
        }

        return "whois";
    };

    _buildReferralTarget = (protocol, host, port) => {
        const cleanHost = `${host ?? ""}`.trim().replace(/[)\],;."'`]+$/g, "");
        const cleanPort = parseInt(port);
        const safePort = Number.isInteger(cleanPort) && cleanPort > 0 && cleanPort <= 65535
            ? cleanPort
            : (this._toReferralProtocol(protocol, cleanPort) === "rwhois" ? 4321 : 43);

        if (!cleanHost) {
            return null;
        }

        return {
            protocol: this._toReferralProtocol(protocol, safePort),
            host: cleanHost,
            port: safePort
        };
    };

    _parseReferralTargets = (text) => {
        const out = [];
        const value = `${text ?? ""}`;

        const protocolMatches = value.matchAll(/\b(r?whois):\/\/([a-z0-9.-]+)(?::([0-9]{1,5}))?/gi);
        for (let [, protocol, host, port] of protocolMatches) {
            const target = this._buildReferralTarget(protocol, host, port);
            if (target) {
                out.push(target);
            }
        }

        const referralLines = value
            .split(/\r?\n/)
            .filter(line => /referr|whois/i.test(line));

        for (let line of referralLines) {
            const hostPortMatches = line.matchAll(/\b((?:[a-z0-9.-]+\.[a-z]{2,}|(?:\d{1,3}\.){3}\d{1,3}))(?::([0-9]{1,5}))\b/gi);
            for (let [, host, port] of hostPortMatches) {
                const target = this._buildReferralTarget(null, host, port);
                if (target) {
                    out.push(target);
                }
            }
        }

        const index = {};
        for (let target of out) {
            index[`${target.host}:${target.port}`] = target;
        }

        return Object.values(index);
    };

    _getReferralTargetsFromObject = (object) => {
        const likelyReferralValues = this._getObjectValuesByKeys(object, [
            "referralserver",
            "referral",
            "refer",
            "whoisserver",
            "whois",
            "remarks",
            "comment",
            "comments"
        ])
            .filter(value => /referr|rwhois|whois:\/\//i.test(value));

        const out = [];
        for (let value of likelyReferralValues) {
            out.push(...this._parseReferralTargets(value));
        }

        const index = {};
        for (let item of out) {
            index[`${item.host}:${item.port}`] = item;
        }

        return Object.values(index);
    };

    _normalizeArinNetRangeObject = (object = {}) => {
        const normalized = {...object};
        const netRange = this._getObjectValuesByKeys(object, ["NetRange", "netrange"])[0];
        const cidr = this._getObjectValuesByKeys(object, ["CIDR", "cidr", "Net6CIDRBlock", "net6cidrblock"])[0];
        const comments = this._getObjectValuesByKeys(object, ["Comment", "comment", "comments"]);
        const updated = this._getObjectValuesByKeys(object, ["Updated", "updated", "last-updated", "last-modified"])[0];

        if (netRange && !normalized.inetnum) {
            normalized.inetnum = netRange;
        }

        if (!normalized.inetnum && !normalized.inet6num && cidr) {
            const cidrs = cidr
                .split(",")
                .map(item => item.trim())
                .filter(item => !!item && item.includes("/"));

            const getAf = (item) => {
                try {
                    return ipUtils.getAddressFamily(item);
                } catch (error) {
                    return null;
                }
            };

            const v4 = cidrs.find(item => getAf(item) === 4);
            const v6 = cidrs.find(item => getAf(item) === 6);

            if (v4) {
                normalized.inetnum = v4;
            }
            if (v6) {
                normalized.inet6num = v6;
            }
        }

        if (!normalized.remarks && comments.length > 0) {
            normalized.remarks = comments;
        }

        if (!normalized["last-updated"] && updated) {
            normalized["last-updated"] = updated;
        }

        return normalized;
    };

    filterFunction = (inetnum) => {

        if (inetnum.geofeed && this.matchGeofeedFile(inetnum.geofeed).length) {
            return true;
        }

        if (this._getRemarksAndComments(inetnum).some(this.testGeofeedRemark)) {
            return true;
        }

        return this._getReferralTargetsFromObject(inetnum).length > 0;
    };

    getBlocks = () => {
        const selector = this.params.af
            .map(i => i === 4 ? "inetnum" : "inet6num");
        const standardFields = [
            "inetnum",
            "inet6num",
            "remarks",
            "comment",
            "Comment",
            "comments",
            "geofeed",
            "Geofeed",
            "last-updated",
            "last-modified",
            "ReferralServer",
            "referralserver",
            "referral",
            "refer",
            "whoisserver",
            "WhoisServer"
        ];

        const arinTypes = [];
        if (this.params.af.includes(4)) {
            arinTypes.push("NetRange");
        }
        if (this.params.af.includes(6)) {
            arinTypes.push("Net6CIDRBlock");
        }

        const arinExtra = this.arinWhois && arinTypes.length > 0
            ? this.arinWhois.getObjects(
                arinTypes,
                this.filterFunction,
                [
                    "NetRange",
                    "Net6CIDRBlock",
                    "CIDR",
                    "Comment",
                    "comments",
                    "ReferralServer",
                    "referralserver",
                    "WhoisServer",
                    "whoisserver",
                    "Updated"
                ]
            )
                .then(blocks => blocks.flat().map(this._normalizeArinNetRangeObject))
                .catch(error => {
                    this.logger.log(`Error: ARIN referral records (${error?.message ?? "Unknown error"})`);
                    return [];
                })
            : Promise.resolve([]);

        return Promise.all([
            this.whois.getObjects(
                selector,
                this.filterFunction,
                standardFields
            )
                .then(blocks => blocks.flat())
                .catch(error => {
                    this.logger.log(`Error: bulk whois records (${error?.message ?? "Unknown error"})`);
                    return [];
                }),
            arinExtra
        ])
            .then(([bulkBlocks, arinReferralBlocks]) => {
                const out = [...bulkBlocks, ...arinReferralBlocks]
                    .filter(i => !!i.inetnum || !!i.inet6num);

                const index = {};
                for (let block of out) {
                    const id = `${block.inetnum || block.inet6num}|${block.geofeed || ""}|${block.ReferralServer || block.referralserver || ""}`;
                    index[id] = block;
                }

                return Object.values(index);
            });
    };

    _getFileName = (file) => {
        return this.cacheDir + md5(file);
    };

    _setGeofeedCacheHeaders = (response, cachedFile) => {
        let setAge = 3600 * 24 * (this.params.geofeedCacheDays || 7); // default 1 week (see draft)

        if (response.headers["cache-control"]) {
            const maxAge = response.headers["cache-control"]
                .split(",")
                .filter(h => h.includes("max-age"))
                .map(h => h.trim())
                .pop();

            let age = maxAge?.split("=")?.pop() ?? 0;
            age = isNaN(age) ? 0 : age;
            setAge = Math.min(Math.max(parseInt(age), 3600), 3600 * 24 * 7); //  Min 1 hour, max 1 week of cache (to avoid random max-age settings)
        }

        this.cacheHeadersIndex[cachedFile] = this.cacheHeadersIndex[cachedFile] ?? moment(this.startTime).add(setAge, "seconds");
    };

    _isCachedGeofeedValid = (cachedFile) => {
        if (this.params.test) {
            return false;
        } else {
            return fs.existsSync(cachedFile) &&
                this.cacheHeadersIndex[cachedFile] &&
                moment(this.cacheHeadersIndex[cachedFile]).isSameOrAfter(this.startTime);
        }
    };

    _importCacheHeaderIndex = () => {
        let tmp;
        if (fs.existsSync(this.cacheHeadersIndexFileName)) {
            tmp = JSON.parse(fs.readFileSync(this.cacheHeadersIndexFileName, "utf-8"));
            for (let key in tmp) {
                tmp[key] = moment(tmp[key]);
            }
        }

        this.cacheHeadersIndex = tmp || {};
    };

    _persistCacheIndex = () => {
        fs.writeFileSync(this.cacheHeadersIndexFileName, JSON.stringify(this.cacheHeadersIndex));
    };

    logEntry = (file, cache) => {
        console.log(`${file} ${cache ? "[cache]" : "[download]"}`);
    };

    _getCustomGeofeedUrls = () => {
        if (!this.params.customFeedsFile) {
            return [];
        }

        if (!fs.existsSync(this.params.customFeedsFile)) {
            const message = `Error: custom feeds file not found: ${this.params.customFeedsFile}`;
            this.logger.log(message);
            console.log(message);
            return [];
        }

        try {
            const content = fs.readFileSync(this.params.customFeedsFile, "utf8");
            const urls = content
                .split(/\r?\n/)
                .map(line => line.trim())
                .filter(line => !!line && !line.startsWith("#"))
                .map(line => this.matchGeofeedFile(line)?.[0])
                .filter(Boolean);

            return [...new Set(urls)];
        } catch (error) {
            const message = `Error: cannot read custom feeds file ${this.params.customFeedsFile} (${error?.message ?? "Unknown error"})`;
            this.logger.log(message);
            console.log(message);
            return [];
        }
    };

    _getGeofeedFile = (file) => {

        const abortTimeout = parseInt(this.params.downloadTimeout) * 1000;

        return new Promise((resolve, reject) => {
            const timeout = setTimeout(() => {
                this.logger.log(`Error: ${file} timeout`);
                resolve(null);
            }, abortTimeout);

            const resolveAndClear = (data) => {
                resolve(data);
                clearTimeout(timeout);
            };

            const cachedFile = this._getFileName(file);

            if (this._isCachedGeofeedValid(cachedFile)) {

                this.logEntry(file, true);
                resolveAndClear();

            } else {

                if (fs.existsSync(cachedFile)) {
                    fs.unlinkSync(cachedFile);
                }

                this.logEntry(file, false);

                axios({
                    url: file,
                    method: "GET",
                    timeout: abortTimeout
                })
                    .then(response => {
                        const data = response.data;
                        if (/<a|<div|<span|<style|<link/gi.test(data)) {
                            const message = `Error: ${file} is not CSV but HTML, stop with this nonsense!`;
                            this.logger.log(message);
                            console.log(message);
                            resolveAndClear(null);
                        } else {
                            fs.writeFileSync(cachedFile, data);
                            this._setGeofeedCacheHeaders(response, cachedFile);

                            resolveAndClear();
                        }
                    })
                    .catch(error => {
                        this.logger.log(`Error: ${file} ${error?.message ?? "Unknown error"}`);
                        resolveAndClear();
                    });
            }
        })
            .then(() => {}) // Avoid empty logs
            .catch(() => {}); // Avoid empty logs
    };


    getGeofeedsFiles = (blocks) => {
        const out = [];
        const customGeofeeds = this._getCustomGeofeedUrls();
        const uniqueBlocks = [...new Set([...blocks.map(i => i.geofeed), ...customGeofeeds].filter(Boolean))];
        const half = Math.floor(uniqueBlocks.length / 2);

        // pre load all files
        return Promise.all([
            batchPromises(10, uniqueBlocks.slice(0, half), file => this._getGeofeedFile(file)),
            batchPromises(10, uniqueBlocks.slice(half), file => this._getGeofeedFile(file))
        ])
            .then(() => {
                if (this.params.disableProcessing) {
                    console.log("All files downloaded. Processing disabled.");
                    return [];
                }

                console.log("All files downloaded. Processing files.");

                for (let block of blocks) {
                    const cachedFile = this._getFileName(block.geofeed);

                    try {
                        const data = fs.readFileSync(cachedFile, "utf8");

                        if (data && data.length) {
                            out.push(this.validateGeofeeds(this.csvParser.parse(block.inetnum, data)));
                        }
                    } catch (error) {
                        // Nothing - these are files that are not CSV
                    }
                }

                for (let file of customGeofeeds) {
                    const cachedFile = this._getFileName(file);

                    try {
                        const data = fs.readFileSync(cachedFile, "utf8");

                        if (data && data.length) {
                            out.push(this.validateGeofeeds(this.csvParser.parse(null, data)));
                        }
                    } catch (error) {
                        // Nothing - these are files that are not CSV
                    }
                }

                const data = out.flat();

                for (let g of data) {
                    if (!this.params.includeZip) {
                        g.zip = null;
                    }
                    g.af = ipUtils.getAddressFamily(g.prefix);
                }


                return data;
            });
    };

    validateGeofeeds = (geofeeds) => {
        return geofeeds
            .filter(geofeed => !!geofeed?.inetnum && !!geofeed?.prefix)
            .filter(geofeed => {
                let errors = geofeed.validate();

                if (this.params.keepInvalidSubdivisions || this.params.removeInvalidSubdivisions) {
                    const noSubErrors = errors.filter(i => !i.includes("Not valid Subdivision Code") && !i.includes("The Subdivision is not inside the Country"));

                    if (this.params.removeInvalidSubdivisions && noSubErrors.length !== errors.length) {
                        geofeed.region = null; // If there is an error in the region and removeInvalidSubdivisions=true, remove the region
                    }

                    errors = noSubErrors; // Ignore subdivision errors.
                }

                if (errors.length > 0) {
                    const message = `${geofeed} ${errors.join(", ")}`;
                    if (this.params.test) {
                        console.log(message);
                    }
                    this.logger.log(message);
                }

                return this.params.keepNonIso || errors.length === 0;
            });

    };

    getMostUpdatedInetnums = (inetnums) => {
        const index = {};
        for (let inetnum of inetnums) {
            const key = `${inetnum.inetnum}|${inetnum.geofeed}`;
            index[key] = (!index[key] || index[key].lastUpdate < inetnum.lastUpdate) ?
                inetnum :
                index[key];
        }

        return Object.values(index);
    };

    setGeofeedPriority = (geofeeds = []) => {
        console.log("Validating prefix ownership");

        return [
            ...this.params.af.includes(4) ? this._setGeofeedPriority(geofeeds.filter(i => i.af === 4)) : [],
            ...this.params.af.includes(6) ? this._setGeofeedPriority(geofeeds.filter(i => i.af === 6)) : []
        ].flat();
    };

    _setGeofeedPriority = (geofeeds = []) => {
        const longestPrefixMatch = new LongestPrefixMatch();

        let tmp = {};
        for (let inetnum of [...new Set(geofeeds.map(i => i.inetnum))]) {
            longestPrefixMatch.addPrefix(inetnum, inetnum);
        }

        for (let geofeed of geofeeds) {
            const inetnum = longestPrefixMatch.getMatch(geofeed.prefix, false);
            if (inetnum && inetnum.length === 1 && geofeed.inetnum === inetnum[0]) {
                tmp[geofeed.prefix] ??= geofeed;
            }
        }

        return Object.values(tmp);
    };

    testGeofeedRemark = (remark) => {
        const value = `${remark ?? ""}`;
        return /geofeed/gi.test(value) && this.matchGeofeedFile(value).length > 0;
    };

    testGeofeedRemarkStrict = (remark) => {
        return /^Geofeed https?:\/\/\S+/gi.test(remark);
    };


    matchGeofeedFile = (remark) => {
        const urls = `${remark ?? ""}`.match(/\bhttps?:\/\/[^\s"'<>]+/gi) || [];
        return [...new Set(urls.map(url => url.replace(/[),.;]+$/g, "")))];
    };

    _extractGeofeedUrlsFromObject = (object = {}) => {
        const geofeedFieldValues = this._getObjectValuesByKeys(object, ["geofeed"]);
        const remarks = this._getRemarksAndComments(object)
            .filter(value => /geofeed|https?:\/\//i.test(value));
        const textHints = this._getObjectTextValues(object)
            .filter(value => /geofeed/i.test(value));

        const urls = [...geofeedFieldValues, ...remarks, ...textHints]
            .map(this.matchGeofeedFile)
            .flat();

        return [...new Set(urls)];
    };

    _extractGeofeedUrlsFromResponse = (response) => {
        const lines = `${response ?? ""}`.split(/\r?\n/).map(line => line.trim()).filter(Boolean);
        const geofeedUrls = lines.filter(line => /geofeed/i.test(line)).map(this.matchGeofeedFile).flat();
        const csvUrls = lines.filter(line => /\.csv/i.test(line)).map(this.matchGeofeedFile).flat();
        const allUrls = this.matchGeofeedFile(lines.join("\n"));

        return [...new Set([...geofeedUrls, ...csvUrls, ...allUrls])];
    };

    _getReferralQuery = (inetnum) => {
        if (!inetnum) {
            return "";
        }

        if (inetnum.includes("/")) {
            return inetnum;
        }

        if (inetnum.includes("-")) {
            return inetnum.split("-")[0].trim();
        }

        return inetnum;
    };

    _logReferral = (message) => {
        if (this.params.silent) {
            return;
        }

        console.log(message);
        this.logger?.log?.(message);
    };

    _logReferralExtractedGeofeeds = ({query, target, depth, geofeeds}) => {
        if (this.params.silent || !geofeeds?.length) {
            return;
        }

        const message = `[referral] query="${query}" source="${target.host}:${target.port}" depth=${depth} geofeeds=${geofeeds.join(" | ")}`;
        this._logReferral(message);
    };

    _sleep = (ms = 2000) => {
        return new Promise(resolve => setTimeout(resolve, ms));
    };

    _isWhoisRateLimitedText = (text) => {
        const value = `${text ?? ""}`.toLowerCase();

        if (!value.trim()) {
            return false;
        }

        return [
            /rate[\s-]*limit/i,
            /too many quer/i,
            /query[\s-]*limit/i,
            /queries exceeded/i,
            /exceeded.*quer/i,
            /limit exceeded/i,
            /please try again later/i,
            /temporarily unavailable/i,
            /temporarily unable/i,
            /slow down/i,
            /quota exceeded/i,
            /connection limit/i
        ].some(regex => regex.test(value));
    };

    _isWhoisRateLimitError = (error) => {
        if (!error) {
            return false;
        }

        if (error.rateLimited) {
            return true;
        }

        const context = `${error?.message ?? ""}\n${error?.stdout ?? ""}\n${error?.stderr ?? ""}`;
        return this._isWhoisRateLimitedText(context);
    };

    _countUniqueGeofeeds = (pairs = []) => {
        return new Set((pairs ?? []).map(item => item?.geofeed).filter(Boolean)).size;
    };

    _ipv4ToBigInt = (ip) => {
        const parts = `${ip ?? ""}`.trim().split(".").map(i => parseInt(i));
        if (parts.length !== 4 || parts.some(i => !Number.isInteger(i) || i < 0 || i > 255)) {
            throw new Error("Invalid IPv4 address");
        }

        return parts.reduce((acc, part) => (acc << 8n) + BigInt(part), 0n);
    };

    _bigIntToIpv4 = (value) => {
        const out = [];
        let remaining = BigInt(value);

        for (let i = 0; i < 4; i++) {
            out.unshift(Number(remaining & 255n));
            remaining >>= 8n;
        }

        return out.join(".");
    };

    _ipv4RangeToCidrs = (startIp, hosts) => {
        const count = parseInt(hosts);
        if (!Number.isInteger(count) || count <= 0) {
            return [];
        }

        try {
            const start = this._ipv4ToBigInt(startIp);
            const end = start + BigInt(count - 1);
            const maxV4 = (1n << 32n) - 1n;
            if (end > maxV4) {
                return [];
            }

            const endIp = this._bigIntToIpv4(end);
            return ipUtils.ipRangeToCidr(startIp, endIp);
        } catch (error) {
            return [];
        }
    };

    _getLiveDelegatedProbeCandidates = () => {
        if (!this.params.arinLiveReferrals) {
            return Promise.resolve([]);
        }

        const rirConfigs = {
            arin: {
                rirIds: ["arin"],
                delegatedUrl: "https://ftp.arin.net/pub/stats/arin/delegated-arin-extended-latest",
                whoisHost: "whois.arin.net"
            },
            ripe: {
                rirIds: ["ripencc", "ripe"],
                delegatedUrl: "https://ftp.ripe.net/pub/stats/ripencc/delegated-ripencc-extended-latest",
                whoisHost: "whois.ripe.net"
            },
            apnic: {
                rirIds: ["apnic"],
                delegatedUrl: "https://ftp.apnic.net/stats/apnic/delegated-apnic-extended-latest",
                whoisHost: "whois.apnic.net"
            },
            lacnic: {
                rirIds: ["lacnic"],
                delegatedUrl: "https://ftp.lacnic.net/pub/stats/lacnic/delegated-lacnic-extended-latest",
                whoisHost: "whois.lacnic.net"
            },
            afrinic: {
                rirIds: ["afrinic"],
                delegatedUrl: "https://ftp.afrinic.net/pub/stats/afrinic/delegated-afrinic-extended-latest",
                whoisHost: "whois.afrinic.net"
            }
        };

        const repos = this.params.include.filter(repo => !!rirConfigs[repo]);
        if (!repos.length) {
            return Promise.resolve([]);
        }

        const cacheDays = Math.max(parseInt(this.params.whoisCacheDays || 3), 1);
        this._logReferral(`[referral][live] enabled repos=${repos.join(",")}`);

        const loadRepoCandidates = (repo) => {
            const config = rirConfigs[repo];
            const cacheFile = `${this.cacheDir}live-referrals-delegated-${repo}`;
            const isCacheFresh = fs.existsSync(cacheFile) &&
                moment().diff(moment(fs.statSync(cacheFile).ctime), "days") <= cacheDays;

            const parse = (content = "") => {
                const out = [];

                for (let line of content.split(/\r?\n/)) {
                    if (!line || line.startsWith("#")) {
                        continue;
                    }

                    const [rir, cc, type, start, value, date, status] = line.split("|");
                    if (!config.rirIds.includes(`${rir ?? ""}`.toLowerCase())) {
                        continue;
                    }

                    if (!["allocated", "assigned"].includes(`${status ?? ""}`.toLowerCase())) {
                        continue;
                    }

                    if (type === "ipv4" && this.params.af.includes(4)) {
                        const prefixes = this._ipv4RangeToCidrs(start, value);
                        const lastUpdate = moment(date, "YYYYMMDD", true);

                        for (let inetnum of prefixes) {
                            const query = ipUtils.getIpAndCidr(inetnum)[0];
                            out.push({
                                rir: repo,
                                inetnum,
                                query,
                                target: {
                                    protocol: "whois",
                                    host: config.whoisHost,
                                    port: 43
                                },
                                lastUpdate: lastUpdate.isValid() ? lastUpdate : moment(0)
                            });
                        }
                    } else if (type === "ipv6" && this.params.af.includes(6)) {
                        const bits = parseInt(value);
                        if (!Number.isInteger(bits) || bits < 0 || bits > 128) {
                            continue;
                        }

                        const inetnum = ipUtils.toPrefix(`${start}/${bits}`);
                        const query = inetnum.split("/")[0];
                        const lastUpdate = moment(date, "YYYYMMDD", true);
                        out.push({
                            rir: repo,
                            inetnum,
                            query,
                            target: {
                                protocol: "whois",
                                host: config.whoisHost,
                                port: 43
                            },
                            lastUpdate: lastUpdate.isValid() ? lastUpdate : moment(0)
                        });
                    }
                }

                const index = {};
                for (let candidate of out) {
                    index[`${candidate.rir}|${candidate.inetnum}`] = candidate;
                }

                return Object.values(index);
            };

            if (isCacheFresh) {
                const candidates = parse(fs.readFileSync(cacheFile, "utf8"));
                this._logReferral(`[referral][live] repo=${repo} source=cache candidates=${candidates.length}`);
                return Promise.resolve(candidates);
            }

            return axios({
                url: config.delegatedUrl,
                method: "GET",
                timeout: 20000
            })
                .then(response => {
                    fs.writeFileSync(cacheFile, response.data);
                    const candidates = parse(response.data);
                    this._logReferral(`[referral][live] repo=${repo} source=download candidates=${candidates.length}`);
                    return candidates;
                })
                .catch(error => {
                    this._logReferral(`Error: ${repo} delegated stats (${error?.message ?? "Unknown error"})`);
                    if (fs.existsSync(cacheFile)) {
                        const candidates = parse(fs.readFileSync(cacheFile, "utf8"));
                        this._logReferral(`[referral][live] repo=${repo} source=stale-cache candidates=${candidates.length}`);
                        return candidates;
                    }
                    return [];
                });
        };

        return Promise.all(repos.map(loadRepoCandidates))
            .then(results => {
                const candidates = results.flat();
                const index = {};
                for (let candidate of candidates) {
                    index[`${candidate.rir}|${candidate.inetnum}`] = candidate;
                }
                return Object.values(index);
            });
    };

    _getLiveReferralGeofeedPairs = (bulkPairs = []) => {
        if (!this.params.arinLiveReferrals) {
            return Promise.resolve([]);
        }

        const lpm = new LongestPrefixMatch();
        for (let pair of bulkPairs ?? []) {
            if (pair?.geofeed && ipUtils.isValidPrefix(pair?.inetnum)) {
                lpm.addPrefix(pair.inetnum, pair.inetnum);
            }
        }

        return this._getLiveDelegatedProbeCandidates()
            .then(candidates => {
                const uncovered = candidates.filter(candidate => {
                    if (!ipUtils.isValidPrefix(candidate?.inetnum)) {
                        return false;
                    }

                    return lpm.getMatch(candidate.inetnum, false).length === 0;
                });

                const toProbe = uncovered;
                const out = [];

                this._logReferral(`[referral][live] candidates=${candidates.length} uncovered=${uncovered.length} probing=${toProbe.length}`);

                if (!toProbe.length) {
                    return [];
                }

                const concurrency = Math.max(parseInt(this.params.referralConcurrency || 10), 1);

                return batchPromises(concurrency, toProbe, async candidate => {
                    const query = candidate.query;
                    const target = candidate.target;
                    this._logReferral(`[referral][live] rir=${candidate.rir} query="${query}" inetnum="${candidate.inetnum}" source="${target.host}:${target.port}" action=probe`);

                    try {
                        const response = await this._runReferralWhoisQuery(target, query);
                        const directUrls = this._extractGeofeedUrlsFromResponse(response);
                        const referrals = this._parseReferralTargets(response)
                            .filter(referral => !(referral.host === target.host && referral.port === target.port));
                        let referralUrls = [];

                        for (let referral of referrals) {
                            referralUrls.push(...(await this._resolveReferralGeofeedUrls(referral, query)));
                        }

                        const geofeeds = [...new Set([...directUrls, ...referralUrls])];

                        if (geofeeds.length > 0) {
                            this._logReferralExtractedGeofeeds({
                                query,
                                target,
                                depth: 0,
                                geofeeds
                            });

                            for (let geofeed of geofeeds) {
                                out.push({
                                    inetnum: candidate.inetnum,
                                    geofeed,
                                    lastUpdate: candidate.lastUpdate
                                });
                            }
                        } else {
                            this._logReferral(`[referral][live] rir=${candidate.rir} query="${query}" inetnum="${candidate.inetnum}" source="${target.host}:${target.port}" geofeeds=none referrals=${referrals.length}`);
                        }
                    } catch (error) {
                        const message = `Error: live referral query rir=${candidate.rir} source=${target.host}:${target.port} query="${query}" (${error?.message ?? "Unknown error"})`;
                        this._logReferral(message);

                        if (this.params.referralFailFast) {
                            throw new Error(message);
                        }
                    }
                })
                    .then(() => out);
            });
    };

    _runReferralWhoisQueryOnce = (target, query) => {
        const timeout = Math.max(parseInt(this.params.referralTimeout || this.params.downloadTimeout || 10), 1) * 1000;
        const args = ["-h", target.host, "-p", `${target.port}`, query];

        return new Promise((resolve, reject) => {
            execFile("whois", args, {timeout, encoding: "utf8", maxBuffer: 1024 * 1024 * 10}, (error, stdout, stderr) => {
                const output = [stdout, stderr].filter(Boolean).join("\n");

                if (this._isWhoisRateLimitedText(output)) {
                    const rateError = new Error(`Rate limit detected for ${target.host}:${target.port}`);
                    rateError.rateLimited = true;
                    rateError.stdout = stdout;
                    rateError.stderr = stderr;
                    reject(rateError);
                    return;
                }

                if (error && this._isWhoisRateLimitError(error)) {
                    const rateError = new Error(`Rate limit detected for ${target.host}:${target.port}`);
                    rateError.rateLimited = true;
                    rateError.stdout = stdout;
                    rateError.stderr = stderr;
                    reject(rateError);
                    return;
                }

                if (error && !output) {
                    reject(error);
                    return;
                }

                resolve(output || "");
            });
        });
    };

    _runReferralWhoisQuery = async (target, query) => {
        const maxRetries = 20;
        const sleepMs = 2000;

        for (let attempt = 0; attempt <= maxRetries; attempt++) {
            try {
                const response = await this._runReferralWhoisQueryOnce(target, query);
                if (attempt > 0) {
                    this._logReferral(`[referral] rate-limit-recovered query="${query}" source="${target.host}:${target.port}" attempts=${attempt + 1}`);
                }
                return response;
            } catch (error) {
                if (!this._isWhoisRateLimitError(error)) {
                    throw error;
                }

                if (attempt < maxRetries) {
                    this._logReferral(`[referral] rate-limit query="${query}" source="${target.host}:${target.port}" retry=${attempt + 1}/${maxRetries} sleep=${sleepMs}ms`);
                    await this._sleep(sleepMs);
                    continue;
                }

                const message = `Error: whois rate limit ${target.host}:${target.port} query="${query}" retries=${maxRetries} exhausted`;
                throw new Error(message);
            }
        }
    };

    _resolveReferralGeofeedUrls = async (target, query) => {
        const queue = [{target, depth: 0}];
        const visited = new Set();
        const out = [];
        const maxDepth = Math.max(parseInt(this.params.referralDepthLimit || 10), 1);

        while (queue.length > 0 && visited.size < maxDepth) {
            const next = queue.shift();
            const depth = next.depth;
            const current = next.target;
            const key = `${current.host}:${current.port}`;

            if (visited.has(key)) {
                continue;
            }

            visited.add(key);

            const cacheKey = `${query}|${key}`;
            this._logReferral(`[referral] query="${query}" source="${key}" depth=${depth} action=query`);
            this.referralQueryCache[cacheKey] ??= this._runReferralWhoisQuery(current, query);

            try {
                const response = await this.referralQueryCache[cacheKey];
                const extractedGeofeeds = this._extractGeofeedUrlsFromResponse(response);
                out.push(...extractedGeofeeds);
                if (extractedGeofeeds.length > 0) {
                    this._logReferralExtractedGeofeeds({
                        query,
                        target: current,
                        depth,
                        geofeeds: extractedGeofeeds
                    });
                } else {
                    this._logReferral(`[referral] query="${query}" source="${current.host}:${current.port}" depth=${depth} geofeeds=none`);
                }

                if (depth + 1 < maxDepth) {
                    const referrals = this._parseReferralTargets(response);
                    this._logReferral(`[referral] query="${query}" source="${current.host}:${current.port}" depth=${depth} referrals=${referrals.length}`);
                    for (let referral of referrals) {
                        const referralKey = `${referral.host}:${referral.port}`;
                        if (!visited.has(referralKey)) {
                            queue.push({target: referral, depth: depth + 1});
                        }
                    }
                }
            } catch (error) {
                const message = `Error: referral lookup ${current.host}:${current.port} (${error?.message ?? "Unknown error"})`;
                this._logReferral(message);

                if (this.params.referralFailFast) {
                    throw new Error(message);
                }
            }
        }

        return [...new Set(out)];
    };

    _getReferralGeofeedInetnumPairs = (objects = []) => {
        const out = [];
        const candidates = [];
        const seen = new Set();

        for (let object of objects ?? []) {
            const targets = this._getReferralTargetsFromObject(object);

            if (!targets.length) {
                continue;
            }

            const inetnums = this._extractInetnums(object);
            const lastUpdate = this._getLastUpdate(object);

            for (let inetnum of inetnums) {
                const query = this._getReferralQuery(inetnum);
                if (!query) {
                    continue;
                }

                for (let target of targets) {
                    const id = `${inetnum}|${query}|${target.host}:${target.port}`;
                    if (!seen.has(id)) {
                        seen.add(id);
                        candidates.push({inetnum, query, target, lastUpdate});
                    }
                }
            }
        }

        if (!candidates.length) {
            this._logReferral("[referral] candidates=0");
            return Promise.resolve([]);
        }

        this._logReferral(`[referral] candidates=${candidates.length}`);

        const concurrency = Math.max(parseInt(this.params.referralConcurrency || 10), 1);

        return batchPromises(concurrency, candidates, ({inetnum, query, target, lastUpdate}) => {
            return this._resolveReferralGeofeedUrls(target, query)
                .then(geofeeds => {
                    for (let geofeed of geofeeds) {
                        out.push({inetnum, geofeed, lastUpdate});
                    }
                });
        })
            .then(() => out)
            .catch(error => {
                if (this.params.referralFailFast) {
                    return Promise.reject(error);
                }

                this.logger.log(`Error: referral lookup interrupted (${error?.message ?? "Unknown error"})`);
                return out;
            });
    };

    translateObject = (object) => {
        const inetnums = this._extractInetnums(object);
        const geofeeds = this._extractGeofeedUrlsFromObject(object);
        const lastUpdate = this._getLastUpdate(object);

        if (!geofeeds.length || !inetnums.length) {
            return [];
        }

        const out = [];
        for (let inetnum of inetnums) {
            for (let geofeed of geofeeds) {
                out.push({inetnum, geofeed, lastUpdate});
            }
        }

        return out;
    };

    getGeofeedInetnumPairs = () => {
        try {
            if (this.params.test) {
                const prefix = ipUtils.toPrefix(this.params.test.toString().trim());

                if (!ipUtils.isValidPrefix(prefix) && !ipUtils.isValidIP(prefix)) {
                    throw new Error("The input must be an IP or a prefix");
                }

                const index = {};

                return Promise.all([
                    lessSpecific({flag: "h", query: prefix}, (data) => {
                        const flat = data.map(i => i.data).flat().flat().flat();
                        const geofeedAttributes = flat.filter(i => i.key.toLowerCase() === "geofeed");
                        const remarks = flat.filter(i => ["remarks", "comment"].includes(i.key.toLowerCase()));
                        return [...geofeedAttributes, ...remarks].length > 0;
                    }, 12)
                        .then(data => data.map(i => i.data).flat()),
                    explicitTransferCheck({flag: "h", query: prefix}).then(data => data.flat().map(i => i?.data).filter(i => !!i).flat())
                ])
                    .then(answers => answers.flat())
                    .then(answers => {

                        const items = answers.filter(i => i.find(i => ["inetnum", "inet6num", "netrange"].includes(i.key.toLowerCase())) && (i.find(i => i.key === "geofeed") || i.find(i => ["remarks", "comment"].includes(i.key.toLowerCase()) && i.value?.some(this.testGeofeedRemark))));

                        const rangeToPrefix = (inetnum) => {
                            return inetnum?.includes("-")
                                ? ipUtils.ipRangeToCidr(...inetnum?.split("-").map(n => n.trim()))
                                : [inetnum];
                        };

                        for (let item of items) {
                            const inetnums = rangeToPrefix(item.find(i => ["inetnum", "inet6num", "netrange"].includes(i.key.toLowerCase()))?.value);
                            const geofeedAttributes = item.find(i => i.key === "geofeed")?.value;
                            const remarks = item.find(i => ["remarks", "comment"].includes(i.key.toLowerCase()) && i.value?.some(this.testGeofeedRemark))?.value.find(this.testGeofeedRemark);

                            const geofeed = this.matchGeofeedFile(geofeedAttributes ?? remarks)?.[0];

                            if (geofeed) {
                                const strict = !remarks || this.testGeofeedRemarkStrict(remarks);

                                if (!strict) {
                                    console.log(`Error: the remark MUST be in the format: Geofeed https://url/file.csv. Uppercase G, no colon, no quotes, and one space. Current remarks: ${strict}`);
                                }

                                inetnums.forEach(inetnum => {
                                    index[`${inetnum}-${geofeed}`] = {
                                        inetnum,
                                        geofeedAttribute: !!geofeedAttributes,
                                        isRemark: !!remarks,
                                        geofeed,
                                        strict,
                                        whois: item,
                                        lastUpdate: moment() // It doesn't matter in this case
                                    };
                                });
                            }
                        }

                        return Object.values(index);
                    });

            } else {
                return this.getBlocks()
                    .then((objects = []) => {
                        const bulkPairs = objects.map(this.translateObject).flat();
                        return Promise.all([
                            this._getReferralGeofeedInetnumPairs(objects),
                            this._getLiveReferralGeofeedPairs(bulkPairs)
                        ])
                            .then(([referralPairs, liveReferralPairs]) => {
                                const referralAndLivePairs = [...referralPairs, ...liveReferralPairs];
                                this.discoveryStats = {
                                    bulkPairs: bulkPairs.length,
                                    referralPairs: referralPairs.length,
                                    livePairs: liveReferralPairs.length,
                                    bulkUniqueGeofeeds: this._countUniqueGeofeeds(bulkPairs),
                                    referralLiveUniqueGeofeeds: this._countUniqueGeofeeds(referralAndLivePairs),
                                    totalUniqueGeofeeds: this._countUniqueGeofeeds([...bulkPairs, ...referralAndLivePairs])
                                };

                                return [...bulkPairs, ...referralAndLivePairs];
                            });
                    })
                    .then(this.getMostUpdatedInetnums);
            }
        } catch (error) {
            return Promise.reject(error);
        }
    };

    getGeofeeds = () => {
        return this.getGeofeedInetnumPairs()
            .then(this.getGeofeedsFiles)
            .then(data => {
                this._persistCacheIndex();
                if (!this.params.test && !this.params.silent) {
                    console.log(`[stats] geofeeds_unique bulk=${this.discoveryStats.bulkUniqueGeofeeds} live_or_referral=${this.discoveryStats.referralLiveUniqueGeofeeds} total=${this.discoveryStats.totalUniqueGeofeeds}`);
                    console.log(`[stats] geofeed_pairs bulk=${this.discoveryStats.bulkPairs} referral=${this.discoveryStats.referralPairs} live=${this.discoveryStats.livePairs}`);
                }
                if (this.params.disableProcessing) {
                    return [];
                }
                return this.params.test ? data : this.setGeofeedPriority(data);
            });
    };

}
