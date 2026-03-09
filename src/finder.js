import batchPromises from "batch-promises";
import axios from "redaxios";
import WhoisParser from "bulk-whois-parser";
import LongestPrefixMatch from "longest-prefix-match";
import CsvParser from "./csvParser";
import GeofeedUrlStore from "./geofeedUrlStore";
import md5 from "md5";
import fs from "fs";
import moment from "moment";
import ipUtils from "ip-sub";
import {explicitTransferCheck, lessSpecific} from "whois-wrapper";
import {execFile} from "child_process";
import {inspect} from "util";
import {Readable, Transform} from "stream";
import {pipeline} from "stream/promises";
import {Agent} from "undici";

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
            include: ["ripe", "afrinic", "apnic", "arin", "lacnic", "caida"],
            output: "result.csv",
            test: null,
            downloadTimeout: 14,
            referralConcurrency: 10,
            referralTimeout: 10,
            referralFailFast: false,
            arinLiveReferrals: false,
            liveReferralMaxProbes: 20000,
            caidaRootUrl: "https://publicdata.caida.org/datasets/geofeed-whois/",
            daysWhoisSuballocationsCache: 7, // Cannot be less than this
            skipSuballocations: false,
            compileSuballocationLocally: false,
            insecure: false,
            pgsql: false,
            pgsqlUrl: null
        };
        this.params = {
            ...defaults,
            ...(params ?? {})
        };
        this.logger = this.params.logger;
        this.cacheDir = this.params.cacheDir.split("/").filter(i => !!i).join("/") + "/";
        this.csvParser = new CsvParser();
        this.startTime = moment();
        this.discoveryStats = {
            bulkPairs: 0,
            livePairs: 0,
            bulkUniqueGeofeeds: 0,
            liveUniqueGeofeeds: 0,
            totalUniqueGeofeeds: 0,
            caidaSnapshot: null,
            caidaListedUrls: 0,
            caidaAdditionalUrls: 0,
            caidaDownloadCandidates: 0,
            caidaDownloadedUrls: 0
        };

        this.cacheHeadersIndexFileName = this.cacheDir + "cache-index.json";
        this._importCacheHeaderIndex();

        this.whoisRepos = ["ripe", "afrinic", "apnic", "arin", "lacnic"];
        this.connectors = this.whoisRepos.filter(key => this.params.include.includes(key));
        this._caidaGeofeedUrlsPromise = null;
        this._geofeedUrlStorePromise = null;
        this._insecureHttpDispatcher = null;

        this.whoisParsers = {};
        for (let repo of this.connectors) {
            this.whoisParsers[repo] = new WhoisParser({
                cacheDir: this.cacheDir,
                repos: [repo],
                daysWhoisSuballocationsCache: this.params.daysWhoisSuballocationsCache,
                skipSuballocations: this.params.skipSuballocations,
                defaultCacheDays: this.params.whoisCacheDays,
                compileSuballocationLocally: this.params.compileSuballocationLocally,
                userAgent: "geofeed-finder",
                deleteCorruptedCacheFile: true
            });
        }
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

    _sanitizeExtractedUrl = (value) => {
        return this._cleanString(value)
            .replace(/[\^\)\]\}>.,;:]+$/g, "")
            .trim();
    };

    _normalizeDiscoverySource = (value) => {
        return this._cleanString(value).toLowerCase();
    };

    _getRequestFetch = (signal = null) => {
        if (!this.params.insecure && !signal) {
            return fetch;
        }

        if (this.params.insecure && !this._insecureHttpDispatcher) {
            this._insecureHttpDispatcher = new Agent({
                connect: {
                    rejectUnauthorized: false
                }
            });
        }

        return (url, options = {}) => {
            const mergedSignal = signal && options?.signal && typeof AbortSignal?.any === "function"
                ? AbortSignal.any([signal, options.signal])
                : (signal || options?.signal || undefined);

            return fetch(url, {
                ...options,
                ...(mergedSignal ? {signal: mergedSignal} : {}),
                ...(this.params.insecure ? {dispatcher: this._insecureHttpDispatcher} : {})
            });
        };
    };

    _closeRequestFetch = async () => {
        if (!this._insecureHttpDispatcher) {
            return;
        }

        try {
            await this._insecureHttpDispatcher.close();
        } catch (error) {
            this.logger?.log?.(`Error: insecure HTTP dispatcher shutdown (${error?.message ?? "Unknown error"})`);
        } finally {
            this._insecureHttpDispatcher = null;
        }
    };

    _axiosRequest = (config = {}) => {
        const timeout = Number.isFinite(Number(config?.timeout))
            ? Number(config.timeout)
            : 0;
        const controller = new AbortController();
        const signal = config?.signal && typeof AbortSignal?.any === "function"
            ? AbortSignal.any([controller.signal, config.signal])
            : (config?.signal || controller.signal);
        let didTimeout = false;
        const timeoutId = timeout > 0
            ? setTimeout(() => {
                didTimeout = true;
                const reason = new Error(`Request timeout after ${timeout}ms`);
                reason.name = "TimeoutError";
                reason.code = "ETIMEDOUT";
                controller.abort(reason);
            }, timeout)
            : null;

        const normalizeError = (error) => {
            const out = error instanceof Error
                ? error
                : Object.assign(new Error(error?.message ?? "Request failed"), error ?? {});

            out.config ??= {
                url: config?.url,
                method: config?.method,
                timeout
            };

            if (didTimeout) {
                out.name = "TimeoutError";
                out.code = "ETIMEDOUT";
                out.isTimeout = true;
                out.message = `Request timeout after ${timeout}ms`;
            }

            return out;
        };

        return axios({
            ...config,
            fetch: this._getRequestFetch(signal)
        })
            .catch(error => Promise.reject(normalizeError(error)))
            .finally(() => {
                if (timeoutId) {
                    clearTimeout(timeoutId);
                }
            });
    };

    _mergeDiscoverySources = (...sources) => {
        return [...new Set(sources
            .flat()
            .map(this._normalizeDiscoverySource)
            .filter(Boolean))]
            .sort();
    };

    _mergeDiscoveredGeofeedUrl = (index, url, sources = []) => {
        const normalizedUrl = this._cleanString(url);
        if (!normalizedUrl) {
            return;
        }

        index.set(normalizedUrl, this._mergeDiscoverySources(index.get(normalizedUrl), sources));
    };

    _upsertGeofeedInetnumPair = (index, pair) => {
        if (!pair?.inetnum || !pair?.geofeed) {
            return;
        }

        const key = `${pair.inetnum}|${pair.geofeed}`;
        const previous = index.get(key);
        const discoverySources = this._mergeDiscoverySources(previous?.discoverySources, pair?.discoverySources);

        if (!previous || previous.lastUpdate < pair.lastUpdate) {
            index.set(key, {
                ...pair,
                discoverySources
            });
            return;
        }

        previous.discoverySources = discoverySources;
    };

    _visitTranslatedObjectPairs = (object, discoverySources = [], visitor = null) => {
        const translatedPairs = this.translateObject({
            ...object,
            discoverySources: this._mergeDiscoverySources(object?.discoverySources, discoverySources)
        });

        for (let pair of translatedPairs) {
            visitor?.(pair);
        }
    };

    _mergeTranslatedObjectPairs = (index, object, discoverySources = []) => {
        this._visitTranslatedObjectPairs(object, discoverySources, pair => {
            this._upsertGeofeedInetnumPair(index, pair);
        });
    };

    _getGeofeedUrlStore = () => {
        if (!this.params.pgsql) {
            return Promise.resolve(null);
        }

        if (!this.params.pgsqlUrl) {
            return Promise.reject(new Error("PGSQL is required when pgsql persistence is enabled"));
        }

        if (!this._geofeedUrlStorePromise) {
            const store = new GeofeedUrlStore({
                url: this.params.pgsqlUrl,
                logger: this.logger
            });

            this._geofeedUrlStorePromise = store.connect()
                .then(() => store)
                .catch(error => {
                    this._geofeedUrlStorePromise = null;
                    throw error;
                });
        }

        return this._geofeedUrlStorePromise;
    };

    _closeGeofeedUrlStore = () => {
        if (!this._geofeedUrlStorePromise) {
            return Promise.resolve();
        }

        return this._geofeedUrlStorePromise
            .then(store => store?.close?.())
            .catch(() => null)
            .then(() => {
                this._geofeedUrlStorePromise = null;
            });
    };

    _upsertDiscoveredGeofeedUrls = (items = []) => {
        if (!this.params.pgsql || !items.length) {
            return Promise.resolve();
        }

        return this._getGeofeedUrlStore()
            .then(store => store?.upsertDiscoveredUrls(items));
    };

    _recordGeofeedFetchResult = (url, status) => {
        return this._recordGeofeedFetchResultWithText(url, status, null);
    };

    _recordGeofeedFetchResultWithText = (url, status, resultText = null) => {
        if (!this.params.pgsql || !url || !status) {
            return Promise.resolve();
        }

        return this._getGeofeedUrlStore()
            .then(store => store?.updateFetchStatus(url, status, resultText));
    };

    _formatFetchError = (error) => {
        if (!error) {
            return "Unknown error";
        }

        const parts = [];
        if (error.stack) {
            parts.push(error.stack);
        } else if (error.message) {
            parts.push(`${error.message}`);
        } else {
            parts.push(inspect(error, {
                depth: 8,
                compact: false,
                breakLength: Infinity
            }));
        }

        const extra = {};
        for (let key of ["name", "code", "errno", "syscall", "hostname", "type"]) {
            if (error?.[key] !== undefined && error?.[key] !== null && error?.[key] !== "") {
                extra[key] = error[key];
            }
        }

        if (error?.config) {
            extra.config = {
                url: error.config.url,
                method: error.config.method,
                timeout: error.config.timeout
            };
        }

        if (error?.response) {
            extra.response = {
                status: error.response.status,
                statusText: error.response.statusText,
                headers: error.response.headers,
                data: error.response.data
            };
        }

        if (error?.cause) {
            extra.cause = error.cause;
        }

        if (Object.keys(extra).length > 0) {
            parts.push(inspect(extra, {
                depth: 8,
                compact: false,
                breakLength: Infinity
            }));
        }

        return parts.join("\n");
    };

    _getFetchResultText = ({status, error, responseData, url, timeoutMs} = {}) => {
        if (status === "downloaded" || status === "cache") {
            return null;
        }

        if (status === "timeout") {
            return `Error: ${url} timeout after ${timeoutMs}ms`;
        }

        if (status === "invalid") {
            return `Error: ${url} returned HTML instead of CSV`;
        }

        if (error) {
            return `Error: ${url}\n${this._formatFetchError(error)}`;
        }

        if (responseData && /<a|<div|<span|<style|<link/gi.test(responseData)) {
            return `Error: ${url} returned HTML instead of CSV`;
        }

        return `Error: ${url} ${status || "failed"}`;
    };

    _isRequestTimeoutError = (error) => {
        return !!error?.isTimeout || error?.code === "ETIMEDOUT" || error?.name === "TimeoutError";
    };

    _buildDiscoveredGeofeedUrlRecords = ({
        blocks = [],
        discoveredUrlRecords = [],
        customGeofeeds = [],
        caidaUrls = []
    } = {}) => {
        const index = new Map();

        for (let block of blocks ?? []) {
            this._mergeDiscoveredGeofeedUrl(index, block?.geofeed, block?.discoverySources);
        }

        for (let item of discoveredUrlRecords ?? []) {
            this._mergeDiscoveredGeofeedUrl(index, item?.url, item?.sources);
        }

        for (let url of customGeofeeds ?? []) {
            this._mergeDiscoveredGeofeedUrl(index, url, ["custom"]);
        }

        for (let url of caidaUrls ?? []) {
            this._mergeDiscoveredGeofeedUrl(index, url, ["caida"]);
        }

        return [...index.entries()]
            .map(([url, sources]) => ({
                url,
                sources: [...sources].sort()
            }));
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

        return false;
    };

    _getBulkGeofeedInetnumPairs = (onPair = null) => {
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
            "last-modified"
        ];

        const arinTypes = [];
        if (this.params.af.includes(4)) {
            arinTypes.push("NetRange");
        }
        if (this.params.af.includes(6)) {
            arinTypes.push("Net6CIDRBlock");
        }

        const loadBulkRecordsForRepo = (repo) => {
            const parser = this.whoisParsers[repo];
            if (!parser) {
                return Promise.resolve([]);
            }

            return parser.forEachObject(
                selector,
                this.filterFunction,
                standardFields,
                (object) => {
                    if (onPair) {
                        this._visitTranslatedObjectPairs(object, [repo], onPair);
                    } else {
                        this._mergeTranslatedObjectPairs(index, object, [repo]);
                    }
                }
            )
                .catch(error => {
                    this.logger.log(`Error: ${repo} bulk whois records (${error?.message ?? "Unknown error"})`);
                    return null;
                });
        };

        const index = onPair ? null : new Map();
        const arinExtra = this.whoisParsers.arin && arinTypes.length > 0
            ? this.whoisParsers.arin.forEachObject(
                arinTypes,
                this.filterFunction,
                [
                    "NetRange",
                    "Net6CIDRBlock",
                    "CIDR",
                    "Comment",
                    "comments",
                    "Updated"
                ],
                (object) => {
                    const normalizedObject = this._normalizeArinNetRangeObject(object);
                    if (onPair) {
                        this._visitTranslatedObjectPairs(normalizedObject, ["arin"], onPair);
                    } else {
                        this._mergeTranslatedObjectPairs(index, normalizedObject, ["arin"]);
                    }
                }
            )
                .catch(error => {
                    this.logger.log(`Error: ARIN bulk records (${error?.message ?? "Unknown error"})`);
                    return null;
                })
            : Promise.resolve(null);

        return Promise.all([
            ...this.connectors.map(loadBulkRecordsForRepo),
            arinExtra
        ])
            .then(() => onPair ? null : [...index.values()]);
    };

    _parseDirectoryNamesFromIndex = (html = "") => {
        const matches = [...`${html}`.matchAll(/href="([^"]+)"/gi)];
        const out = [];

        for (let match of matches) {
            const href = `${match?.[1] ?? ""}`.trim();
            if (!href || href.startsWith("?") || href.includes("Parent Directory") || !href.endsWith("/")) {
                continue;
            }

            const name = href
                .split("/")
                .map(i => i.trim())
                .filter(Boolean)
                .pop();

            if (name) {
                out.push(name);
            }
        }

        return [...new Set(out)];
    };

    _getLatestCaidaSnapshot = () => {
        const base = `${this.params.caidaRootUrl}`.replace(/\/+$/g, "") + "/";
        const pickLatest = (url, pattern) => {
            return this._axiosRequest({url, method: "GET", timeout: 20000})
                .then(response => {
                    const names = this._parseDirectoryNamesFromIndex(response?.data)
                        .filter(name => pattern.test(name))
                        .sort((a, b) => parseInt(a) - parseInt(b));
                    return names.pop() || null;
                });
        };

        return pickLatest(base, /^\d{4}$/)
            .then(year => {
                if (!year) {
                    return null;
                }
                return pickLatest(`${base}${year}/`, /^\d{2}$/)
                    .then(month => {
                        if (!month) {
                            return null;
                        }

                        return pickLatest(`${base}${year}/${month}/`, /^\d{2}$/)
                            .then(day => {
                                if (!day) {
                                    return null;
                                }

                                return {year, month, day, url: `${base}${year}/${month}/${day}/`};
                            });
                    });
            });
    };

    _extractUrlsFromCaidaList = (content = "") => {
        const urls = content
            .split(/\r?\n/)
            .map(i => i.trim())
            .filter(i => !!i && !i.startsWith("#"))
            .map(line => line.match(/https?:\/\/[^\s"'<>]+/gi) || [])
            .flat()
            .map(this._sanitizeExtractedUrl)
            .filter(Boolean);
        return [...new Set(urls)];
    };

    _fetchCaidaGeofeedUrls = () => {
        return this._getLatestCaidaSnapshot()
            .then(snapshot => {
                if (!snapshot) {
                    return [];
                }

                this.discoveryStats.caidaSnapshot = `${snapshot.year}-${snapshot.month}-${snapshot.day}`;

                const files = [
                    "standard_geofeeds.txt",
                    "non_standard_geofeeds.txt"
                ];

                return Promise.allSettled(files.map(file => this._axiosRequest({
                    url: `${snapshot.url}${file}`,
                    method: "GET",
                    timeout: 20000
                })))
                    .then(results => {
                        const out = [];
                        for (let result of results) {
                            if (result.status === "fulfilled") {
                                out.push(...this._extractUrlsFromCaidaList(result.value?.data));
                            } else {
                                this.logger.log(`Error: caida source (${result?.reason?.message ?? "Unknown error"})`);
                            }
                        }
                        const urls = [...new Set(out)];
                        this.discoveryStats.caidaListedUrls = urls.length;
                        return urls;
                    });
            })
            .catch(error => {
                this.logger.log(`Error: caida source (${error?.message ?? "Unknown error"})`);
                return [];
            });
    };

    _getCaidaGeofeedUrls = () => {
        if (!this.params.include.includes("caida")) {
            return Promise.resolve([]);
        }

        if (!this._caidaGeofeedUrlsPromise) {
            this._caidaGeofeedUrlsPromise = this._fetchCaidaGeofeedUrls();
        }

        return this._caidaGeofeedUrlsPromise;
    };

    _getHeaderValue = (headers, name) => {
        if (!headers || !name) {
            return null;
        }

        if (typeof headers.get === "function") {
            return headers.get(name);
        }

        return headers?.[name.toLowerCase()] ?? headers?.[name] ?? null;
    };

    _getFileName = (file) => {
        return this.cacheDir + md5(file);
    };

    _getTemporaryDirectory = () => {
        return `${this.cacheDir}tmp/`;
    };

    _getTemporaryFileName = (cachedFile) => {
        const fileName = `${cachedFile ?? ""}`.split("/").pop();
        return `${this._getTemporaryDirectory()}${fileName}.tmp`;
    };

    _looksLikeHtmlPrefix = (buffer) => {
        if (!buffer?.length) {
            return false;
        }

        const prefix = buffer
            .toString("utf8")
            .replace(/^\uFEFF/, "")
            .trimStart()
            .toLowerCase();

        return /^(?:<!doctype\s+html\b|<html\b|<head\b|<body\b|<div\b|<span\b|<style\b|<link\b|<a\b)/i.test(prefix);
    };

    _streamResponseToFile = async (response, targetFile) => {
        if (!response?.body) {
            throw new Error("Error: empty response body");
        }

        const sniffLimit = 8192;
        const finder = this;
        let prefixBuffer = Buffer.alloc(0);
        let decided = false;

        const sniffHtmlPrefix = new Transform({
            transform(chunk, encoding, callback) {
                const data = Buffer.isBuffer(chunk)
                    ? chunk
                    : Buffer.from(chunk);

                if (decided) {
                    callback(null, data);
                    return;
                }

                prefixBuffer = Buffer.concat([prefixBuffer, data]);

                if (finder._looksLikeHtmlPrefix(prefixBuffer)) {
                    const error = new Error("HTML instead of CSV");
                    error.geofeedInvalid = true;
                    error.responseData = prefixBuffer.toString("utf8");
                    callback(error);
                    return;
                }

                if (prefixBuffer.length >= sniffLimit) {
                    decided = true;
                    const out = prefixBuffer;
                    prefixBuffer = Buffer.alloc(0);
                    callback(null, out);
                    return;
                }

                callback();
            },
            flush(callback) {
                if (decided || prefixBuffer.length === 0) {
                    callback();
                    return;
                }

                if (finder._looksLikeHtmlPrefix(prefixBuffer)) {
                    const error = new Error("HTML instead of CSV");
                    error.geofeedInvalid = true;
                    error.responseData = prefixBuffer.toString("utf8");
                    callback(error);
                    return;
                }

                this.push(prefixBuffer);
                prefixBuffer = Buffer.alloc(0);
                callback();
            }
        });

        await pipeline(
            Readable.fromWeb(response.body),
            sniffHtmlPrefix,
            fs.createWriteStream(targetFile, {flags: "w"})
        );
    };

    _setGeofeedCacheHeaders = (response, cachedFile) => {
        let setAge = 3600 * 24 * (this.params.geofeedCacheDays || 7); // default 1 week (see draft)

        const cacheControl = this._getHeaderValue(response?.headers, "cache-control");
        if (cacheControl) {
            const maxAge = cacheControl
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

    _getGeofeedFile = async (file) => {
        const abortTimeout = parseInt(this.params.downloadTimeout) * 1000;
        const cachedFile = this._getFileName(file);
        const temporaryFile = this._getTemporaryFileName(cachedFile);

        if (this._isCachedGeofeedValid(cachedFile)) {
            this.logEntry(file, true);
            await this._recordGeofeedFetchResultWithText(file, "cache", this._getFetchResultText({status: "cache"}));
            return {file, status: "cache"};
        }

        if (fs.existsSync(temporaryFile)) {
            fs.unlinkSync(temporaryFile);
        }

        fs.mkdirSync(this._getTemporaryDirectory(), {recursive: true});

        this.logEntry(file, false);

        const controller = new AbortController();
        const requestFetch = this._getRequestFetch(controller.signal);
        let didTimeout = false;
        const timeoutId = setTimeout(() => {
            didTimeout = true;
            const reason = new Error(`Request timeout after ${abortTimeout}ms`);
            reason.name = "TimeoutError";
            reason.code = "ETIMEDOUT";
            controller.abort(reason);
        }, abortTimeout);

        try {
            const response = await requestFetch(file, {
                method: "GET"
            });

            if (!response.ok) {
                const error = new Error(`Request failed with status code ${response.status}`);
                error.response = {
                    status: response.status,
                    statusText: response.statusText,
                    headers: Object.fromEntries(response.headers?.entries?.() ?? [])
                };
                throw error;
            }

            await this._streamResponseToFile(response, temporaryFile);
            fs.renameSync(temporaryFile, cachedFile);
            this._setGeofeedCacheHeaders(response, cachedFile);
            await this._recordGeofeedFetchResultWithText(file, "downloaded", this._getFetchResultText({status: "downloaded", url: file}));
            return {file, status: "downloaded"};
        } catch (rawError) {
            const error = rawError instanceof Error
                ? rawError
                : Object.assign(new Error(rawError?.message ?? "Request failed"), rawError ?? {});

            if (didTimeout) {
                error.name = "TimeoutError";
                error.code = "ETIMEDOUT";
                error.isTimeout = true;
                error.message = `Request timeout after ${abortTimeout}ms`;
            }

            if (fs.existsSync(temporaryFile)) {
                fs.unlinkSync(temporaryFile);
            }

            if (error?.geofeedInvalid) {
                const message = this._getFetchResultText({
                    status: "invalid",
                    url: file,
                    responseData: error.responseData
                });
                this.logger.log(message);
                console.log(message);
                await this._recordGeofeedFetchResultWithText(file, "invalid", message);
                return {file, status: "invalid"};
            }

            const status = this._isRequestTimeoutError(error)
                ? "timeout"
                : "failed";
            const resultText = this._getFetchResultText({
                status,
                error: status === "failed" ? error : null,
                url: file,
                timeoutMs: abortTimeout
            });
            this.logger.log(resultText);
            await this._recordGeofeedFetchResultWithText(file, status, resultText);
            return {file, status};
        } finally {
            clearTimeout(timeoutId);
        }
    };


    getGeofeedsFiles = (blocks) => {
        const out = [];
        const customGeofeeds = this._getCustomGeofeedUrls();
        const isDiscoveryOnly = !Array.isArray(blocks);
        const whoisUrls = isDiscoveryOnly
            ? (blocks?.whoisUrls ?? [])
            : blocks.map(i => i.geofeed);
        const whoisAndCustomUrls = [...new Set([...whoisUrls, ...customGeofeeds].filter(Boolean))];

        return this._getCaidaGeofeedUrls()
            .then(caidaUrls => {
                const baseSet = new Set(whoisAndCustomUrls);
                const caidaAdditionalUrls = [...new Set((caidaUrls ?? []).filter(url => !baseSet.has(url)))];
                const caidaAdditionalSet = new Set(caidaAdditionalUrls);
                const allUrls = [...new Set([...whoisAndCustomUrls, ...(caidaUrls ?? [])])];
                const urlsToCheck = allUrls;
                const half = Math.floor(urlsToCheck.length / 2);
                const caidaDownloadCandidates = urlsToCheck
                    .filter(url => caidaAdditionalSet.has(url))
                    .filter(url => !this._isCachedGeofeedValid(this._getFileName(url)))
                    .length;
                const discoveredUrls = this._buildDiscoveredGeofeedUrlRecords({
                    blocks: isDiscoveryOnly ? [] : blocks,
                    discoveredUrlRecords: isDiscoveryOnly ? (blocks?.discoveredUrlRecords ?? []) : [],
                    customGeofeeds,
                    caidaUrls
                });

                this.discoveryStats.caidaAdditionalUrls = caidaAdditionalUrls.length;
                this.discoveryStats.caidaDownloadCandidates = caidaDownloadCandidates;

                return this._upsertDiscoveredGeofeedUrls(discoveredUrls)
                    .then(() => Promise.all([
                        batchPromises(10, urlsToCheck.slice(0, half), file => this._getGeofeedFile(file)),
                        batchPromises(10, urlsToCheck.slice(half), file => this._getGeofeedFile(file))
                    ]))
                    .then(results => {
                        const downloadResults = results.flat();
                        this.discoveryStats.caidaDownloadedUrls = downloadResults
                            .filter(item => item?.status === "downloaded" && caidaAdditionalSet.has(item?.file))
                            .length;

                        return {caidaAdditionalUrls};
                    });
            })
            .then(({caidaAdditionalUrls}) => {
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

                for (let file of caidaAdditionalUrls) {
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
            const previous = index[key];
            const discoverySources = this._mergeDiscoverySources(previous?.discoverySources, inetnum?.discoverySources);

            if (!previous || previous.lastUpdate < inetnum.lastUpdate) {
                index[key] = {
                    ...inetnum,
                    discoverySources
                };
            } else {
                previous.discoverySources = discoverySources;
            }
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
        return [...new Set(urls.map(this._sanitizeExtractedUrl).filter(Boolean))];
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

    _getDownloadOnlyWhoisDiscovery = () => {
        const bulkPairKeys = new Set();
        const livePairKeys = new Set();
        const bulkGeofeeds = new Set();
        const liveGeofeeds = new Set();
        const allWhoisGeofeeds = new Set();
        const discoveredUrlIndex = new Map();
        const bulkPrefixes = new Set();
        const bulkPrefixMatcher = new LongestPrefixMatch();

        const addBulkPair = (pair) => {
            const key = `${pair?.inetnum}|${pair?.geofeed}`;
            if (!pair?.inetnum || !pair?.geofeed) {
                return;
            }

            this._mergeDiscoveredGeofeedUrl(discoveredUrlIndex, pair.geofeed, pair.discoverySources);
            if (bulkPairKeys.has(key)) {
                return;
            }

            bulkPairKeys.add(key);
            bulkGeofeeds.add(pair.geofeed);
            allWhoisGeofeeds.add(pair.geofeed);

            if (ipUtils.isValidPrefix(pair.inetnum) && !bulkPrefixes.has(pair.inetnum)) {
                bulkPrefixes.add(pair.inetnum);
                bulkPrefixMatcher.addPrefix(pair.inetnum, pair.inetnum);
            }
        };

        const addLivePair = (pair) => {
            const key = `${pair?.inetnum}|${pair?.geofeed}`;
            if (!pair?.inetnum || !pair?.geofeed) {
                return;
            }

            this._mergeDiscoveredGeofeedUrl(discoveredUrlIndex, pair.geofeed, pair.discoverySources);
            if (livePairKeys.has(key)) {
                return;
            }

            livePairKeys.add(key);
            liveGeofeeds.add(pair.geofeed);
            allWhoisGeofeeds.add(pair.geofeed);
        };

        return this._getBulkGeofeedInetnumPairs(addBulkPair)
            .then(() => this._getLiveReferralGeofeedPairs({
                bulkPrefixMatcher,
                onPair: addLivePair
            }))
            .then(() => {
                this.discoveryStats = {
                    ...this.discoveryStats,
                    bulkPairs: bulkPairKeys.size,
                    livePairs: livePairKeys.size,
                    bulkUniqueGeofeeds: bulkGeofeeds.size,
                    liveUniqueGeofeeds: liveGeofeeds.size,
                    totalUniqueGeofeeds: allWhoisGeofeeds.size
                };

                return {
                    whoisUrls: [...discoveredUrlIndex.keys()],
                    discoveredUrlRecords: [...discoveredUrlIndex.entries()].map(([url, sources]) => ({
                        url,
                        sources: [...sources].sort()
                    }))
                };
            });
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

            return this._axiosRequest({
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

    _getLiveReferralGeofeedPairs = (options = {}) => {
        if (!this.params.arinLiveReferrals) {
            return Promise.resolve([]);
        }

        const {
            bulkPairs = [],
            bulkPrefixMatcher = null,
            onPair = null
        } = Array.isArray(options)
            ? {bulkPairs: options}
            : (options ?? {});
        const lpm = bulkPrefixMatcher || new LongestPrefixMatch();
        if (!bulkPrefixMatcher) {
            for (let pair of bulkPairs ?? []) {
                if (pair?.geofeed && ipUtils.isValidPrefix(pair?.inetnum)) {
                    lpm.addPrefix(pair.inetnum, pair.inetnum);
                }
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

                const maxProbes = Math.max(parseInt(this.params.liveReferralMaxProbes || 0), 0);
                const sortedUncovered = [...uncovered]
                    .sort((a, b) => (b?.lastUpdate?.valueOf?.() ?? 0) - (a?.lastUpdate?.valueOf?.() ?? 0));
                const toProbe = maxProbes > 0
                    ? sortedUncovered.slice(0, maxProbes)
                    : sortedUncovered;

                this._logReferral(`[referral][live] candidates=${candidates.length} uncovered=${uncovered.length} probing=${toProbe.length} max_probes=${maxProbes > 0 ? maxProbes : "unlimited"}`);
                if (maxProbes > 0 && uncovered.length > maxProbes) {
                    this._logReferral(`[referral][live] probe-limit applied skipped=${uncovered.length - maxProbes}`);
                }

                if (!toProbe.length) {
                    return onPair ? null : [];
                }

                const concurrency = Math.max(parseInt(this.params.referralConcurrency || 10), 1);
                const out = onPair ? null : [];

                return batchPromises(concurrency, toProbe, async candidate => {
                    const query = candidate.query;
                    const target = candidate.target;
                    this._logReferral(`[referral][live] rir=${candidate.rir} query="${query}" inetnum="${candidate.inetnum}" source="${target.host}:${target.port}" action=probe`);

                    try {
                        const response = await this._runReferralWhoisQuery(target, query);
                        const geofeeds = this._extractGeofeedUrlsFromResponse(response);

                        if (geofeeds.length > 0) {
                            this._logReferralExtractedGeofeeds({
                                query,
                                target,
                                depth: 0,
                                geofeeds
                            });

                            for (let geofeed of geofeeds) {
                                const pair = {
                                    inetnum: candidate.inetnum,
                                    geofeed,
                                    lastUpdate: candidate.lastUpdate,
                                    discoverySources: [candidate.rir]
                                };

                                if (onPair) {
                                    onPair(pair);
                                } else {
                                    out.push(pair);
                                }
                            }
                        } else {
                            this._logReferral(`[referral][live] rir=${candidate.rir} query="${query}" inetnum="${candidate.inetnum}" source="${target.host}:${target.port}" geofeeds=none`);
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

    translateObject = (object) => {
        const inetnums = this._extractInetnums(object);
        const geofeeds = this._extractGeofeedUrlsFromObject(object);
        const lastUpdate = this._getLastUpdate(object);
        const discoverySources = this._mergeDiscoverySources(object?.discoverySources);

        if (!geofeeds.length || !inetnums.length) {
            return [];
        }

        const out = [];
        for (let inetnum of inetnums) {
            for (let geofeed of geofeeds) {
                out.push({inetnum, geofeed, lastUpdate, discoverySources});
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
                                        lastUpdate: moment(), // It doesn't matter in this case
                                        discoverySources: ["rdap-test"]
                                    };
                                });
                            }
                        }

                        return Object.values(index);
                    });

            } else {
                if (this.params.disableProcessing && !this.params.test) {
                    return this._getDownloadOnlyWhoisDiscovery();
                }

                return this._getBulkGeofeedInetnumPairs()
                    .then((bulkPairs = []) => this._getLiveReferralGeofeedPairs(bulkPairs)
                        .then((liveReferralPairs) => {
                            this.discoveryStats = {
                                bulkPairs: bulkPairs.length,
                                livePairs: liveReferralPairs.length,
                                bulkUniqueGeofeeds: this._countUniqueGeofeeds(bulkPairs),
                                liveUniqueGeofeeds: this._countUniqueGeofeeds(liveReferralPairs),
                                totalUniqueGeofeeds: this._countUniqueGeofeeds([...bulkPairs, ...liveReferralPairs])
                            };

                            return [...bulkPairs, ...liveReferralPairs];
                        }))
                    .then(this.getMostUpdatedInetnums);
            }
        } catch (error) {
            return Promise.reject(error);
        }
    };

    getGeofeeds = () => {
        const initializePersistence = this.params.pgsql
            ? this._getGeofeedUrlStore()
            : Promise.resolve();

        return initializePersistence
            .then(() => this.getGeofeedInetnumPairs())
            .then(this.getGeofeedsFiles)
            .then(data => {
                this._persistCacheIndex();
                if (!this.params.test && !this.params.silent) {
                    console.log(`[stats] geofeeds_unique bulk=${this.discoveryStats.bulkUniqueGeofeeds} live=${this.discoveryStats.liveUniqueGeofeeds} total=${this.discoveryStats.totalUniqueGeofeeds}`);
                    console.log(`[stats] geofeed_pairs bulk=${this.discoveryStats.bulkPairs} live=${this.discoveryStats.livePairs}`);
                    if (this.params.include.includes("caida")) {
                        const snapshot = this.discoveryStats.caidaSnapshot || "unknown";
                        console.log(`[stats] caida snapshot=${snapshot} listed=${this.discoveryStats.caidaListedUrls} additional=${this.discoveryStats.caidaAdditionalUrls} download_candidates=${this.discoveryStats.caidaDownloadCandidates} downloaded=${this.discoveryStats.caidaDownloadedUrls}`);
                    }
                }
                if (this.params.disableProcessing) {
                    return [];
                }
                return this.params.test ? data : this.setGeofeedPriority(data);
            })
            .finally(() => Promise.allSettled([
                this._closeGeofeedUrlStore(),
                this._closeRequestFetch()
            ]));
    };

}
