export default class GeofeedUrlStore {
    constructor(params = {}) {
        this.url = `${params.url ?? ""}`.trim();
        this.logger = params.logger;
        let Pool;

        try {
            ({Pool} = require("pg"));
        } catch (error) {
            throw new Error(`Error: PostgreSQL persistence requires the pg package (${error?.message ?? "Unknown error"})`);
        }

        this.pool = new Pool({
            connectionString: this.url,
            allowExitOnIdle: true
        });
    }

    _logError = (message) => {
        this.logger?.log?.(message);
    };

    _normalizeSources = (sources = []) => {
        return [...new Set((sources ?? [])
            .map(source => `${source ?? ""}`.trim().toLowerCase())
            .filter(Boolean))]
            .sort();
    };

    connect = async () => {
        try {
            await this.pool.query("SELECT 1 FROM geofeed_urls LIMIT 1");
            return this;
        } catch (error) {
            await this.close();
            throw new Error(`Error: PostgreSQL geofeed_urls table is unavailable (${error?.message ?? "Unknown error"}). Run sql/geofeed_urls.sql first.`);
        }
    };

    upsertDiscoveredUrls = async (items = []) => {
        const index = {};

        for (let item of items ?? []) {
            const url = `${item?.url ?? ""}`.trim();
            if (!url) {
                continue;
            }

            index[url] ??= new Set();

            for (let source of this._normalizeSources(item?.sources)) {
                index[url].add(source);
            }
        }

        const urls = Object.keys(index);
        if (!urls.length) {
            return;
        }

        const records = urls.map(url => ({
            url,
            sources: [...index[url]].sort()
        }));

        await this.pool.query(`
            WITH incoming AS (
                SELECT
                    item->>'url' AS url,
                    COALESCE(
                        ARRAY(
                            SELECT DISTINCT source
                            FROM jsonb_array_elements_text(COALESCE(item->'sources', '[]'::jsonb)) AS source
                            WHERE source IS NOT NULL AND btrim(source) <> ''
                            ORDER BY source
                        ),
                        ARRAY[]::text[]
                    ) AS sources
                FROM jsonb_array_elements($1::jsonb) AS item
            )
            INSERT INTO geofeed_urls (url, last_seen_at, sources)
            SELECT incoming.url, now(), incoming.sources
            FROM incoming
            ON CONFLICT (url) DO UPDATE
            SET
                last_seen_at = now(),
                sources = ARRAY(
                    SELECT DISTINCT source
                    FROM unnest(geofeed_urls.sources || EXCLUDED.sources) AS source
                    WHERE source IS NOT NULL AND btrim(source) <> ''
                    ORDER BY source
                )
        `, [JSON.stringify(records)]);
    };

    updateFetchStatus = async (url, status, resultText = null) => {
        const normalizedUrl = `${url ?? ""}`.trim();
        const normalizedStatus = `${status ?? ""}`.trim().toLowerCase();
        const normalizedResultText = resultText === null || resultText === undefined
            ? null
            : `${resultText}`.trim() || null;

        if (!normalizedUrl || !normalizedStatus) {
            return;
        }

        await this.pool.query(`
            INSERT INTO geofeed_urls (
                url,
                last_checked_at,
                last_success_at,
                last_fetch_status,
                result_text
            )
            VALUES (
                $1,
                now(),
                CASE WHEN $2 = 'downloaded' THEN now() ELSE NULL END,
                $2,
                CASE WHEN $2 = 'downloaded' OR $2 = 'cache' THEN NULL ELSE $3 END
            )
            ON CONFLICT (url) DO UPDATE
            SET
                last_checked_at = EXCLUDED.last_checked_at,
                last_fetch_status = EXCLUDED.last_fetch_status,
                result_text = EXCLUDED.result_text,
                last_success_at = CASE
                    WHEN EXCLUDED.last_fetch_status = 'downloaded' THEN EXCLUDED.last_checked_at
                    ELSE geofeed_urls.last_success_at
                END
        `, [normalizedUrl, normalizedStatus, normalizedResultText]);
    };

    close = async () => {
        try {
            await this.pool.end();
        } catch (error) {
            this._logError(`Error: PostgreSQL pool shutdown (${error?.message ?? "Unknown error"})`);
        }
    };
}
