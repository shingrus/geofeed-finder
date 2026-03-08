create table geofeed_urls (
  id bigint generated always as identity primary key,
  url text not null unique,
  first_seen_at timestamptz not null default now(),
  last_seen_at timestamptz not null default now(),
  last_checked_at timestamptz,
  last_success_at timestamptz,
  last_fetch_status text,
  sources text[] not null default '{}'
);

create index geofeed_urls_last_seen_at_idx
  on geofeed_urls (last_seen_at);

create index geofeed_urls_last_checked_at_idx
  on geofeed_urls (last_checked_at);
