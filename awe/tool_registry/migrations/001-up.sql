BEGIN;
CREATE SCHEMA awe_tr01;
REVOKE ALL ON SCHEMA awe_tr01 FROM PUBLIC;
CREATE ROLE awe_tr01_reader NOLOGIN NOSUPERUSER NOBYPASSRLS;
CREATE ROLE awe_tr01_ingester NOLOGIN NOSUPERUSER NOBYPASSRLS;
CREATE TABLE awe_tr01.schema_version(version integer PRIMARY KEY CHECK(version=1));
INSERT INTO awe_tr01.schema_version VALUES(1);
CREATE TABLE awe_tr01.principals(login name PRIMARY KEY,tenant_id text NOT NULL,actor_id text NOT NULL,expires_at timestamptz NOT NULL,revoked boolean NOT NULL DEFAULT false);
CREATE TABLE awe_tr01.projects(project_id text PRIMARY KEY,tenant_id text NOT NULL,epoch bigint NOT NULL DEFAULT 1 CHECK(epoch>0));
CREATE TABLE awe_tr01.memberships(project_id text REFERENCES awe_tr01.projects,login name REFERENCES awe_tr01.principals,PRIMARY KEY(project_id,login));
CREATE FUNCTION awe_tr01.check_scope(p text,tenant text DEFAULT NULL,actor text DEFAULT NULL) RETURNS boolean
LANGUAGE sql STABLE SECURITY DEFINER SET search_path=pg_catalog,awe_tr01 AS $$
 SELECT EXISTS(SELECT 1 FROM memberships m JOIN principals a USING(login) JOIN projects x USING(project_id)
 WHERE m.project_id=p AND a.login=session_user AND NOT a.revoked AND a.expires_at>clock_timestamp()
 AND x.tenant_id=a.tenant_id AND (tenant IS NULL OR a.tenant_id=tenant) AND (actor IS NULL OR a.actor_id=actor));
$$;
CREATE TABLE awe_tr01.sources(source_id text PRIMARY KEY,kind text NOT NULL CHECK(kind IN ('CATALOG','MCP','GITHUB','NPM','PYPI','DOCS')),url text NOT NULL,trust_rank integer NOT NULL CHECK(trust_rank BETWEEN 0 AND 100));
CREATE TABLE awe_tr01.snapshots(snapshot_id text PRIMARY KEY CHECK(snapshot_id ~ '^[a-f0-9]{64}$'),source_id text NOT NULL REFERENCES awe_tr01.sources,observed_at timestamptz NOT NULL,body_digest text NOT NULL,etag text,cursor_value text,fetch_state text NOT NULL CHECK(fetch_state IN ('LOCAL','FETCHED','UNAVAILABLE','RATE_LIMITED','NOT_MODIFIED')));
CREATE TABLE awe_tr01.tools(tool_id text PRIMARY KEY,title text NOT NULL,canonical_url text NOT NULL UNIQUE,type text NOT NULL,category text NOT NULL,
 found boolean NOT NULL DEFAULT true,study_status text NOT NULL DEFAULT 'METADATA_REVIEWED' CHECK(study_status IN ('FOUND','METADATA_REVIEWED')),
 revision bigint NOT NULL DEFAULT 1 CHECK(revision>0),disabled boolean NOT NULL DEFAULT false,compromised boolean NOT NULL DEFAULT false,
 risk text NOT NULL DEFAULT 'UNKNOWN',hazards text[] NOT NULL DEFAULT '{}',vendor text NOT NULL DEFAULT 'UNKNOWN',last_seen timestamptz NOT NULL,
 search_vector tsvector NOT NULL,metadata_digest text NOT NULL);
CREATE TABLE awe_tr01.project_tools(project_id text REFERENCES awe_tr01.projects,tool_id text REFERENCES awe_tr01.tools,permitted boolean NOT NULL DEFAULT false CHECK(NOT permitted),PRIMARY KEY(project_id,tool_id));
CREATE TABLE awe_tr01.source_records(snapshot_id text REFERENCES awe_tr01.snapshots,original_id text NOT NULL,tool_id text REFERENCES awe_tr01.tools,source_row integer NOT NULL CHECK(source_row>0),locator text NOT NULL,raw_digest text NOT NULL,raw_record jsonb NOT NULL CHECK(jsonb_typeof(raw_record)='object'),PRIMARY KEY(snapshot_id,original_id));
CREATE TABLE awe_tr01.aliases(alias text NOT NULL,tool_id text REFERENCES awe_tr01.tools,snapshot_id text REFERENCES awe_tr01.snapshots,PRIMARY KEY(alias,tool_id,snapshot_id));
CREATE TABLE awe_tr01.source_observations(snapshot_id text REFERENCES awe_tr01.snapshots,original_id text NOT NULL,tool_id text REFERENCES awe_tr01.tools,version_claim text NOT NULL,status_claim text NOT NULL,observed_at timestamptz NOT NULL,claims jsonb NOT NULL,PRIMARY KEY(snapshot_id,original_id));
CREATE TABLE awe_tr01.capabilities(capability text PRIMARY KEY);
CREATE TABLE awe_tr01.tool_capabilities(tool_id text REFERENCES awe_tr01.tools,capability text REFERENCES awe_tr01.capabilities,certainty text NOT NULL CHECK(certainty IN ('INFERRED_FROM_DESCRIPTION','TESTED')),PRIMARY KEY(tool_id,capability));
CREATE TABLE awe_tr01.releases(tool_id text REFERENCES awe_tr01.tools,version text NOT NULL,entry_type text NOT NULL DEFAULT 'UNKNOWN',platform text[] NOT NULL DEFAULT '{}',dependencies jsonb NOT NULL DEFAULT '[]',auth_requirement text NOT NULL DEFAULT 'UNKNOWN',
 verified text NOT NULL DEFAULT 'NOT_RUN' CHECK(verified IN ('NOT_RUN','TESTED','FAILED')),available text NOT NULL DEFAULT 'UNKNOWN' CHECK(available IN ('UNKNOWN','AVAILABLE','UNAVAILABLE')),valid_until timestamptz,
 input_schema_digest text,manifest_digest text,signed_manifest jsonb,PRIMARY KEY(tool_id,version));
CREATE UNIQUE INDEX one_current_release ON awe_tr01.releases(tool_id) WHERE version='UNKNOWN';
CREATE TABLE awe_tr01.costs(tool_id text REFERENCES awe_tr01.tools,version text NOT NULL,amount_micros numeric(20,0) CHECK(amount_micros>=0),currency text CHECK(currency ~ '^[A-Z]{3}$'),basis text NOT NULL DEFAULT 'UNKNOWN',checked_at timestamptz,PRIMARY KEY(tool_id,version),FOREIGN KEY(tool_id,version) REFERENCES awe_tr01.releases);
CREATE TABLE awe_tr01.licenses(tool_id text REFERENCES awe_tr01.tools,version text NOT NULL,expression text NOT NULL DEFAULT 'UNKNOWN',evidence_url text,checked_at timestamptz,PRIMARY KEY(tool_id,version),FOREIGN KEY(tool_id,version) REFERENCES awe_tr01.releases);
CREATE TABLE awe_tr01.reviews(review_id bigint GENERATED ALWAYS AS IDENTITY PRIMARY KEY,tool_id text REFERENCES awe_tr01.tools,kind text NOT NULL,certainty text NOT NULL,evidence_digest text NOT NULL,reviewed_at timestamptz NOT NULL,reviewer text NOT NULL,details jsonb NOT NULL);
CREATE TABLE awe_tr01.revisions(tool_id text REFERENCES awe_tr01.tools,revision bigint NOT NULL,changed_at timestamptz NOT NULL DEFAULT clock_timestamp(),changed_by name NOT NULL DEFAULT session_user,old_record jsonb,new_record jsonb NOT NULL,PRIMARY KEY(tool_id,revision));
CREATE FUNCTION awe_tr01.track_revision() RETURNS trigger LANGUAGE plpgsql SET search_path=pg_catalog,awe_tr01 AS $$
BEGIN
 INSERT INTO revisions(tool_id,revision,old_record,new_record) VALUES(NEW.tool_id,NEW.revision,CASE WHEN TG_OP='UPDATE' THEN to_jsonb(OLD) ELSE NULL END,to_jsonb(NEW));
 RETURN NEW;
END;$$;
CREATE FUNCTION awe_tr01.bump_revision() RETURNS trigger LANGUAGE plpgsql AS $$BEGIN NEW.revision:=OLD.revision+1;RETURN NEW;END;$$;
CREATE TRIGGER tool_revision_number BEFORE UPDATE ON awe_tr01.tools FOR EACH ROW EXECUTE FUNCTION awe_tr01.bump_revision();
CREATE TRIGGER tool_revision AFTER INSERT OR UPDATE ON awe_tr01.tools FOR EACH ROW EXECUTE FUNCTION awe_tr01.track_revision();
CREATE INDEX tools_fts ON awe_tr01.tools USING gin(search_vector);
CREATE INDEX tool_caps_lookup ON awe_tr01.tool_capabilities(capability,tool_id);
CREATE INDEX source_record_tool ON awe_tr01.source_records(tool_id);
CREATE INDEX projects_by_login ON awe_tr01.memberships(login,project_id);
ALTER TABLE awe_tr01.project_tools ENABLE ROW LEVEL SECURITY;
ALTER TABLE awe_tr01.project_tools FORCE ROW LEVEL SECURITY;
CREATE POLICY project_visibility ON awe_tr01.project_tools FOR SELECT USING(awe_tr01.check_scope(project_id));
ALTER TABLE awe_tr01.tools ENABLE ROW LEVEL SECURITY;
ALTER TABLE awe_tr01.tools FORCE ROW LEVEL SECURITY;
CREATE POLICY tool_visibility ON awe_tr01.tools FOR SELECT USING(EXISTS(SELECT 1 FROM awe_tr01.project_tools p WHERE p.tool_id=tools.tool_id));
DO $$DECLARE t text;BEGIN FOREACH t IN ARRAY ARRAY['aliases','tool_capabilities','releases','costs','licenses','reviews','revisions'] LOOP
 EXECUTE format('ALTER TABLE awe_tr01.%I ENABLE ROW LEVEL SECURITY',t);
 EXECUTE format('ALTER TABLE awe_tr01.%I FORCE ROW LEVEL SECURITY',t);
 EXECUTE format('CREATE POLICY scoped_visibility ON awe_tr01.%I FOR SELECT USING(EXISTS(SELECT 1 FROM awe_tr01.tools t WHERE t.tool_id=%I.tool_id))',t,t);
END LOOP;END;$$;
CREATE FUNCTION awe_tr01.tool_view(tid text) RETURNS jsonb LANGUAGE sql STABLE SECURITY INVOKER SET search_path=pg_catalog,awe_tr01 AS $$
 SELECT jsonb_build_object('tool_id',t.tool_id,'title',t.title,'revision',t.revision,'version',r.version,'found',t.found,'studied',t.study_status,'permitted',false,'disabled',t.disabled,'compromised',t.compromised,'hazards',t.hazards,'risk',t.risk,
 'capabilities',COALESCE((SELECT jsonb_agg(capability ORDER BY capability) FROM tool_capabilities WHERE tool_id=t.tool_id),'[]'::jsonb),
 'verified',r.verified,'available',r.available,'valid_until',r.valid_until,'platform',r.platform,'input_schema_digest',r.input_schema_digest,'manifest_digest',r.manifest_digest,'signed_manifest',r.signed_manifest,
 'cost',jsonb_build_object('amount_micros',c.amount_micros::text,'currency',c.currency,'basis',COALESCE(c.basis,'UNKNOWN'),'checked_at',c.checked_at))
 FROM tools t JOIN LATERAL(SELECT * FROM releases WHERE tool_id=t.tool_id ORDER BY (verified='TESTED') DESC,version DESC LIMIT 1) r ON true
 LEFT JOIN costs c ON c.tool_id=t.tool_id AND c.version=r.version WHERE t.tool_id=tid;
$$;
CREATE FUNCTION awe_tr01.discover(p text,caps text[],mode text,platform_filter text,cost_limit text,currency_filter text,n integer,words text) RETURNS SETOF jsonb
LANGUAGE plpgsql STABLE SECURITY INVOKER SET search_path=pg_catalog,awe_tr01 AS $$
BEGIN
 IF p IS NULL OR n IS NULL OR caps IS NULL OR mode IS NULL OR NOT check_scope(p) OR n NOT BETWEEN 1 AND 20 OR COALESCE(array_length(caps,1),0) NOT BETWEEN 1 AND 8 OR mode NOT IN ('CANDIDATES','VERIFIED') OR length(words)>160 THEN RAISE EXCEPTION 'TR_SEARCH_DENIED'; END IF;
 RETURN QUERY SELECT v FROM (SELECT t.tool_id,tool_view(t.tool_id) v,(SELECT count(*) FROM tool_capabilities tc WHERE tc.tool_id=t.tool_id AND tc.capability=ANY(caps))*100 score
 FROM tools t JOIN project_tools pt USING(tool_id) WHERE pt.project_id=p AND NOT t.disabled AND NOT t.compromised AND cardinality(t.hazards)=0
 AND (words IS NULL OR t.search_vector @@ websearch_to_tsquery('simple',words))
 AND EXISTS(SELECT 1 FROM tool_capabilities tc WHERE tc.tool_id=t.tool_id AND tc.capability=ANY(caps))) q
 WHERE (mode='CANDIDATES' OR (v->>'verified'='TESTED' AND v->>'available'='AVAILABLE' AND (v->>'valid_until')::timestamptz>clock_timestamp()))
 AND (platform_filter IS NULL OR (v->'platform') ? platform_filter)
 AND (cost_limit IS NULL OR (v->'cost'->>'currency'=currency_filter AND (v->'cost'->>'amount_micros')::numeric<=cost_limit::numeric))
 ORDER BY score+CASE WHEN v->>'verified'='TESTED' THEN 20 ELSE 0 END+CASE WHEN v->>'available'='AVAILABLE' THEN 10 ELSE 0 END DESC,tool_id COLLATE "C" LIMIT n;
END;$$;
CREATE FUNCTION awe_tr01.ingest(b jsonb) RETURNS jsonb LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog,awe_tr01 AS $$
DECLARE r jsonb; sid text:=b->>'snapshot_id'; count_rows integer:=0; c text; changed boolean;
BEGIN
 IF pg_column_size(b)>33554432 OR jsonb_typeof(b->'records')<>'array' OR jsonb_array_length(b->'records')>5000 OR sid !~ '^[a-f0-9]{64}$' THEN RAISE EXCEPTION 'TR_BATCH'; END IF;
 IF EXISTS(SELECT 1 FROM snapshots WHERE snapshot_id=sid) THEN
  IF (SELECT body_digest FROM snapshots WHERE snapshot_id=sid) IS DISTINCT FROM b->>'body_digest' THEN RAISE EXCEPTION 'TR_SNAPSHOT_COLLISION'; END IF;
  RETURN jsonb_build_object('status','REPLAY','physical_decision','DENY');
 END IF;
 IF EXISTS(SELECT 1 FROM sources WHERE source_id=b->>'source_id' AND (kind<>b->>'kind' OR url<>b->>'url' OR trust_rank<>(b->>'trust_rank')::integer)) THEN RAISE EXCEPTION 'TR_SOURCE_IDENTITY_CHANGED'; END IF;
 INSERT INTO sources VALUES(b->>'source_id',b->>'kind',b->>'url',(b->>'trust_rank')::integer) ON CONFLICT(source_id) DO NOTHING;
 INSERT INTO snapshots VALUES(sid,b->>'source_id',(b->>'observed_at')::timestamptz,b->>'body_digest',b->>'etag',b->>'cursor_value',b->>'fetch_state');
 FOR r IN SELECT value FROM jsonb_array_elements(b->'records') LOOP
  IF r->>'tool_id' !~ '^tool_[a-f0-9]{40}$' OR length(r->>'description')>200000 OR r->>'canonical_url' !~ '^https?://' OR length(r->>'original_id') NOT BETWEEN 1 AND 160 THEN RAISE EXCEPTION 'TR_RECORD'; END IF;
  IF EXISTS(SELECT 1 FROM tools WHERE tool_id=r->>'tool_id' AND canonical_url<>r->>'canonical_url') THEN RAISE EXCEPTION 'TR_TOOL_IDENTITY_CHANGED'; END IF;
  changed:=EXISTS(SELECT 1 FROM tools WHERE tool_id=r->>'tool_id' AND metadata_digest<>r->>'raw_digest');
  INSERT INTO tools(tool_id,title,canonical_url,type,category,hazards,last_seen,search_vector,metadata_digest)
   VALUES(r->>'tool_id',r->>'title',r->>'canonical_url',r->>'type',r->>'category',ARRAY(SELECT jsonb_array_elements_text(r->'hazards')),(r->>'last_seen')::timestamptz,
    to_tsvector('simple',COALESCE(r->>'title','')||' '||COALESCE(r->>'description','')),r->>'raw_digest')
   ON CONFLICT(tool_id) DO UPDATE SET title=EXCLUDED.title,type=EXCLUDED.type,category=EXCLUDED.category,
    hazards=ARRAY(SELECT DISTINCT unnest(tools.hazards||EXCLUDED.hazards)),last_seen=EXCLUDED.last_seen,search_vector=EXCLUDED.search_vector,metadata_digest=EXCLUDED.metadata_digest
   WHERE tools.metadata_digest<>EXCLUDED.metadata_digest OR tools.last_seen<EXCLUDED.last_seen;
  IF changed THEN UPDATE releases SET verified='NOT_RUN',available='UNKNOWN',valid_until=NULL,manifest_digest=NULL,signed_manifest=NULL WHERE tool_id=r->>'tool_id'; END IF;
  INSERT INTO source_records VALUES(sid,r->>'original_id',r->>'tool_id',(r->>'source_row')::integer,r->'locator'->>'pointer',r->>'raw_digest',r);
  INSERT INTO aliases VALUES(r->>'original_id',r->>'tool_id',sid) ON CONFLICT DO NOTHING;
  INSERT INTO source_observations VALUES(sid,r->>'original_id',r->>'tool_id',COALESCE(r->'source_claims'->>'version','UNKNOWN'),COALESCE(r->'source_claims'->>'status','UNKNOWN'),(r->>'last_seen')::timestamptz,COALESCE(NULLIF(r->'source_claims','null'::jsonb),'{}'::jsonb));
  INSERT INTO releases(tool_id,version) VALUES(r->>'tool_id','UNKNOWN') ON CONFLICT DO NOTHING;
  INSERT INTO costs(tool_id,version) VALUES(r->>'tool_id','UNKNOWN') ON CONFLICT DO NOTHING;
  INSERT INTO licenses(tool_id,version) VALUES(r->>'tool_id','UNKNOWN') ON CONFLICT DO NOTHING;
  FOR c IN SELECT jsonb_array_elements_text(r->'capabilities') LOOP
   IF NOT EXISTS(SELECT 1 FROM capabilities WHERE capability=c) THEN RAISE EXCEPTION 'TR_UNKNOWN_CAPABILITY'; END IF;
   INSERT INTO tool_capabilities VALUES(r->>'tool_id',c,'INFERRED_FROM_DESCRIPTION') ON CONFLICT DO NOTHING;
  END LOOP;
  count_rows:=count_rows+1;
 END LOOP;
 RETURN jsonb_build_object('status','IMPORTED','records',count_rows,'physical_decision','DENY');
END;$$;
INSERT INTO awe_tr01.capabilities SELECT unnest(ARRAY['browser.screenshot','browser.automation','document.generate','document.convert','code.test','code.develop','mcp.server','agent.orchestrate','search.web','memory.retrieve','data.store','security.scan','media.image','media.audio','media.video','model.inference','infra.observe','backup.restore']);
REVOKE ALL ON ALL TABLES IN SCHEMA awe_tr01 FROM PUBLIC;
REVOKE ALL ON ALL FUNCTIONS IN SCHEMA awe_tr01 FROM PUBLIC;
GRANT USAGE ON SCHEMA awe_tr01 TO awe_tr01_reader,awe_tr01_ingester;
GRANT SELECT ON awe_tr01.tools,awe_tr01.project_tools,awe_tr01.aliases,awe_tr01.tool_capabilities,awe_tr01.releases,awe_tr01.costs,awe_tr01.licenses,awe_tr01.reviews,awe_tr01.revisions,awe_tr01.capabilities TO awe_tr01_reader;
GRANT EXECUTE ON FUNCTION awe_tr01.check_scope(text,text,text),awe_tr01.tool_view(text),awe_tr01.discover(text,text[],text,text,text,text,integer,text) TO awe_tr01_reader;
GRANT EXECUTE ON FUNCTION awe_tr01.ingest(jsonb) TO awe_tr01_ingester;
COMMIT;
