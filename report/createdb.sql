CREATE TABLE reports(
  id TEXT PRIMARY KEY, 
  name TEXT NOT NULL
);

CREATE TABLE report_data(
  id TEXT PRIMARY KEY references reports on delete cascade,
  link_self TEXT NOT NULL,
  link_item TEXT NOT NULL,
  retrieved_at BIGINT NOT NULL,
  sha256_hash TEXT, 
  md5_hash TEXT,
  sha1_hash TEXT,
  size BIGINT,
  malicious INT NOT NULL,
  suspicious INT NOT NULL,
  undetected INT NOT NULL,
  harmless INT NOT NULL,
  timeout INT NOT NULL,
  confirmed_timeout INT NOT NULL,
  failure INT NOT NULL,
  type_unsupported INT NOT NULL
);

CREATE TABLE results(
  id TEXT references reports on delete cascade,
  engine TEXT,
  method TEXT NOT NULL,
  version TEXT,
  engine_update TEXT,
  category TEXT,
  result TEXT,
  PRIMARY KEY(id, engine)
);