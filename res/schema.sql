--
-- PostgreSQL database dump
--

-- Dumped from database version 9.5.7
-- Dumped by pg_dump version 9.5.7

SET statement_timeout = 0;
SET lock_timeout = 0;
SET client_encoding = 'UTF8';
SET standard_conforming_strings = on;
SET check_function_bodies = false;
SET client_min_messages = warning;
SET row_security = off;

--
-- Name: plpgsql; Type: EXTENSION; Schema: -; Owner: 
--

CREATE EXTENSION IF NOT EXISTS plpgsql WITH SCHEMA pg_catalog;


--
-- Name: EXTENSION plpgsql; Type: COMMENT; Schema: -; Owner: 
--

COMMENT ON EXTENSION plpgsql IS 'PL/pgSQL procedural language';


SET search_path = public, pg_catalog;

SET default_tablespace = '';

SET default_with_oids = false;

--
-- Name: cases; Type: TABLE; Schema: public; Owner: postgres
--

CREATE TABLE cases (
    uuid character varying(50) NOT NULL,
    submittime timestamp with time zone NOT NULL,
    sha256 text,
    fname text,
    status text NOT NULL,
    vm_uuid character varying(50),
    starttime timestamp with time zone,
    endtime timestamp with time zone,
    interactive boolean,
    reboots integer,
    banking boolean,
    web boolean,
    vm_os text,
    runtime integer DEFAULT 180,
	runstyle integer,
	priority integer DEFAULT 0
);


ALTER TABLE cases OWNER TO postgres;

--
-- Name: suspects; Type: TABLE; Schema: public; Owner: postgres
--

CREATE TABLE suspects (
    sha256 text NOT NULL,
    sha1 text,
    md5 text,
    originalname text,
    magic text,
    avresult text,
	exifdata jsonb,
	yararesult jsonb,
    uploadtime timestamp with time zone
);


ALTER TABLE suspects OWNER TO postgres;

--
-- Name: victims; Type: TABLE; Schema: public; Owner: postgres
--

CREATE TABLE victims (
    libvirtname character varying(100),
    uuid character varying(50) NOT NULL,
	guid character varying(50),
    hostname text,
    os text,
    ip text,
    username text,
    password text,
    diskfile text,
    status text,
    runcounter integer DEFAULT 0,
    last_reboot timestamp without time zone,
	display_x integer,
	display_y integer,
	ms_office_type integer,
	ms_office_string text,
	malware_pos_x integer,
	malware_pos_y integer
);


ALTER TABLE victims OWNER TO postgres;

--
-- Name: workerstate; Type: TABLE; Schema: public; Owner: postgres
--

CREATE TABLE workerstate (
    id integer,
    pid integer NOT NULL,
    uuid character varying(50) NOT NULL,
    "position" character varying(50) NOT NULL,
    params text,
    job_uuid character varying(50)
);


ALTER TABLE workerstate OWNER TO postgres;

--
-- Name: victimfiles; Type TABLE; Schema: public; Owner: postgres
--

CREATE TABLE victimfiles (
	uuid varchar(50),
	file_path text NOT NULL,
	os_path text,
	file_stat jsonb,
	yararesult jsonb,
	mimetype text,
	avresult text,
	sha256 varchar(64),
	saved boolean NOT NULL,
	is_artifact boolean DEFAULT FALSE,
	alltext text,
	PRIMARY KEY(uuid, file_path)
);

ALTER TABLE victimfiles OWNER TO postgres;


--
-- Name: sysmon_evts; Type TABLE; Schema: public; Owner: postgres
--

CREATE TABLE sysmon_evts (
	uuid varchar(50),
	recordID int NOT NULL,
	eventID int NOT NULL,
	timestamp timestamp with time zone NOT NULL,
	executionProcess int,
	executionThread int,
	computer text,
	eventData jsonb,
	evt_xml xml,
	alltext text,
	is_artifact boolean DEFAULT FALSE
);

ALTER TABLE sysmon_evts OWNER TO postgres;

CREATE TABLE suricata_dns (
	id SERIAL PRIMARY KEY,
	uuid varchar(50),
	src_ip inet,
	src_port int,
	dest_ip inet,
	dest_port int,
	"timestamp" timestamp with time zone,
	dnsdata jsonb,
	alltext text,
	is_artifact boolean DEFAULT FALSE
);

ALTER TABLE suricata_dns OWNER TO postgres;

CREATE TABLE suricata_http (
	id SERIAL PRIMARY KEY,
	uuid varchar(50),
	src_ip inet,
	src_port int,
	dest_ip inet,
	dest_port int,
	"timestamp" timestamp with time zone,
	httpdata jsonb,
	alltext text,
	is_artifact boolean DEFAULT FALSE
);

ALTER TABLE suricata_http OWNER TO postgres;

CREATE TABLE suricata_alert (
	id SERIAL PRIMARY KEY,
	uuid varchar(50),
	src_ip inet,
	src_port int,
	dest_ip inet,
	dest_port int,
	"timestamp" timestamp with time zone,
	alert jsonb,
	payload text,
	alltext text,
	is_artifact boolean DEFAULT FALSE
);

ALTER TABLE suricata_alert OWNER TO postgres;

CREATE TABLE suricata_tls (
	id SERIAL PRIMARY KEY,
	uuid varchar(50),
	src_ip inet,
	src_port int,
	dest_ip inet,
	dest_port int,
	"timestamp" timestamp with time zone,
	tlsdata jsonb,
	alltext text,
	is_artifact boolean DEFAULT FALSE
);

ALTER TABLE suricata_tls OWNER TO postgres;


CREATE TABLE pcap_summary (
	id SERIAL PRIMARY KEY,
	uuid varchar(50),
	src_ip inet,
	src_port int,
	dest_ip inet,
	dest_port int,
	protocol text
);

ALTER TABLE pcap_summary OWNER TO postgres;

--
-- Name: sysmon_evts_pkey; Type: CONSTRAINT; Schema: public; Owner: postgres
--

ALTER TABLE ONLY sysmon_evts
	ADD CONSTRAINT sysmon_evts_pkey PRIMARY KEY (uuid, recordID);

--
-- Name: cases_pkey; Type: CONSTRAINT; Schema: public; Owner: postgres
--

ALTER TABLE ONLY cases
    ADD CONSTRAINT cases_pkey PRIMARY KEY (uuid);


--
-- Name: suspects_pkey; Type: CONSTRAINT; Schema: public; Owner: postgres
--

ALTER TABLE ONLY suspects
    ADD CONSTRAINT suspects_pkey PRIMARY KEY (sha256);


--
-- Name: victims_pkey; Type: CONSTRAINT; Schema: public; Owner: postgres
--

ALTER TABLE ONLY victims
    ADD CONSTRAINT victims_pkey PRIMARY KEY (uuid);


--
-- Name: workerstate_pkey; Type: CONSTRAINT; Schema: public; Owner: postgres
--

ALTER TABLE ONLY workerstate
    ADD CONSTRAINT workerstate_pkey PRIMARY KEY (uuid);


--
-- Name: cases_sha256_fkey; Type: FK CONSTRAINT; Schema: public; Owner: postgres
--

ALTER TABLE ONLY cases
    ADD CONSTRAINT cases_sha256_fkey FOREIGN KEY (sha256) REFERENCES suspects(sha256);


--
-- Name: victimfiles_fkey; Type: FK CONSTRAINT; Schema: public; Owner: postgres
--

ALTER TABLE ONLY victimfiles
    ADD CONSTRAINT victimfiles_uuid_fkey FOREIGN KEY (uuid) REFERENCES cases(uuid);

--
-- Name: sysmon_evts_fkey; Type: FK CONSTRAINT; Schema: public; Owner: postgres
--

ALTER TABLE ONLY sysmon_evts
    ADD CONSTRAINT sysmon_evts_uuid_fkey FOREIGN KEY (uuid) REFERENCES cases(uuid);


--
-- Name: workerstate_uuid_fkey; Type: FK CONSTRAINT; Schema: public; Owner: postgres
--

ALTER TABLE ONLY workerstate
    ADD CONSTRAINT workerstate_uuid_fkey FOREIGN KEY (uuid) REFERENCES victims(uuid);


ALTER TABLE ONLY suricata_dns
	ADD CONSTRAINT uuid FOREIGN KEY (uuid) REFERENCES cases(uuid);
	
ALTER TABLE ONLY suricata_http
	ADD CONSTRAINT uuid FOREIGN KEY (uuid) REFERENCES cases(uuid);
	
ALTER TABLE ONLY suricata_alert
	ADD CONSTRAINT uuid FOREIGN KEY (uuid) REFERENCES cases(uuid);
	
ALTER TABLE ONLY suricata_tls
	ADD CONSTRAINT uuid FOREIGN KEY (uuid) REFERENCES cases(uuid);

ALTER TABLE ONLY pcap_summary
	ADD CONSTRAINT uuid FOREIGN KEY (uuid) REFERENCES cases(uuid);

CREATE FUNCTION http_text() RETURNS trigger AS $http_text$
	BEGIN
		NEW.alltext := concat_ws(' ', NEW.httpdata#>'{url}', NEW.httpdata#>'{hostname}', NEW.httpdata#>'{http_user_agent}');
		RETURN NEW;
	END;
$http_text$ LANGUAGE plpgsql;

CREATE TRIGGER http_text BEFORE INSERT OR UPDATE ON suricata_http
	FOR EACH ROW EXECUTE PROCEDURE http_text();
	
CREATE FUNCTION dns_text() RETURNS trigger AS $dns_text$
	BEGIN
		NEW.alltext := concat_ws(' ', NEW.dnsdata#>'{rdata}', NEW.dnsdata#>'{rrname}');
		RETURN NEW;
	END;
$dns_text$ LANGUAGE plpgsql;

CREATE TRIGGER dns_text BEFORE INSERT OR UPDATE ON suricata_dns
	FOR EACH ROW EXECUTE PROCEDURE dns_text();

CREATE FUNCTION tls_text() RETURNS trigger AS $tls_text$
	BEGIN
		NEW.alltext := concat_ws(' ', NEW.tlsdata#>'{sni}', NEW.tlsdata#>'{subject}', NEW.tlsdata#>'{issuerdn}');
		RETURN NEW;
	END;
$tls_text$ LANGUAGE plpgsql;

CREATE TRIGGER tls_text BEFORE INSERT OR UPDATE ON suricata_tls
	FOR EACH ROW EXECUTE PROCEDURE tls_text();
	
CREATE FUNCTION alert_text() RETURNS trigger AS $alert_text$
	BEGIN
		NEW.alltext := NEW.alert#>'{signature}';
		RETURN NEW;
	END;
$alert_text$ LANGUAGE plpgsql;

CREATE TRIGGER alert_text BEFORE INSERT OR UPDATE ON suricata_alert
	FOR EACH ROW EXECUTE PROCEDURE alert_text();

CREATE FUNCTION sysmon_text() RETURNS trigger AS $sysmon_text$
	BEGIN
		IF NEW.eventid = 1 THEN
			NEW.alltext = concat_ws(' ', NEW.eventdata#>'{Image}', NEW.eventdata#>'{CommandLine}', NEW.eventdata#>'{ParentImage}');
		END IF;
		IF NEW.eventid = 2 THEN
			NEW.alltext = concat_ws(' ', NEW.eventdata#>'{Image}', NEW.eventdata#>'{TargetFilename}');
		END IF;
		IF NEW.eventid = 3 THEN
			NEW.alltext = concat_ws(' ', NEW.eventdata#>'{Image}', NEW.eventdata#>'{DestinationHostname}');
		END IF;
		IF NEW.eventid = 5 THEN
			NEW.alltext = NEW.eventdata#>'{Image}';
		END IF;
		IF NEW.eventid = 6 THEN
			NEW.alltext = concat_ws(' ', NEW.eventdata#>'{ImageLoaded}', NEW.eventdata#>'{Signature}');
		END IF;
		IF NEW.eventid = 7 THEN
			NEW.alltext = concat_ws(' ', NEW.eventdata#>'{Image}', NEW.eventdata#>'{ImageLoaded}', NEW.eventdata#>'{Company}');
		END IF;
		IF NEW.eventid = 8 THEN
			NEW.alltext = concat_ws(' ', NEW.eventdata#>'{SourceImage}', NEW.eventdata#>'{TargetImage}');
		END IF;
		IF NEW.eventid = 9 THEN
			NEW.alltext = NEW.eventdata#>'{Image}';
		END IF;
		IF NEW.eventid = 10 THEN
			NEW.alltext = concat_ws(' ', NEW.eventdata#>'{SourceImage}', NEW.eventdata#>'{TargetImage}');
		END IF;
		IF NEW.eventid = 11 THEN
			NEW.alltext = concat_ws(' ', NEW.eventdata#>'{Image}', NEW.eventdata#>'{TargetFilename}');
		END IF;
		IF NEW.eventid = 12 THEN
			NEW.alltext = concat_ws(' ', NEW.eventdata#>'{Image}', NEW.eventdata#>'{TargetObject}');
		END IF;
		IF NEW.eventid = 13 THEN
			NEW.alltext = concat_ws(' ', NEW.eventdata#>'{Image}', NEW.eventdata#>'{TargetObject}', NEW.eventdata#>'{Details}');
		END IF;
		IF NEW.eventid = 14 THEN
			NEW.alltext = concat_ws(' ', NEW.eventdata#>'{Image}', NEW.eventdata#>'{TargetObject}', NEW.eventdata#>'{NewName}');
		END IF;
		IF NEW.eventid = 15 THEN
			NEW.alltext = concat_ws(' ', NEW.eventdata#>'{Image}', NEW.eventdata#>'{TargetFilename}');
		END IF;
		IF NEW.eventid = 17 THEN
			NEW.alltext = concat_ws(' ', NEW.eventdata#>'{Image}', NEW.eventdata#>'{PipeName}');
		END IF;
		IF NEW.eventid = 18 THEN
			NEW.alltext = concat_ws(' ', NEW.eventdata#>'{Image}', NEW.eventdata#>'{PipeName}');
		END IF;
		RETURN NEW;
	END;
$sysmon_text$ LANGUAGE plpgsql;

CREATE TRIGGER sysmon_text BEFORE INSERT OR UPDATE ON sysmon_evts
	FOR EACH ROW EXECUTE PROCEDURE sysmon_text();

CREATE FUNCTION file_text() RETURNS trigger AS $file_text$
	BEGIN
		NEW.alltext := concat_ws(' ', NEW.os_path, NEW.avresult, (SELECT string_agg(key, ' ') FROM jsonb_object_keys(NEW.yararesult) as key));
		RETURN NEW;
	END;
$file_text$ LANGUAGE plpgsql;

CREATE TRIGGER file_text BEFORE INSERT OR UPDATE ON victimfiles
	FOR EACH ROW EXECUTE PROCEDURE file_text();
	
CREATE INDEX http_trgm ON suricata_http USING GIN(alltext gin_trgm_ops);
CREATE INDEX tls_trgm ON suricata_tls USING GIN(alltext gin_trgm_ops);
CREATE INDEX dns_trgm ON suricata_dns USING GIN(alltext gin_trgm_ops);
CREATE INDEX alert_trgm ON suricata_alert USING GIN(alltext gin_trgm_ops);
CREATE INDEX sysmon_trgm ON sysmon_evts USING GIN(alltext gin_trgm_ops);
CREATE INDEX files_trgm ON victimfiles USING GIN(alltext gin_trgm_ops);
	
--
-- Name: public; Type: ACL; Schema: -; Owner: postgres
--

REVOKE ALL ON SCHEMA public FROM PUBLIC;
REVOKE ALL ON SCHEMA public FROM postgres;
GRANT ALL ON SCHEMA public TO postgres;
GRANT ALL ON SCHEMA public TO PUBLIC;


--
-- Name: cases; Type: ACL; Schema: public; Owner: postgres
--

REVOKE ALL ON TABLE cases FROM PUBLIC;
REVOKE ALL ON TABLE cases FROM postgres;
GRANT ALL ON TABLE cases TO postgres;


--
-- Name: suspects; Type: ACL; Schema: public; Owner: postgres
--

REVOKE ALL ON TABLE suspects FROM PUBLIC;
REVOKE ALL ON TABLE suspects FROM postgres;
GRANT ALL ON TABLE suspects TO postgres;


--
-- Name: victims; Type: ACL; Schema: public; Owner: postgres
--

REVOKE ALL ON TABLE victims FROM PUBLIC;
REVOKE ALL ON TABLE victims FROM postgres;
GRANT ALL ON TABLE victims TO postgres;


--
-- Name: workerstate; Type: ACL; Schema: public; Owner: postgres
--

REVOKE ALL ON TABLE workerstate FROM PUBLIC;
REVOKE ALL ON TABLE workerstate FROM postgres;
GRANT ALL ON TABLE workerstate TO postgres;

--
-- Name: victimfiles; Type: ACL; Schema: public; Owner: postgres
--

REVOKE ALL ON TABLE victimfiles FROM PUBLIC;
REVOKE ALL ON TABLE victimfiles FROM postgres;
GRANT ALL ON TABLE victimfiles TO postgres;

--
-- Name: sysmon_evts; Type: ACL; Schema: public; Owner: postgres
--

REVOKE ALL ON TABLE sysmon_evts FROM PUBLIC;
REVOKE ALL ON TABLE sysmon_evts FROM postgres;
GRANT ALL ON TABLE sysmon_evts TO postgres;

REVOKE ALL ON TABLE suricata_dns FROM PUBLIC;
REVOKE ALL ON TABLE suricata_dns FROM postgres;
GRANT ALL ON TABLE suricata_dns TO postgres;

REVOKE ALL ON TABLE suricata_http FROM PUBLIC;
REVOKE ALL ON TABLE suricata_http FROM postgres;
GRANT ALL ON TABLE suricata_http TO postgres;

REVOKE ALL ON TABLE suricata_alert FROM PUBLIC;
REVOKE ALL ON TABLE suricata_alert FROM postgres;
GRANT ALL ON TABLE suricata_alert TO postgres;

REVOKE ALL ON TABLE suricata_tls FROM PUBLIC;
REVOKE ALL ON TABLE suricata_tls FROM postgres;
GRANT ALL ON TABLE suricata_tls TO postgres;

REVOKE ALL ON TABLE pcap_summary FROM PUBLIC;
REVOKE ALL ON TABLE pcap_summary FROM postgres;
GRANT ALL ON TABLE pcap_summary TO postgres;

--
-- PostgreSQL database dump complete
--

