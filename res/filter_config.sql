--
-- PostgreSQL database dump
--

-- Dumped from database version 9.6.11
-- Dumped by pg_dump version 9.6.11

-- Started on 2019-05-30 22:31:36 BST

SET statement_timeout = 0;
SET lock_timeout = 0;
SET idle_in_transaction_session_timeout = 0;
SET client_encoding = 'UTF8';
SET standard_conforming_strings = on;
SELECT pg_catalog.set_config('search_path', '', false);
SET check_function_bodies = false;
SET client_min_messages = warning;
SET row_security = off;

SET default_tablespace = '';

SET default_with_oids = false;

--
-- TOC entry 203 (class 1259 OID 39198)
-- Name: filter_config; Type: TABLE; Schema: public; Owner: postgres
--

CREATE TABLE filter_config (
	id SERIAL PRIMARY KEY,
	"enabled" boolean DEFAULT TRUE,
	evttype int,
	conditions jsonb
);

ALTER TABLE filter_config OWNER TO postgres;

CREATE TABLE filter_evttypes (
	evttype int PRIMARY KEY,
	evtname text,
	datasource text
);

ALTER TABLE filter_evttypes OWNER TO postgres;


COPY filter_config (id, enabled, conditions, evttype) FROM stdin;
1	t	[{"field": "eventdata", "method": "rex", "pattern": ["^C:\\\\\\\\Windows\\\\\\\\system32\\\\\\\\schtasks.exe /delete /f /TN \\"Microsoft\\\\\\\\Windows\\\\\\\\Customer Experience Improvement Program\\\\\\\\Uploader\\"", "^C:\\\\\\\\Windows\\\\\\\\system32\\\\\\\\sc.exe start w32time task_started", "^taskhost.exe \\\\$\\\\(Arg0\\\\)", "^\\"taskhost.exe\\"", "^taskhost.exe SYSTEM", "^C:\\\\\\\\Windows\\\\\\\\splwow64.exe", "C:\\\\\\\\Program Files\\\\\\\\Internet Explorer\\\\\\\\iexplore.exe", "C:\\\\\\\\Windows\\\\\\\\system32\\\\\\\\wermgr.exe -queuereporting", "C:\\\\\\\\Windows\\\\\\\\System32\\\\\\\\sdclt.exe /CONFIGNOTIFICATION"], "object_path": ["CommandLine"]}]	1
2	t	[{"field": "eventdata", "method": "rex", "pattern": ["^C:\\\\\\\\Windows\\\\\\\\System32\\\\\\\\wsqmcons.exe"], "object_path": ["ParentCommandLine"]}]	1
8	t	[{"field": "dnsdata", "method": "rex", "pattern": ["\\\\.in-addr\\\\.arpa$", "\\\\.msftncsi\\\\.com$", "\\\\.windowsupdate\\\\.com$", "\\\\.microsoft\\\\.com$", "\\\\.symcd\\\\.com$", "\\\\.symcb\\\\.com$", "\\\\.verisign\\\\.com$", "\\\\.symantec\\\\.com$", "\\\\.bing\\\\.com$", "\\\\.identrust\\\\.com$", "\\\\.google\\\\.com$", "\\\\.amazontrust\\\\.com$", "\\\\.comodoca\\\\.com$", "\\\\.trustwave\\\\.com$", "\\\\.usertrust\\\\.com$", "\\\\.digicert\\\\.com$", "\\\\.godaddy\\\\.com$", "\\\\.geotrust\\\\.com$", "\\\\.globalsign\\\\.com$", "\\\\.rapidssl\\\\.com$", "\\\\.msftncsi\\\\.com$", "\\\\.windows\\\\.com$", "\\\\.verisign\\\\.com$", "\\\\.bing\\\\.com$", "\\\\.windows\\\\.com$"], "object_path": ["rdata"]}]	20
10	t	[{"field": "httpdata", "method": "rex", "pattern": ["\\\\.windowsupdate\\\\.com$", "\\\\.microsoft\\\\.com$", "\\\\.symcd\\\\.com$", "\\\\.windows\\\\.com$", "\\\\.verisign\\\\.com$", "\\\\.bing\\\\.com$", "\\\\.windows\\\\.com$"], "object_path": ["hostname"]}]	21
11	t	[{"field": "tlsdata", "method": "rex", "pattern": ["\\\\.windowsupdate\\\\.com$", "\\\\.microsoft\\\\.com$", "\\\\.symcd\\\\.com$", "\\\\.windows\\\\.com$", "\\\\.verisign\\\\.com$", "\\\\.bing\\\\.com$", "\\\\.windows\\\\.com$"], "object_path": ["sni"]}]	22
12	t	[{"field": "os_path", "method": "rex", "pattern": ["^C:\\\\\\\\Windows\\\\\\\\Temp\\\\\\\\.*?\\\\.sqm$", "^C:\\\\\\\\Windows\\\\\\\\System32\\\\\\\\config\\\\\\\\systemprofile\\\\\\\\AppData\\\\\\\\LocalLow\\\\\\\\Microsoft\\\\\\\\CryptnetUrlCache", "^C:\\\\\\\\ProgramData\\\\\\\\Microsoft\\\\\\\\Windows\\\\\\\\WER", "^C:\\\\\\\\ProgramData\\\\\\\\Microsoft\\\\\\\\RAC\\\\\\\\Temp", "^C:\\\\\\\\Windows\\\\\\\\Performance\\\\\\\\WinSAT", "^C:\\\\\\\\ProgramData\\\\\\\\Microsoft\\\\\\\\Vault", "^C:\\\\\\\\Windows\\\\\\\\System32\\\\\\\\LogFiles", "C:\\\\\\\\Windows\\\\\\\\System32\\\\\\\\config\\\\\\\\SYSTEM$", "C:\\\\\\\\Windows\\\\\\\\System32\\\\\\\\config\\\\\\\\SOFTWARE$", "C:\\\\\\\\Windows\\\\\\\\System32\\\\\\\\config\\\\\\\\SECURITY$", "\\\\\\\\AppData\\\\\\\\Local\\\\\\\\Microsoft\\\\\\\\Windows\\\\\\\\WebCache\\\\\\\\WebCache\\\\w+\\\\.tmp$", "\\\\\\\\Appdata\\\\\\\\Local\\\\\\\\Microsoft\\\\\\\\Windows\\\\\\\\History\\\\\\\\History.IE5\\\\\\\\MSHist\\\\d+\\\\\\\\container.dat$", "NTUSER.DAT$", "\\\\\\\\~\\\\$Normal.dotm$"]}]	30
14	t	[{"field": "dest_ip", "method": "eq", "pattern": ["208.67.222.222", "208.67.220.220", "8.8.8.8", "4.4.4.4"]}, {"field": "dest_port", "method": "eq", "pattern": [53]}]	31
15	t	[{"field": "protocol", "method": "eq", "pattern": ["UDP"]}, {"field": "src_ip", "method": "eq", "pattern": ["208.67.222.222", "208.67.220.220", "8.8.8.8", "4.4.4.4"]}, {"field": "src_port", "method": "eq", "pattern": [53]}]	31
5	t	[{"field": "eventdata", "method": "eq", "pattern": ["c:\\\\windows\\\\system32\\\\samlib.dll"], "object_path": ["ImageLoaded"]}, {"field": "eventdata", "method": "rex", "pattern": ["c:\\\\\\\\program files\\\\\\\\internet explorer\\\\\\\\iexplore.exe$"], "object_path": ["Image"]}]	6
3	t	[{"field": "eventdata", "method": "eq", "pattern": ["c:\\\\windows\\\\system32\\\\wlanapi.dll"], "object_path": ["ImageLoaded"]}, {"field": "eventdata", "method": "rex", "pattern": ["c:\\\\\\\\windows\\\\\\\\coffeesvc.exe$", "C:\\\\\\\\Windows\\\\\\\\System32\\\\\\\\svchost.exe$"], "object_path": ["Image"]}]	6
16	t	[{"field": "protocol", "method": "eq", "pattern": ["UDP"]}, {"field": "dest_port", "method": "eq", "pattern": [5355, 123]}]	31
4	t	[{"field": "eventdata", "method": "eq", "pattern": ["c:\\\\windows\\\\system32\\\\cryptdll.dll"], "object_path": ["ImageLoaded"]}, {"field": "eventdata", "method": "rex", "pattern": ["c:\\\\\\\\windows\\\\\\\\system32\\\\\\\\svchost.exe$"], "object_path": ["Image"]}]	6
13	t	[{"field": "eventdata", "method": "rex", "pattern": ["^C:\\\\\\\\Windows\\\\\\\\System32\\\\\\\\wsqmcons.exe"], "object_path": ["CommandLine"]}, {"field": "eventdata", "method": "eq", "pattern": ["C:\\\\Windows\\\\system32\\\\services.exe"], "object_path": ["ParentCommandLine"]}]	1
6	t	[{"field": "eventdata", "method": "rex", "pattern": ["\\\\\\\\Software\\\\\\\\Microsoft\\\\\\\\Internet Explorer\\\\\\\\Toolbar$"], "object_path": ["TargetObject"]}]	11
7	t	[{"field": "eventdata", "method": "rex", "pattern": ["\\\\\\\\Software\\\\\\\\Microsoft\\\\\\\\Windows\\\\\\\\CurrentVersion\\\\\\\\Explorer\\\\\\\\FileExts\\\\\\\\[^\\\\\\\\]+\\\\\\\\OpenWithList\\\\\\\\a$", "\\\\\\\\Software\\\\\\\\Microsoft\\\\\\\\Windows\\\\\\\\CurrentVersion\\\\\\\\Internet Settings\\\\\\\\ProxyServer$", "\\\\\\\\Software\\\\\\\\Microsoft\\\\\\\\Office\\\\\\\\Common\\\\\\\\Smart Tag\\\\\\\\Applications\\\\\\\\OpusApp\\\\\\\\FriendlyName", "\\\\\\\\System\\\\\\\\CurrentControlSet\\\\\\\\Control\\\\\\\\Power\\\\\\\\User\\\\\\\\PowerSchemes", "\\\\\\\\SOFTWARE\\\\\\\\Microsoft\\\\\\\\Windows\\\\\\\\CurrentVersion\\\\\\\\RunOnce\\\\\\\\WinSATRestorePower$"], "object_path": ["TargetObject"]}]	12
17	t	[{"field": "protocol", "method": "eq", "pattern": ["UDP"]}, {"field": "dest_port", "method": "eq", "pattern": [137]}, {"field": "src_port", "method": "eq", "pattern": [137]}]	31
18	t	[{"field": "protocol", "method": "eq", "pattern": ["TCP"]}, {"field": "dest_port", "method": "eq", "pattern": [80, 443]}]	31
9	t	[{"field": "dnsdata", "method": "rex", "pattern": ["\\\\.in-addr\\\\.arpa$", "\\\\.msftncsi\\\\.com$", "\\\\.windowsupdate\\\\.com$", "\\\\.windows\\\\.com$", "\\\\.akamaitechnologies\\\\.com$", "\\\\.a-msedge\\\\.net$", "\\\\.microsoft\\\\.com$", "\\\\.in-addr\\\\.arpa$", "consent\\\\.google\\\\.com$", "\\\\.bing\\\\.com$"], "object_path": ["rrname"]}]	20
\.


--
-- TOC entry 2239 (class 0 OID 0)
-- Dependencies: 202
-- Name: filter_config_id_seq; Type: SEQUENCE SET; Schema: public; Owner: postgres
--

SELECT pg_catalog.setval('public.filter_config_id_seq', 18, true);


--
-- TOC entry 2111 (class 2606 OID 39207)
-- Name: filter_config filter_config_pkey; Type: CONSTRAINT; Schema: public; Owner: postgres
--

ALTER TABLE ONLY public.filter_config
    ADD CONSTRAINT filter_config_pkey PRIMARY KEY (id);


--
-- TOC entry 2112 (class 2606 OID 39216)
-- Name: filter_config evttype; Type: FK CONSTRAINT; Schema: public; Owner: postgres
--

ALTER TABLE ONLY public.filter_config
    ADD CONSTRAINT evttype FOREIGN KEY (evttype) REFERENCES public.filter_evttypes(evttype);


--
-- TOC entry 2237 (class 0 OID 0)
-- Dependencies: 203
-- Name: TABLE filter_config; Type: ACL; Schema: public; Owner: postgres
--

GRANT ALL ON TABLE public.filter_config TO antfarm;
GRANT ALL ON TABLE filter_evttypes TO antfarm;


-- Completed on 2019-05-30 22:31:36 BST

--
-- PostgreSQL database dump complete
--