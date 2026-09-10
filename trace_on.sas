/* -------------------------------------------------------
   trace_on.sas
   Minimal tracing required for cookie-aware analysis
   ------------------------------------------------------- */

%include 'trace_auth.sas';

list stime;
list log configuration;
list attributes category="Loggers";

/* --- REQUIRED FOR PYTHON TOOL --- */

/* Real cookie numbers (GetCookie / PutCookie) */
set attribute category="Loggers" name="App.Meta" value="Debug";

/* Thread lifetime (IOM CALL / IOM RETURN + inString / outString) */
set attribute category="Loggers" name="App.OMI.OMI.DoRequest" value="Trace";
set attribute category="Loggers" name="App.OMI.MetadataTransport" value="Trace";

/* Performance metrics: OBJ / RQ / RESP / TIME */
set attribute category="Loggers" name="Perf.Meta" value="Info";

/* --- KEEP BASE NOISE LOW --- */

set attribute category="Loggers" name="App" value="Info";
set attribute category="Loggers" name="IOM" value="Info";

/* Optional: comment OUT unless debugging auth */
set attribute category="Loggers" name="Audit" value="OFF";
set attribute category="Loggers" name="Audit.Authentication" value="TRACE";

/* Optional: safety for large XML returns */
set attribute category="Properties" name="IOM.JnlStrMax" value="1000000";
set attribute category="Properties" name="IOM.JnlLineMax" value="1000000";

list attributes category="Loggers";
list attributes category="Properties";

quit;
