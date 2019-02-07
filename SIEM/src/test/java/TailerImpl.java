//import LogTailer
import java.io.*;
import java.util.Random;
import javax.swing.text.html.HTMLDocument.Iterator;
import com.espertech.esper.client.*;
import java.time.LocalTime;



public class TailerImpl {
	
    public static void main(String argv[]) {
    	
		EPServiceProvider engine = EPServiceProviderManager.getDefaultProvider();

    	// init Esper Engine and Patterns
        initFTPbruteForce(engine);
        initHTTPflood(engine);
        
        EPRuntime epRunTime = engine.getEPRuntime();
        
        // ####################################################### //
        // 	Beachte die zwei Pfade zu den jeweiligen Log Dateien   //
        // ####################################################### //
        
        // start FTP listener
        // 
        String ftpFilePath = "C:/Program Files (x86)/FileZilla Server/Logs/FileZilla Server.log";
        File ftpLogFile = new File(ftpFilePath);

        LogTailer ftpTailer = new LogTailer(ftpLogFile);
        LogTailerFTP ftpListener = new LogTailerFTP(epRunTime);
        ftpTailer.addListener(ftpListener);

        //
        //	Falls diesen Log Tailer nicht starten möchtest 
        //	einfach die kommende Zeile mit "new Thread etc." auskommentieren
        // 
        new Thread(ftpTailer).start();


        // start HTTP Listener
        //
        String httpFilePath = "C:/Apache24/logs/access.log";
        File httpLogFile = new File(httpFilePath);

        LogTailer httpTailer = new LogTailer(httpLogFile);
        LogTailerHTTP httpListener = new LogTailerHTTP(epRunTime);
        httpTailer.addListener(httpListener);

        //
        //	Falls diesen Log Tailer nicht starten möchtest 
        //	einfach die kommende Zeile mit "new Thread etc." auskommentieren
        // 
        new Thread(httpTailer).start();
        
    }
    
  
    static void initFTPbruteForce(EPServiceProvider engine) {
    	
    	//Configuration cepConfig = new Configuration();
		//cepConfig.addEventType("Success", successAttempt.class.getName());
        //cepConfig.addEventType("Failed", failedAttempt.class.getName());
        
		//EPServiceProvider engine = EPServiceProviderManager.getProvider("CEP",cepConfig);
		
		//EPServiceProvider engine = EPServiceProviderManager.getDefaultProvider();

		engine.getEPAdministrator().getConfiguration().addEventType("Success", successAttempt.class.getName());
		engine.getEPAdministrator().getConfiguration().addEventType("Failed", failedAttempt.class.getName());

		
		
		//EPRuntime cepRT = engine.getEPRuntime();
		
		
		String epl = "create schema suspicious (source string, fails long)";
		EPAdministrator cepAdm = engine.getEPAdministrator();engine.getEPAdministrator().createEPL(epl);
		epl = "create schema failedBySource as (source string, fails long)";
        engine.getEPAdministrator().createEPL(epl);
        epl = "create schema failedByUser as (user string, fails long)";
        engine.getEPAdministrator().createEPL(epl);
        epl = "create schema successBySource as (source string, success long)";
        engine.getEPAdministrator().createEPL(epl);
        epl = "create schema successAndFailsBySource as (source string, fails long, success long)";
        engine.getEPAdministrator().createEPL(epl);
        epl = "create schema suspiciousSources as (source string, failrate double)";
        engine.getEPAdministrator().createEPL(epl);
        epl = "create schema attack as (source string)";
        engine.getEPAdministrator().createEPL(epl);
        

        cepAdm.createEPL("create window failWindow#length(1000000) as Failed");
        cepAdm.createEPL("create window successWindow#length(1000000) as Success");
        
        cepAdm.createEPL("create window fbs#lastevent as failedBySource");
        cepAdm.createEPL("create window sbs#lastevent as successBySource");
        cepAdm.createEPL("create window fbu#lastevent as failedByUser");
        cepAdm.createEPL("create window fbus#length(1000000) as failedBySource");
        cepAdm.createEPL("create window safbus#length(1000000) as successAndFailsBySource");
        
        cepAdm.createEPL("create window suspSources#lastevent as suspiciousSources");
        cepAdm.createEPL("create window suspSources2#length(1000000) as suspiciousSources");
        cepAdm.createEPL("create window att#lastevent as attack");
        cepAdm.createEPL("create window attu#length(1000000) as attack");
        
        cepAdm.createEPL("insert into failWindow select source, user from Failed").addListener(new AListener());
        
        cepAdm.createEPL("insert into successWindow select source, user from Success").addListener(new AListener());
        
        cepAdm.createEPL("insert into fbs select source, Count(*) as fails from failWindow group by source having Count(*)>19");
        cepAdm.createEPL("insert into fbu select user, Count(*) as fails from failWindow group by user having Count(*)>19");
        cepAdm.createEPL("on fbs insert into sbs select (select source from fbs), Count(*) as success from successWindow where successWindow.source=(select source from fbs) ");
        cepAdm.createEPL("on fbu insert into fbus select source, Count(*) as fails from failWindow  where failWindow.user =(select user from fbu) group by source");
        cepAdm.createEPL("insert into safbus select fbus.source as source, fbus.fails as fails, (select count(*) from successWindow where successWindow.source=fbus.source) as success from fbus").addListener(new AListener());
        cepAdm.createEPL("select count(*) from fbus").addListener(new AListener());
        
        cepAdm.createEPL("on sbs insert into suspSources select fbs.source as source, (fbs.fails/(fbs.fails+(select success from sbs))) as failrate from fbs");
        cepAdm.createEPL("on safbus insert into suspSources2 select safbus.source as source, safbus.fails/(safbus.fails+safbus.success) as failrate from safbus").addListener(new AListener());
        cepAdm.createEPL("on safbus delete from safbus");
        cepAdm.createEPL("on safbus delete from fbus");
        
        cepAdm.createEPL("on suspSources insert into att select suspSources.source as source from suspSources where suspSources.failrate>0.95");
        cepAdm.createEPL("on suspSources2 insert into attu select suspSources2.source as source from suspSources2 where suspSources2.failrate>0.95").addListener(new AListener());
        
        cepAdm.createEPL("on att delete from failWindow where failWindow.source =(select source from fbs)").addListener(new AListener());
        cepAdm.createEPL("on att delete from successWindow where successWindow.source =(select source from fbs)").addListener(new AListener());
        cepAdm.createEPL("on attu delete from successWindow where successWindow.source=(select source from fbus)").addListener(new AListener());
        cepAdm.createEPL("on attu delete from failWindow where failWindow.source=(select attu.source from attu)").addListener(new AListener());
        
        cepAdm.createEPL("on suspSources2 delete from suspSources2");
        cepAdm.createEPL("on att select att.source from att");
        
        //return cepRT;
    }
    
    
	public static class AListener implements UpdateListener {
        public void update(EventBean[] newData, EventBean[] oldData) {
        	for(int i=0;i<newData.length;i++)
        		System.out.println(newData[i].getUnderlying());
//        	System.out.println(newData.length);
        	System.out.println();
        }
	}
	
    static void initHTTPflood(EPServiceProvider engine) {

		//EPServiceProvider engine = EPServiceProviderManager.getDefaultProvider();

		engine.getEPAdministrator().getConfiguration().addEventType(EPLhttpEventConfig.class);

		// List of different IPs accessing the same document in a given timeframe
		String timeBetweenArrivalOfRequestsForSameWantedDocuments = "5 sec";
		String timeFrameOfAllSimiliarRequests = "10 min";

		String ep_sameDoc = "insert into list_of_different_ips_accessing_same_document "
				+ "select a.sourceip as source1, b.sourceip as source2, a.wantedDocument as wantedDoc, a.timeStamp as time, a.counter as currentCount "
				+ "from pattern [every a=EPLhttpEventConfig -> b=EPLhttpEventConfig(a.sourceip != b.sourceip"
				+ ", a.wantedDocument = b.wantedDocument) " + "where timer:within("
				+ timeBetweenArrivalOfRequestsForSameWantedDocuments + ")" + "]#time(" + timeFrameOfAllSimiliarRequests
				+ ")";

		EPStatement statement_ep_sameDoc = engine.getEPAdministrator().createEPL(ep_sameDoc);

		statement_ep_sameDoc.addListener((newData, oldData) -> {
			for (int i = 0; i < newData.length; i++) {
				String source1 = (String) newData[i].get("source1");
				String source2 = (String) newData[i].get("source2");
				String wantedDoc = (String) newData[i].get("wantedDoc");
				LocalTime time = (LocalTime) newData[i].get("time");
				long currentCount = (long) newData[i].get("currentCount");
				
				System.out.println(
						String.format("DEBUG Same Document: %d %s IP1: %s, IP2: %s, Doc: %s", currentCount, time, source1, source2, wantedDoc));
			}
		});

		// Check if ep_sameDoc happens too often
		int maxCountOfSameDoc = 50;

		String ep_sameDocTooOften = "select a.source1 as source1, a.source2 as source2, a.wantedDoc as wantedDoc "
				+ "from pattern [every a=list_of_different_ips_accessing_same_document] "
				+ "group by a.source1 having count(a.source1) > " + maxCountOfSameDoc;
		EPStatement statement_ep_sameDocTooOften = engine.getEPAdministrator().createEPL(ep_sameDocTooOften);

		statement_ep_sameDocTooOften.addListener((newData, oldData) -> {
			for (int i = 0; i < newData.length; i++) {
				String source1 = (String) newData[i].get("source1");
				String source2 = (String) newData[i].get("source2");
				System.out.println(
						String.format("%s and %s access (different) documents simultaneously too often, probably Bots",
								source1, source2));
			}
		});

		// Get, single IP, single target

		String timeBetweenArrivalOfRequestsForSameIPSameTarget = "5 sec";
		String timeFrameOfRequests = "10 min";

		String ep_sameIPsameTarget = "insert into list_of_same_ip_same_document "
				+ "select a.sourceip as source1, a.wantedDocument as wantedDoc, a.timeStamp as time, a.counter as currentCount "
				+ "from pattern [every a=EPLhttpEventConfig -> b=EPLhttpEventConfig(a.sourceip = b.sourceip"
				+ ", a.wantedDocument = b.wantedDocument) " + "where timer:within("
				+ timeBetweenArrivalOfRequestsForSameIPSameTarget + ")" + "]#time(" + timeFrameOfRequests + ")";
		EPStatement statement_ep_sameIPsameTarget = engine.getEPAdministrator().createEPL(ep_sameIPsameTarget);

		statement_ep_sameIPsameTarget.addListener((newData, oldData) -> {
			for (int i = 0; i < newData.length; i++) {
				String source1 = (String) newData[i].get("source1");
				String wantedDoc = (String) newData[i].get("wantedDoc");
				//LocalTime time = (LocalTime) newData[i].get("time");
				long currentCounter = (long) newData[i].get("currentCount");

				System.out.println(
						String.format(" %d DEBUG Same IP Same Document: IP: %s, Document: %s", currentCounter, source1, wantedDoc));
			}
		});

		// Check if sameIPSameTarget happens too often
		int maxCountOfSameIPSameTargetTooOften = 30;

		String ep_sameIPSameTargetTooOften = "select a.source1 as source1, a.wantedDoc as wantedDoc "
				+ "from pattern [every a=list_of_same_ip_same_document] "
				+ "group by a.source1 having count(a.source1) > " + maxCountOfSameIPSameTargetTooOften;
		EPStatement statement_ep_sameIPSameTargetTooOften = engine.getEPAdministrator()
				.createEPL(ep_sameIPSameTargetTooOften);

		statement_ep_sameIPSameTargetTooOften.addListener((newData, oldData) -> {
			for (int i = 0; i < newData.length; i++) {
				String source1 = (String) newData[i].get("source1");
				String wantedDoc = (String) newData[i].get("wantedDoc");
				System.out.println(String.format("IP: %s is accessing %s too often", source1, wantedDoc));
			}
		});

		// Check if ep_sameDocSingleDocTooOften happens too often
		int maxCountOfsameDocSingleDocTooOften = 20;

		String ep_sameDocSingleDocTooOften = "select a.source1 as source1, a.source2 as source2, a.wantedDoc as wantedDoc "
				+ "from pattern [every a=list_of_different_ips_accessing_same_document] "
				+ "group by a.wantedDoc, a.source1 having count(a.wantedDoc) > " + maxCountOfsameDocSingleDocTooOften;
		EPStatement statement_ep_sameDocSingleDocTooOften = engine.getEPAdministrator()
				.createEPL(ep_sameDocSingleDocTooOften);

		statement_ep_sameDocSingleDocTooOften.addListener((newData, oldData) -> {
			for (int i = 0; i < newData.length; i++) {
				String source1 = (String) newData[i].get("source1");
				String source2 = (String) newData[i].get("source2");
				String wantedDoc = (String) newData[i].get("wantedDoc");
				System.out.println(
						String.format("%s and %s access %s too often, probably bots", source1, source2, wantedDoc));
			}
		});

		// Get, single IP, different targets

		String timeBetweenArrivalOfRequestsForSameWantedDocumentsForSameIPSpam = "5 sec";
		String timeFrameOfAllSimiliarRequestsForSameIPSpam = "10 min";
		String maxCountOfSingleIPAccess = "50";

		String ep_sameIPDifTarget = "select a.sourceip as source1 " + "from pattern [every a=EPLhttpEventConfig "
				+ "where timer:within(" + timeBetweenArrivalOfRequestsForSameWantedDocumentsForSameIPSpam + ")"
				+ "]#time(" + timeFrameOfAllSimiliarRequestsForSameIPSpam + ") "
				+ "group by a.sourceip having count(a.sourceip) > " + maxCountOfSingleIPAccess;
		EPStatement statement_ep_sameIPDifTarget = engine.getEPAdministrator().createEPL(ep_sameIPDifTarget);

		statement_ep_sameIPDifTarget.addListener((newData, oldData) -> {
			for (int i = 0; i < newData.length; i++) {
				String source1 = (String) newData[i].get("source1");
				System.out.println(String.format("%s is accessing different documents too often", source1));
			}
		});

		// Get, different IPs, single target

		String timeBetweenArrivalOfRequestsForSameWantedDocumentsForDifIPSpam = "5 sec";
		String timeFrameOfAllSimiliarRequestsForDifIPSpam = "10 min";
		String maxCountOfDifIPAccess = "50";

		String ep_difIPSameTarget = "select a.sourceip as source1, a.wantedDocument as wantedDoc "
				+ "from pattern [every a=EPLhttpEventConfig " + "where timer:within("
				+ timeBetweenArrivalOfRequestsForSameWantedDocumentsForDifIPSpam + ")" + "]#time("
				+ timeFrameOfAllSimiliarRequestsForDifIPSpam + ") "
				+ "group by a.wantedDocument having count(a.wantedDocument) > " + maxCountOfDifIPAccess;
		EPStatement statement_ep_difIPSameTarget = engine.getEPAdministrator().createEPL(ep_difIPSameTarget);

		statement_ep_difIPSameTarget.addListener((newData, oldData) -> {
			for (int i = 0; i < newData.length; i++) {
				String wantedDoc = (String) newData[i].get("wantedDoc");
				System.out.println(String.format(
						"Document %s is being accessed too often in a short timeframe. If no other warnings exist, consider reducing simultaneous user access",
						wantedDoc));
			}
		});

		// Get, different IPs, different targets

		String timeBetweenArrivalOfRequestsForSameWantedDocumentsForDifIPDifTargetSpam = "5 sec";
		String timeFrameOfAllSimiliarRequestsForDifIPDifTargetSpam = "10 min";
		String maxCountOfDifIPDifTargetAccess = "50";

		String ep_difIPDifTarget = "select a.sourceip as source1, a.wantedDocument as wantedDoc "
				+ "from pattern [every a=EPLhttpEventConfig " + "where timer:within("
				+ timeBetweenArrivalOfRequestsForSameWantedDocumentsForDifIPDifTargetSpam + ")" + "]#time("
				+ timeFrameOfAllSimiliarRequestsForDifIPDifTargetSpam + ") " + "having count(*) > "
				+ maxCountOfDifIPDifTargetAccess;
		EPStatement statement_ep_difIPDifTarget = engine.getEPAdministrator().createEPL(ep_difIPDifTarget);

		statement_ep_difIPDifTarget.addListener((newData, oldData) -> {
			for (int i = 0; i < newData.length; i++) {
				System.out.println(String.format(
						"Too many IPs are accessing different documents in a short timeframe. If no other warnings exist, consider reducing simultaneous user access"));
			}
		});

		//return engine.getEPRuntime();
    }
    
    


}   

